//! EIP-712 typed data as a fixed-capacity pool (E-3 P1): no heap, no tree.
//!
//! `eip712.rs` answers "what does this typed data mean" by building owned values
//! (`Vec` / `String` / `BTreeMap`). That shape cannot run on the signer: the device
//! has no allocator, and a hostile QR must never drive unbounded allocation. This
//! module is the zero-heap twin of that parser — it reads the SAME wire (no copies)
//! into caller-provided fixed arrays and hands back read-only views.
//!
//! ```text
//! JSON wire ──scan──> Eip712Type[]  + Eip712Field[]   (the `types` table)
//!            ──scan──> Eip712Node[]                  (domain tree + message tree)
//!                     arena bytes                     (escaped strings only)
//! ```
//!
//! **Offset space (the `MapPool` rule, `chain/btc/psbt.rs`).** Every stored string
//! is named by `(off, len)` in ONE address space whose base is the wire: `off <
//! wire.len()` means "these bytes are already in the wire, borrow them", otherwise
//! the bytes live at `off - wire.len()` in the arena. Unescaped JSON strings are
//! therefore free (they are already sitting in the wire, decoded == raw); only a
//! string that carries a JSON escape is decoded into the arena.
//!
//! **Node layout.** A node's DIRECT children form one contiguous block (`first_child`,
//! `n_children`), which is what makes `children_of` a plain slice; a child's own
//! children get a block of their own, allocated afterwards. Blocks are handed out in
//! allocation order, so every descendant has a higher index than its ancestor — the
//! property `depth_of` relies on.
//!
//! **Capacity is not format.** Running out of nodes / types / fields / arena bytes
//! is `BufferTooSmall` with `ErrorContext::RequiredLength(needed)`: the request is
//! well-formed, it just exceeds what this device models, and the screen must say
//! "request too large" instead of "request data not recognized" (the B-7 lesson).
//! A malformed request answers `EncodingInvalidFormat` instead.
//!
//! **Syntax parity with `eip712.rs`.** The acceptance surface is pinned to the
//! alloc parser by `tests/eip712_pool.rs::syntax_acceptance_matches_alloc_parser`:
//! the scanner below accepts exactly what `eip712::parse_json` accepts (including
//! its quirks: raw control bytes inside strings are allowed, numbers are integers
//! only, `\uXXXX` goes through `u32::from_str_radix` + `char::from_u32`) and applies
//! the same three budgets. Do not tighten one side without the other.
//!
//! **P1 scope.** This module only fills the pool and exposes views. Recomputing the
//! digest from these views and showing the request to the user land in P2/P3; the
//! value payloads are therefore kept as raw text (`"0x…"`, `"115792…"`, `"true"`)
//! rather than decoded numbers — the encoder is the next step's job.
//!
//! **Not-yet-validated.** Atom CONTENT validation (address hex, `uintN` width,
//! `bytesN` length) is deliberately deferred to the encoder: this step answers
//! "does the document have the shape the type table describes", not "is every
//! number inside its declared width".

use crate::error::{ErrorContext, Result, ShlosiloError, ShlosiloErrorKind};

// ─── node kinds ──────────────────────────────────────────────────────────────

/// `bytesN` (N in 1..=32): payload = the raw `"0x…"` text.
pub const KIND_BYTES32: u8 = 0;
/// `address`: payload = the raw `"0x…"` text.
pub const KIND_ADDRESS: u8 = 1;
/// `uintN`: payload = the decimal text (string or JSON number literal).
pub const KIND_UINT256: u8 = 2;
/// `intN`: payload = the decimal text (may carry a leading `-`).
pub const KIND_INT256: u8 = 3;
/// `bool`: payload = `"true"` / `"false"`.
pub const KIND_BOOL: u8 = 4;
/// `string`: payload = the decoded UTF-8 bytes.
pub const KIND_STRING: u8 = 5;
/// `bytes`: payload = the raw text (dynamic hex or literal bytes).
pub const KIND_BYTES: u8 = 6;
/// A struct: payload = the type name; children = the fields in declaration order.
pub const KIND_STRUCT: u8 = 7;
/// An array: no payload; children = the elements in document order. Whether the
/// elements are atoms or structs is readable from `children_of(0).kind` (P3's fold
/// strategy needs exactly that, which is why there is no extra field for it).
pub const KIND_ARRAY: u8 = 8;

// ─── the JSON budgets (copies, not moves) ────────────────────────────────────

/// Same number as `eip712::JSON_MAX_LEN` (16384). Kept as a private copy because
/// that constant is private to `eip712.rs` and making it `pub` is P4's change; the
/// parity pin fails loudly if the two ever drift apart.
const JSON_MAX_LEN: usize = 16 * 1024;
/// Same number as `eip712::JSON_MAX_DEPTH` (32): nesting levels, containers counted.
const JSON_MAX_DEPTH: u32 = 32;
/// Same number as `eip712::JSON_MAX_NODES` (4096): one per JSON value, containers included.
const JSON_MAX_NODES: u32 = 4096;

// ─── records ─────────────────────────────────────────────────────────────────

/// One value-tree node. 16 bytes; a node's children are contiguous in the pool.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Eip712Node {
    /// [`KIND_BYTES32`] … [`KIND_ARRAY`].
    pub kind: u8,
    /// Payload offset (wire-or-arena address space; see the module docs), or 0.
    pub off: u32,
    /// Payload byte length (String/Bytes/atom text/type name), or 0.
    pub len: u32,
    /// Index of the first child (Struct/Array); 0 when the node has none.
    pub first_child: u16,
    /// Number of children.
    pub n_children: u16,
}

/// One entry of the type table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Eip712Type {
    /// Offset of the type name (wire-or-arena address space).
    pub name_off: u16,
    /// Type name length in bytes.
    pub name_len: u8,
    /// Number of fields this type declares.
    pub n_fields: u8,
    /// Index of the type's first field in the field pool (fields are contiguous).
    pub first_field: u16,
}

/// One `(field name, field type)` pair, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Eip712Field {
    /// Offset of the field name (wire-or-arena address space).
    pub name_off: u16,
    /// Field name length in bytes.
    pub name_len: u8,
    /// Offset of the field's type string.
    pub type_off: u16,
    /// Field type string length in bytes.
    pub type_len: u8,
}

/// The node record is the hot type of the review/hash walk: 16 bytes must hold.
const _: () = assert!(core::mem::size_of::<Eip712Node>() == 16);

// ─── the pool ────────────────────────────────────────────────────────────────

/// Fixed-capacity EIP-712 pool: the type table, the value trees and the string arena.
///
/// Filled by [`parse`]; every mutator is private to this module so a caller can only
/// ever see a fully-built pool. All views are read-only and total (they answer
/// `Result` / `Option`, never a panic).
pub struct Eip712Pool<'a> {
    wire: &'a [u8],
    arena: &'a mut [u8],
    arena_used: usize,
    nodes: &'a mut [Eip712Node],
    nodes_len: usize,
    types: &'a mut [Eip712Type],
    types_len: usize,
    fields: &'a mut [Eip712Field],
    fields_len: usize,
    /// `primaryType` string (wire-or-arena offset + length).
    primary_type: Option<(u16, u8)>,
    /// Root node of the `message` tree.
    message_root: Option<u16>,
    /// Root node of the `domain` tree.
    domain_root: Option<u16>,
}

// ─── views ───────────────────────────────────────────────────────────────────

impl<'a> Eip712Pool<'a> {
    fn new_in(
        wire: &'a [u8],
        arena: &'a mut [u8],
        nodes: &'a mut [Eip712Node],
        types: &'a mut [Eip712Type],
        fields: &'a mut [Eip712Field],
    ) -> Self {
        Self {
            wire,
            arena,
            arena_used: 0,
            nodes,
            nodes_len: 0,
            types,
            types_len: 0,
            fields,
            fields_len: 0,
            primary_type: None,
            message_root: None,
            domain_root: None,
        }
    }

    /// Number of types in the table.
    pub fn types_len(&self) -> usize {
        self.types_len
    }

    /// Type record `idx`, or `None` when out of range.
    pub fn type_at(&self, idx: usize) -> Option<&Eip712Type> {
        if idx >= self.types_len {
            return None;
        }
        self.types.get(idx)
    }

    /// The type's name (borrowed from the wire or the arena, never copied).
    pub fn type_name(&self, ty: &Eip712Type) -> Result<&str> {
        self.str_at(ty.name_off as u32, ty.name_len as u32)
    }

    /// The type's fields, in declaration order.
    pub fn fields_of(&self, ty: &Eip712Type) -> Result<&[Eip712Field]> {
        let first = ty.first_field as usize;
        let n = ty.n_fields as usize;
        let end = first.checked_add(n).ok_or_else(fmt_err)?;
        if end > self.fields_len {
            return Err(fmt_err());
        }
        self.fields.get(first..end).ok_or_else(fmt_err)
    }

    /// The field's name.
    pub fn field_name(&self, field: &Eip712Field) -> Result<&str> {
        self.str_at(field.name_off as u32, field.name_len as u32)
    }

    /// The field's declared type string (`"address"`, `"PermitDetails[]"`, …).
    pub fn field_type(&self, field: &Eip712Field) -> Result<&str> {
        self.str_at(field.type_off as u32, field.type_len as u32)
    }

    /// Node `idx`, or `None` when out of range.
    pub fn node(&self, idx: usize) -> Option<&Eip712Node> {
        if idx >= self.nodes_len {
            return None;
        }
        self.nodes.get(idx)
    }

    /// The direct children of node `idx`, as one slice.
    pub fn children_of(&self, idx: usize) -> Result<&[Eip712Node]> {
        let n = self.node(idx).ok_or_else(fmt_err)?;
        let first = n.first_child as usize;
        let count = n.n_children as usize;
        let end = first.checked_add(count).ok_or_else(fmt_err)?;
        if end > self.nodes_len {
            return Err(fmt_err());
        }
        self.nodes.get(first..end).ok_or_else(fmt_err)
    }

    /// The node's payload bytes (decoded text for atoms, the type name for a struct).
    pub fn payload(&self, node: &Eip712Node) -> Result<&[u8]> {
        self.bytes_at(node.off, node.len)
    }

    /// How many levels below its tree root node `idx` sits (the root itself is 0).
    pub fn depth_of(&self, idx: usize) -> Result<usize> {
        if idx >= self.nodes_len {
            return Err(fmt_err());
        }
        for root in [self.domain_root, self.message_root].into_iter().flatten() {
            if let Some(d) = self.depth_in(root as usize, idx, 0, 0) {
                return Ok(d);
            }
        }
        Err(fmt_err())
    }

    /// The `primaryType` string.
    pub fn primary_type(&self) -> Result<&str> {
        let (off, len) = self.primary_type.ok_or_else(fmt_err)?;
        self.str_at(off as u32, len as u32)
    }

    /// Root of the `message` value tree.
    pub fn message(&self) -> Result<&Eip712Node> {
        self.node(self.message_root.ok_or_else(fmt_err)? as usize)
            .ok_or_else(fmt_err)
    }

    /// Root of the `domain` value tree (drawn with the built-in `EIP712Domain` type).
    pub fn domain(&self) -> Result<&Eip712Node> {
        self.node(self.domain_root.ok_or_else(fmt_err)? as usize)
            .ok_or_else(fmt_err)
    }

    /// Index of the `message` root (for callers that walk by index rather than by
    /// reference — the hash and review walks in P2/P3 do).
    pub fn message_root(&self) -> Option<u16> {
        self.message_root
    }

    /// Index of the `domain` root.
    pub fn domain_root(&self) -> Option<u16> {
        self.domain_root
    }

    /// Nodes written so far (domain tree + message tree).
    pub fn nodes_len(&self) -> usize {
        self.nodes_len
    }

    /// Fields written so far (sum over all types).
    pub fn fields_len(&self) -> usize {
        self.fields_len
    }

    /// Arena bytes consumed (escaped strings and the built-in domain type name).
    pub fn arena_used(&self) -> usize {
        self.arena_used
    }

    /// Index of the type called `name`, `"EIP712Domain"` included when present.
    pub fn type_index(&self, name: &str) -> Option<u16> {
        self.type_index_bytes(name.as_bytes()).ok().flatten()
    }

    // ─── byte access (the MapPool offset rule) ───────────────────────────────

    /// Resolve `(off, len)` in the wire-or-arena address space.
    fn bytes_at(&self, off: u32, len: u32) -> Result<&[u8]> {
        let off = off as usize;
        let len = len as usize;
        let end = off.checked_add(len).ok_or_else(fmt_err)?;
        if off < self.wire.len() {
            return self.wire.get(off..end).ok_or_else(fmt_err);
        }
        let start = off - self.wire.len();
        let end = start.checked_add(len).ok_or_else(fmt_err)?;
        self.arena.get(start..end).ok_or_else(fmt_err)
    }

    /// Same, but the bytes are known to be wire bytes (a JSON span under `'a`).
    fn wire_span(&self, span: Span) -> Result<&'a [u8]> {
        let start = span.off as usize;
        let end = start.checked_add(span.len as usize).ok_or_else(fmt_err)?;
        self.wire.get(start..end).ok_or_else(fmt_err)
    }

    fn str_at(&self, off: u32, len: u32) -> Result<&str> {
        core::str::from_utf8(self.bytes_at(off, len)?).map_err(|_| fmt_err())
    }

    /// Depth of `target` inside the subtree rooted at `cur`.
    ///
    /// Descendant blocks always have higher indices than their ancestor, so a child
    /// index above the target cannot contain it; `guard` keeps a (never expected)
    /// cyclic pool from recursing forever.
    fn depth_in(&self, cur: usize, target: usize, depth: usize, guard: usize) -> Option<usize> {
        if guard > JSON_MAX_DEPTH as usize + 1 || cur > target {
            return None;
        }
        if cur == target {
            return Some(depth);
        }
        let n = self.node(cur)?;
        let first = n.first_child as usize;
        for j in 0..n.n_children as usize {
            let child = first.checked_add(j)?;
            if child > target {
                return None;
            }
            if let Some(found) = self.depth_in(child, target, depth + 1, guard + 1) {
                return Some(found);
            }
        }
        None
    }

    fn type_index_bytes(&self, name: &[u8]) -> Result<Option<u16>> {
        for i in 0..self.types_len {
            let ty = self.types.get(i).ok_or_else(fmt_err)?;
            let this = self.bytes_at(ty.name_off as u32, ty.name_len as u32)?;
            if this == name {
                return Ok(Some(i as u16));
            }
        }
        Ok(None)
    }

    // ─── storage helpers (fill side) ─────────────────────────────────────────

    /// Copy `bytes` into the arena and return their `(off, len)`.
    ///
    /// Nothing is committed unless the whole payload fits (F-19): a failed request
    /// must not leave the arena half-eaten with no record pointing at the bytes.
    fn place_arena(&mut self, bytes: &[u8]) -> Result<(u32, u32)> {
        let need = bytes.len();
        let end = self
            .arena_used
            .checked_add(need)
            .ok_or_else(|| cap_err(need))?;
        if end > self.arena.len() {
            return Err(cap_err(end));
        }
        let off = self
            .wire
            .len()
            .checked_add(self.arena_used)
            .ok_or_else(|| cap_err(end))?;
        if off > u32::MAX as usize {
            return Err(cap_err(end));
        }
        let dst = self
            .arena
            .get_mut(self.arena_used..end)
            .ok_or_else(|| cap_err(end))?;
        dst.copy_from_slice(bytes);
        self.arena_used = end;
        Ok((off as u32, need as u32))
    }

    /// Place a JSON string body: borrow the wire bytes when the string carries no
    /// escape (the common case — nothing is copied), decode into the arena otherwise.
    fn place_json_string(&mut self, span: Span) -> Result<(u32, u32)> {
        let enc = self.wire_span(span)?;
        if !enc.contains(&b'\\') {
            return Ok((span.off, span.len));
        }
        let need = decoded_len(enc)?;
        let end = self
            .arena_used
            .checked_add(need)
            .ok_or_else(|| cap_err(need))?;
        if end > self.arena.len() {
            return Err(cap_err(end));
        }
        let off = self
            .wire
            .len()
            .checked_add(self.arena_used)
            .ok_or_else(|| cap_err(end))?;
        if off > u32::MAX as usize {
            return Err(cap_err(end));
        }
        let dst = self
            .arena
            .get_mut(self.arena_used..end)
            .ok_or_else(|| cap_err(end))?;
        decode_into(enc, dst)?;
        self.arena_used = end;
        Ok((off as u32, need as u32))
    }

    /// Same, narrowed to the `u16` name fields of [`Eip712Type`] / [`Eip712Field`].
    fn place_name(&mut self, span: Span) -> Result<(u16, u8)> {
        let enc = self.wire_span(span)?;
        let need = if enc.contains(&b'\\') {
            decoded_len(enc)?
        } else {
            span.len as usize
        };
        if need > u8::MAX as usize {
            return Err(cap_err(need));
        }
        let (off, len) = self.place_json_string(span)?;
        if off > u16::MAX as u32 {
            return Err(cap_err(off as usize));
        }
        Ok((off as u16, len as u8))
    }

    fn push_type(&mut self, name_off: u16, name_len: u8) -> Result<u16> {
        if self.types_len >= self.types.len() {
            return Err(cap_err(self.types_len + 1));
        }
        if self.fields_len > u16::MAX as usize {
            return Err(cap_err(self.fields_len));
        }
        let idx = self.types_len;
        let rec = self.types.get_mut(idx).ok_or_else(|| cap_err(idx + 1))?;
        *rec = Eip712Type {
            name_off,
            name_len,
            n_fields: 0,
            first_field: self.fields_len as u16,
        };
        self.types_len += 1;
        Ok(idx as u16)
    }

    fn patch_type_fields(&mut self, type_idx: u16, n_fields: u8) -> Result<()> {
        let rec = self.types.get_mut(type_idx as usize).ok_or_else(fmt_err)?;
        rec.n_fields = n_fields;
        Ok(())
    }

    fn push_field(&mut self, name: (u16, u8), ty: (u16, u8)) -> Result<()> {
        if self.fields_len >= self.fields.len() {
            return Err(cap_err(self.fields_len + 1));
        }
        let rec = self
            .fields
            .get_mut(self.fields_len)
            .ok_or_else(|| cap_err(self.fields_len + 1))?;
        *rec = Eip712Field {
            name_off: name.0,
            name_len: name.1,
            type_off: ty.0,
            type_len: ty.1,
        };
        self.fields_len += 1;
        Ok(())
    }

    /// Reserve one node slot (the caller fills it with `set_node`).
    fn alloc_slot(&mut self) -> Result<usize> {
        if self.nodes_len >= self.nodes.len() {
            return Err(cap_err(self.nodes_len + 1));
        }
        let idx = self.nodes_len;
        self.nodes_len += 1;
        Ok(idx)
    }

    /// Reserve `count` contiguous sibling slots; returns the first index.
    fn alloc_block(&mut self, count: usize) -> Result<usize> {
        if count > u16::MAX as usize {
            return Err(cap_err(count));
        }
        let end = self
            .nodes_len
            .checked_add(count)
            .ok_or_else(|| cap_err(count))?;
        if end > self.nodes.len() {
            return Err(cap_err(end));
        }
        if end > u16::MAX as usize {
            return Err(cap_err(end));
        }
        let first = self.nodes_len;
        self.nodes_len = end;
        Ok(first)
    }

    fn set_node(&mut self, slot: usize, node: Eip712Node) -> Result<()> {
        let dst = self.nodes.get_mut(slot).ok_or_else(fmt_err)?;
        *dst = node;
        Ok(())
    }
}

// ─── the JSON scanner (skip / read, no tree) ─────────────────────────────────

/// Value tag reported by [`Scanner::scan_value`].
const TAG_OBJECT: u8 = 0;
const TAG_ARRAY: u8 = 1;
const TAG_STRING: u8 = 2;
const TAG_NUMBER: u8 = 3;
const TAG_TRUE: u8 = 4;
const TAG_FALSE: u8 = 5;
const TAG_NULL: u8 = 6;

/// A byte span of the wire, as absolute offsets into the whole document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Span {
    off: u32,
    len: u32,
}

impl Span {
    fn narrow(self, len: usize) -> Result<Self> {
        if len > self.len as usize {
            return Err(fmt_err());
        }
        Ok(Self {
            off: self.off,
            len: len as u32,
        })
    }
}

/// Just enough JSON to know where every value starts and ends.
///
/// It builds nothing: the same wire is walked twice (types first, then the values the
/// types imply), which is why there is no intermediate tree to allocate.
struct Scanner<'a> {
    wire: &'a [u8],
    /// Absolute wire position of `wire[0]` (sub-spans are scanned as their own wire).
    base: usize,
    pos: usize,
    depth: u32,
    nodes: u32,
}

impl<'a> Scanner<'a> {
    fn new(wire: &'a [u8], base: usize) -> Self {
        Self {
            wire,
            base,
            pos: 0,
            depth: 0,
            nodes: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.wire.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn take(&mut self, byte: u8) -> Result<()> {
        if self.peek() != Some(byte) {
            return Err(fmt_err());
        }
        self.pos += 1;
        Ok(())
    }

    fn count_node(&mut self) -> Result<()> {
        self.nodes += 1;
        if self.nodes > JSON_MAX_NODES {
            return Err(fmt_err());
        }
        Ok(())
    }

    fn span(&self, start: usize) -> Span {
        Span {
            off: (self.base + start) as u32,
            len: (self.pos - start) as u32,
        }
    }

    /// The wire bytes of a span produced by this scanner.
    fn span_bytes(&self, span: Span) -> Result<&'a [u8]> {
        let start = (span.off as usize)
            .checked_sub(self.base)
            .ok_or_else(fmt_err)?;
        let end = start.checked_add(span.len as usize).ok_or_else(fmt_err)?;
        self.wire.get(start..end).ok_or_else(fmt_err)
    }

    /// Scan a JSON string and report its body. Escape sequences are validated the
    /// way `eip712.rs` validates them so the two parsers agree on what is a string.
    fn scan_string(&mut self) -> Result<Span> {
        self.take(b'"')?;
        let start = self.pos;
        loop {
            let b = self.peek().ok_or_else(fmt_err)?;
            match b {
                b'"' => {
                    let span = self.span(start);
                    self.pos += 1;
                    return Ok(span);
                }
                b'\\' => {
                    self.pos += 1;
                    self.scan_escape()?;
                }
                // Every other byte passes through, control bytes included: that is
                // what `eip712.rs::Parser::parse_string` does, and the pin holds the
                // two parsers to the same answer.
                _ => self.pos += 1,
            }
        }
    }

    /// Validate one escape (the backslash is already consumed).
    fn scan_escape(&mut self) -> Result<()> {
        let b = self.peek().ok_or_else(fmt_err)?;
        match b {
            b'"' | b'\\' | b'/' | b'n' | b't' | b'r' | b'b' | b'f' => {
                self.pos += 1;
                Ok(())
            }
            b'u' => {
                self.pos += 1;
                let end = self.pos.checked_add(4).ok_or_else(fmt_err)?;
                let hex = self.wire.get(self.pos..end).ok_or_else(fmt_err)?;
                self.pos = end;
                let text = core::str::from_utf8(hex).map_err(|_| fmt_err())?;
                let code = u32::from_str_radix(text, 16).map_err(|_| fmt_err())?;
                match char::from_u32(code) {
                    Some(_) => Ok(()),
                    // Lone surrogates are not characters (same rejection as eip712.rs).
                    None => Err(fmt_err()),
                }
            }
            _ => Err(fmt_err()),
        }
    }

    /// Scan an integer literal, rejecting what `str::parse::<i64>` rejects.
    fn scan_number(&mut self) -> Result<Span> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        let digits = self.wire.get(digits_start..self.pos).ok_or_else(fmt_err)?;
        if digits.is_empty() {
            return Err(fmt_err());
        }
        let limit = if negative {
            (i64::MIN as i128).unsigned_abs()
        } else {
            i64::MAX as u128
        };
        let mut value: u128 = 0;
        for &d in digits {
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add((d - b'0') as u128))
                .ok_or_else(fmt_err)?;
            if value > limit {
                return Err(fmt_err());
            }
        }
        Ok(self.span(start))
    }

    fn scan_literal(&mut self, text: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(text.len()).ok_or_else(fmt_err)?;
        if self.wire.get(self.pos..end) != Some(text) {
            return Err(fmt_err());
        }
        self.pos = end;
        Ok(())
    }

    fn scan_object(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > JSON_MAX_DEPTH {
            return Err(fmt_err());
        }
        let out = self.scan_object_inner();
        self.depth -= 1;
        out
    }

    fn scan_object_inner(&mut self) -> Result<()> {
        self.take(b'{')?;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            self.scan_string()?;
            self.skip_ws();
            self.take(b':')?;
            self.scan_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(fmt_err()),
            }
        }
    }

    fn scan_array(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > JSON_MAX_DEPTH {
            return Err(fmt_err());
        }
        let out = self.scan_array_inner();
        self.depth -= 1;
        out
    }

    fn scan_array_inner(&mut self) -> Result<()> {
        self.take(b'[')?;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.scan_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(fmt_err()),
            }
        }
    }

    /// Validate one value and report its span and tag.
    ///
    /// For a string the span is the BODY (quotes excluded), because that is the
    /// payload a caller keeps; for an object or array it is the whole range
    /// (`{...}` / `[...]`), because that is what a sub-scan needs. Numbers and the
    /// `true` / `false` / `null` literals report their token.
    fn scan_value(&mut self) -> Result<(Span, u8)> {
        self.count_node()?;
        self.skip_ws();
        let start = self.pos;
        if self.peek() == Some(b'"') {
            return Ok((self.scan_string()?, TAG_STRING));
        }
        let tag = match self.peek().ok_or_else(fmt_err)? {
            b'{' => {
                self.scan_object()?;
                TAG_OBJECT
            }
            b'[' => {
                self.scan_array()?;
                TAG_ARRAY
            }
            b'-' | b'0'..=b'9' => {
                self.scan_number()?;
                TAG_NUMBER
            }
            b't' => {
                self.scan_literal(b"true")?;
                TAG_TRUE
            }
            b'f' => {
                self.scan_literal(b"false")?;
                TAG_FALSE
            }
            b'n' => {
                self.scan_literal(b"null")?;
                TAG_NULL
            }
            _ => return Err(fmt_err()),
        };
        Ok((self.span(start), tag))
    }
}

/// Walks the elements of one JSON array in document order.
struct ArrayWalker<'a> {
    sc: Scanner<'a>,
    started: bool,
    done: bool,
}

impl<'a> ArrayWalker<'a> {
    fn new(arr: &'a [u8], base: usize) -> Self {
        let mut sc = Scanner::new(arr, base);
        // The array itself is one level down from its parent object.
        sc.depth = 1;
        Self {
            sc,
            started: false,
            done: false,
        }
    }

    fn next(&mut self) -> Result<Option<(Span, u8)>> {
        if self.done {
            return Ok(None);
        }
        if !self.started {
            self.sc.depth += 1;
            if self.sc.depth > JSON_MAX_DEPTH {
                return Err(fmt_err());
            }
            self.sc.take(b'[')?;
            self.started = true;
            self.sc.skip_ws();
            if self.sc.peek() == Some(b']') {
                self.sc.pos += 1;
                self.sc.depth -= 1;
                self.done = true;
                return Ok(None);
            }
        } else {
            self.sc.skip_ws();
            match self.sc.peek() {
                Some(b',') => self.sc.pos += 1,
                Some(b']') => {
                    self.sc.pos += 1;
                    self.sc.depth -= 1;
                    self.done = true;
                    return Ok(None);
                }
                _ => return Err(fmt_err()),
            }
        }
        Ok(Some(self.sc.scan_value()?))
    }
}

// ─── escape decoding (only used for strings that carry a backslash) ───────────

/// Decode one unit of a JSON string body: `(decoded bytes, produced, consumed)`.
fn decode_unit(enc: &[u8], at: usize) -> Result<([u8; 4], usize, usize)> {
    let b = *enc.get(at).ok_or_else(fmt_err)?;
    if b != b'\\' {
        return Ok(([b, 0, 0, 0], 1, 1));
    }
    let esc = *enc.get(at + 1).ok_or_else(fmt_err)?;
    let simple = match esc {
        b'"' => b'"',
        b'\\' => b'\\',
        b'/' => b'/',
        b'n' => b'\n',
        b't' => b'\t',
        b'r' => b'\r',
        b'b' => 0x08,
        b'f' => 0x0c,
        b'u' => 0,
        _ => return Err(fmt_err()),
    };
    if esc != b'u' {
        return Ok(([simple, 0, 0, 0], 1, 2));
    }
    let start = at + 2;
    let end = start.checked_add(4).ok_or_else(fmt_err)?;
    let hex = enc.get(start..end).ok_or_else(fmt_err)?;
    let text = core::str::from_utf8(hex).map_err(|_| fmt_err())?;
    let code = u32::from_str_radix(text, 16).map_err(|_| fmt_err())?;
    let ch = char::from_u32(code).ok_or_else(fmt_err)?;
    let mut buf = [0u8; 4];
    let produced = ch.encode_utf8(&mut buf).len();
    Ok((buf, produced, 6))
}

/// Decoded length of a JSON string body.
fn decoded_len(enc: &[u8]) -> Result<usize> {
    let mut at = 0usize;
    let mut out = 0usize;
    while at < enc.len() {
        let (_, produced, consumed) = decode_unit(enc, at)?;
        out = out.checked_add(produced).ok_or_else(fmt_err)?;
        at = at.checked_add(consumed).ok_or_else(fmt_err)?;
    }
    Ok(out)
}

/// Decode a JSON string body into `dst` (which must hold exactly `decoded_len` bytes).
fn decode_into(enc: &[u8], dst: &mut [u8]) -> Result<()> {
    let mut at = 0usize;
    let mut out = 0usize;
    while at < enc.len() {
        let (buf, produced, consumed) = decode_unit(enc, at)?;
        let end = out.checked_add(produced).ok_or_else(fmt_err)?;
        let slot = dst.get_mut(out..end).ok_or_else(fmt_err)?;
        slot.copy_from_slice(buf.get(..produced).ok_or_else(fmt_err)?);
        out = end;
        at = at.checked_add(consumed).ok_or_else(fmt_err)?;
    }
    if out == dst.len() {
        Ok(())
    } else {
        Err(fmt_err())
    }
}

/// Does a JSON string body decode to exactly `want`?
///
/// Streaming so that a key comparison never needs a buffer: the pool stores names
/// decoded, the JSON stores them encoded, and both spellings must match.
fn json_eq_decoded(enc: &[u8], want: &[u8]) -> Result<bool> {
    if !enc.contains(&b'\\') {
        return Ok(enc == want);
    }
    let mut at = 0usize;
    let mut out = 0usize;
    while at < enc.len() {
        let (buf, produced, consumed) = decode_unit(enc, at)?;
        let end = out.checked_add(produced).ok_or_else(fmt_err)?;
        if want.get(out..end) != Some(buf.get(..produced).ok_or_else(fmt_err)?) {
            return Ok(false);
        }
        out = end;
        at = at.checked_add(consumed).ok_or_else(fmt_err)?;
    }
    Ok(out == want.len())
}

// ─── type classification ─────────────────────────────────────────────────────

/// What a declared type string names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// An atom, carrying its node kind.
    Atom(u8),
    /// An array; `elem_len` is the byte length of the element type inside the same
    /// type string (the array suffix `[…]` is dropped, exactly as `eip712.rs` does).
    Array { elem_len: u32 },
    /// A user type, carrying its index in the type table.
    Struct(u16),
}

/// Width of a `bytesN` atom (N in 1..=32); `None` for anything else.
///
/// Mirrors `eip712.rs::bytes_n_width`, including the rejection of `bytes`,
/// `bytes0` and `bytes33` — a width outside 1..=32 must not classify as an atom.
fn bytes_n_width(ty: &str) -> Option<usize> {
    let suffix = ty.strip_prefix("bytes")?;
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match suffix.parse::<usize>() {
        Ok(n) if (1..=32).contains(&n) => Some(n),
        _ => None,
    }
}

/// Node kind of an EIP-712 atom type, or `None` when `ty` names a struct.
fn atom_kind(ty: &str) -> Option<u8> {
    if ty == "string" {
        return Some(KIND_STRING);
    }
    if ty == "bytes" {
        return Some(KIND_BYTES);
    }
    if ty == "bool" {
        return Some(KIND_BOOL);
    }
    if ty == "address" {
        return Some(KIND_ADDRESS);
    }
    if ty.starts_with("uint") {
        return Some(KIND_UINT256);
    }
    if ty.starts_with("int") {
        return Some(KIND_INT256);
    }
    if bytes_n_width(ty).is_some() {
        return Some(KIND_BYTES32);
    }
    None
}

// ─── fill: pass 1 (types + primaryType) ──────────────────────────────────────

impl<'a> Eip712Pool<'a> {
    /// Reject a type name the table already carries (`BTreeMap::insert` parity: the
    /// alloc parser keeps the LAST declaration, which would make the digest cover a
    /// different field set than the one we show — refuse instead).
    fn reject_duplicate_type(&self, name: Span) -> Result<()> {
        let enc = self.wire_span(name)?;
        for i in 0..self.types_len {
            let ty = self.types.get(i).ok_or_else(fmt_err)?;
            let known = self.bytes_at(ty.name_off as u32, ty.name_len as u32)?;
            if json_eq_decoded(enc, known)? {
                return Err(fmt_err());
            }
        }
        Ok(())
    }

    /// Fill the `types` object (the scanner sits on its `{`).
    fn fill_types(&mut self, sc: &mut Scanner<'a>) -> Result<()> {
        sc.depth += 1;
        if sc.depth > JSON_MAX_DEPTH {
            return Err(fmt_err());
        }
        let out = self.fill_types_inner(sc);
        sc.depth -= 1;
        out
    }

    fn fill_types_inner(&mut self, sc: &mut Scanner<'a>) -> Result<()> {
        sc.take(b'{')?;
        sc.skip_ws();
        if sc.peek() == Some(b'}') {
            sc.pos += 1;
            return Ok(());
        }
        loop {
            sc.skip_ws();
            let name = sc.scan_string()?;
            self.reject_duplicate_type(name)?;
            sc.skip_ws();
            sc.take(b':')?;
            sc.skip_ws();
            let (name_off, name_len) = self.place_name(name)?;
            let type_idx = self.push_type(name_off, name_len)?;
            let n_fields = self.fill_type_fields(sc)?;
            self.patch_type_fields(type_idx, n_fields)?;
            sc.skip_ws();
            match sc.peek() {
                Some(b',') => sc.pos += 1,
                Some(b'}') => {
                    sc.pos += 1;
                    return Ok(());
                }
                _ => return Err(fmt_err()),
            }
        }
    }

    /// Fill one `[{name, type}, …]` declaration list; returns the field count.
    fn fill_type_fields(&mut self, sc: &mut Scanner<'a>) -> Result<u8> {
        sc.depth += 1;
        if sc.depth > JSON_MAX_DEPTH {
            return Err(fmt_err());
        }
        let out = self.fill_type_fields_inner(sc);
        sc.depth -= 1;
        out
    }

    fn fill_type_fields_inner(&mut self, sc: &mut Scanner<'a>) -> Result<u8> {
        sc.take(b'[')?;
        sc.skip_ws();
        let mut count: u8 = 0;
        if sc.peek() == Some(b']') {
            sc.pos += 1;
            return Ok(0);
        }
        loop {
            sc.skip_ws();
            let (name, ty) = self.scan_field_decl(sc)?;
            if count == u8::MAX {
                return Err(cap_err(count as usize + 1));
            }
            // Capacity before bytes: a refused field must not eat the arena (F-19).
            if self.fields_len >= self.fields.len() {
                return Err(cap_err(self.fields_len + 1));
            }
            let name_placed = self.place_name(name)?;
            let ty_placed = self.place_name(ty)?;
            self.push_field(name_placed, ty_placed)?;
            count += 1;
            sc.skip_ws();
            match sc.peek() {
                Some(b',') => sc.pos += 1,
                Some(b']') => {
                    sc.pos += 1;
                    return Ok(count);
                }
                _ => return Err(fmt_err()),
            }
        }
    }

    /// Read one `{"name": …, "type": …}` declaration.
    ///
    /// Extra keys are ignored (`internalType` is what wallets send and the alloc
    /// parser ignores too); a repeated `name`/`type` key is refused, because the two
    /// parsers must not disagree about which declaration is meant.
    fn scan_field_decl(&self, sc: &mut Scanner<'a>) -> Result<(Span, Span)> {
        sc.depth += 1;
        if sc.depth > JSON_MAX_DEPTH {
            return Err(fmt_err());
        }
        let out = self.scan_field_decl_inner(sc);
        sc.depth -= 1;
        out
    }

    fn scan_field_decl_inner(&self, sc: &mut Scanner<'a>) -> Result<(Span, Span)> {
        sc.take(b'{')?;
        let mut name: Option<Span> = None;
        let mut ty: Option<Span> = None;
        sc.skip_ws();
        if sc.peek() == Some(b'}') {
            return Err(fmt_err());
        }
        loop {
            sc.skip_ws();
            let key = sc.scan_string()?;
            let key_bytes = sc.span_bytes(key)?;
            let is_name = json_eq_decoded(key_bytes, b"name")?;
            let is_type = json_eq_decoded(key_bytes, b"type")?;
            sc.skip_ws();
            sc.take(b':')?;
            sc.skip_ws();
            if !is_name && !is_type {
                sc.scan_value()?;
            } else {
                let value = sc.scan_string()?;
                if is_name {
                    if name.is_some() {
                        return Err(fmt_err());
                    }
                    name = Some(value);
                } else {
                    if ty.is_some() {
                        return Err(fmt_err());
                    }
                    ty = Some(value);
                }
            }
            sc.skip_ws();
            match sc.peek() {
                Some(b',') => sc.pos += 1,
                Some(b'}') => {
                    sc.pos += 1;
                    break;
                }
                _ => return Err(fmt_err()),
            }
        }
        match (name, ty) {
            (Some(n), Some(t)) => Ok((n, t)),
            _ => Err(fmt_err()),
        }
    }

    // ─── fill: pass 2 (domain + message, driven by the type table) ───────────

    /// Classify a declared type string against the type table.
    fn classify(&self, ty: Span) -> Result<Class> {
        let bytes = self.bytes_at(ty.off, ty.len)?;
        let text = core::str::from_utf8(bytes).map_err(|_| fmt_err())?;
        // Array suffix first: `eip712.rs` splits at the first `[` before it looks at
        // atoms, so `uint256[]` is an array of `uint256` and `A[2]` an array of `A`.
        if let Some(at) = text.find('[') {
            return Ok(Class::Array {
                elem_len: at as u32,
            });
        }
        if let Some(kind) = atom_kind(text) {
            return Ok(Class::Atom(kind));
        }
        match self.type_index_bytes(bytes)? {
            Some(idx) => Ok(Class::Struct(idx)),
            None => Err(fmt_err()),
        }
    }

    /// Find `name` among the members of the object at `obj`.
    ///
    /// Returns the first value's `(span, tag)` and how many members carried the name.
    /// `matches > 1` is a duplicate key (the alloc parser rejects those) and
    /// `matches == 0` is a missing field (it rejects those too).
    fn find_member(&self, obj: Span, name: &[u8]) -> Result<(Option<(Span, u8)>, usize)> {
        let bytes = self.wire_span(obj)?;
        let mut sc = Scanner::new(bytes, obj.off as usize);
        sc.depth = 1;
        sc.take(b'{')?;
        sc.skip_ws();
        if sc.peek() == Some(b'}') {
            return Ok((None, 0));
        }
        let mut found: Option<(Span, u8)> = None;
        let mut matches = 0usize;
        loop {
            sc.skip_ws();
            let key = sc.scan_string()?;
            let key_bytes = sc.span_bytes(key)?;
            sc.skip_ws();
            sc.take(b':')?;
            sc.skip_ws();
            if json_eq_decoded(key_bytes, name)? {
                let value = sc.scan_value()?;
                if matches == 0 {
                    found = Some(value);
                }
                matches += 1;
            } else {
                sc.scan_value()?;
            }
            sc.skip_ws();
            match sc.peek() {
                Some(b',') => sc.pos += 1,
                Some(b'}') => break,
                _ => return Err(fmt_err()),
            }
        }
        Ok((found, matches))
    }

    /// Shape check: does a JSON value of this tag fit an atom of this kind?
    ///
    /// Only the JSON SHAPE is decided here; the atom's own validity (hex digits,
    /// declared width) belongs to the encoder.
    fn atom_shape_ok(kind: u8, tag: u8) -> bool {
        match kind {
            KIND_BOOL => matches!(tag, TAG_TRUE | TAG_FALSE),
            KIND_STRING | KIND_BYTES | KIND_ADDRESS | KIND_BYTES32 => tag == TAG_STRING,
            KIND_UINT256 | KIND_INT256 => matches!(tag, TAG_STRING | TAG_NUMBER),
            _ => false,
        }
    }

    /// Write one value (and its descendants) into the reserved `slot`.
    fn fill_value(&mut self, ty: Span, value: (Span, u8), slot: usize) -> Result<()> {
        let (val, tag) = value;
        match self.classify(ty)? {
            Class::Array { elem_len } => {
                if tag != TAG_ARRAY {
                    return Err(fmt_err());
                }
                let elem_ty = ty.narrow(elem_len as usize)?;
                let bytes = self.wire_span(val)?;
                let mut walker = ArrayWalker::new(bytes, val.off as usize);
                let mut count = 0usize;
                while walker.next()?.is_some() {
                    count += 1;
                }
                let first = self.alloc_block(count)?;
                self.set_node(
                    slot,
                    Eip712Node {
                        kind: KIND_ARRAY,
                        off: 0,
                        len: 0,
                        first_child: first as u16,
                        n_children: count as u16,
                    },
                )?;
                let mut walker = ArrayWalker::new(bytes, val.off as usize);
                for i in 0..count {
                    let item = walker.next()?.ok_or_else(fmt_err)?;
                    self.fill_value(elem_ty, item, first + i)?;
                }
                Ok(())
            }
            Class::Atom(kind) => {
                if !Self::atom_shape_ok(kind, tag) {
                    return Err(fmt_err());
                }
                let (off, len) = if tag == TAG_STRING {
                    self.place_json_string(val)?
                } else {
                    // Numbers and the `true`/`false` literals stay in the wire.
                    (val.off, val.len)
                };
                self.set_node(
                    slot,
                    Eip712Node {
                        kind,
                        off,
                        len,
                        first_child: 0,
                        n_children: 0,
                    },
                )
            }
            Class::Struct(type_idx) => {
                if tag != TAG_OBJECT {
                    return Err(fmt_err());
                }
                let ty_rec = *self.type_at(type_idx as usize).ok_or_else(fmt_err)?;
                let n_fields = ty_rec.n_fields as usize;
                if n_fields > u16::MAX as usize {
                    return Err(cap_err(n_fields));
                }
                let first = self.alloc_block(n_fields)?;
                // The struct's payload is its type name, which is the field type
                // string itself — already stored, so nothing is copied here.
                let (off, len) = if ty.len as usize > u8::MAX as usize {
                    return Err(cap_err(ty.len as usize));
                } else {
                    (ty.off, ty.len)
                };
                self.set_node(
                    slot,
                    Eip712Node {
                        kind: KIND_STRUCT,
                        off,
                        len,
                        first_child: first as u16,
                        n_children: n_fields as u16,
                    },
                )?;
                for j in 0..n_fields {
                    let field = {
                        let fields = self.fields_of(&ty_rec)?;
                        *fields.get(j).ok_or_else(fmt_err)?
                    };
                    let (found, matches) = {
                        let name = self.bytes_at(field.name_off as u32, field.name_len as u32)?;
                        self.find_member(val, name)?
                    };
                    if matches == 0 || matches > 1 {
                        return Err(fmt_err());
                    }
                    let member = found.ok_or_else(fmt_err)?;
                    let field_ty = Span {
                        off: field.type_off as u32,
                        len: field.type_len as u32,
                    };
                    self.fill_value(field_ty, member, first + j)?;
                }
                Ok(())
            }
        }
    }

    /// Fill the `domain` tree using the built-in `EIP712Domain` type.
    ///
    /// The field list and the leniency mirror `eip712.rs::json_to_domain`: a domain
    /// key whose JSON shape does not match is skipped rather than refused (wallets
    /// disagree about `chainId` as a string, and the digest is over the declared
    /// domain type, not over whatever extra keys the wallet added).
    fn fill_domain(&mut self, obj: Span) -> Result<()> {
        const DOMAIN_TYPE: &[u8] = b"EIP712Domain";
        const DOMAIN_FIELDS: [(&[u8], u8, bool); 5] = [
            (b"name", KIND_STRING, false),
            (b"version", KIND_STRING, false),
            (b"chainId", KIND_UINT256, true),
            (b"verifyingContract", KIND_ADDRESS, false),
            (b"salt", KIND_BYTES32, false),
        ];
        let mut present: [Option<(u8, Span)>; 5] = [None; 5];
        let mut count = 0usize;
        for (name, kind, number_only) in DOMAIN_FIELDS {
            let (found, matches) = self.find_member(obj, name)?;
            if matches > 1 {
                return Err(fmt_err());
            }
            let Some((span, tag)) = found else {
                continue;
            };
            let shape_ok = if number_only {
                tag == TAG_NUMBER
            } else {
                tag == TAG_STRING
            };
            if !shape_ok {
                continue;
            }
            let entry = present.get_mut(count).ok_or_else(|| cap_err(count + 1))?;
            *entry = Some((kind, span));
            count += 1;
        }
        let (name_off, name_len) = self.place_arena(DOMAIN_TYPE)?;
        let slot = self.alloc_slot()?;
        let first = self.alloc_block(count)?;
        self.set_node(
            slot,
            Eip712Node {
                kind: KIND_STRUCT,
                off: name_off,
                len: name_len,
                first_child: first as u16,
                n_children: count as u16,
            },
        )?;
        for i in 0..count {
            let (kind, span) = present.get(i).and_then(|e| *e).ok_or_else(fmt_err)?;
            let (off, len) = self.place_json_string(span)?;
            self.set_node(
                first + i,
                Eip712Node {
                    kind,
                    off,
                    len,
                    first_child: 0,
                    n_children: 0,
                },
            )?;
        }
        self.domain_root = Some(slot as u16);
        Ok(())
    }

    /// Fill the `message` tree, driven by `primaryType`.
    fn fill_message(&mut self, value: (Span, u8)) -> Result<()> {
        let (off, len) = self.primary_type.ok_or_else(fmt_err)?;
        let ty = Span {
            off: off as u32,
            len: len as u32,
        };
        let slot = self.alloc_slot()?;
        self.fill_value(ty, value, slot)?;
        self.message_root = Some(slot as u16);
        Ok(())
    }
}

// ─── entry point ─────────────────────────────────────────────────────────────

/// Parse EIP-712 typed data into a caller-provided pool.
///
/// `wire` is the JSON document (borrowed, never copied); `arena`, `nodes`, `types`
/// and `fields` are the caller's storage — the same shape as
/// `psbt::parse_psbt_into`, so production passes a carved workspace and tests pass
/// local arrays. Capacity failures are `BufferTooSmall` with the size that would
/// have been needed; malformed documents are `EncodingInvalidFormat`.
pub fn parse<'a>(
    wire: &'a [u8],
    arena: &'a mut [u8],
    nodes: &'a mut [Eip712Node],
    types: &'a mut [Eip712Type],
    fields: &'a mut [Eip712Field],
) -> Result<Eip712Pool<'a>> {
    if wire.len() > JSON_MAX_LEN {
        return Err(fmt_err());
    }
    // The alloc parser takes `&str`, so anything that is not UTF-8 could never have
    // reached it. Rejecting it here keeps the two acceptance surfaces equal.
    if core::str::from_utf8(wire).is_err() {
        return Err(fmt_err());
    }
    let mut pool = Eip712Pool::new_in(wire, arena, nodes, types, fields);
    let mut seen = [false; 4];
    let mut spans: [Option<(Span, u8)>; 4] = [None; 4];

    let mut sc = Scanner::new(wire, 0);
    sc.skip_ws();
    sc.take(b'{')?;
    sc.depth = 1;
    sc.skip_ws();
    if sc.peek() == Some(b'}') {
        sc.pos += 1;
    } else {
        loop {
            sc.skip_ws();
            let key = sc.scan_string()?;
            let key_bytes = sc.span_bytes(key)?;
            sc.skip_ws();
            sc.take(b':')?;
            sc.skip_ws();
            let slot = if json_eq_decoded(key_bytes, b"types")? {
                Some(0usize)
            } else if json_eq_decoded(key_bytes, b"primaryType")? {
                Some(1)
            } else if json_eq_decoded(key_bytes, b"domain")? {
                Some(2)
            } else if json_eq_decoded(key_bytes, b"message")? {
                Some(3)
            } else {
                None
            };
            if let Some(i) = slot {
                if seen.get(i).copied().unwrap_or(true) {
                    return Err(fmt_err());
                }
                if let Some(flag) = seen.get_mut(i) {
                    *flag = true;
                }
            }
            match slot {
                // `types` is walked in place: its records go straight into the pool.
                Some(0) => pool.fill_types(&mut sc)?,
                Some(1) => {
                    let value = sc.scan_value()?;
                    if value.1 != TAG_STRING {
                        return Err(fmt_err());
                    }
                    if let Some(slot) = spans.get_mut(1) {
                        *slot = Some(value);
                    }
                }
                Some(i) => {
                    let value = sc.scan_value()?;
                    if i == 2 && value.1 != TAG_OBJECT {
                        // `json_to_domain` refuses a domain that is not an object.
                        return Err(fmt_err());
                    }
                    if let Some(slot) = spans.get_mut(i) {
                        *slot = Some(value);
                    }
                }
                None => {
                    sc.scan_value()?;
                }
            }
            sc.skip_ws();
            match sc.peek() {
                Some(b',') => sc.pos += 1,
                Some(b'}') => {
                    sc.pos += 1;
                    break;
                }
                _ => return Err(fmt_err()),
            }
        }
    }
    sc.depth -= 1;
    sc.skip_ws();
    if sc.pos < wire.len() {
        // Trailing data (same rule as `eip712::parse_json`): unparsed bytes may carry
        // semantics we would not show the user.
        return Err(fmt_err());
    }
    if seen.iter().any(|s| !s) {
        return Err(fmt_err());
    }

    let primary = spans.get(1).and_then(|s| *s).ok_or_else(fmt_err)?.0;
    let (pt_off, pt_len) = pool.place_name(primary)?;
    pool.primary_type = Some((pt_off, pt_len));

    // Pass 2: the type table now decides what the values mean.
    let domain = spans.get(2).and_then(|s| *s).ok_or_else(fmt_err)?.0;
    let message = spans.get(3).and_then(|s| *s).ok_or_else(fmt_err)?;
    pool.fill_domain(domain)?;
    pool.fill_message(message)?;
    Ok(pool)
}

// ─── error helpers ───────────────────────────────────────────────────────────

/// Malformed typed data (syntax, or a shape the type table does not allow).
fn fmt_err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// Capacity, not format: the request is well-formed but needs `need` units of the
/// pool that ran out (nodes / types / fields / arena bytes). It must reach the user
/// as "request too large", never as "request data not recognized" (B-7).
fn cap_err(need: usize) -> ShlosiloError {
    ShlosiloError::with_context(
        ShlosiloErrorKind::BufferTooSmall,
        ErrorContext::RequiredLength(need),
    )
}
