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
//! **P1 scope.** The container: [`parse`] fills the pool and the views above expose it.
//! Value payloads are kept as raw text (`"0x…"`, `"115792…"`, `"true"`) rather than
//! decoded numbers, because decoding is the encoder's job.
//!
//! **P2 scope (this step).** The algorithm layer: [`encode_type_pool`],
//! [`type_hash_pool`], [`hash_struct_pool`] and [`signing_hash_pool`] recompute the
//! EIP-712 digest from these views, byte for byte the digest `eip712.rs` signs.
//! `tests/eip712_pool_hash.rs` holds both implementations against each other on every
//! real-world sample and on the keystone golden vectors — that differential pin, not
//! this comment, is what keeps them equal. `eip712.rs` keeps the alloc face for
//! callers that already own parsed values; the two faces are the same pattern
//! `eip155`/`eip1559` use for their parts / complete-transaction builders.
//!
//! **Atom content is validated.** P1 only checked the JSON shape; [`parse`] now also
//! decodes each atom against its declared type — `uintN`/`intN` inside the declared
//! width (`eip712.rs::fits_declared_width`, audit A3c-F17), `bytesN` exactly N bytes,
//! `address` exactly 20 — through the same decoder the hash layer uses, so the pool
//! cannot accept an atom the digest layer would refuse. Domain values are the one
//! exception and stay lenient at parse time: `eip712.rs::json_to_domain` SKIPS a
//! domain key whose shape does not fit instead of refusing the document, so the pool
//! must too, and the content check moves to [`signing_hash_pool`], where a declared
//! field must have a usable value (audit A3c-F16).

use crate::encoding::keccak256::{self, KeccakSink};
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

// ─── the built-in domain slots ───────────────────────────────────────────────

/// The domain type's name. `eip712.rs` takes the domain's field list from the
/// request's own `EIP712Domain` declaration; the pool builds the tree from the fixed
/// slot list below, so the hash layer maps one onto the other.
const DOMAIN_TYPE_NAME: &str = "EIP712Domain";

/// The standard domain slots in canonical order: `(field name, declared type, node
/// kind, may arrive as a JSON number)`. Only `chainId` may be a bare number — wallets
/// disagree about it and `eip712.rs::json_to_domain` accepts just the number form.
const DOMAIN_FIELDS: [(&str, &str, u8, bool); 5] = [
    ("name", "string", KIND_STRING, false),
    ("version", "string", KIND_STRING, false),
    ("chainId", "uint256", KIND_UINT256, true),
    ("verifyingContract", "address", KIND_ADDRESS, false),
    ("salt", "bytes32", KIND_BYTES32, false),
];

// ─── the JSON syntax budgets (one home) ──────────────────────────────────────

/// Bytes of typed-data JSON one request may carry. Profile-derived
/// (`min(16 KiB, ur_payload_max)`, see `build.rs`): a document larger than the inbound
/// transport can deliver is not a limit anyone can reach.
pub(crate) const JSON_MAX_LEN: usize = crate::limits::EIP712_JSON_BYTES_MAX;
/// Nesting levels of the JSON document itself (containers count).
pub(crate) const JSON_MAX_DEPTH: u32 = 32;
/// JSON values in one document (containers count).
pub(crate) const JSON_MAX_NODES: u32 = 4096;

// The three A3c-F15 budgets live **here**, not in `eip712`: this module is compiled on
// every face (it is the zero-heap production container) while `eip712` is an
// `alloc-fallback`/test convenience, so the alloc parser imports them from here. The
// scanner below must accept exactly what `eip712::parse_json` accepts, and these budgets
// are part of that surface — one home, no copies.

// ─── the container budgets (profile-sourced) ─────────────────────────────────

/// Type-table entries a request may declare (`WS_BYTES` sizes the `types` slice from
/// this, so the table refuses through the slice it was given).
pub(crate) const TYPES_MAX: usize = crate::limits::EIP712_TYPES_MAX;
/// Fields one type may declare. Unlike the pool slices this ceiling is per record and
/// is enforced in the parser: one type declaring everything the table can hold would
/// leave no room for the types it references.
pub(crate) const TYPE_FIELDS_MAX: usize = crate::limits::EIP712_TYPE_FIELDS_MAX;
/// Value-tree nodes — one per struct, array and atom (`WS_BYTES` sizes the `nodes`).
///
/// The count covers **both** trees the pool holds: `domain` (root plus one child per
/// declared field, so up to 6) and `message`. The spike's published figures
/// (`tests/eip712_budget_spike.rs`, 6..104 typical, 310 for a 3+40 batch) count the
/// message tree only, so the pool's own spend is that plus the domain.
pub(crate) const NODES_MAX: usize = crate::limits::EIP712_NODES_MAX;
/// Nesting levels of the value tree, the root struct counted as 1.
pub(crate) const DEPTH_MAX: usize = crate::limits::EIP712_DEPTH_MAX;
/// Bytes one type name, field name or field type string may occupy.
pub(crate) const NAME_BYTES: usize = crate::limits::EIP712_NAME_BYTES;
/// Decoded name / string-value bytes (`WS_BYTES` sizes the arena from this).
pub(crate) const ARENA_BYTES: usize = crate::limits::EIP712_ARENA_BYTES;

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
    /// Which canonical domain slots [`DOMAIN_FIELDS`] the `domain` tree holds, one bit
    /// per slot. The children are stored in slot order with no names attached, and a
    /// subsequence of kinds is ambiguous (`[string]` is `name` or `version`), so the
    /// hash layer needs this to map a declared `EIP712Domain` field onto its value.
    domain_mask: u8,
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
            domain_mask: 0,
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

    /// Bitmap of the standard domain slots the document filled: bit `slot` set means the
    /// value for `domain_slot_field(slot)` is present, and the domain's children hold the
    /// present slots in canonical order (so the value for a set bit is the child at
    /// `count_ones(bits below it)`).
    ///
    /// The domain's children carry no names — the wire's `EIP712Domain` declaration is a
    /// fixed list this module owns — so a caller that has to LABEL a domain value (the
    /// review page) reads the name from that list and the presence from here.
    pub(crate) fn domain_mask(&self) -> u8 {
        self.domain_mask
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
        // The name budget is per name, not per pool: a 4 KiB arena would happily hold one
        // absurd type name and the screen would then have to display it.
        if need > NAME_BYTES {
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

    /// Consume a run of ASCII digits (at least one; the caller has looked ahead).
    fn skip_digits(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
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
        self.skip_digits();
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

/// The element type of a declared type string (`"Person[2]"` → `"Person"`), the same
/// split at the first `[` that `eip712.rs::atom_type` makes.
fn strip_array_suffix(ty: &str) -> &str {
    match ty.find('[') {
        Some(at) => ty.get(..at).unwrap_or(ty),
        None => ty,
    }
}

// ─── atom decoding (shared by the fill pass and the hash layer) ───────────────

/// Value of one hex digit (`eip712.rs::hex_nibble`).
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Is this an even-length run of hex digits? (`eip712.rs::parse_hex_bytes`'s test,
/// minus the prefix handling: a wallet may spell `address` without `0x`, and the
/// alloc parser accepts that.)
fn is_hex(hex: &[u8]) -> bool {
    hex.len().is_multiple_of(2) && hex.iter().all(|b| hex_nibble(*b).is_some())
}

/// Decode `payload` into `dst`, whose length fixes the expected size. One optional
/// `0x` prefix is skipped. `false` when the text is not exactly `dst.len()` bytes of
/// hex.
fn hex_decode_at(payload: &[u8], dst: &mut [u8]) -> bool {
    let hex = payload.strip_prefix(b"0x".as_slice()).unwrap_or(payload);
    if !is_hex(hex) || hex.len() / 2 != dst.len() {
        return false;
    }
    for (i, slot) in dst.iter_mut().enumerate() {
        let hi = hex.get(2 * i).copied().and_then(hex_nibble).unwrap_or(0);
        let lo = hex
            .get(2 * i + 1)
            .copied()
            .and_then(hex_nibble)
            .unwrap_or(0);
        *slot = (hi << 4) | lo;
    }
    true
}

/// Absorb the bytes an (already [`is_hex`]-validated) hex run spells out.
fn absorb_hex(sink: &mut KeccakSink, hex: &[u8]) {
    let mut chunk = [0u8; 32];
    let mut used = 0usize;
    let mut at = 0usize;
    while at < hex.len() {
        let hi = hex.get(at).copied().and_then(hex_nibble).unwrap_or(0);
        let lo = hex.get(at + 1).copied().and_then(hex_nibble).unwrap_or(0);
        if let Some(slot) = chunk.get_mut(used) {
            *slot = (hi << 4) | lo;
        }
        used += 1;
        at += 2;
        if used == chunk.len() {
            sink.absorb(&chunk);
            used = 0;
        }
    }
    if let Some(tail) = chunk.get(..used) {
        if !tail.is_empty() {
            sink.absorb(tail);
        }
    }
}

/// Decimal (base 10) text → 32-byte big-endian, arbitrary precision
/// (`eip712.rs::parse_uint256_string`). `None` when the text is not all digits or the
/// value does not fit 256 bits — dropping the carry out of the top byte would turn
/// `2^256 + 6` into `6` (audit A3c-F18).
fn decimal_word(text: &[u8]) -> Option<[u8; 32]> {
    let mut word = [0u8; 32];
    for &d in text {
        if !d.is_ascii_digit() {
            return None;
        }
        let digit = u16::from(d - b'0');
        // word *= 10
        let mut carry: u16 = 0;
        for slot in word.iter_mut().rev() {
            let prod = u16::from(*slot) * 10 + carry;
            *slot = (prod & 0xff) as u8;
            carry = prod >> 8;
        }
        if carry != 0 {
            return None;
        }
        // word += digit
        let mut carry = digit;
        for slot in word.iter_mut().rev() {
            let sum = u16::from(*slot) + carry;
            *slot = (sum & 0xff) as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
        if carry != 0 {
            return None;
        }
    }
    Some(word)
}

/// `uintN` text → 32-byte word: `0x`-hex (at most 32 bytes, right-aligned) or decimal.
fn uint_word(payload: &[u8]) -> Result<[u8; 32]> {
    if payload.starts_with(b"0x") || payload.starts_with(b"0X") {
        // `parse_hex_bytes` only knows the lowercase prefix, so `0X…` is malformed
        // hex and the alloc parser answers an error.
        let hex = payload.strip_prefix(b"0x".as_slice()).ok_or_else(fmt_err)?;
        if !is_hex(hex) {
            return Err(fmt_err());
        }
        let n = hex.len() / 2;
        let mut word = [0u8; 32];
        let dst = word
            .get_mut(32usize.checked_sub(n).ok_or_else(fmt_err)?..)
            .ok_or_else(fmt_err)?;
        if !hex_decode_at(hex, dst) {
            return Err(fmt_err());
        }
        Ok(word)
    } else {
        decimal_word(payload).ok_or_else(fmt_err)
    }
}

/// `intN` text → 32-byte two's-complement word (`eip712.rs::parse_int256_string`):
/// `0x`-hex, or a decimal `i64`/`u64` magnitude with an optional leading `-`.
fn int_word(payload: &[u8]) -> Result<[u8; 32]> {
    if payload.starts_with(b"0x") {
        return uint_word(payload);
    }
    let text = core::str::from_utf8(payload).map_err(|_| fmt_err())?;
    let (negative, magnitude) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    // The alloc parser goes through `str::parse::<u64>` here, so `+5` is accepted and
    // anything past `u64` is not.
    let n: u64 = magnitude.parse().map_err(|_| fmt_err())?;
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&n.to_be_bytes());
    if negative {
        // Two's complement as `(!n) + 1`, so there is no borrow bookkeeping to get
        // wrong (audit A3c-N1).
        for slot in word.iter_mut() {
            *slot = !*slot;
        }
        let mut carry: u16 = 1;
        for slot in word.iter_mut().rev() {
            let sum = u16::from(*slot) + carry;
            *slot = sum as u8;
            carry = sum >> 8;
        }
    }
    Ok(word)
}

/// Does a 32-byte big-endian value fit the declared `intN` / `uintN` width?
///
/// Port of `eip712.rs::fits_declared_width` (audit A3c-F17): the bytes above the
/// declared width must be the correct extension (zeros unsigned, the sign byte
/// signed), and the width must be a multiple of 8 within 8..=256.
fn fits_declared_width(word: &[u8; 32], ty: &str, signed: bool) -> bool {
    let suffix = if signed {
        ty.strip_prefix("int")
    } else {
        ty.strip_prefix("uint")
    };
    let Some(suffix) = suffix else {
        return false;
    };
    let bits: u32 = if suffix.is_empty() {
        256
    } else {
        match suffix.parse::<u32>() {
            Ok(bits) => bits,
            Err(_) => return false,
        }
    };
    if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
        return false;
    }
    let covered = (bits / 8) as usize;
    let top = 32usize.saturating_sub(covered);
    if signed {
        let sign_byte = match word.get(top) {
            Some(b) if b & 0x80 != 0 => 0xffu8,
            _ => 0x00u8,
        };
        word.get(..top)
            .unwrap_or(&[])
            .iter()
            .all(|&b| b == sign_byte)
    } else {
        word.get(..top).unwrap_or(&[]).iter().all(|&b| b == 0)
    }
}

/// Which hex spelling a `bytesN` atom accepts.
///
/// The alloc parser is not uniform about this, and the pool mirrors it rather than
/// smoothing it over: a MESSAGE field goes through `json_to_eip712_value` →
/// `parse_dynamic_bytes_hex` (the `0x` prefix is required), while a domain `salt` goes
/// through `json_to_domain` → `parse_bytes32_hex` → `parse_hex_bytes` (the prefix is
/// optional). `address` is prefix-optional on both paths, so it ignores this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HexForm {
    /// `0x` required.
    Prefixed,
    /// `0x` optional.
    Bare,
}

/// Decode one atom payload into the 32-byte word EIP-712 hashes, validating it
/// against the DECLARED type: `address` must be 20 bytes, `bytesN` exactly N,
/// `uintN`/`intN` inside the declared width. `string` and `bytes` are hashed as they
/// stand and are not words, so they answer an error here.
///
/// One decoder for both faces of the pool: [`parse`] calls it to reject a request the
/// digest could not represent, and the hash layer calls it to get the word.
fn atom_word(ty: &str, kind: u8, payload: &[u8], form: HexForm) -> Result<[u8; 32]> {
    if atom_kind(ty) != Some(kind) {
        return Err(fmt_err());
    }
    match kind {
        KIND_ADDRESS => {
            let mut address = [0u8; 20];
            if !hex_decode_at(payload, &mut address) {
                return Err(fmt_err());
            }
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&address);
            Ok(word)
        }
        KIND_BYTES32 => {
            let width = bytes_n_width(ty).ok_or_else(fmt_err)?;
            let hex = match form {
                HexForm::Prefixed => payload.strip_prefix(b"0x".as_slice()).ok_or_else(fmt_err)?,
                HexForm::Bare => payload.strip_prefix(b"0x".as_slice()).unwrap_or(payload),
            };
            let mut word = [0u8; 32];
            let dst = word.get_mut(..width).ok_or_else(fmt_err)?;
            if !hex_decode_at(hex, dst) {
                return Err(fmt_err());
            }
            Ok(word)
        }
        KIND_UINT256 => {
            let word = uint_word(payload)?;
            if !fits_declared_width(&word, ty, false) {
                return Err(fmt_err());
            }
            Ok(word)
        }
        KIND_INT256 => {
            let word = int_word(payload)?;
            if !fits_declared_width(&word, ty, true) {
                return Err(fmt_err());
            }
            Ok(word)
        }
        KIND_BOOL => {
            let mut word = [0u8; 32];
            match payload {
                b"true" => word[31] = 1,
                b"false" => {}
                _ => return Err(fmt_err()),
            }
            Ok(word)
        }
        _ => Err(fmt_err()),
    }
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
            // Per-type ceiling before the record width: one type must not consume the whole
            // field table, which every declared type shares.
            if count as usize >= TYPE_FIELDS_MAX {
                return Err(cap_err(count as usize + 1));
            }
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
    fn fill_value(&mut self, ty: Span, value: (Span, u8), slot: usize, depth: usize) -> Result<()> {
        // The value tree is filled by recursion, so its nesting is a stack budget as well
        // as a container budget: refuse past the profile's ceiling instead of discovering it
        // as a device abort.
        if depth > DEPTH_MAX {
            return Err(cap_err(depth));
        }
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
                    self.fill_value(elem_ty, item, first + i, depth + 1)?;
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
                // Content check: the same decoder the hash layer uses, so the pool can
                // never accept an atom the digest layer would refuse (the alloc parser
                // validates in `json_to_eip712_value`). `string` and `bytes` carry no
                // declared width — they are hashed as they stand.
                if !matches!(kind, KIND_STRING | KIND_BYTES) {
                    let declared = self.str_at(ty.off, ty.len)?;
                    let payload = self.bytes_at(off, len)?;
                    atom_word(declared, kind, payload, HexForm::Prefixed)?;
                }
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
                    self.fill_value(field_ty, member, first + j, depth + 1)?;
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
        let domain_type = DOMAIN_TYPE_NAME.as_bytes();
        let mut present: [Option<(u8, Span)>; DOMAIN_FIELDS.len()] = [None; DOMAIN_FIELDS.len()];
        let mut count = 0usize;
        let mut mask: u8 = 0;
        for (slot, (name, _declared, kind, number_only)) in DOMAIN_FIELDS.iter().enumerate() {
            let (found, matches) = self.find_member(obj, name.as_bytes())?;
            if matches > 1 {
                return Err(fmt_err());
            }
            let Some((span, tag)) = found else {
                continue;
            };
            let shape_ok = if *number_only {
                tag == TAG_NUMBER
            } else {
                tag == TAG_STRING
            };
            if !shape_ok {
                continue;
            }
            let entry = present.get_mut(count).ok_or_else(|| cap_err(count + 1))?;
            *entry = Some((*kind, span));
            count += 1;
            // Remember WHICH slot this child is: the hash layer maps a declared
            // `EIP712Domain` field onto its value through this bit.
            mask |= 1u8
                .checked_shl(slot as u32)
                .ok_or_else(|| cap_err(slot + 1))?;
        }
        let (name_off, name_len) = self.place_arena(domain_type)?;
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
        self.domain_mask = mask;
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
        self.fill_value(ty, value, slot, 1)?;
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
        // A well-formed document that is simply larger than this device models answered
        // "request too large" on the screen, never "not recognized" (B-7).
        return Err(cap_err(wire.len()));
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

// ─── the algorithm layer (P2) ────────────────────────────────────────────────
//
// Everything below recomputes what `eip712.rs` computes from owned values, reading
// only the pool's views. The four entries mirror the alloc names one for one:
//
//   encodeType(T)   = "T(fieldType field,…)" + every type T reaches, alphabetical
//   typeHash(T)     = keccak256(encodeType(T))
//   hashStruct(S)   = keccak256(typeHash(S) ‖ encodeData(S))
//   signingHash     = keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message))
//
// The container is fixed, so the two things the alloc version gets for free — a
// `Vec` for the encoded type string and a `BTreeSet` for the visited types — are a
// caller buffer and a bitmap here. Both are bounded and both answer `BufferTooSmall`
// instead of truncating: a truncated type hash signs a different digest.

/// Stack scratch for the `encodeType` string.
///
/// The length depends only on the TYPE TABLE, never on the values: the largest sample
/// measured (`tests/eip712_budget_spike.rs`, Seaport `OrderComponents`) is 450 B, and a
/// bulk order carrying 40 offers — 11 KB of JSON — encodes to the same 450 B.
const ENCODE_TYPE_MAX: usize = crate::limits::EIP712_ENCODE_TYPE_BYTES;

/// Types `encodeType` can walk. The visited set is one bit per declared type; 64 is
/// 16x the largest real-world table the spike measured (4 types).
const ENCODE_TYPE_TYPES_MAX: usize = 64;

/// Frames on the `encodeType` walk stack. A type is entered at most once, so the depth
/// is bounded by the type count.
const ENCODE_TYPE_FRAMES: usize = ENCODE_TYPE_TYPES_MAX;

/// "This frame has not emitted a sub type yet".
const NO_FIELD: u16 = u16::MAX;

/// Per-node struct hashes one `hash_struct_pool` walk can keep.
///
/// The array is addressed by NODE INDEX (a subtraction, no map), so a slot is reserved
/// per node of the walked span even though only Struct nodes are written into it. The
/// largest sample measured (seaport bulk 3+40) walks 310 nodes. Overshooting the bound
/// is `BufferTooSmall` (capacity, not format); P4 sizes this against the carrier's stack
/// profile, which is why it is a named constant here instead of a caller buffer.
const NODE_HASH_SLOTS: usize = 384;

/// Per-node `hashStruct` results of one walk, addressed by `node index - base`.
struct NodeHashes<'h> {
    hashes: &'h [[u8; 32]],
    base: usize,
}

impl NodeHashes<'_> {
    fn get(&self, idx: usize) -> Result<[u8; 32]> {
        let at = idx.checked_sub(self.base).ok_or_else(fmt_err)?;
        self.hashes.get(at).copied().ok_or_else(|| cap_err(at + 1))
    }
}

/// Bounded writer for the `encodeType` string (the alloc version appends to a
/// `String`).
struct TypeOut<'b> {
    out: &'b mut [u8],
    pos: usize,
}

impl TypeOut<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or_else(|| cap_err(self.pos))?;
        let dst = self
            .out
            .get_mut(self.pos..end)
            .ok_or_else(|| cap_err(end))?;
        dst.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn put_str(&mut self, text: &str) -> Result<()> {
        self.put(text.as_bytes())
    }
}

/// One level of the type walk: which type's fields are being enumerated, and how far
/// the enumeration got.
#[derive(Clone, Copy)]
struct TypeFrame {
    /// Index of the type whose fields this frame is walking.
    ty: u16,
    /// Field index of the last sub type this frame emitted ([`NO_FIELD`] before the
    /// first one).
    last: u16,
}

/// Is the visited bit for `idx` set?
fn seen_bit(bits: u64, idx: u16) -> bool {
    let idx = idx as usize;
    if idx >= ENCODE_TYPE_TYPES_MAX {
        return false;
    }
    bits & (1u64 << idx) != 0
}

fn mark_seen(bits: &mut u64, idx: u16) -> Result<()> {
    let idx = idx as usize;
    if idx >= ENCODE_TYPE_TYPES_MAX {
        return Err(cap_err(idx + 1));
    }
    *bits |= 1u64 << idx;
    Ok(())
}

/// `TypeName(fieldType fieldName,…)` in DECLARATION order (`eip712.rs::encode_type`:
/// the declaration list is not re-sorted, only the types it reaches are).
fn write_type_def(pool: &Eip712Pool<'_>, idx: u16, out: &mut TypeOut<'_>) -> Result<()> {
    let ty = *pool.type_at(idx as usize).ok_or_else(fmt_err)?;
    out.put_str(pool.type_name(&ty)?)?;
    out.put(b"(")?;
    for (i, field) in pool.fields_of(&ty)?.iter().enumerate() {
        if i > 0 {
            out.put(b",")?;
        }
        out.put_str(pool.field_type(field)?)?;
        out.put(b" ")?;
        out.put_str(pool.field_name(field)?)?;
    }
    out.put(b")")
}

/// The next sub type `frame` must emit: the alphabetically smallest one this frame has
/// not emitted yet, i.e. exactly what iterating `eip712.rs`'s `BTreeSet` yields.
///
/// Names are compared as byte strings (the order `String: Ord` gives there), and a name
/// that appears on two fields of one type is emitted once — both fall out of the
/// "strictly after the last emitted name" selection.
fn next_subtype(pool: &Eip712Pool<'_>, frame: &TypeFrame, seen: u64) -> Result<Option<(u16, u16)>> {
    let ty = *pool.type_at(frame.ty as usize).ok_or_else(fmt_err)?;
    let fields = pool.fields_of(&ty)?;
    let after = match frame.last {
        NO_FIELD => None,
        last => {
            let field = fields.get(last as usize).ok_or_else(fmt_err)?;
            Some(strip_array_suffix(pool.field_type(field)?))
        }
    };
    let mut best: Option<(u16, u16, &str)> = None;
    for (i, field) in fields.iter().enumerate() {
        let name = strip_array_suffix(pool.field_type(field)?);
        // Atoms are part of the string that is already written; only user types get a
        // definition of their own.
        if atom_kind(name).is_some() {
            continue;
        }
        if let Some(last) = after {
            if name <= last {
                continue;
            }
        }
        // A field type the table does not declare is what `types.get(sub)` refuses.
        let sub = pool.type_index(name).ok_or_else(fmt_err)?;
        if seen_bit(seen, sub) {
            continue;
        }
        let keep = match best {
            Some((_, _, current)) => name < current,
            None => true,
        };
        if keep {
            best = Some((i as u16, sub, name));
        }
    }
    Ok(best.map(|(i, sub, _)| (i, sub)))
}

/// EIP-712 `encodeType`: the primary type's declaration, then every type it reaches
/// (alphabetical, depth-first, deduplicated) — byte for byte the string
/// `eip712.rs::encode_type` builds.
///
/// Writes into `out` and answers the number of bytes written; an `out` that is too
/// small is `BufferTooSmall` with the length that would have been needed.
pub fn encode_type_pool(pool: &Eip712Pool<'_>, primary: &str, out: &mut [u8]) -> Result<usize> {
    if pool.types_len() > ENCODE_TYPE_TYPES_MAX {
        // The visited set is one bit per type: a table this wide cannot be walked.
        return Err(cap_err(pool.types_len()));
    }
    let first = pool.type_index(primary).ok_or_else(fmt_err)?;
    let mut out = TypeOut { out, pos: 0 };
    write_type_def(pool, first, &mut out)?;
    let mut seen = 0u64;
    mark_seen(&mut seen, first)?;
    let mut frames = [TypeFrame {
        ty: 0,
        last: NO_FIELD,
    }; ENCODE_TYPE_FRAMES];
    *frames.get_mut(0).ok_or_else(|| cap_err(1))? = TypeFrame {
        ty: first,
        last: NO_FIELD,
    };
    let mut depth = 1usize;
    while depth > 0 {
        // The top frame is the one being advanced; a frame that has no candidates left
        // is done, which pops it. Children push, so this is a depth-first walk without
        // a recursive call.
        let at = depth - 1;
        let frame = *frames.get(at).ok_or_else(fmt_err)?;
        let Some((last, sub)) = next_subtype(pool, &frame, seen)? else {
            depth = at;
            continue;
        };
        if let Some(slot) = frames.get_mut(at) {
            slot.last = last;
        }
        write_type_def(pool, sub, &mut out)?;
        mark_seen(&mut seen, sub)?;
        *frames.get_mut(depth).ok_or_else(|| cap_err(depth + 1))? = TypeFrame {
            ty: sub,
            last: NO_FIELD,
        };
        depth += 1;
    }
    Ok(out.pos)
}

/// `typeHash(T) = keccak256(encodeType(T))`.
pub fn type_hash_pool(pool: &Eip712Pool<'_>, primary: &str) -> Result<[u8; 32]> {
    let mut encoded = [0u8; ENCODE_TYPE_MAX];
    let n = encode_type_pool(pool, primary, &mut encoded)?;
    keccak256::hash(encoded.get(..n).ok_or_else(|| cap_err(n))?)
}

/// One atom value, absorbed into `sink`: `string` and `bytes` contribute their own
/// keccak, everything else its 32-byte word (`eip712.rs::encode_value`).
fn encode_atom_pool(
    pool: &Eip712Pool<'_>,
    ty: &str,
    node: &Eip712Node,
    form: HexForm,
    sink: &mut KeccakSink,
) -> Result<()> {
    let payload = pool.payload(node)?;
    match node.kind {
        KIND_STRING => {
            let mut inner = KeccakSink::new();
            inner.absorb(payload);
            sink.absorb(&inner.finalize());
            Ok(())
        }
        KIND_BYTES => {
            // `0x`-hex when the text parses as hex, the literal text otherwise — the
            // alloc parser's fallback in `json_to_eip712_value`.
            let mut inner = KeccakSink::new();
            match payload.strip_prefix(b"0x".as_slice()) {
                Some(hex) if is_hex(hex) => absorb_hex(&mut inner, hex),
                _ => inner.absorb(payload),
            }
            sink.absorb(&inner.finalize());
            Ok(())
        }
        _ => {
            sink.absorb(&atom_word(ty, node.kind, payload, form)?);
            Ok(())
        }
    }
}

/// One field value, absorbed into `sink` (`eip712.rs::encode_value`).
fn encode_value_pool(
    pool: &Eip712Pool<'_>,
    ty: &str,
    idx: usize,
    node: &Eip712Node,
    hashes: &NodeHashes<'_>,
    sink: &mut KeccakSink,
) -> Result<()> {
    if let Some(at) = ty.find('[') {
        // An array hashes the concatenation of its element encodings, so it is one
        // nested keccak: the sink streams, which is why no concat buffer exists here.
        let elem = ty.get(..at).ok_or_else(fmt_err)?;
        if node.kind != KIND_ARRAY {
            return Err(fmt_err());
        }
        let mut inner = KeccakSink::new();
        let first = node.first_child as usize;
        for j in 0..node.n_children as usize {
            let child_idx = first.checked_add(j).ok_or_else(fmt_err)?;
            let child = *pool.node(child_idx).ok_or_else(fmt_err)?;
            encode_value_pool(pool, elem, child_idx, &child, hashes, &mut inner)?;
        }
        sink.absorb(&inner.finalize());
        return Ok(());
    }
    match node.kind {
        KIND_STRUCT => {
            // A nested struct contributes the struct hash the reverse pass already
            // computed. `eip712.rs` takes that struct's name from the value itself, and
            // the pool stores the declared field type as the node's payload — they must
            // be the same name or the two faces hash different types.
            if pool.payload(node)? != ty.as_bytes() {
                return Err(fmt_err());
            }
            sink.absorb(&hashes.get(idx)?);
            Ok(())
        }
        // An array value under a type that declares no array suffix.
        KIND_ARRAY => Err(fmt_err()),
        _ => encode_atom_pool(pool, ty, node, HexForm::Prefixed, sink),
    }
}

/// `hashStruct` of the struct node at `idx`, whose children are already hashed.
fn hash_struct_node(
    pool: &Eip712Pool<'_>,
    node: &Eip712Node,
    hashes: &NodeHashes<'_>,
) -> Result<[u8; 32]> {
    let name = core::str::from_utf8(pool.payload(node)?).map_err(|_| fmt_err())?;
    let type_idx = pool.type_index(name).ok_or_else(fmt_err)?;
    let ty = *pool.type_at(type_idx as usize).ok_or_else(fmt_err)?;
    let fields = pool.fields_of(&ty)?;
    if fields.len() != node.n_children as usize {
        // `encode_data` refuses a value list that does not match the declaration.
        return Err(fmt_err());
    }
    let mut sink = KeccakSink::new();
    sink.absorb(&type_hash_pool(pool, name)?);
    let first = node.first_child as usize;
    for (j, field) in fields.iter().enumerate() {
        let child_idx = first.checked_add(j).ok_or_else(fmt_err)?;
        let child = *pool.node(child_idx).ok_or_else(fmt_err)?;
        encode_value_pool(
            pool,
            pool.field_type(field)?,
            child_idx,
            &child,
            hashes,
            &mut sink,
        )?;
    }
    Ok(sink.finalize())
}

/// `hashStruct(S) = keccak256(typeHash(S) ‖ encodeData(S))` for the struct at `root`.
///
/// **One reverse pass, no recursive call.** P1 hands out a node's child block after the
/// node itself, so every child index is higher than its parent's: walking the pool
/// backwards is a bottom-up traversal, and node `i`'s struct hash is ready before its
/// parent asks for it. The hashes live in a bounded stack array — a tree that does not
/// fit is `BufferTooSmall`, never a silently truncated digest.
///
/// The walk starts at the pool's LAST node, so a subtree root (a nested struct rather
/// than the message root) also hashes the nodes above its own subtree. Those results are
/// never read; they only cost time, and the bound is measured on that span.
pub fn hash_struct_pool(pool: &Eip712Pool<'_>, root: u16) -> Result<[u8; 32]> {
    let base = root as usize;
    let node = *pool.node(base).ok_or_else(fmt_err)?;
    if node.kind != KIND_STRUCT {
        return Err(fmt_err());
    }
    let span = pool.nodes_len().saturating_sub(base);
    if span > NODE_HASH_SLOTS {
        return Err(cap_err(span));
    }
    let mut hashes = [[0u8; 32]; NODE_HASH_SLOTS];
    let mut idx = pool.nodes_len();
    while idx > base {
        idx -= 1;
        let node = *pool.node(idx).ok_or_else(fmt_err)?;
        if node.kind != KIND_STRUCT {
            // Atoms are encoded where they are consumed (they cost no slot), and an
            // array's encoding is folded into whoever declares it.
            continue;
        }
        let view = NodeHashes {
            hashes: &hashes,
            base,
        };
        let hash = hash_struct_node(pool, &node, &view)?;
        let at = idx.checked_sub(base).ok_or_else(fmt_err)?;
        *hashes.get_mut(at).ok_or_else(|| cap_err(at + 1))? = hash;
    }
    NodeHashes {
        hashes: &hashes,
        base,
    }
    .get(base)
}

/// `domainSeparator = hashStruct(EIP712Domain)` for the pool's domain tree.
///
/// The field list and its ORDER come from the request's own `EIP712Domain` declaration,
/// exactly as `eip712.rs::separator_with_types` reads them — not from the built-in
/// standard list, because a document that declares a narrower domain (`{chainId,
/// verifyingContract}`, which Safe sends) signs a different digest than one declaring
/// all four fields. The pool's tree keeps the canonical slot order with no names
/// attached, so each declared field finds its value through `domain_mask`; a declared
/// field the document never filled is `EncodingInvalidFormat` (audit A3c-F16), while a
/// value the declaration does not cover is left out — the same asymmetry the alloc face
/// has, and the reason the domain stays lenient at parse time.
fn domain_separator_pool(pool: &Eip712Pool<'_>) -> Result<[u8; 32]> {
    let root_idx = pool.domain_root().ok_or_else(fmt_err)? as usize;
    let root = *pool.node(root_idx).ok_or_else(fmt_err)?;
    if root.kind != KIND_STRUCT {
        return Err(fmt_err());
    }
    let type_idx = pool.type_index(DOMAIN_TYPE_NAME).ok_or_else(fmt_err)?;
    let ty = *pool.type_at(type_idx as usize).ok_or_else(fmt_err)?;
    let mut sink = KeccakSink::new();
    sink.absorb(&type_hash_pool(pool, DOMAIN_TYPE_NAME)?);
    let first = root.first_child as usize;
    for field in pool.fields_of(&ty)? {
        let declared = pool.field_type(field)?;
        // `separator_with_types` answers `missing()` for a declared field it has no
        // value for, and an unknown (name, type) pair is such a field.
        let slot = domain_slot(pool.field_name(field)?, declared).ok_or_else(fmt_err)?;
        let bit = 1u8.checked_shl(u32::from(slot)).ok_or_else(fmt_err)?;
        if pool.domain_mask & bit == 0 {
            return Err(fmt_err());
        }
        // Children sit in canonical slot order, so the value's position is the number of
        // present slots before it.
        let before = (pool.domain_mask & (bit - 1)).count_ones() as usize;
        let child_idx = first.checked_add(before).ok_or_else(fmt_err)?;
        let child = *pool.node(child_idx).ok_or_else(fmt_err)?;
        encode_atom_pool(pool, declared, &child, HexForm::Bare, &mut sink)?;
    }
    Ok(sink.finalize())
}

/// The canonical slot a declared `(name, type)` pair maps to, if any.
/// `separator_with_types` accepts exactly these four pairs plus `salt`.
fn domain_slot(name: &str, declared: &str) -> Option<u8> {
    DOMAIN_FIELDS
        .iter()
        .position(|(known_name, known_type, _, _)| *known_name == name && *known_type == declared)
        .map(|slot| slot as u8)
}

/// Standard domain slots, in canonical order (the order the domain's children are stored
/// in). Callers that must put a NAME on a domain value — the review page — iterate this
/// and consult [`Eip712Pool::domain_mask`]; the tree itself carries no field names,
/// because the domain's `EIP712Domain` declaration is a fixed list this module already
/// owns. One home: a caller cannot invent a sixth slot or reorder the five.
pub(crate) const DOMAIN_SLOTS: usize = DOMAIN_FIELDS.len();

/// The canonical name and declared type of standard domain slot `slot`.
pub(crate) fn domain_slot_field(slot: usize) -> Option<(&'static str, &'static str)> {
    DOMAIN_FIELDS
        .get(slot)
        .map(|(name, declared, _, _)| (*name, *declared))
}

/// The EIP-712 digest: `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message))`.
pub fn signing_hash_pool(pool: &Eip712Pool<'_>) -> Result<[u8; 32]> {
    let separator = domain_separator_pool(pool)?;
    let root = pool.message_root().ok_or_else(fmt_err)?;
    let struct_hash = hash_struct_pool(pool, root)?;
    let mut sink = KeccakSink::new();
    sink.absorb(&[0x19, 0x01]);
    sink.absorb(&separator);
    sink.absorb(&struct_hash);
    Ok(sink.finalize())
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

// ─── caller workspace: one region, one length ────────────────────────────────

/// Alignment every carved span starts on (`Eip712Node` carries `u32` payload offsets).
const WS_ALIGN: usize = core::mem::align_of::<Eip712Node>();

/// Round `off` up to [`WS_ALIGN`].
const fn ws_up(off: usize) -> usize {
    (off + WS_ALIGN - 1) & !(WS_ALIGN - 1)
}

const WS_NODES_OFF: usize = 0;
const WS_NODES_BYTES: usize = NODES_MAX * core::mem::size_of::<Eip712Node>();
const WS_TYPES_OFF: usize = ws_up(WS_NODES_OFF + WS_NODES_BYTES);
const WS_TYPES_BYTES: usize = TYPES_MAX * core::mem::size_of::<Eip712Type>();
const WS_FIELDS_OFF: usize = ws_up(WS_TYPES_OFF + WS_TYPES_BYTES);
const WS_FIELDS_BYTES: usize = TYPES_MAX * TYPE_FIELDS_MAX * core::mem::size_of::<Eip712Field>();
const WS_ARENA_OFF: usize = ws_up(WS_FIELDS_OFF + WS_FIELDS_BYTES);

/// Bytes the pool writes starting at the *aligned* base: the four spans, padded.
const WS_REGIONS: usize = ws_up(WS_ARENA_OFF + ARENA_BYTES);

/// Bytes a caller must reserve for one pool: [`WS_REGIONS`] plus the worst-case base
/// shift, so a caller that allocates exactly this always fits whatever alignment its
/// buffer starts on (`SignWsLayout` adds a region of this size; the review formula adds
/// the same figure).
///
/// The region is handed to `parse` through `eip712_pool::parse_in`, which carves the
/// four spans below out of it.
pub(crate) const WS_BYTES: usize = WS_REGIONS + WS_ALIGN - 1;

/// [`parse`] over a caller-carved region instead of four separate slabs.
///
/// `ws` is one plain byte region of at least [`WS_BYTES`] (the sign workspace and the
/// review workspace both reserve exactly that). Two things the four-slab entry cannot
/// promise are settled here:
///
/// - **Alignment.** A `&mut [u8]` says nothing about its base address, and the node /
///   type / field slabs are read through aligned references. The base is rounded up to
///   [`WS_ALIGN`] here, which is why [`WS_BYTES`] carries the worst-case shift.
/// - **Initialisation.** The caller's bytes may be dirty (a reused workspace, a
///   re-scanned request over the previous one's leftovers). The four spans are zeroed
///   before the parse so a stale record can never be read as this document's.
///
/// The whole region is either usable or the call fails: a short region answers
/// `BufferTooSmall` with [`WS_BYTES`], exactly like `carve_sign_ws` answers `None`.
pub(crate) fn parse_in<'a>(wire: &'a [u8], ws: &'a mut [u8]) -> Result<Eip712Pool<'a>> {
    if ws.len() < WS_BYTES {
        // Whole-region failure, never a partial pool: the four spans are sized from
        // the same budgets, so a region that misses one of them misses all four.
        return Err(cap_err(WS_BYTES));
    }
    let raw = ws.as_mut_ptr() as usize;
    let aligned = ws_up(raw);
    let shift = aligned - raw;
    let end = aligned
        .checked_add(WS_REGIONS)
        .ok_or_else(|| cap_err(WS_BYTES))?;
    if end > raw + ws.len() {
        // Cannot happen with `ws.len() >= WS_BYTES` (the shift is in the budget), but
        // the check is the one that makes the pointer arithmetic below safe.
        return Err(cap_err(WS_BYTES));
    }
    // Clear the four spans: the caller hands over bytes, not values.
    // SAFETY: the span [aligned, aligned + WS_REGIONS) was just proved to lie inside
    // `ws`, and `aligned` is a live, writable, non-aliased base derived from `ws`.
    let base = unsafe { ws.as_mut_ptr().add(shift) };
    unsafe { core::ptr::write_bytes(base, 0, WS_REGIONS) };
    // SAFETY: `WS_NODES_OFF`/`WS_TYPES_OFF`/`WS_FIELDS_OFF`/`WS_ARENA_OFF` are the
    // const offsets `WS_REGIONS` was computed from (`ws_up` of each previous span), so
    // every sub-span starts on its own alignment, the four are disjoint, and their
    // total ends at `WS_REGIONS`. The counts are the slab capacities the byte counts
    // were derived from, so each slice is exactly as long as the bytes reserved for it.
    // `ws` is not touched again after this point, so no safe reference aliases them.
    unsafe {
        let nodes: &'a mut [Eip712Node] =
            core::slice::from_raw_parts_mut(base.add(WS_NODES_OFF).cast::<Eip712Node>(), NODES_MAX);
        let types: &'a mut [Eip712Type] =
            core::slice::from_raw_parts_mut(base.add(WS_TYPES_OFF).cast::<Eip712Type>(), TYPES_MAX);
        let fields: &'a mut [Eip712Field] = core::slice::from_raw_parts_mut(
            base.add(WS_FIELDS_OFF).cast::<Eip712Field>(),
            TYPES_MAX * TYPE_FIELDS_MAX,
        );
        let arena: &'a mut [u8] =
            core::slice::from_raw_parts_mut(base.add(WS_ARENA_OFF), ARENA_BYTES);
        parse(wire, arena, nodes, types, fields)
    }
}

/// The `chainId` a typed-data document declares in its top-level `domain`, if it has
/// one this device can read.
///
/// This is the pre-check `check_network` can afford: it walks the document with the
/// same [`Scanner`] the parser uses but fills no pool, so it runs on the C-ABI network
/// gate where no workspace exists. `Ok(None)` means "nothing to compare" (no `domain`,
/// no `chainId`, or a value that is not a non-negative integer that fits a `u64`) and
/// the network gate is skipped; a document that is not valid JSON at all is
/// `EncodingInvalidFormat`, because then there is no request to reason about.
///
/// Only the shape `eip712.rs::json_to_domain` accepts can reach the digest (a JSON
/// number for `chainId`; a string form is dropped there), so a value of any other
/// shape answers `Ok(None)` here as well — the two faces skip the same documents.
pub(crate) fn domain_chain_id(json: &[u8]) -> Result<Option<u64>> {
    if json.len() > JSON_MAX_LEN {
        return Err(cap_err(json.len()));
    }
    if core::str::from_utf8(json).is_err() {
        return Err(fmt_err());
    }
    let mut sc = Scanner::new(json, 0);
    sc.skip_ws();
    sc.take(b'{')?;
    sc.depth = 1;
    let mut domain: Option<Span> = None;
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
            if json_eq_decoded(key_bytes, b"domain")? {
                if domain.is_some() {
                    // `parse` refuses a repeated top-level key; the pre-check reports
                    // the same document as malformed rather than picking one.
                    return Err(fmt_err());
                }
                let (span, tag) = sc.scan_value()?;
                // A `domain` that is not an object is refused by `parse`; either way it
                // carries no chain id we could compare.
                domain = if tag == TAG_OBJECT { Some(span) } else { None };
            } else {
                sc.scan_value()?;
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
    if sc.pos < json.len() {
        return Err(fmt_err());
    }
    let span = match domain {
        Some(span) => span,
        None => return Ok(None),
    };
    // Second pass, over the `domain` object only.
    let bytes = sc.span_bytes(span)?;
    let mut ds = Scanner::new(bytes, span.off as usize);
    ds.depth = 1;
    ds.take(b'{')?;
    ds.skip_ws();
    if ds.peek() == Some(b'}') {
        return Ok(None);
    }
    let mut value: Option<u64> = None;
    let mut seen = false;
    loop {
        ds.skip_ws();
        let key = ds.scan_string()?;
        let key_bytes = ds.span_bytes(key)?;
        ds.skip_ws();
        ds.take(b':')?;
        ds.skip_ws();
        if json_eq_decoded(key_bytes, b"chainId")? {
            if seen {
                // Duplicate member: `find_member` refuses the document, so there is no
                // single chain id to compare against the selected network.
                return Err(fmt_err());
            }
            seen = true;
            value = scan_u64_lenient(&mut ds)?;
        } else {
            ds.scan_value()?;
        }
        ds.skip_ws();
        match ds.peek() {
            Some(b',') => ds.pos += 1,
            Some(b'}') => break,
            _ => return Err(fmt_err()),
        }
    }
    Ok(value)
}

/// Read the value after `chainId` as a decimal `u64`, or answer "nothing to compare".
///
/// The reads here are deliberately placed on the *value token* rather than run through
/// [`Scanner::scan_value`], because the caller's question is "is there a chain id I can
/// compare", not "is this member well formed": a `chainId` sent as an object, an array, a
/// string or a negative literal is a shape `eip712.rs::json_to_domain` drops, so the only
/// honest answer is `Ok(None)` (skip the pre-check) instead of a format error that would
/// describe a document the digest layer may still sign.
///
/// A literal past `u64` answers `Ok(None)` here as well, but it never gets this far: the
/// document-level scan bounds every number to the `i64` domain (the same bound `parse`
/// applies), so such a request is already refused as torn by both faces.
fn scan_u64_lenient(sc: &mut Scanner<'_>) -> Result<Option<u64>> {
    match sc.peek() {
        Some(b'0'..=b'9') => {}
        Some(b'-') => {
            // A negative chain id is not a chain id; consume the token so the caller's
            // separator check still sees the object's real punctuation.
            sc.pos += 1;
            let start = sc.pos;
            sc.skip_digits();
            return if sc.pos > start {
                Ok(None)
            } else {
                Err(fmt_err())
            };
        }
        // Objects, arrays, strings, literals: shape `json_to_domain` drops, so there is
        // nothing to compare.
        _ => {
            sc.scan_value()?;
            return Ok(None);
        }
    }
    let start = sc.pos;
    sc.skip_digits();
    let digits = sc.wire.get(start..sc.pos).ok_or_else(fmt_err)?;
    // A trailing `.`/`e` would be a number the pool refuses anyway; leave it to the
    // caller's separator check, which turns it into a format error.
    let mut value: u64 = 0;
    for &d in digits {
        let next = match value.checked_mul(10) {
            Some(v) => v,
            None => return Ok(None),
        };
        value = match next.checked_add((d - b'0') as u64) {
            Some(v) => v,
            None => return Ok(None),
        };
    }
    Ok(Some(value))
}

// ─── budget pins (E-3 P4) ────────────────────────────────────────────────────

#[cfg(test)]
mod budget_pins {
    //! Every container budget is proved in **both** directions: the last value that fits
    //! and the first one refused, with the error the screen turns into "request too
    //! large". A one-sided pin passes just as happily when a ceiling sits one slot too
    //! high, and the device then refuses a request it should have signed.
    //!
    //! The pool at profile capacity is the harness: the slab sizes come from the same
    //! constants `WS_BYTES` reserves, so a pin that fits here fits on the carrier.

    use super::*;
    use alloc::string::{String, ToString};

    /// The four slabs at profile capacity.
    fn slabs() -> (
        [u8; ARENA_BYTES],
        [Eip712Node; NODES_MAX],
        [Eip712Type; TYPES_MAX],
        [Eip712Field; TYPES_MAX * TYPE_FIELDS_MAX],
    ) {
        (
            [0u8; ARENA_BYTES],
            [Eip712Node::default(); NODES_MAX],
            [Eip712Type::default(); TYPES_MAX],
            [Eip712Field::default(); TYPES_MAX * TYPE_FIELDS_MAX],
        )
    }

    /// Parse `doc` at profile capacity; returns the measured counts.
    fn measured(doc: &[u8]) -> (usize, usize, usize, usize) {
        let (mut arena, mut nodes, mut types, mut fields) = slabs();
        let pool = parse(doc, &mut arena, &mut nodes, &mut types, &mut fields)
            .unwrap_or_else(|e| panic!("expected the document to fit: {e:?}"));
        (
            pool.types_len(),
            pool.fields_len(),
            pool.nodes_len(),
            pool.arena_used(),
        )
    }

    /// Parse `doc` at profile capacity, expecting a refusal.
    fn refuse(doc: &[u8]) -> ShlosiloError {
        let (mut arena, mut nodes, mut types, mut fields) = slabs();
        match parse(doc, &mut arena, &mut nodes, &mut types, &mut fields) {
            Ok(_) => panic!("expected a refusal, the document parsed"),
            Err(e) => e,
        }
    }

    /// One real ERC-2612 permit, the shape the signing path is being wired for.
    const PERMIT: &[u8] = br#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},"primaryType":"Permit","domain":{"name":"USD Coin","version":"2","chainId":1,"verifyingContract":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},"message":{"owner":"0x1111111111111111111111111111111111111111","spender":"0x2222222222222222222222222222222222222222","value":"1000000","nonce":0,"deadline":1700000000}}"#;

    /// A document with `n` declared types; the first holds `fields` uint256 fields.
    fn doc_types(n: usize, fields: usize) -> String {
        let mut types = String::from("{");
        for t in 0..n {
            if t > 0 {
                types.push(',');
            }
            types.push_str(&alloc::format!("\"T{t}\":["));
            let count = if t == 0 { fields } else { 1 };
            for f in 0..count {
                if f > 0 {
                    types.push(',');
                }
                types.push_str(&alloc::format!(
                    "{{\"name\":\"f{f}\",\"type\":\"uint256\"}}"
                ));
            }
            types.push(']');
        }
        types.push('}');
        let mut message = String::from("{");
        for f in 0..fields {
            if f > 0 {
                message.push(',');
            }
            message.push_str(&alloc::format!("\"f{f}\":{f}"));
        }
        message.push('}');
        alloc::format!(
            "{{\"types\":{types},\"primaryType\":\"T0\",\"domain\":{{}},\"message\":{message}}}"
        )
    }

    /// A document whose only field is `name: ty`, with `value` as its message.
    fn doc_field(name: &str, ty: &str, value: &str) -> String {
        alloc::format!(
            "{{\"types\":{{\"T\":[{{\"name\":\"{name}\",\"type\":\"{ty}\"}}]}},\
             \"primaryType\":\"T\",\"domain\":{{}},\"message\":{{\"{name}\":{value}}}}}"
        )
    }

    /// `[[…atom…]]` with `levels` brackets.
    fn nest(levels: usize, atom: &str) -> String {
        let mut s = String::new();
        for _ in 0..levels {
            s.push('[');
        }
        s.push_str(atom);
        for _ in 0..levels {
            s.push(']');
        }
        s
    }

    /// `1,1,…,1` with `n` elements.
    fn atom_list(n: usize) -> String {
        let mut s = String::new();
        for i in 0..n {
            if i > 0 {
                s.push(',');
            }
            s.push('1');
        }
        s
    }

    fn required_len(err: &ShlosiloError) -> usize {
        match err.context {
            ErrorContext::RequiredLength(need) => need,
            ref other => panic!("expected RequiredLength, got {other:?}"),
        }
    }

    #[test]
    fn workspace_geometry_is_the_sum_of_its_padded_spans() {
        assert_eq!(WS_NODES_OFF % WS_ALIGN, 0, "node slab alignment");
        assert_eq!(WS_TYPES_OFF % WS_ALIGN, 0, "type slab alignment");
        assert_eq!(WS_FIELDS_OFF % WS_ALIGN, 0, "field slab alignment");
        assert_eq!(WS_ARENA_OFF % WS_ALIGN, 0, "arena slab alignment");
        assert_eq!(
            WS_TYPES_OFF,
            ws_up(WS_NODES_OFF + WS_NODES_BYTES),
            "type slab starts after the node slab"
        );
        assert_eq!(
            WS_FIELDS_OFF,
            ws_up(WS_TYPES_OFF + WS_TYPES_BYTES),
            "field slab starts after the type slab"
        );
        assert_eq!(
            WS_ARENA_OFF,
            ws_up(WS_FIELDS_OFF + WS_FIELDS_BYTES),
            "arena starts after the field slab"
        );
        assert_eq!(
            WS_REGIONS,
            ws_up(WS_ARENA_OFF + ARENA_BYTES),
            "the carved region ends at the arena tail"
        );
        assert_eq!(
            WS_BYTES,
            WS_REGIONS + WS_ALIGN - 1,
            "the reserve carries the worst-case base shift"
        );
        const _: () = assert!(
            WS_BYTES >= WS_NODES_BYTES + WS_TYPES_BYTES + WS_FIELDS_BYTES + ARENA_BYTES,
            "WS_BYTES is smaller than its own slabs"
        );
    }

    #[test]
    fn a_real_permit_fits_every_profile_budget() {
        let (types, fields, nodes, arena) = measured(PERMIT);
        // Spike regression: the measured cost of a real shape stays inside the knobs. A
        // budget change that breaks this moves the numbers in limits/*.toml.
        assert!(types <= TYPES_MAX, "types {types} > {TYPES_MAX}");
        assert!(
            fields <= TYPES_MAX * TYPE_FIELDS_MAX,
            "fields {fields} > {}",
            TYPES_MAX * TYPE_FIELDS_MAX
        );
        assert!(nodes <= NODES_MAX, "nodes {nodes} > {NODES_MAX}");
        assert!(arena <= ARENA_BYTES, "arena {arena} > {ARENA_BYTES}");
    }

    #[test]
    fn a_field_over_the_per_type_ceiling_is_refused() {
        // Per type, not per pool: the field slab holds many more records than one type may
        // claim, so this pin can only pass if the parser enforces the per-record ceiling.
        let (_, fields_at, _, _) = measured(doc_types(1, TYPE_FIELDS_MAX).as_bytes());
        assert_eq!(fields_at, TYPE_FIELDS_MAX);

        let err = refuse(doc_types(1, TYPE_FIELDS_MAX + 1).as_bytes());
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::BufferTooSmall,
            "capacity, not format"
        );
        assert_eq!(
            required_len(&err),
            TYPE_FIELDS_MAX + 1,
            "reports the count it needed"
        );
    }

    #[test]
    fn a_type_table_over_the_budget_is_refused() {
        let (types_at, _, _, _) = measured(doc_types(TYPES_MAX, 1).as_bytes());
        assert_eq!(types_at, TYPES_MAX);

        let err = refuse(doc_types(TYPES_MAX + 1, 1).as_bytes());
        assert_eq!(err.kind, ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(required_len(&err), TYPES_MAX + 1);
    }

    #[test]
    fn a_name_over_the_budget_is_refused() {
        let long = "n".repeat(NAME_BYTES);
        measured(doc_field(&long, "uint256", "1").as_bytes());

        let err = refuse(doc_field(&"n".repeat(NAME_BYTES + 1), "uint256", "1").as_bytes());
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::BufferTooSmall,
            "field name over budget"
        );
        assert_eq!(required_len(&err), NAME_BYTES + 1);

        // The same ceiling covers a field's type string.
        let long_ty = "u".repeat(NAME_BYTES + 1);
        let err = refuse(doc_field("x", &long_ty, "1").as_bytes());
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::BufferTooSmall,
            "field type over budget"
        );
    }

    /// A chain of `levels` types: `A{i}` holds one field of type `A{i+1}`, the last one an
    /// atom — so the value tree nests `levels` structs plus the closing atom. Nested array
    /// types cannot express this: both parsers split a type at its FIRST `[`, so
    /// `uint256[1][1]` reads as a one-dimensional array (parity with the alloc face).
    fn doc_chain(levels: usize) -> String {
        let mut types = String::from("{");
        for i in 0..levels {
            if i > 0 {
                types.push(',');
            }
            let field = if i + 1 < levels {
                alloc::format!("{{\"name\":\"inner\",\"type\":\"A{}\"}}", i + 1)
            } else {
                "{\"name\":\"v\",\"type\":\"uint256\"}".to_string()
            };
            types.push_str(&alloc::format!("\"A{i}\":[{field}]"));
        }
        types.push('}');
        let mut message = String::from("{\"v\":1}");
        for _ in 0..levels - 1 {
            message = alloc::format!("{{\"inner\":{message}}}");
        }
        alloc::format!(
            "{{\"types\":{types},\"primaryType\":\"A0\",\"domain\":{{}},\"message\":{message}}}"
        )
    }

    #[test]
    fn a_value_tree_deeper_than_the_budget_is_refused() {
        // The atom closes the chain, so `levels` structs put it at depth `levels + 1`.
        let levels_at = DEPTH_MAX - 1;
        measured(doc_chain(levels_at).as_bytes());

        let err = refuse(doc_chain(DEPTH_MAX).as_bytes());
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::BufferTooSmall,
            "capacity, not format"
        );
        assert_eq!(
            required_len(&err),
            DEPTH_MAX + 1,
            "reports the depth it needed"
        );
        // Discriminator: the same document is inside the type budget, so the refusal can
        // only come from the depth ceiling.
        const _: () = assert!(DEPTH_MAX <= TYPES_MAX, "the chain must fit the type table");
    }

    #[test]
    fn a_node_count_over_the_budget_is_refused() {
        // One node per struct, array and atom: a single `uint256[k]` field costs `k + 2`.
        // Message root + array + atoms + the empty `domain` object: the budget covers the
        // whole pool, not the message tree alone.
        let (_, _, nodes_at, _) = measured(
            doc_field(
                "a",
                &alloc::format!("uint256[{}]", NODES_MAX - 3),
                &nest(1, &atom_list(NODES_MAX - 3)),
            )
            .as_bytes(),
        );
        assert_eq!(nodes_at, NODES_MAX, "the document spends the whole budget");

        let over = doc_field(
            "a",
            &alloc::format!("uint256[{}]", NODES_MAX - 2),
            &nest(1, &atom_list(NODES_MAX - 2)),
        );
        assert!(
            over.len() < JSON_MAX_LEN,
            "the oversized document still fits the JSON budget"
        );
        let err = refuse(over.as_bytes());
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::BufferTooSmall,
            "capacity, not format"
        );
        assert!(
            required_len(&err) > NODES_MAX,
            "reports what it needed, not what it had"
        );
    }

    #[test]
    fn an_oversized_document_is_a_capacity_error() {
        // The byte budget is the one the transport can actually deliver
        // (min(16 KiB, ur_payload_max)), and an over-budget document is refused as
        // "request too large" — never as "not recognized".
        let err = refuse(&alloc::vec![b' '; JSON_MAX_LEN + 1]);
        assert_eq!(err.kind, ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(required_len(&err), JSON_MAX_LEN + 1);

        // Exactly at the budget, the same document is still refused for its content — which
        // proves the length check is a `>` and not a `>=`.
        let err = refuse(&alloc::vec![b' '; JSON_MAX_LEN]);
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::EncodingInvalidFormat,
            "at the budget the refusal must come from the parser, not the length check"
        );
    }
}

// ─── P3 pins: the workspace carve and the network pre-check ──────────────────

#[cfg(test)]
mod ws_pins {
    //! The two entry points E-3 P3 added: [`parse_in`], which carves one caller region into
    //! the pool's four spans, and [`domain_chain_id`], which the network gate runs with no
    //! workspace at all.
    //!
    //! `parse_in`'s whole job is the two things the slab entry cannot promise — a base
    //! address it does not control and bytes it did not write — so the pins are poison, every
    //! base alignment, and the one-byte-short region. `domain_chain_id`'s job is to never
    //! turn "cannot tell" into "malformed", so the pins walk the shapes that have no
    //! readable integer in them.
    use super::*;

    /// One real ERC-2612 permit (USDC on mainnet) — the document the sign path is wired for.
    const PERMIT: &[u8] = br#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},"primaryType":"Permit","domain":{"name":"USD Coin","version":"2","chainId":1,"verifyingContract":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},"message":{"owner":"0x1111111111111111111111111111111111111111","spender":"0x2222222222222222222222222222222222222222","value":"1000000","nonce":0,"deadline":1700000000}}"#;

    /// What one parse measured: `(types, fields, nodes, arena bytes)`.
    fn counts(pool: &Eip712Pool<'_>) -> (usize, usize, usize, usize) {
        (
            pool.types_len(),
            pool.fields_len(),
            pool.nodes_len(),
            pool.arena_used(),
        )
    }

    /// The same document through the four-slab entry, which owns no carve and no
    /// initialisation duty — the reference a carve must reproduce exactly.
    fn slab_counts(doc: &[u8]) -> (usize, usize, usize, usize) {
        let mut arena = [0u8; ARENA_BYTES];
        let mut nodes = [Eip712Node::default(); NODES_MAX];
        let mut types = [Eip712Type::default(); TYPES_MAX];
        let mut fields = [Eip712Field::default(); TYPES_MAX * TYPE_FIELDS_MAX];
        let pool = parse(doc, &mut arena, &mut nodes, &mut types, &mut fields)
            .expect("the document fits the profile's budgets");
        counts(&pool)
    }

    /// A region pre-filled with 0xAA: every record the parse leaves un-written would be
    /// poison read back as a node, a type or a field.
    #[test]
    fn parse_in_ignores_poison_in_the_region() {
        let want = slab_counts(PERMIT);
        let mut ws = alloc::vec![0xAAu8; WS_BYTES];
        let pool = parse_in(PERMIT, &mut ws).expect("parse over poison");
        assert_eq!(
            counts(&pool),
            want,
            "poison changed what the parse measured"
        );
        assert_eq!(pool.primary_type().unwrap(), "Permit");
    }

    /// The base address is the caller's, so the pool must round it up itself for every
    /// alignment the region can start on.
    #[test]
    fn parse_in_places_the_pool_at_any_base_offset() {
        let want = slab_counts(PERMIT);
        for offset in 0..WS_ALIGN {
            let mut backing = alloc::vec![0xAAu8; WS_BYTES + offset];
            let ws = &mut backing[offset..];
            let pool = parse_in(PERMIT, ws)
                .unwrap_or_else(|e| panic!("offset {offset} must parse, got {e:?}"));
            assert_eq!(&pool.arena_used().to_le_bytes(), &want.3.to_le_bytes());
            assert_eq!(
                (pool.types_len(), pool.fields_len(), pool.nodes_len()),
                (want.0, want.1, want.2),
                "offset {offset} measured a different pool"
            );
        }
    }

    /// One byte short is `BufferTooSmall` naming the size that fits — the carve never
    /// half-succeeds (same contract as `carve_sign_ws`).
    #[test]
    fn parse_in_refuses_a_region_one_byte_short() {
        let mut short = alloc::vec![0u8; WS_BYTES - 1];
        let err = match parse_in(PERMIT, &mut short) {
            Ok(_) => panic!("a region one byte short cannot hold a pool"),
            Err(e) => e,
        };
        assert_eq!(err.kind, ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(err.context, ErrorContext::RequiredLength(WS_BYTES));
    }

    /// The pre-check reads `domain.chainId`, not a same-named message field.
    #[test]
    fn domain_chain_id_reads_the_domain_only() {
        assert_eq!(domain_chain_id(PERMIT).expect("readable"), Some(1));
        let message_only = br#"{"types":{"T":[{"name":"chainId","type":"uint256"}]},"primaryType":"T","domain":{"chainId":5},"message":{"chainId":1}}"#;
        assert_eq!(
            domain_chain_id(message_only).expect("readable"),
            Some(5),
            "the message's own field must not shadow the domain's"
        );
    }

    /// Values with no readable `u64` in them are "nothing to compare": the network gate skips
    /// the request instead of calling it malformed.
    ///
    /// Every shape here is a document `parse` also accepts (or refuses for its own reasons),
    /// so the skip never blesses something the signer would reject as malformed: the scanner
    /// both faces share is what validates the document, and this function only reads one
    /// member out of it.
    #[test]
    fn domain_chain_id_skips_what_it_cannot_read() {
        let skippable: [&[u8]; 6] = [
            br#"{"types":{},"primaryType":"T","domain":{},"message":{}}"#,
            br#"{"types":{},"primaryType":"T","domain":{"name":"x"},"message":{}}"#,
            br#"{"types":{},"primaryType":"T","domain":{"chainId":{"a":1}},"message":{}}"#,
            br#"{"types":{},"primaryType":"T","domain":{"chainId":[1]},"message":{}}"#,
            br#"{"types":{},"primaryType":"T","domain":{"chainId":"1"},"message":{}}"#,
            br#"{"types":{},"primaryType":"T","domain":{"chainId":-1},"message":{}}"#,
        ];
        for doc in skippable {
            match domain_chain_id(doc) {
                Ok(None) => {}
                other => panic!(
                    "{}: expected a skip, got {other:?}",
                    core::str::from_utf8(doc).expect("utf8")
                ),
            }
        }
        // A chain id past `i64::MAX` cannot survive the document scan at all (the shared
        // scanner bounds numbers to the `i64` domain, exactly as `parse` does), so the gate
        // reports the document the signer would report: torn, not "unknown network".
        let big = br#"{"types":{},"primaryType":"T","domain":{"chainId":9223372036854775808},"message":{}}"#;
        assert_eq!(
            domain_chain_id(big).unwrap_err().kind,
            ShlosiloErrorKind::EncodingInvalidFormat,
            "a number the shared scanner cannot read fails the whole document on both faces"
        );
    }

    /// A document that is not JSON is a format error — there is no request to reason about,
    /// and silence here would let a torn payload reach the gate looking chainless.
    #[test]
    fn domain_chain_id_refuses_a_tear_in_the_json() {
        let broken: [&[u8]; 3] = [
            br#"{"types":"#,
            br#"{"types":{},"domain":{"chainId":1}"#,
            br#"{"types":{} } trailing"#,
        ];
        for doc in broken {
            assert_eq!(
                domain_chain_id(doc).unwrap_err().kind,
                ShlosiloErrorKind::EncodingInvalidFormat
            );
        }
        // A repeated member is ambiguous, not "the first one wins": `find_member` refuses the
        // same document, so the pre-check reports the same verdict.
        let repeated =
            br#"{"types":{},"primaryType":"T","domain":{"chainId":1,"chainId":2},"message":{}}"#;
        assert_eq!(
            domain_chain_id(repeated).unwrap_err().kind,
            ShlosiloErrorKind::EncodingInvalidFormat
        );
    }
}
