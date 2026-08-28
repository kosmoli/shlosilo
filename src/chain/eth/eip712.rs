//! ETH EIP-712 typed data signing (Phase 5 v9.1)
//!
//! 实现 EIP-712 typed data hash + ECDSA sign. 完整支持域分隔符 (domainSeparator)
//! 和 struct hash (hashStruct) 递归计算.
//!
//! **不实现 JSON parser** (调用方负责解析 typed data JSON → types + values),
//! 我们提供 Rust enum API (`Eip712TypeDef` / `Eip712Value`) 让 caller 直接构造.
//!
//! ## 算法摘要
//!
//! ```text
//! signingHash = keccak256(0x1901 || domainSeparator || hashStruct(message))
//! domainSeparator = hashStruct(EIP712Domain)
//! hashStruct(s) = keccak256(typeHash(s) || encodeData(s))
//! typeHash(s) = keccak256("Type1(Type2 x,uint256 y,...)")
//! encodeData(s) = 字段按类型编码:
//!   - bytesN: N bytes (left-padded with zeros for int, right-padded for address)
//!   - string: keccak256(bytes)
//!   - bytes: keccak256(bytes)
//!   - int/N: 32 bytes big-endian (signed)
//!   - uint/N: 32 bytes big-endian (unsigned)
//!   - bool: 32 bytes (0x00..00 or 0x00..01)
//!   - address: 32 bytes (left-padded with zeros to 32 bytes)
//!   - bytes32: 32 bytes raw
//!   - struct: hashStruct(s) (递归)
//!   - arrayN[k] of T: keccak256(encodeData(t1) || ... || encodeData(tk))
//! ```text

    extern crate alloc;
use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::types::SecretBytes;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[cfg(test)]
extern crate std;

// ─── 类型定义 ──────────────────────────────────────────────────────

/// EIP-712 typed data 类型定义:
/// `typeName -> Vec<(fieldName, fieldType)>`
///
/// 例如:
/// ```text
/// "EIP712Domain" -> [("name", "string"), ("version", "string"), ("chainId", "uint256"), ("verifyingContract", "address")]
/// "Mail" -> [("from", "Person"), ("to", "Person"), ("contents", "string")]
/// "Person" -> [("name", "string"), ("wallet", "address")]
/// ```text
pub type Types = BTreeMap<String, Vec<(String, String)>>;

/// EIP-712 value: 树状结构, 支持任意嵌套 struct 和 array
#[derive(Clone, Debug)]
pub enum Eip712Value {
    /// bytes32 raw 32 bytes
    Bytes32([u8; 32]),
    /// address (20 bytes)
    Address([u8; 20]),
    /// uint256 (32 bytes big-endian)
    Uint256([u8; 32]),
    /// int256 (32 bytes signed big-endian)
    Int256([u8; 32]),
    /// bool
    Bool(bool),
    /// string (UTF-8 bytes)
    String(Vec<u8>),
    /// dynamic bytes
    Bytes(Vec<u8>),
    /// struct reference: (typeName, fieldValues in struct declaration order)
    Struct(String, Vec<Eip712Value>),
    /// array of T (fixed or dynamic)
    Array(Vec<Eip712Value>),
}

/// EIP-712 Domain (matches EIP712Domain typed data)
#[derive(Clone, Debug, Default)]
pub struct Eip712Domain {
    pub name: Option<String>,
    pub version: Option<String>,
    pub chain_id: Option<[u8; 32]>,
    pub verifying_contract: Option<[u8; 20]>,
    pub salt: Option<[u8; 32]>,
}

// ─── typeHash (encode_type + keccak256) ──────────────────────────────

/// 构造 EIP-712 type signature: `TypeName(Type1 field1,Type2 field2,...)`
/// 字段按字母序排序 (per EIP-712 spec)
pub fn encode_type(primary_type: &str, types: &Types) -> Result<String> {
    // 检查 primary_type 存在
    let fields = types.get(primary_type).ok_or_else(|| {
        ShlosiloError::with_context(
            ShlosiloErrorKind::EncodingInvalidFormat,
            crate::error::ErrorContext::None /* was format */,
        )
    })?;

    // primary type 的字段直接列出（不需字母序排序？EIP-712 spec 规定 yes）
    let mut type_str = String::from(primary_type);
    type_str.push('(');
    for (i, (name, ty)) in fields.iter().enumerate() {
        if i > 0 {
            type_str.push(',');
        }
        type_str.push_str(ty);
        type_str.push(' ');
        type_str.push_str(name);
    }
    type_str.push(')');

    // 递归插入子类型 (按 type name 字母序)
    let mut visited = alloc::collections::BTreeSet::new();
    visited.insert(primary_type.to_string());
    add_subtypes(primary_type, types, &mut visited, &mut type_str)?;

    Ok(type_str)
}

fn add_subtypes(
    type_name: &str,
    types: &Types,
    visited: &mut alloc::collections::BTreeSet<String>,
    out: &mut String,
) -> Result<()> {
    let fields = types.get(type_name).ok_or_else(|| {
        ShlosiloError::with_context(
            ShlosiloErrorKind::EncodingInvalidFormat,
            crate::error::ErrorContext::None /* was format */,
        )
    })?;
    // 收集未访问的 sub-struct type names
    let mut sub_types: alloc::collections::BTreeSet<String> =
        alloc::collections::BTreeSet::new();
    for (_, ty) in fields {
        // 解析 atom 类型 (e.g. "Person" from "Person", "Mail[2]" from "Mail[]")
        let atom = atom_type(ty);
        if !is_atom(atom) {
            // 是 struct 类型, 检查是否需要递归
            if !visited.contains(atom) {
                sub_types.insert(atom.to_string());
            }
        }
    }
    for sub in &sub_types {
        visited.insert(sub.clone());
        // 递归子 struct
        let sub_fields = types.get(sub).ok_or_else(|| {
            ShlosiloError::with_context(
                ShlosiloErrorKind::EncodingInvalidFormat,
                crate::error::ErrorContext::None /* was format */,
            )
        })?;
        out.push_str(sub);
        out.push('(');
        for (i, (name, ty)) in sub_fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(ty);
            out.push(' ');
            out.push_str(name);
        }
        out.push(')');
        // 子 struct 的 subtypes
        add_subtypes(sub, types, visited, out)?;
    }
    Ok(())
}

/// Strip array suffix: "Person[2]" -> "Person", "uint256[]" -> "uint256"
fn atom_type(ty: &str) -> &str {
    if let Some(pos) = ty.find('[') {
        &ty[..pos]
    } else {
        ty
    }
}

/// 是否 atom 类型 (EIP-712 预定义: bytesN, string, bytes, intN, uintN, bool, address)
fn is_atom(ty: &str) -> bool {
    matches!(
        ty,
        "string" | "bytes" | "address" | "bool"
    ) || ty.starts_with("int")
        || ty.starts_with("uint")
        || (ty.starts_with("bytes") && ty.len() > 5 && is_numeric_suffix(&ty[5..]))
}

fn is_numeric_suffix(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// 算 typeHash: `keccak256(type_signature_string)`
pub fn type_hash(primary_type: &str, types: &Types) -> Result<[u8; 32]> {
    let type_str = encode_type(primary_type, types)?;
    keccak256::hash(type_str.as_bytes())
}

// ─── encode_data ──────────────────────────────────────────────────

/// 算 hashStruct: `keccak256(typeHash || encodeData(s))`
pub fn hash_struct(
    primary_type: &str,
    value: &Eip712Value,
    types: &Types,
) -> Result<[u8; 32]> {
    let type_hash_bytes = type_hash(primary_type, types)?;
    let encoded = encode_data(primary_type, value, types)?;
    let mut concat = Vec::with_capacity(32 + encoded.len());
    concat.extend_from_slice(&type_hash_bytes);
    concat.extend_from_slice(&encoded);
    keccak256::hash(&concat)
}

/// 编码结构体 (不含 typeHash prefix)
fn encode_data(
    primary_type: &str,
    value: &Eip712Value,
    types: &Types,
) -> Result<Vec<u8>> {
    let fields = types.get(primary_type).ok_or_else(|| {
        ShlosiloError::with_context(
            ShlosiloErrorKind::EncodingInvalidFormat,
            crate::error::ErrorContext::None /* was format */,
        )
    })?;
    // 必须 Struct 类型, fields 长度匹配
    let field_values = match value {
        Eip712Value::Struct(_, vs) => vs,
        _ => {
            return Err(ShlosiloError::with_context(
                ShlosiloErrorKind::EncodingInvalidFormat,
                crate::error::ErrorContext::None /* was format */,
            ));
        }
    };
    if field_values.len() != fields.len() {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::EncodingInvalidFormat,
            crate::error::ErrorContext::None /* was format */,
        ));
    }
    let mut out = Vec::with_capacity(32 * fields.len());
    for ((_name, ty), v) in fields.iter().zip(field_values.iter()) {
        let encoded = encode_value(ty, v, types)?;
        out.extend_from_slice(&encoded);
    }
    Ok(out)
}

fn encode_value(ty: &str, value: &Eip712Value, types: &Types) -> Result<Vec<u8>> {
    // 处理 array 后缀
    if let Some(bracket_pos) = ty.find('[') {
        let elem_ty = &ty[..bracket_pos];
        let array_values = match value {
            Eip712Value::Array(vs) => vs,
            _ => {
                return Err(ShlosiloError::with_context(
                    ShlosiloErrorKind::EncodingInvalidFormat,
                    crate::error::ErrorContext::None /* was format */,
                ));
            }
        };
        // keccak256(concat(encodeData(t1), encodeData(t2), ...))
        let mut encoded_items = Vec::with_capacity(32 * array_values.len());
        for item in array_values {
            encoded_items.extend_from_slice(&encode_value(elem_ty, item, types)?);
        }
        return Ok(keccak256::hash(&encoded_items)?.to_vec());
    }

    // atom 类型 / struct
    match value {
        Eip712Value::Bytes32(b) => Ok(b.to_vec()),
        Eip712Value::Address(a) => {
            // address → 32 bytes (left-padded)
            let mut out = [0u8; 32];
            out[12..].copy_from_slice(a);
            Ok(out.to_vec())
        }
        Eip712Value::Uint256(u) => Ok(u.to_vec()),
        Eip712Value::Int256(i) => Ok(i.to_vec()),
        Eip712Value::Bool(b) => {
            let mut out = [0u8; 32];
            out[31] = if *b { 1 } else { 0 };
            Ok(out.to_vec())
        }
        Eip712Value::String(s) => Ok(keccak256::hash(s)?.to_vec()),
        Eip712Value::Bytes(b) => Ok(keccak256::hash(b)?.to_vec()),
        Eip712Value::Struct(name, vs) => {
            // 递归
            hash_struct(name, &Eip712Value::Struct(name.clone(), vs.clone()), types).map(|h| h.to_vec())
        }
        Eip712Value::Array(_) => {
            // 已经上面处理
            Err(ShlosiloError::with_context(
                ShlosiloErrorKind::EncodingInvalidFormat,
                crate::error::ErrorContext::None /* was format */,
            ))
        }
    }
}

// ─── domainSeparator ────────────────────────────────────────────────

impl Eip712Domain {
    /// 构造 domain 类型定义 (标准的 EIP712Domain fields, 与 EIP-712 spec 一致)
    pub fn standard_type_def() -> Types {
        let mut types = BTreeMap::new();
        types.insert(
            "EIP712Domain".to_string(),
            alloc::vec![
                ("name".to_string(), "string".to_string()),
                ("version".to_string(), "string".to_string()),
                ("chainId".to_string(), "uint256".to_string()),
                ("verifyingContract".to_string(), "address".to_string()),
            ],
        );
        types
    }

    /// 算 domainSeparator = hashStruct(EIP712Domain)
    pub fn separator(&self) -> Result<[u8; 32]> {
        self.separator_with_types(&Self::standard_type_def())
    }

    /// 自定义类型定义 (例如带 salt)
    pub fn separator_with_types(&self, types: &Types) -> Result<[u8; 32]> {
        let fields = types.get("EIP712Domain").ok_or_else(|| {
            ShlosiloError::with_context(
                ShlosiloErrorKind::EncodingInvalidFormat,
                crate::error::ErrorContext::None,
            )
        })?;
        // 构造 field values
        let mut values = Vec::with_capacity(fields.len());
        for (name, ty) in fields {
            let v = match (name.as_str(), ty.as_str()) {
                ("name", "string") => Eip712Value::String(self.name.clone().unwrap_or_default().into_bytes()),
                ("version", "string") => Eip712Value::String(self.version.clone().unwrap_or_default().into_bytes()),
                ("chainId", "uint256") => match self.chain_id {
                    Some(c) => Eip712Value::Uint256(c),
                    None => Eip712Value::Uint256([0u8; 32]),
                },
                ("verifyingContract", "address") => match self.verifying_contract {
                    Some(a) => Eip712Value::Address(a),
                    None => Eip712Value::Address([0u8; 20]),
                },
                ("salt", "bytes32") => match self.salt {
                    Some(s) => Eip712Value::Bytes32(s),
                    None => Eip712Value::Bytes32([0u8; 32]),
                },
                _ => {
                    return Err(ShlosiloError::with_context(
                        ShlosiloErrorKind::EncodingInvalidFormat,
                        crate::error::ErrorContext::None /* was format */,
                    ));
                }
            };
            values.push(v);
        }
        let domain_struct = Eip712Value::Struct("EIP712Domain".to_string(), values);
        hash_struct("EIP712Domain", &domain_struct, types)
    }
}

// ─── signing_hash ──────────────────────────────────────────────────

/// 算 EIP-712 signing hash:
/// `keccak256(0x1901 || domainSeparator || hashStruct(message))`
pub fn signing_hash(
    domain: &Eip712Domain,
    primary_type: &str,
    message: &Eip712Value,
    types: &Types,
) -> Result<[u8; 32]> {
    let domain_separator = domain.separator_with_types(types)?;
    let struct_hash = hash_struct(primary_type, message, types)?;
    let mut concat = Vec::with_capacity(2 + 32 + 32);
    concat.push(0x19);
    concat.push(0x01);
    concat.extend_from_slice(&domain_separator);
    concat.extend_from_slice(&struct_hash);
    keccak256::hash(&concat)
}

/// EIP-712 签名输入
/// P1-03：私钥走 `SecretBytes<32>`——不 Clone 不 Debug、ZeroizeOnDrop、常时比较。
pub struct Eip712SignInput {
    pub domain: Eip712Domain,
    pub primary_type: String,
    pub message: Eip712Value,
    pub types: Types,
    pub private_key: SecretBytes<32>,
}

/// EIP-712 签名输出
#[derive(Clone, Debug)]
pub struct Eip712SignedTx {
    pub signing_hash: [u8; 32],
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// y_parity: 0 或 1 (EIP-1552 引入)
    pub y_parity: u8,
}

/// 签名 EIP-712 typed data
pub fn sign_eip712(input: &Eip712SignInput) -> Result<Eip712SignedTx> {
    let sk = sign::sk_from_pk(input.private_key.expose())?;
    let sighash = signing_hash(&input.domain, &input.primary_type, &input.message, &input.types)?;

    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let y_parity = sign::apply_low_s(&sighash, &sk, &mut r_bytes, &mut s_bytes)?;

    Ok(Eip712SignedTx {
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        y_parity,
    })
}

// ─── TypedData 顶层结构 (v9.1.1) ───────────────────────────────────

/// EIP-712 typed data 完整结构: domain + primary_type + message + types
#[derive(Clone, Debug)]
pub struct TypedData {
    pub types: Types,
    pub primary_type: String,
    pub domain: Eip712Domain,
    pub message: Eip712Value,
}

impl TypedData {
    pub fn new(
        types: Types,
        primary_type: String,
        domain: Eip712Domain,
        message: Eip712Value,
    ) -> Self {
        Self {
            types,
            primary_type,
            domain,
            message,
        }
    }

    /// 计算 signing hash
    pub fn signing_hash(&self) -> Result<[u8; 32]> {
        signing_hash(&self.domain, &self.primary_type, &self.message, &self.types)
    }

    /// 签名 (复用于 v9.1 的 sign_eip712)
    pub fn sign(&self, private_key: SecretBytes<32>) -> Result<Eip712SignedTx> {
        let input = Eip712SignInput {
            domain: self.domain.clone(),
            primary_type: self.primary_type.clone(),
            message: self.message.clone(),
            types: self.types.clone(),
            private_key,
        };
        sign_eip712(&input)
    }

    /// 屏幕摘要 (L1 pure, 给 L3 显示用)
    /// 格式: "Type: field1=val1, field2=val2 | Type.subfield=value"
    pub fn summary(&self) -> String {
        format!(
            "Type: {}\nDomain: {}\nMessage: {}",
            self.primary_type,
            self.domain.summary(),
            summary_value(&self.primary_type, &self.message, &self.types, 0)
        )
    }
}

impl Eip712Domain {
    /// 简短摘要
    pub fn summary(&self) -> String {
        let mut s = String::from("EIP712Domain{");
        let mut first = true;
        if let Some(name) = &self.name {
            s.push_str(&format!("name=\"{}\"", name));
            first = false;
        }
        if let Some(v) = &self.version {
            if !first {
                s.push(',');
            }
            s.push_str(&format!("version=\"{}\"", v));
            first = false;
        }
        if let Some(c) = &self.chain_id {
            if !first {
                s.push(',');
            }
            s.push_str(&format!("chainId=0x{}", hex_encode_short(c)));
            first = false;
        }
        if let Some(vc) = &self.verifying_contract {
            if !first {
                s.push(',');
            }
            s.push_str(&format!(
                "verifyingContract=0x{}",
                hex_encode_short(&{
                    let mut a = [0u8; 32];
                    a[12..].copy_from_slice(vc);
                    a
                })
            ));
            first = false;
        }
        if let Some(salt) = &self.salt {
            if !first {
                s.push(',');
            }
            s.push_str(&format!("salt=0x{}", hex_encode_short(salt)));
        }
        s.push('}');
        s
    }
}

/// 递归生成 value 摘要
#[allow(clippy::only_used_in_recursion)] // 数组元素递归时沿用外层 type_name
fn summary_value(
    type_name: &str,
    value: &Eip712Value,
    types: &Types,
    depth: usize,
) -> String {
    let indent = "  ".repeat(depth);
    match value {
        Eip712Value::Bytes32(b) => format!("0x{}", hex_encode_short(b)),
        Eip712Value::Address(a) => {
            let mut padded = [0u8; 32];
            padded[12..].copy_from_slice(a);
            format!("0x{}", hex_encode_short(&padded))
        }
        Eip712Value::Uint256(u) => format!("0x{}", hex_encode_short(u)),
        Eip712Value::Int256(i) => format!("0x{}", hex_encode_short(i)),
        Eip712Value::Bool(b) => format!("{}", b),
        Eip712Value::String(s) => {
            // UTF-8 lossy display
            match core::str::from_utf8(s) {
                Ok(utf8) => format!("\"{}\"", utf8),
                Err(_) => format!("0x{}", hex_encode_short(s)),
            }
        }
        Eip712Value::Bytes(b) => format!("0x{}", hex_encode_short(b)),
        Eip712Value::Struct(name, fields) => {
            let mut s = format!("{}{} {{", indent, name);
            let empty = Vec::new();
            let field_defs = types.get(name).unwrap_or(&empty);
            for (i, v) in fields.iter().enumerate() {
                let field_name = field_defs
                    .get(i)
                    .map(|(n, _)| n.as_str())
                    .unwrap_or("?");
                let field_type = field_defs
                    .get(i)
                    .map(|(_, t)| t.as_str())
                    .unwrap_or("?");
                s.push('\n');
                s.push_str(&format!(
                    "{}  {}: {}",
                    indent,
                    field_name,
                    summary_value(field_type, v, types, depth + 1)
                ));
            }
            s.push('\n');
            s.push_str(&format!("{}{}", indent, "}"));
            s
        }
        Eip712Value::Array(items) => {
            let mut s = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&summary_value(type_name, item, types, depth));
            }
            s.push(']');
            s
        }
    }
}

fn hex_encode_short(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&alloc::format!("{:02x}", b));
    }
    s
}

// ─── JSON Parser (v9.1.1 自实现, 零依赖) ────────────────────────────────

/// 最小 JSON 值
#[derive(Clone, Debug)]
pub enum JsonValue {
    Null,
    Bool(bool),
    /// 整数 (EIP-712 JSON 里的 number 都解析为 i64; 大数用字符串)
    Num(i64),
    String_(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

/// JSON 解析错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    UnexpectedEnd,
    UnexpectedChar(char, usize),
    InvalidEscape(char),
    InvalidUnicodeEscape,
    InvalidNumber(usize),
    TrailingData,
    ExpectedKey,
    ExpectedColon,
    NumberOutOfRange,
}

impl core::fmt::Display for JsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JsonError::UnexpectedEnd => f.write_str("unexpected end of input"),
            JsonError::UnexpectedChar(c, p) => {
                write!(f, "unexpected character '{}' at position {}", c, p)
            }
            JsonError::InvalidEscape(c) => write!(f, "invalid escape character '{}'", c),
            JsonError::InvalidUnicodeEscape => f.write_str("invalid \\u escape"),
            JsonError::InvalidNumber(p) => write!(f, "invalid number at position {}", p),
            JsonError::TrailingData => f.write_str("trailing data after JSON value"),
            JsonError::ExpectedKey => f.write_str("expected string key"),
            JsonError::ExpectedColon => f.write_str("expected ':'"),
            JsonError::NumberOutOfRange => f.write_str("number out of range"),
        }
    }
}

/// 解析 JSON 字符串 (允许尾部空白)
pub fn parse_json(s: &str) -> core::result::Result<JsonValue, JsonError> {
    let mut p = Parser { input: s, pos: 0 };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos < p.input.len() {
        return Err(JsonError::TrailingData);
    }
    Ok(v)
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> core::result::Result<JsonValue, JsonError> {
        self.skip_ws();
        match self.peek() {
            Some('n') => self.parse_null(),
            Some('t') | Some('f') => self.parse_bool(),
            Some('"') => self.parse_string().map(JsonValue::String_),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_object(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(JsonError::UnexpectedChar(c, self.pos)),
            None => Err(JsonError::UnexpectedEnd),
        }
    }

    fn parse_null(&mut self) -> core::result::Result<JsonValue, JsonError> {
        if self.input[self.pos..].starts_with("null") {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(JsonError::UnexpectedChar('n', self.pos))
        }
    }

    fn parse_bool(&mut self) -> core::result::Result<JsonValue, JsonError> {
        if self.input[self.pos..].starts_with("true") {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if self.input[self.pos..].starts_with("false") {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(JsonError::UnexpectedChar(self.peek().unwrap(), self.pos))
        }
    }

    fn parse_string(&mut self) -> core::result::Result<String, JsonError> {
        if self.advance() != Some('"') {
            return Err(JsonError::UnexpectedChar('"', self.pos));
        }
        let mut out = String::new();
        loop {
            match self.advance() {
                Some('"') => return Ok(out),
                Some('\\') => {
                    let esc = self.advance().ok_or(JsonError::UnexpectedEnd)?;
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{08}'),
                        'f' => out.push('\u{0c}'),
                        'u' => {
                            // \uXXXX → 4 hex digits
                            let hex_str = self.input.get(self.pos..self.pos + 4).ok_or(
                                JsonError::InvalidUnicodeEscape,
                            )?;
                            self.pos += 4;
                            let code = u32::from_str_radix(hex_str, 16)
                                .map_err(|_| JsonError::InvalidUnicodeEscape)?;
                            let c = char::from_u32(code).ok_or(JsonError::InvalidUnicodeEscape)?;
                            out.push(c);
                        }
                        _ => return Err(JsonError::InvalidEscape(esc)),
                    }
                }
                Some(c) => out.push(c),
                None => return Err(JsonError::UnexpectedEnd),
            }
        }
    }

    fn parse_number(&mut self) -> core::result::Result<JsonValue, JsonError> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s = &self.input[start..self.pos];
        let n: i64 = s.parse().map_err(|_| JsonError::NumberOutOfRange)?;
        Ok(JsonValue::Num(n))
    }

    fn parse_array(&mut self) -> core::result::Result<JsonValue, JsonError> {
        self.advance(); // '['
        let mut arr = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(JsonValue::Array(arr));
        }
        loop {
            arr.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some(']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(arr));
                }
                Some(c) => return Err(JsonError::UnexpectedChar(c, self.pos)),
                None => return Err(JsonError::UnexpectedEnd),
            }
        }
    }

    fn parse_object(&mut self) -> core::result::Result<JsonValue, JsonError> {
        self.advance(); // '{'
        let mut obj = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(JsonValue::Object(obj));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.advance() != Some(':') {
                return Err(JsonError::ExpectedColon);
            }
            let value = self.parse_value()?;
            obj.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some('}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(obj));
                }
                Some(c) => return Err(JsonError::UnexpectedChar(c, self.pos)),
                None => return Err(JsonError::UnexpectedEnd),
            }
        }
    }
}

// ─── JSON → Eip712TypedData (v9.1.1) ──────────────────────────────────

/// 解析 EIP-712 typed data JSON (eth_signTypedData_v4 标准格式)
pub fn parse_typed_data_v4(json: &str) -> core::result::Result<TypedData, JsonError> {
    let v = parse_json(json)?;
    let obj = match v {
        JsonValue::Object(o) => o,
        _ => return Err(JsonError::UnexpectedChar('?', 0)),
    };

    // types: { TypeName: [{name: ..., type: ...}, ...] }
    let types_json = obj.get("types").ok_or(JsonError::ExpectedKey)?;
    let mut types: Types = BTreeMap::new();
    if let JsonValue::Object(type_map) = types_json {
        for (type_name, fields_json) in type_map {
            if let JsonValue::Array(fields_arr) = fields_json {
                let mut fields = Vec::new();
                for f in fields_arr {
                    if let JsonValue::Object(fo) = f {
                        let name = match fo.get("name") {
                            Some(JsonValue::String_(s)) => s.clone(),
                            _ => return Err(JsonError::ExpectedKey),
                        };
                        let ty = match fo.get("type") {
                            Some(JsonValue::String_(s)) => s.clone(),
                            _ => return Err(JsonError::ExpectedKey),
                        };
                        fields.push((name, ty));
                    } else {
                        return Err(JsonError::UnexpectedChar('?', self_pos(f)));
                    }
                }
                types.insert(type_name.clone(), fields);
            } else {
                return Err(JsonError::UnexpectedChar('?', self_pos(fields_json)));
            }
        }
    } else {
        return Err(JsonError::UnexpectedChar('?', self_pos(types_json)));
    }

    // primaryType
    let primary_type = match obj.get("primaryType") {
        Some(JsonValue::String_(s)) => s.clone(),
        _ => return Err(JsonError::ExpectedKey),
    };

    // domain
    let domain_json = obj.get("domain").ok_or(JsonError::ExpectedKey)?;
    let domain = json_to_domain(domain_json)?;

    // message
    let message_json = obj.get("message").ok_or(JsonError::ExpectedKey)?;
    let message = json_to_eip712_value(message_json, &primary_type, &types)?;

    Ok(TypedData {
        types,
        primary_type,
        domain,
        message,
    })
}

fn self_pos(v: &JsonValue) -> usize {
    let _ = v;
    0
}

/// JSON object → Eip712Domain
fn json_to_domain(v: &JsonValue) -> core::result::Result<Eip712Domain, JsonError> {
    let obj = match v {
        JsonValue::Object(o) => o,
        _ => return Err(JsonError::UnexpectedChar('?', 0)),
    };
    let mut d = Eip712Domain::default();
    if let Some(JsonValue::String_(s)) = obj.get("name") {
        d.name = Some(s.clone());
    }
    if let Some(JsonValue::String_(s)) = obj.get("version") {
        d.version = Some(s.clone());
    }
    if let Some(JsonValue::Num(n)) = obj.get("chainId") {
        let mut bytes = [0u8; 32];
        bytes[32 - 8..].copy_from_slice(&n.to_be_bytes());
        d.chain_id = Some(bytes);
    }
    if let Some(JsonValue::String_(s)) = obj.get("verifyingContract") {
        // 0x 开头 42 字符 hex → 20 字节 address
        if let Some(addr_bytes) = parse_address_hex(s) {
            d.verifying_contract = Some(addr_bytes);
        }
    }
    if let Some(JsonValue::String_(s)) = obj.get("salt") {
        if let Some(salt_bytes) = parse_bytes32_hex(s) {
            d.salt = Some(salt_bytes);
        }
    }
    Ok(d)
}

/// JSON value → Eip712Value (按 type_name 字段类型)
fn json_to_eip712_value(
    json: &JsonValue,
    type_name: &str,
    types: &Types,
) -> core::result::Result<Eip712Value, JsonError> {
    // 处理 array 后缀
    if let Some(bracket_pos) = type_name.find('[') {
        let elem_ty = &type_name[..bracket_pos];
        if let JsonValue::Array(arr) = json {
            let mut items = Vec::with_capacity(arr.len());
            for item in arr {
                items.push(json_to_eip712_value(item, elem_ty, types)?);
            }
            return Ok(Eip712Value::Array(items));
        } else {
            return Err(JsonError::UnexpectedChar('?', 0));
        }
    }

    // bytes32 / uint256 / int256 / address / bool / string / bytes
    match type_name {
        "string" => {
            if let JsonValue::String_(s) = json {
                Ok(Eip712Value::String(s.as_bytes().to_vec()))
            } else {
                Err(JsonError::UnexpectedChar('?', 0))
            }
        }
        "bytes" => {
            // bytes 可以是 0x hex string
            if let JsonValue::String_(s) = json {
                if let Some(bytes) = parse_dynamic_bytes_hex(s) {
                    Ok(Eip712Value::Bytes(bytes))
                } else {
                    Ok(Eip712Value::Bytes(s.as_bytes().to_vec()))
                }
            } else {
                Err(JsonError::UnexpectedChar('?', 0))
            }
        }
        "bool" => {
            if let JsonValue::Bool(b) = json {
                Ok(Eip712Value::Bool(*b))
            } else {
                Err(JsonError::UnexpectedChar('?', 0))
            }
        }
        "address" => {
            if let JsonValue::String_(s) = json {
                if let Some(addr) = parse_address_hex(s) {
                    Ok(Eip712Value::Address(addr))
                } else {
                    Err(JsonError::UnexpectedChar('?', 0))
                }
            } else {
                Err(JsonError::UnexpectedChar('?', 0))
            }
        }
        t if t.starts_with("uint") || t == "uint256" => {
            if let JsonValue::String_(s) = json {
                // uint256 经常作为字符串 (避免精度损失)
                if let Some(bytes) = parse_uint256_string(s) {
                    Ok(Eip712Value::Uint256(bytes))
                } else {
                    Err(JsonError::UnexpectedChar('?', 0))
                }
            } else if let JsonValue::Num(n) = json {
                let mut bytes = [0u8; 32];
                bytes[32 - 8..].copy_from_slice(&n.to_be_bytes());
                Ok(Eip712Value::Uint256(bytes))
            } else {
                Err(JsonError::UnexpectedChar('?', 0))
            }
        }
        t if t.starts_with("int") || t == "int256" => {
            if let JsonValue::String_(s) = json {
                if let Some(bytes) = parse_int256_string(s) {
                    Ok(Eip712Value::Int256(bytes))
                } else {
                    Err(JsonError::UnexpectedChar('?', 0))
                }
            } else if let JsonValue::Num(n) = json {
                let mut bytes = [0u8; 32];
                bytes[32 - 8..].copy_from_slice(&n.to_be_bytes());
                Ok(Eip712Value::Int256(bytes))
            } else {
                Err(JsonError::UnexpectedChar('?', 0))
            }
        }
        t if t.starts_with("bytes") && t.len() > 5 && t[5..].chars().all(|c| c.is_ascii_digit()) => {
            // bytesN (固定大小)
            if let JsonValue::String_(s) = json {
                if let Some(bytes) = parse_dynamic_bytes_hex(s) {
                    let n: usize = t[5..].parse().unwrap_or(0);
                    if bytes.len() == n {
                        let mut padded = [0u8; 32];
                        padded[..n].copy_from_slice(&bytes);
                        Ok(Eip712Value::Bytes32(padded))
                    } else {
                        Err(JsonError::UnexpectedChar('?', 0))
                    }
                } else {
                    Err(JsonError::UnexpectedChar('?', 0))
                }
            } else {
                Err(JsonError::UnexpectedChar('?', 0))
            }
        }
        // struct 类型
        type_name => {
            if let JsonValue::Object(obj) = json {
                let fields = types.get(type_name).ok_or(JsonError::ExpectedKey)?;
                let mut field_values = Vec::with_capacity(fields.len());
                for (name, ty) in fields {
                    let v = obj.get(name).ok_or(JsonError::ExpectedKey)?;
                    field_values.push(json_to_eip712_value(v, ty, types)?);
                }
                Ok(Eip712Value::Struct(type_name.to_string(), field_values))
            } else {
                Err(JsonError::UnexpectedChar('?', 0))
            }
        }
    }
}

/// 解析 "0x..." 格式 hex 字符串
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_address_hex(s: &str) -> Option<[u8; 20]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 20 {
        return None;
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn parse_bytes32_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn parse_dynamic_bytes_hex(s: &str) -> Option<Vec<u8>> {
    if s.starts_with("0x") {
        parse_hex_bytes(s)
    } else {
        None
    }
}

/// 解析 uint256 字符串 (允许 0x hex 或十进制, 支持任意精度)
fn parse_uint256_string(s: &str) -> Option<[u8; 32]> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let bytes = parse_hex_bytes(s)?;
        if bytes.len() > 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr[32 - bytes.len()..].copy_from_slice(&bytes);
        Some(arr)
    } else {
        // 十进制任意精度: 手动按字节算
        let mut arr = [0u8; 32];
        for c in s.chars() {
            if !c.is_ascii_digit() {
                return None;
            }
            let digit = c as u16 - b'0' as u16;
            // arr *= 10, 然后 + digit
            let mut carry: u16 = 0;
            for i in (0..32).rev() {
                let prod = (arr[i] as u16) * 10 + carry;
                arr[i] = (prod & 0xff) as u8;
                carry = prod >> 8;
            }
            // arr += digit (低位)
            let mut c2: u16 = digit;
            for i in (0..32).rev() {
                let sum = arr[i] as u16 + c2;
                arr[i] = (sum & 0xff) as u8;
                c2 = sum >> 8;
                if c2 == 0 {
                    break;
                }
            }
            if c2 != 0 {
                return None; // overflow
            }
        }
        Some(arr)
    }
}

/// 解析 int256 字符串 (允许负数)
fn parse_int256_string(s: &str) -> Option<[u8; 32]> {
    if s.starts_with("0x") {
        parse_uint256_string(s) // int256 hex 同 uint256 二补码
    } else {
        let negative = s.starts_with('-');
        let abs_str = if negative { &s[1..] } else { s };
        let n: u64 = abs_str.parse().ok()?;
        let mut arr = [0u8; 32];
        if negative {
            // 二补码: n 的 256-bit 补码 = 2^256 - n
            let mut bytes = [0u8; 32];
            bytes[32 - 8..].copy_from_slice(&n.to_be_bytes());
            // (2^256 - n) via 256-bit subtraction: 0 - n with borrow
            let mut result = [0u8; 32];
            let mut borrow: u16 = 0;
            for i in (0..32).rev() {
                let diff = 0_u16 - (bytes[i] as u16) - borrow;
                result[i] = diff as u8;
                borrow = (diff >> 15) & 1; // borrow if diff > 255
                if (diff & 0xFF00) != 0 {
                    borrow = 1;
                }
            }
            arr = result;
        } else {
            arr[32 - 8..].copy_from_slice(&n.to_be_bytes());
        }
        Some(arr)
    }
}

// ─── Human-Readable Parser (v9.1.1 自实现, 零依赖) ──────────────────────

/// 解析 EIP-712 v1 human-readable typed data 字符串
/// 例: `Mail(Person from,Person to,string contents)Person(string name,address wallet)`
/// + 配套 message (空白分隔的 key/value 对)
pub fn parse_typed_data_human_readable(types_str: &str) -> core::result::Result<Types, JsonError> {
    let mut p = HumanReadableParser { input: types_str, pos: 0 };
    p.skip_ws();
    let types = p.parse_types()?;
    p.skip_ws();
    if p.pos < p.input.len() {
        return Err(JsonError::TrailingData);
    }
    Ok(types)
}

struct HumanReadableParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> HumanReadableParser<'a> {
    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
    }

    /// 解析 TypeName(field_type field_name, ...) 序列
    fn parse_types(&mut self) -> core::result::Result<Types, JsonError> {
        let mut types = BTreeMap::new();
        while self.peek().is_some() {
            self.skip_ws();
            if self.peek().is_none() {
                break;
            }
            // TypeName
            let type_name = self.parse_identifier()?;
            if self.advance() != Some('(') {
                return Err(JsonError::UnexpectedChar('(', self.pos));
            }
            // fields
            let mut fields = Vec::new();
            self.skip_ws();
            if self.peek() == Some(')') {
                self.pos += 1;
            } else {
                loop {
                    self.skip_ws();
                    let field_type = self.parse_identifier()?;
                    self.skip_ws();
                    let field_name = self.parse_identifier()?;
                    fields.push((field_name, field_type));
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => {
                            self.pos += 1;
                        }
                        Some(')') => {
                            self.pos += 1;
                            break;
                        }
                        Some(c) => return Err(JsonError::UnexpectedChar(c, self.pos)),
                        None => return Err(JsonError::UnexpectedEnd),
                    }
                }
            }
            types.insert(type_name, fields);
        }
        Ok(types)
    }

    fn parse_identifier(&mut self) -> core::result::Result<String, JsonError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '[' || c == ']' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(JsonError::ExpectedKey);
        }
        Ok(self.input[start..self.pos].to_string())
    }
}

// ─── 测试 ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use std::eprintln;

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            let hi = match bytes[i] {
                b'0'..=b'9' => bytes[i] - b'0',
                b'a'..=b'f' => bytes[i] - b'a' + 10,
                b'A'..=b'F' => bytes[i] - b'A' + 10,
                _ => panic!("invalid hex"),
            };
            let lo = match bytes[i + 1] {
                b'0'..=b'9' => bytes[i + 1] - b'0',
                b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
                b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
                _ => panic!("invalid hex"),
            };
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn mail_types() -> Types {
        let mut types = BTreeMap::new();
        types.insert(
            "EIP712Domain".to_string(),
            alloc::vec![
                ("name".to_string(), "string".to_string()),
                ("version".to_string(), "string".to_string()),
                ("chainId".to_string(), "uint256".to_string()),
                ("verifyingContract".to_string(), "address".to_string()),
            ],
        );
        types.insert(
            "Person".to_string(),
            alloc::vec![
                ("name".to_string(), "string".to_string()),
                ("wallet".to_string(), "address".to_string()),
            ],
        );
        types.insert(
            "Mail".to_string(),
            alloc::vec![
                ("from".to_string(), "Person".to_string()),
                ("to".to_string(), "Person".to_string()),
                ("contents".to_string(), "string".to_string()),
            ],
        );
        types
    }

    /// EIP-712 spec official example: signing hash should be
    /// `d4fd0e7886e54c16a24e747f2af9dd8dd530b32793f9c9f9520bec70ac7c7bc0`
    #[test]
    fn eip712_spec_example() {
        let types = mail_types();

        let domain = Eip712Domain {
            name: Some("Ether Mail".to_string()),
            version: Some("1".to_string()),
            chain_id: Some({
                let mut b = [0u8; 32];
                b[31] = 1;
                b
            }),
            verifying_contract: Some({
                let mut a = [0u8; 20];
                a[0] = 0xCc; a[1] = 0xCC; a[2] = 0xcc; a[3] = 0xCC;
                a[4] = 0xcC; a[5] = 0xCC; a[6] = 0xCC; a[7] = 0xCC;
                a[8] = 0xCC; a[9] = 0xcC; a[10] = 0xCc; a[11] = 0xCc;
                a[12] = 0xcC; a[13] = 0xCC; a[14] = 0xCC; a[15] = 0xCC;
                a[16] = 0xCc; a[17] = 0xCc; a[18] = 0xcC; a[19] = 0xCC;
                a
            }),
            salt: None,
        };

        let alice_addr: [u8; 20] =
            hex_decode("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")
                .try_into()
                .unwrap();
        let bob_addr: [u8; 20] =
            hex_decode("bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")
                .try_into()
                .unwrap();

        let alice = Eip712Value::Struct(
            "Person".to_string(),
            vec![
                Eip712Value::String(b"Cow".to_vec()),
                Eip712Value::Address(alice_addr),
            ],
        );

        let bob = Eip712Value::Struct(
            "Person".to_string(),
            vec![
                Eip712Value::String(b"Bob".to_vec()),
                Eip712Value::Address(bob_addr),
            ],
        );

        let mail = Eip712Value::Struct(
            "Mail".to_string(),
            vec![
                alice,
                bob,
                Eip712Value::String(b"Hello, Bob!".to_vec()),
            ],
        );

        let signing_hash_bytes = signing_hash(&domain, "Mail", &mail, &types).unwrap();
        let expected_hex = "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";
        let expected = hex_decode(expected_hex);
        assert_eq!(
            &signing_hash_bytes[..],
            &expected[..],
            "EIP-712 spec example signing hash mismatch"
        );
    }

    /// 单独测 typeHash
    #[test]
    fn type_hash_spec() {
        let types = mail_types();
        let h = type_hash("EIP712Domain", &types).unwrap();
        let expected = hex_decode("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");
        assert_eq!(&h[..], &expected[..], "domain typeHash mismatch");
    }

    /// 单独测 Mail typeHash
    #[test]
    fn mail_type_hash_spec() {
        let types = mail_types();
        let h = type_hash("Mail", &types).unwrap();
        let expected = hex_decode("a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2");
        assert_eq!(&h[..], &expected[..], "Mail typeHash mismatch");
    }

    /// Domain separator 测试
    #[test]
    fn domain_separator_spec() {
        let types = mail_types();
        let domain = Eip712Domain {
            name: Some("Ether Mail".to_string()),
            version: Some("1".to_string()),
            chain_id: Some({
                let mut b = [0u8; 32];
                b[31] = 1;
                b
            }),
            verifying_contract: Some({
                let mut a = [0u8; 20];
                a[0] = 0xCc; a[1] = 0xCC; a[2] = 0xcc; a[3] = 0xCC;
                a[4] = 0xcC; a[5] = 0xCC; a[6] = 0xCC; a[7] = 0xCC;
                a[8] = 0xCC; a[9] = 0xcC; a[10] = 0xCc; a[11] = 0xCc;
                a[12] = 0xcC; a[13] = 0xCC; a[14] = 0xCC; a[15] = 0xCC;
                a[16] = 0xCc; a[17] = 0xCc; a[18] = 0xcC; a[19] = 0xCC;
                a
            }),
            salt: None,
        };
        let sep = domain.separator_with_types(&types).unwrap();
        let expected =
            hex_decode("f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
        assert_eq!(&sep[..], &expected[..], "domainSeparator mismatch");
    }

    /// 完整 sign_eip712 + 比对 signing hash
    /// 使用 spec 完整测试向量 (name=Ether Mail, alice 0xCD2a..., bob 0xbBbB...)
    /// Expected signing hash: 0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2
    ///
    /// **不比较 r/s**: shlosilo 用 k256 0.14 (RFC6979 + low-s + y_parity 翻转),
    /// spec 例用 ethereumjs util (RFC6979 + high-s, y_parity=0). 同一 sighash 有两组合法签名。
    /// spec v=28 对应 high-s; shlosilo 默认 low-s, y_parity 可能 = 1 (flip 后).
    /// **如果 shlosilo 高对称也 high-s (y_parity=0)**; 低对称 low-s + y_parity=1.
    #[test]
    fn sign_eip712_full_pipeline() {
        // spec test private key = keccak256("cow")
        let private_key_bytes =
            hex_decode("c85ef7d16391b42513a3f97753017c4d7343c8406e034a8cbf16d6dc7c6e3c89");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let types = mail_types();
        let domain = Eip712Domain {
            name: Some("Ether Mail".to_string()),
            version: Some("1".to_string()),
            chain_id: Some({
                let mut b = [0u8; 32];
                b[31] = 1;
                b
            }),
            verifying_contract: Some({
                let mut a = [0u8; 20];
                a[0] = 0xCc; a[1] = 0xCC; a[2] = 0xcc; a[3] = 0xCC;
                a[4] = 0xcC; a[5] = 0xCC; a[6] = 0xCC; a[7] = 0xCC;
                a[8] = 0xCC; a[9] = 0xcC; a[10] = 0xCc; a[11] = 0xCc;
                a[12] = 0xcC; a[13] = 0xCC; a[14] = 0xCC; a[15] = 0xCC;
                a[16] = 0xCc; a[17] = 0xCc; a[18] = 0xcC; a[19] = 0xCC;
                a
            }),
            salt: None,
        };
        let alice_addr: [u8; 20] =
            hex_decode("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")
                .try_into()
                .unwrap();
        let bob_addr: [u8; 20] =
            hex_decode("bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")
                .try_into()
                .unwrap();

        let alice = Eip712Value::Struct(
            "Person".to_string(),
            vec![
                Eip712Value::String(b"Cow".to_vec()),
                Eip712Value::Address(alice_addr),
            ],
        );
        let bob = Eip712Value::Struct(
            "Person".to_string(),
            vec![
                Eip712Value::String(b"Bob".to_vec()),
                Eip712Value::Address(bob_addr),
            ],
        );
        let mail = Eip712Value::Struct(
            "Mail".to_string(),
            vec![alice, bob, Eip712Value::String(b"Hello, Bob!".to_vec())],
        );

        let input = Eip712SignInput {
            domain,
            primary_type: "Mail".to_string(),
            message: mail,
            types,
            private_key,
        };
        let signed = sign_eip712(&input).unwrap();

        // Verify signing hash matches spec (this is the security-critical value)
        let expected_hash =
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";
        let expected_hash_bytes = hex_decode(expected_hash);
        assert_eq!(
            &signed.signing_hash[..],
            &expected_hash_bytes[..],
            "signing hash should match EIP-712 spec"
        );
        // y_parity 0 或 1 都 normal (取决于 RFC6979 k + low-s flip)
        assert!(signed.y_parity == 0 || signed.y_parity == 1);
        // r, s 是 32 bytes 非零
        assert_ne!(signed.r, [0u8; 32]);
        assert_ne!(signed.s, [0u8; 32]);
    }

    /// 确定性
    #[test]
    fn deterministic_signing() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let types = mail_types();
        let domain = Eip712Domain {
            name: Some("Test".to_string()),
            version: Some("1".to_string()),
            chain_id: Some([0u8; 32]),
            verifying_contract: None,
            salt: None,
        };
        let msg = Eip712Value::Struct(
            "Mail".to_string(),
            vec![
                Eip712Value::Struct(
                    "Person".to_string(),
                    vec![
                        Eip712Value::String(b"Alice".to_vec()),
                        Eip712Value::Address([1u8; 20]),
                    ],
                ),
                Eip712Value::Struct(
                    "Person".to_string(),
                    vec![
                        Eip712Value::String(b"Bob".to_vec()),
                        Eip712Value::Address([2u8; 20]),
                    ],
                ),
                Eip712Value::String(b"hi".to_vec()),
            ],
        );

        let input = Eip712SignInput {
            domain,
            primary_type: "Mail".to_string(),
            message: msg,
            types,
            private_key,
        };
        let s1 = sign_eip712(&input).unwrap();
        let s2 = sign_eip712(&input).unwrap();
        assert_eq!(s1.r, s2.r);
        assert_eq!(s1.s, s2.s);
        assert_eq!(s1.y_parity, s2.y_parity);
    }

    /// 不同 domain → 不同 hash
    #[test]
    fn different_domain_different_hash() {
        let types = mail_types();
        let d1 = Eip712Domain {
            name: Some("App1".to_string()),
            version: Some("1".to_string()),
            chain_id: Some([0u8; 32]),
            verifying_contract: None,
            salt: None,
        };
        let mut d2 = d1.clone();
        d2.name = Some("App2".to_string());
        let msg = Eip712Value::Struct(
            "Mail".to_string(),
            vec![
                Eip712Value::Struct("Person".to_string(), vec![Eip712Value::String(b"x".to_vec()), Eip712Value::Address([1u8; 20])]),
                Eip712Value::Struct("Person".to_string(), vec![Eip712Value::String(b"y".to_vec()), Eip712Value::Address([2u8; 20])]),
                Eip712Value::String(b"z".to_vec()),
            ],
        );
        let h1 = signing_hash(&d1, "Mail", &msg, &types).unwrap();
        let h2 = signing_hash(&d2, "Mail", &msg, &types).unwrap();
        assert_ne!(h1, h2);
    }

    /// 数组支持
    #[test]
    fn array_field() {
        // Types: Person has address[] wallets
        let mut types = BTreeMap::new();
        types.insert(
            "Person".to_string(),
            alloc::vec![
                ("name".to_string(), "string".to_string()),
                ("wallets".to_string(), "address[]".to_string()),
            ],
        );
        let person = Eip712Value::Struct(
            "Person".to_string(),
            vec![
                Eip712Value::String(b"Alice".to_vec()),
                Eip712Value::Array(vec![
                    Eip712Value::Address([1u8; 20]),
                    Eip712Value::Address([2u8; 20]),
                ]),
            ],
        );
        let hash = hash_struct("Person", &person, &types).unwrap();
        // 不验证具体值, 只确认不 panic
        assert_eq!(hash.len(), 32);
    }

    // ─── v9.1.1 JSON Parser + Human-Readable Parser + TypedData API ───

    /// JSON parser 基本测试: object / string / number / bool / null / array
    #[test]
    fn json_parser_basic() {
        let v = parse_json(r#"{"name": "Alice", "age": 30, "active": true, "tags": ["a", "b"]}"#).unwrap();
        match v {
            JsonValue::Object(obj) => {
                assert_eq!(obj.len(), 4);
                match obj.get("name").unwrap() {
                    JsonValue::String_(s) => assert_eq!(s, "Alice"),
                    _ => panic!("expected string"),
                }
                match obj.get("age").unwrap() {
                    JsonValue::Num(n) => assert_eq!(*n, 30),
                    _ => panic!("expected number"),
                }
            }
            _ => panic!("expected object"),
        }
    }

    /// JSON parser 错误处理
    #[test]
    fn json_parser_errors() {
        assert!(parse_json("").is_err());
        assert!(parse_json("{").is_err());
        assert!(parse_json("{\"a\": }").is_err());
        assert!(parse_json("{\"a\" \"b\"}").is_err());
        assert!(parse_json("[1, 2,").is_err());
        assert!(parse_json("{\"a\": 1} extra").is_err());
    }

    /// parse_typed_data_v4 + signing_hash 端到端 (EIP-712 Example.js 完整 JSON)
    #[test]
    fn parse_typed_data_v4_full() {
        let json = r#"{
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                },
                "contents": "Hello, Bob!"
            }
        }"#;

        let td = parse_typed_data_v4(json).unwrap();
        assert_eq!(td.primary_type, "Mail");
        assert_eq!(td.domain.name.as_deref(), Some("Ether Mail"));
        assert_eq!(td.domain.chain_id.unwrap()[31], 1);

        // 验证 signing hash 与 v9.1 spec 一致
        let expected_hash =
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";
        let h = td.signing_hash().unwrap();
        let expected = hex_decode(expected_hash);
        assert_eq!(&h[..], &expected[..], "JSON v4 parse → signing_hash mismatch");
    }

    /// parse_typed_data_v4 with uint256 as string (大数, 避免精度损失)
    #[test]
    fn parse_typed_data_v4_uint256_string() {
        // 简化的 uint256 字符串测试
        let json = r#"{
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"}
                ],
                "Permit": [
                    {"name": "value", "type": "uint256"}
                ]
            },
            "primaryType": "Permit",
            "domain": {"name": "Dai", "version": "1"},
            "message": {
                "value": "115792089237316195423570985008687907853269984665640564039457584007913129639935"
            }
        }"#;
        let r = parse_typed_data_v4(json);
        match r {
            Ok(td) => {
                match &td.message {
                    Eip712Value::Struct(_, fields) => match &fields[0] {
                        Eip712Value::Uint256(bytes) => {
                            // 2^256 - 1
                            assert!(bytes.iter().all(|b| *b == 0xff));
                        }
                        _ => panic!("expected uint256, got {:?}", fields[0]),
                    },
                    _ => panic!("expected struct"),
                }
            }
            Err(e) => panic!("parse error: {:?}", e),
        }
    }

    /// Human-readable parser: Mail(Person from,Person to,string contents)Person(string name,address wallet)
    #[test]
    fn human_readable_parser_basic() {
        let types_str = "Mail(Person from,Person to,string contents)Person(string name,address wallet)";
        let types = parse_typed_data_human_readable(types_str).unwrap();
        assert!(types.contains_key("Mail"));
        assert!(types.contains_key("Person"));
        let mail_fields = types.get("Mail").unwrap();
        assert_eq!(mail_fields.len(), 3);
        assert_eq!(mail_fields[0].1, "Person");
        assert_eq!(mail_fields[0].0, "from");
    }

    /// TypedData.signing_hash + sign 顶层 API
    #[test]
    fn typed_data_top_level_api() {
        let private_key_bytes =
            hex_decode("c85ef7d16391b42513a3f97753017c4d7343c8406e034a8cbf16d6dc7c6e3c89");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let json = r#"{
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!"
            }
        }"#;

        let td = parse_typed_data_v4(json).unwrap();
        let signed = td.sign(private_key).unwrap();

        // spec 验证: signing hash 匹配
        let expected_hash =
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";
        assert_eq!(
            &signed.signing_hash[..],
            &hex_decode(expected_hash)[..],
            "TypedData.sign() signing_hash mismatch"
        );
        assert!(signed.y_parity == 0 || signed.y_parity == 1);
    }

    /// TypedData.summary 给 L3 显示
    #[test]
    fn typed_data_summary() {
        let json = r#"{
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Test",
                "version": "1"
            },
            "message": {
                "from": {"name": "Alice", "wallet": "0x000000000000000000000000000000000000c0c0"},
                "to": {"name": "Bob", "wallet": "0x000000000000000000000000000000000000b0b0"},
                "contents": "Hi!"
            }
        }"#;
        let td = parse_typed_data_v4(json).unwrap();
        let summary = td.summary();
        // 验证摘要包含 domain + message 信息
        assert!(summary.contains("EIP712Domain"));
        assert!(summary.contains("Alice"));
        assert!(summary.contains("Bob"));
        assert!(summary.contains("Hi!"));
    }

    /// Array 字段解析
    #[test]
    fn parse_typed_data_v4_array() {
        let json = r#"{
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"}
                ],
                "Multi": [
                    {"name": "values", "type": "uint256[]"}
                ]
            },
            "primaryType": "Multi",
            "domain": {"name": "Test", "version": "1"},
            "message": {
                "values": ["1", "2", "3"]
            }
        }"#;
        let td = parse_typed_data_v4(json).unwrap();
        match &td.message {
            Eip712Value::Struct(_, fields) => match &fields[0] {
                Eip712Value::Array(arr) => {
                    assert_eq!(arr.len(), 3);
                    match &arr[0] {
                        Eip712Value::Uint256(b) => assert_eq!(b[31], 1),
                        _ => panic!("expected uint256"),
                    }
                }
                _ => panic!("expected array"),
            },
            _ => panic!("expected struct"),
        }
    }
}