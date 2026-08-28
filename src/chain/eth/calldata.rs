//! ETH calldata ABI 解码（硬编码 selector，不是通用 ABI JSON）
//!
//! Phase 5 v9.17
//!
//! ERC-20：`transfer` / `approve` / `increaseAllowance` / `transferFrom`
//! ERC-721/1155：`setApprovalForAll` 完整解码；`safeTransferFrom*` 只识别 selector。

extern crate alloc;

use alloc::string::String;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// 解码后的 calldata（给确认屏，不是签名输入）
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedCalldata {
    Empty,
    Transfer { to: [u8; 20], amount: [u8; 32] },
    Approve { spender: [u8; 20], amount: [u8; 32] },
    IncreaseAllowance { spender: [u8; 20], added: [u8; 32] },
    TransferFrom {
        from: [u8; 20],
        to: [u8; 20],
        amount: [u8; 32],
    },
    SetApprovalForAll { operator: [u8; 20], approved: bool },
    /// 721/1155 等：认出 selector，不拆动态参数
    KnownSelector { name: &'static str, selector: [u8; 4] },
    Unknown { selector: [u8; 4] },
}

const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SEL_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const SEL_INCREASE: [u8; 4] = [0x39, 0x50, 0x93, 0x51];
const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const SEL_SET_APPROVAL: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65];
const SEL_SAFE721: [u8; 4] = [0x42, 0x84, 0x2e, 0x0e];
const SEL_SAFE721_DATA: [u8; 4] = [0xb8, 0x8d, 0x4f, 0xde];
const SEL_SAFE1155: [u8; 4] = [0xf2, 0x42, 0x43, 0x2a];

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

fn word(input: &[u8], i: usize) -> Result<&[u8; 32]> {
    let start = 4 + i * 32;
    let end = start + 32;
    if input.len() < end {
        return Err(err());
    }
    input[start..end].try_into().map_err(|_| err())
}

fn address_word(w: &[u8; 32]) -> Result<[u8; 20]> {
    if w[..12].iter().any(|&b| b != 0) {
        return Err(err());
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..]);
    Ok(a)
}

fn bool_word(w: &[u8; 32]) -> Result<bool> {
    if w[..31].iter().any(|&b| b != 0) {
        return Err(err());
    }
    match w[31] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(err()),
    }
}

fn amount_word(w: &[u8; 32]) -> [u8; 32] {
    *w
}

pub fn decode_calldata(input: &[u8]) -> Result<DecodedCalldata> {
    if input.is_empty() {
        return Ok(DecodedCalldata::Empty);
    }
    if input.len() < 4 {
        return Err(err());
    }
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&input[..4]);
    match sel {
        SEL_TRANSFER => {
            let to = address_word(word(input, 0)?)?;
            let amount = amount_word(word(input, 1)?);
            Ok(DecodedCalldata::Transfer { to, amount })
        }
        SEL_APPROVE => {
            let spender = address_word(word(input, 0)?)?;
            let amount = amount_word(word(input, 1)?);
            Ok(DecodedCalldata::Approve { spender, amount })
        }
        SEL_INCREASE => {
            let spender = address_word(word(input, 0)?)?;
            let added = amount_word(word(input, 1)?);
            Ok(DecodedCalldata::IncreaseAllowance { spender, added })
        }
        SEL_TRANSFER_FROM => {
            let from = address_word(word(input, 0)?)?;
            let to = address_word(word(input, 1)?)?;
            let amount = amount_word(word(input, 2)?);
            Ok(DecodedCalldata::TransferFrom { from, to, amount })
        }
        SEL_SET_APPROVAL => {
            let operator = address_word(word(input, 0)?)?;
            let approved = bool_word(word(input, 1)?)?;
            Ok(DecodedCalldata::SetApprovalForAll { operator, approved })
        }
        SEL_SAFE721 | SEL_SAFE721_DATA | SEL_SAFE1155 => Ok(DecodedCalldata::KnownSelector {
            name: "safeTransferFrom",
            selector: sel,
        }),
        _ => Ok(DecodedCalldata::Unknown { selector: sel }),
    }
}

/// 按 token decimals 格式化 32-byte big-endian 金额（keystone `parse_amount` 行为）
pub fn format_token_amount(amount: &[u8; 32], decimals: u32) -> Result<String> {
    if decimals > 77 {
        return Err(err());
    }
    let mut digits = [0u8; 78];
    for &b in amount {
        let mut carry = b as u16;
        for i in (0..78).rev() {
            let v = digits[i] as u16 * 256 + carry;
            digits[i] = (v % 10) as u8;
            carry = v / 10;
        }
    }
    let dec = decimals as usize;
    let int_end = 78 - dec;
    let mut int_start = 0;
    while int_start + 1 < int_end && digits[int_start] == 0 {
        int_start += 1;
    }
    let mut s = String::new();
    for &d in &digits[int_start..int_end] {
        s.push(char::from(b'0' + d));
    }
    if dec == 0 {
        return Ok(s);
    }
    let frac = &digits[int_end..];
    if frac.iter().all(|&d| d == 0) {
        return Ok(s);
    }
    s.push('.');
    let mut frac_end = frac.len();
    while frac_end > 0 && frac[frac_end - 1] == 0 {
        frac_end -= 1;
    }
    for &d in &frac[..frac_end] {
        s.push(char::from(b'0' + d));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use crate::encoding::keccak256;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn selector(sig: &str) -> [u8; 4] {
        let h = keccak256::hash(sig.as_bytes()).unwrap();
        let mut s = [0u8; 4];
        s.copy_from_slice(&h[..4]);
        s
    }

    #[test]
    fn selectors_match_canonical() {
        assert_eq!(selector("transfer(address,uint256)"), hex_decode("a9059cbb")[..]);
        assert_eq!(selector("approve(address,uint256)"), hex_decode("095ea7b3")[..]);
        assert_eq!(
            selector("increaseAllowance(address,uint256)"),
            hex_decode("39509351")[..]
        );
        assert_eq!(
            selector("transferFrom(address,address,uint256)"),
            hex_decode("23b872dd")[..]
        );
        assert_eq!(
            selector("setApprovalForAll(address,bool)"),
            hex_decode("a22cb465")[..]
        );
        assert_eq!(
            selector("safeTransferFrom(address,address,uint256)"),
            hex_decode("42842e0e")[..]
        );
        assert_eq!(
            selector("safeTransferFrom(address,address,uint256,bytes)"),
            hex_decode("b88d4fde")[..]
        );
        assert_eq!(
            selector("safeTransferFrom(address,address,uint256,uint256,bytes)"),
            hex_decode("f242432a")[..]
        );
    }

    #[test]
    fn keystone_parse_erc20_transfer() {
        let input = hex_decode(
            "a9059cbb0000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de7340000000000000000000000000000000000000000000000000000000000000064",
        );
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::Transfer { to, amount } => {
                assert_eq!(
                    crate::encoding::hex::encode(&to),
                    "5df9b87991262f6ba471f09758cde1c0fc1de734"
                );
                assert_eq!(format_token_amount(&amount, 18).unwrap(), "0.0000000000000001");
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn keystone_parse_erc20_transfer_ten_tokens() {
        let input = hex_decode(
            "a9059cbb0000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de7340000000000000000000000000000000000000000000000008ac7230489e80000",
        );
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::Transfer { amount, .. } => {
                assert_eq!(format_token_amount(&amount, 18).unwrap(), "10");
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn keystone_parse_erc20_transfer_zero() {
        let input = hex_decode(
            "a9059cbb0000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de7340000000000000000000000000000000000000000000000000000000000000000",
        );
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::Transfer { amount, .. } => {
                assert_eq!(format_token_amount(&amount, 18).unwrap(), "0");
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn keystone_parse_erc20_transfer_max_uint() {
        let input = hex_decode(
            "a9059cbb0000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de734ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::Transfer { amount, .. } => {
                assert_eq!(
                    format_token_amount(&amount, 18).unwrap(),
                    "115792089237316195423570985008687907853269984665640564039457.584007913129639935"
                );
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn keystone_parse_erc20_approve() {
        let input = hex_decode(
            "095ea7b30000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de73400000000000000000000000000000000000000000000000000000000006acfc0",
        );
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::Approve { spender, amount } => {
                assert_eq!(
                    crate::encoding::hex::encode(&spender),
                    "5df9b87991262f6ba471f09758cde1c0fc1de734"
                );
                assert_eq!(format_token_amount(&amount, 18).unwrap(), "0.000000000007");
            }
            other => panic!("expected Approve, got {other:?}"),
        }
    }

    #[test]
    fn decode_transfer_from() {
        let input = hex_decode(
            "23b872dd000000000000000000000000111111111111111111111111111111111111111100000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000001",
        );
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::TransferFrom { from, to, amount } => {
                assert_eq!(
                    crate::encoding::hex::encode(&from),
                    "1111111111111111111111111111111111111111"
                );
                assert_eq!(
                    crate::encoding::hex::encode(&to),
                    "2222222222222222222222222222222222222222"
                );
                assert_eq!(format_token_amount(&amount, 0).unwrap(), "1");
            }
            other => panic!("expected TransferFrom, got {other:?}"),
        }
    }

    #[test]
    fn decode_increase_allowance() {
        let input = hex_decode(
            "395093510000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de7340000000000000000000000000000000000000000000000000de0b6b3a7640000",
        );
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::IncreaseAllowance { spender, added } => {
                assert_eq!(
                    crate::encoding::hex::encode(&spender),
                    "5df9b87991262f6ba471f09758cde1c0fc1de734"
                );
                assert_eq!(format_token_amount(&added, 18).unwrap(), "1");
            }
            other => panic!("expected IncreaseAllowance, got {other:?}"),
        }
    }

    #[test]
    fn decode_set_approval_for_all() {
        let input = hex_decode(
            "a22cb4650000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de7340000000000000000000000000000000000000000000000000000000000000001",
        );
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::SetApprovalForAll { operator, approved } => {
                assert_eq!(
                    crate::encoding::hex::encode(&operator),
                    "5df9b87991262f6ba471f09758cde1c0fc1de734"
                );
                assert!(approved);
            }
            other => panic!("expected SetApprovalForAll, got {other:?}"),
        }
    }

    #[test]
    fn decode_erc721_safe_transfer_selector_only() {
        let input = hex_decode("42842e0e");
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::KnownSelector { name, selector } => {
                assert_eq!(name, "safeTransferFrom");
                assert_eq!(selector, hex_decode("42842e0e")[..]);
            }
            other => panic!("expected KnownSelector, got {other:?}"),
        }
    }

    #[test]
    fn decode_empty_is_native() {
        assert_eq!(decode_calldata(&[]).unwrap(), DecodedCalldata::Empty);
    }

    #[test]
    fn decode_unknown_selector() {
        let input = hex_decode("deadbeef0000000000000000000000000000000000000000000000000000000000000000");
        match decode_calldata(&input).unwrap() {
            DecodedCalldata::Unknown { selector } => {
                assert_eq!(selector, hex_decode("deadbeef")[..]);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn dirty_address_padding_rejected() {
        // first 12 bytes of address word not zero
        let input = hex_decode(
            "a9059cbb0000000000000000000000015df9b87991262f6ba471f09758cde1c0fc1de7340000000000000000000000000000000000000000000000000000000000000001",
        );
        assert!(decode_calldata(&input).is_err());
    }

    #[test]
    fn transfer_too_short_rejected() {
        let input = hex_decode("a9059cbb0000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de734");
        assert!(decode_calldata(&input).is_err());
    }
}
