//! ETH transaction summary / risk flags (Phase 5 v9.18)
//!
//! L1 pure functions: turn EIP-155 / EIP-1559 structures + v9.17 calldata decoding
//! into confirmation-screen data. No DEX/swap recognition.

#[cfg(feature = "alloc-fallback")]
extern crate alloc;
// Consumers live behind alloc-fallback / cfg(test).
#[cfg(feature = "alloc-fallback")]
#[allow(unused_imports)]
use alloc::string::String;

use crate::chain::eth::calldata::{decode_calldata, DecodedCalldata};
// The String formatter lives behind alloc-fallback with its consumer.
#[cfg(feature = "alloc-fallback")]
use crate::chain::eth::calldata::format_token_amount;
use crate::chain::eth::eip155::Eip155Transaction;
use crate::chain::eth::eip1559::Eip1559Transaction;
use crate::error::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EthCallKind {
    NativeTransfer,
    ContractCreation,
    Token(DecodedCalldata),
    UnknownCall { selector: [u8; 4] },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthTxSummary {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub gas_limit: u64,
    /// max fee = max_fee_per_gas * gas_limit (1559); legacy uses gas_price * gas_limit
    pub max_fee_wei: u128,
    pub call: EthCallKind,
    /// unlimited approval (approve / increaseAllowance with amount all 1s)
    pub unlimited_approval: bool,
    pub is_contract_creation: bool,
}

fn classify_call(destination: Option<[u8; 20]>, data: &[u8]) -> Result<(EthCallKind, bool)> {
    if destination.is_none() {
        return Ok((EthCallKind::ContractCreation, false));
    }
    if data.is_empty() {
        return Ok((EthCallKind::NativeTransfer, false));
    }
    match decode_calldata(data)? {
        DecodedCalldata::Empty => Ok((EthCallKind::NativeTransfer, false)),
        DecodedCalldata::Unknown { selector } => Ok((EthCallKind::UnknownCall { selector }, false)),
        DecodedCalldata::Approve { amount, spender } => {
            let unlimited = amount.iter().all(|&b| b == 0xff);
            Ok((
                EthCallKind::Token(DecodedCalldata::Approve { spender, amount }),
                unlimited,
            ))
        }
        DecodedCalldata::IncreaseAllowance { added, spender } => {
            let unlimited = added.iter().all(|&b| b == 0xff);
            Ok((
                EthCallKind::Token(DecodedCalldata::IncreaseAllowance { spender, added }),
                unlimited,
            ))
        }
        other => Ok((EthCallKind::Token(other), false)),
    }
}

pub fn summarize_eip1559(tx: &Eip1559Transaction) -> Result<EthTxSummary> {
    let (call, unlimited_approval) = classify_call(tx.destination, &tx.data)?;
    Ok(EthTxSummary {
        chain_id: tx.chain_id,
        nonce: tx.nonce,
        to: tx.destination,
        value: tx.amount,
        gas_limit: tx.gas_limit,
        max_fee_wei: tx.max_fee_per_gas.saturating_mul(tx.gas_limit as u128),
        call,
        unlimited_approval,
        is_contract_creation: tx.destination.is_none(),
    })
}

pub fn summarize_eip155(tx: &Eip155Transaction) -> Result<EthTxSummary> {
    let (call, unlimited_approval) = classify_call(tx.destination, &tx.data)?;
    Ok(EthTxSummary {
        chain_id: tx.chain_id,
        nonce: tx.nonce,
        to: tx.destination,
        value: tx.amount,
        gas_limit: tx.gas_limit,
        max_fee_wei: tx.gas_price.saturating_mul(tx.gas_limit as u128),
        call,
        unlimited_approval,
        is_contract_creation: tx.destination.is_none(),
    })
}

/// Format a 32-byte token amount into an 18-decimal string (for tests and the confirmation screen)
#[cfg(feature = "alloc-fallback")]
pub fn format_eth_wei(wei: u128) -> Result<String> {
    let mut buf = [0u8; 32];
    let bytes = wei.to_be_bytes();
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    format_token_amount(&buf, 18)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;
    use alloc::vec;
    use alloc::vec::Vec;

    fn hex_decode(s: &str) -> Vec<u8> {
        let s: alloc::string::String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn addr(s: &str) -> [u8; 20] {
        hex_decode(s).try_into().unwrap()
    }

    #[test]
    fn native_transfer_1559() {
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21_000,
            destination: Some(addr("49ab56b91fc982fd6ec1ec7bb87d74efa6da30ab")),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };
        let s = summarize_eip1559(&tx).unwrap();
        assert_eq!(s.chain_id, 1);
        assert_eq!(s.nonce, 42);
        assert_eq!(s.value, 1_000_000_000_000_000_000);
        assert_eq!(s.max_fee_wei, 100_000_000_000u128 * 21_000);
        assert_eq!(s.call, EthCallKind::NativeTransfer);
        assert!(!s.unlimited_approval);
        assert!(!s.is_contract_creation);
        assert_eq!(format_eth_wei(s.value).unwrap(), "1");
    }

    #[test]
    fn contract_creation() {
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 1_000_000,
            destination: None,
            amount: 0,
            data: vec![0x60, 0x80].into(),
        };
        let s = summarize_eip1559(&tx).unwrap();
        assert_eq!(s.call, EthCallKind::ContractCreation);
        assert!(s.is_contract_creation);
    }

    #[test]
    fn erc20_transfer_decoded() {
        let data = hex_decode(
            "a9059cbb0000000000000000000000005df9b87991262f6ba471f09758cde1c0fc1de7340000000000000000000000000000000000000000000000000000000000000001",
        );
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 1,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 65_000,
            destination: Some(addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")),
            amount: 0,
            data: data.into(),
        };
        let s = summarize_eip1559(&tx).unwrap();
        match s.call {
            EthCallKind::Token(DecodedCalldata::Transfer { to, amount }) => {
                assert_eq!(hex::encode(&to), "5df9b87991262f6ba471f09758cde1c0fc1de734");
                assert_eq!(amount[31], 1);
            }
            other => panic!("{other:?}"),
        }
        assert!(!s.unlimited_approval);
    }

    #[test]
    fn unlimited_approve_flagged() {
        let data = hex_decode(
            "095ea7b3\
             0000000000000000000000001111111111111111111111111111111111111111\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 50_000,
            destination: Some([0u8; 20]),
            amount: 0,
            data: data.into(),
        };
        let s = summarize_eip155(&tx).unwrap();
        assert!(s.unlimited_approval);
        assert_eq!(s.max_fee_wei, 20_000_000_000u128 * 50_000);
        match s.call {
            EthCallKind::Token(DecodedCalldata::Approve { .. }) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_selector_kept() {
        let mut data = vec![0xde, 0xad, 0xbe, 0xef];
        data.extend_from_slice(&[0u8; 32]);
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 21_000,
            destination: Some([1u8; 20]),
            amount: 0,
            data: data.into(),
        };
        let s = summarize_eip1559(&tx).unwrap();
        match s.call {
            EthCallKind::UnknownCall { selector } => {
                assert_eq!(selector, [0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("{other:?}"),
        }
    }
}
