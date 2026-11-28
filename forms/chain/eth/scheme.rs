//! The ETH request's scheme: one mapping, read by both faces.
//!
//! # Why this is a module and not a `match` in two files
//!
//! `data_type` decides which preimage is signed over, and therefore which bytes the operator must
//! be shown. The signing face and the review face each used to carry their own copy of that
//! dispatch, with a comment in both saying "same dispatch as the other one" — a comment is not a
//! mechanism. A fifth `data_type` (or a re-ordered arm) added to one face and not the other would
//! let an operator confirm one shape while the signer computed another, which is the worst class
//! of defect this product can have.
//!
//! So the mapping lives here, both faces call it, and a pin test compares their verdicts over
//! every `data_type` value.
//!
//! # What it deliberately does not do
//!
//! It does not parse. The scheme names *which* parser and *which* preimage; the transaction model
//! (`Eip155Transaction`, `Eip1559Transaction`, the typed-data pool) stays with the code that owns
//! it, because those types borrow the request and cannot live in a `Copy` enum.

use crate::types::sign_protocol::{EcdsaPreimage, SignProtocol};
use crate::ur::codec::eth_sign_request::EthSignDataType;

/// Which ETH request shape a `data_type` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthScheme {
    /// `data_type` 1: legacy transaction, EIP-155 protected (bare RLP preimage, no type byte).
    Legacy,
    /// `data_type` 4: typed transaction, EIP-1559 (`0x02 || rlp([...])`).
    FeeMarket,
    /// `data_type` 2: EIP-712 typed data (the domain-separated struct hash).
    TypedData,
    /// `data_type` 3: EIP-191 `personal_sign` over the raw message.
    Personal,
}

impl EthScheme {
    /// The scheme a request names, or `None` for a shape this product does not sign.
    ///
    /// The `data_type` enum is closed, so `None` is only reachable if the codec grows a value
    /// before this mapping does — and then both faces refuse it rather than one of them guessing.
    pub const fn for_data_type(data_type: EthSignDataType) -> Option<Self> {
        match data_type {
            EthSignDataType::Transaction => Some(Self::Legacy),
            EthSignDataType::TypedTransaction => Some(Self::FeeMarket),
            EthSignDataType::TypedData => Some(Self::TypedData),
            EthSignDataType::PersonalMessage => Some(Self::Personal),
        }
    }

    /// The typed-transaction envelope byte this scheme accepts, if it is a typed transaction.
    ///
    /// Only EIP-1559 is signable today. The other valid type bytes (EIP-2930 `0x01`, EIP-4844
    /// `0x03`, EIP-7702 `0x04`) are named so they answer `FeatureNotImplemented` instead of
    /// degrading into a generic format error — "we do not sign this yet" and "this is corrupt"
    /// must not look alike on the wire.
    pub const fn accepts_type_byte(byte: u8) -> bool {
        byte == 0x02
    }

    /// A valid-but-unsignable typed-transaction envelope.
    pub const fn is_known_unsignable_type_byte(byte: u8) -> bool {
        matches!(byte, 0x01 | 0x03 | 0x04)
    }

    /// The signing protocol this scheme uses.
    ///
    /// Legacy carries its `chain_id` in the preimage, which is why it is the one variant that
    /// needs data: an EIP-155 signature over the wrong chain id is well-formed and worthless.
    pub const fn protocol(self, chain_id: Option<u64>) -> SignProtocol {
        let preimage = match self {
            Self::Legacy => EcdsaPreimage::EthereumLegacy { chain_id },
            Self::FeeMarket => EcdsaPreimage::EthereumFeeMarket,
            Self::TypedData => EcdsaPreimage::EthereumTypedData,
            Self::Personal => EcdsaPreimage::EthereumPersonal,
        };
        SignProtocol::ethereum_tx(preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_DATA_TYPES: [EthSignDataType; 4] = [
        EthSignDataType::Transaction,
        EthSignDataType::TypedTransaction,
        EthSignDataType::TypedData,
        EthSignDataType::PersonalMessage,
    ];

    #[test]
    fn every_data_type_maps_to_exactly_one_scheme() {
        let mut seen = alloc::vec::Vec::new();
        for dt in ALL_DATA_TYPES {
            let scheme = EthScheme::for_data_type(dt).expect("every data_type must map");
            assert!(
                !seen.contains(&scheme),
                "{dt:?} collides with an earlier scheme"
            );
            seen.push(scheme);
        }
        assert_eq!(seen.len(), 4, "four shapes, four schemes");
    }

    #[test]
    fn each_scheme_names_a_distinct_preimage() {
        let protocols = [
            EthScheme::Legacy.protocol(Some(1)),
            EthScheme::FeeMarket.protocol(None),
            EthScheme::TypedData.protocol(None),
            EthScheme::Personal.protocol(None),
        ];
        for (i, a) in protocols.iter().enumerate() {
            for (j, b) in protocols.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "schemes {i} and {j} must not share a protocol");
                }
            }
        }
    }

    #[test]
    fn legacy_carries_its_chain_id_into_the_protocol() {
        // The one place the protocol needs data: same scheme, different chain, different preimage.
        let mainnet = EthScheme::Legacy.protocol(Some(1));
        let sepolia = EthScheme::Legacy.protocol(Some(11155111));
        let unprotected = EthScheme::Legacy.protocol(None);
        assert_ne!(mainnet, sepolia);
        assert_ne!(mainnet, unprotected);
    }

    #[test]
    fn typed_envelope_bytes_are_classified() {
        assert!(EthScheme::accepts_type_byte(0x02), "EIP-1559 is signable");
        for byte in [0x01u8, 0x03, 0x04] {
            assert!(
                EthScheme::is_known_unsignable_type_byte(byte),
                "{byte:#04x} is a valid envelope we do not sign — it must not look corrupt"
            );
            assert!(!EthScheme::accepts_type_byte(byte));
        }
        assert!(!EthScheme::is_known_unsignable_type_byte(0x05));
    }
}
