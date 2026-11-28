//! The closed set of signing protocols, and the facts that distinguish them.
//!
//! # Why this type exists (chain-axis design §5, three dispatch granularities)
//!
//! A chain is not one signing protocol. One BTC PSBT can carry a segwit v0 input (ECDSA over a
//! BIP-143 preimage, 64-byte `r||s` in the PSBT map) and a taproot input (Schnorr over a BIP-341
//! preimage, 64-byte `r||s` in a different slot) **in the same request under one operator
//! authorization**. So "which protocol signs this task" cannot be decided by the chain name: the
//! request level decides *what to show and what to authorize*, the task level decides *how to
//! compute one signature*, and the assembly level puts the results back together.
//!
//! This module is the middle one. It is a closed set keyed on **curve × scheme × preimage** —
//! not on wire family, because a PSBT mixing taproot and segwit would otherwise need per-input
//! dispatch one level up, and not on curve alone, because BTC and ETH share secp256k1 while their
//! preimage constructions have nothing in common.
//!
//! # What the variants must distinguish
//!
//! Two tasks that agree on curve and scheme but differ in **preimage** produce different bytes for
//! the same message; two that differ only in **output encoding** produce the same signature
//! material but must be written into different containers. Both distinctions are carried here, and
//! [`SignProtocol::signature_len`] is the first property that falls out of them — the buffer
//! pre-checks, the C-ABI length table and the review face all need that number, and deriving it
//! from the protocol keeps them from drifting apart.
//!
//! # What is deliberately NOT in the set
//!
//! RSA-PSS, EdDSA (SLIP-0010) and anything else the library carries for chains this product does
//! not sign for. A protocol variant earns its place here when a wired chain signs with it; the
//! capability vocabulary (`capabilities/_primitives.toml`) is where "available but unused" lives.

use crate::types::chain_kind::ChainKind;

/// Which preimage construction an ECDSA task signs over.
///
/// These are not interchangeable encodings of one another: the same transaction yields different
/// digests under each, and using the wrong one produces a signature that verifies against nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdsaPreimage {
    /// BIP-143 (segwit v0: P2WPKH and P2SH-wrapped P2WPKH).
    Bip143,
    /// The pre-BIP-143 digest (SigVersion BASE): a legacy P2PKH input signs over the
    /// scriptCode-carrying serialization, which is a DIFFERENT preimage from BIP-143 — not a
    /// variant of it. Signing legacy with the BIP-143 construction produces a signature the
    /// network rejects, and it verifies against nothing locally either.
    LegacyBase,
    /// Ethereum legacy / EIP-155 (RLP of the unsigned fields; `chain_id` folds into `v` when set).
    EthereumLegacy { chain_id: Option<u64> },
    /// EIP-1559 (RLP with the fee-cap fields, typed envelope `0x02`).
    EthereumFeeMarket,
    /// EIP-712 typed data (the domain-separated struct hash).
    EthereumTypedData,
    /// EIP-191 `personal_sign` (the `\x19Ethereum Signed Message:\n` prefix).
    EthereumPersonal,
    /// BIP-137 / BIP-322 Bitcoin message signing.
    BitcoinMessage,
}

/// How the ECDSA signature leaves the signer.
///
/// `r||s` is the same 64 bytes in both cases; the Ethereum shapes append the recovery byte and it
/// means something different in each (y-parity inside typed data, `27/28` for a message, `chain_id`
/// arithmetic for legacy). That semantic lives at the assembly layer — here only the width matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdsaOutput {
    /// 64 bytes: `r || s`.
    Rs64,
    /// 65 bytes: `r || s || v`.
    Rsv65,
}

/// Which preimage construction a Schnorr (BIP-340) task signs over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchnorrPreimage {
    /// BIP-341 key-path sighash (taproot spend of the output key).
    Bip341KeyPath,
    /// BIP-340 over a message that is already a digest (Schnorr message signing).
    Bip340Message,
}

/// One signature task's protocol.
///
/// Construct with the helpers below rather than by hand: they encode which preimage a given wire
/// shape actually uses, which is the fact that is easy to get wrong and hard to notice (a wrong
/// preimage verifies against nothing, but the signature still *looks* well-formed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignProtocol {
    /// ECDSA over secp256k1, RFC-6979 nonces.
    Secp256k1Ecdsa {
        preimage: EcdsaPreimage,
        output: EcdsaOutput,
    },
    /// Schnorr (BIP-340) over secp256k1.
    Secp256k1Schnorr { preimage: SchnorrPreimage },
    /// CLSAG ring signature over edwards25519 (CryptoNote v2 / RingCT).
    Edwards25519ClsagV2,
}

impl SignProtocol {
    /// A BTC segwit v0 input (P2WPKH, or P2SH-wrapped P2WPKH): ECDSA over the BIP-143 preimage,
    /// bare `r || s` in the map.
    pub const fn btc_input_segwit_v0() -> Self {
        Self::Secp256k1Ecdsa {
            preimage: EcdsaPreimage::Bip143,
            output: EcdsaOutput::Rs64,
        }
    }

    /// A BTC legacy P2PKH input: ECDSA over the SigVersion BASE preimage (see
    /// [`EcdsaPreimage::LegacyBase`] for why it is not the BIP-143 one).
    pub const fn btc_input_legacy() -> Self {
        Self::Secp256k1Ecdsa {
            preimage: EcdsaPreimage::LegacyBase,
            output: EcdsaOutput::Rs64,
        }
    }

    /// A BTC taproot key-path spend: Schnorr over the BIP-341 sighash.
    pub const fn btc_taproot_keypath() -> Self {
        Self::Secp256k1Schnorr {
            preimage: SchnorrPreimage::Bip341KeyPath,
        }
    }

    /// An Ethereum transaction (legacy with or without EIP-155, or EIP-1559): ECDSA with the
    /// recovery byte appended.
    pub const fn ethereum_tx(preimage: EcdsaPreimage) -> Self {
        Self::Secp256k1Ecdsa {
            preimage,
            output: EcdsaOutput::Rsv65,
        }
    }

    /// Size of one signature in the bytes this product emits.
    ///
    /// The number a caller needs for buffer pre-checks. It is a property of the protocol, not of
    /// the chain, which is why it is not a table keyed by [`ChainKind`].
    pub const fn signature_len(self) -> usize {
        match self {
            Self::Secp256k1Ecdsa { output, .. } => match output {
                EcdsaOutput::Rs64 => 64,
                EcdsaOutput::Rsv65 => 65,
            },
            Self::Secp256k1Schnorr { .. } => 64,
            Self::Edwards25519ClsagV2 => 96,
        }
    }

    /// The protocol a wired chain signs its *primary* request shape with, or `None` when this
    /// product does not sign for that chain at all.
    ///
    /// A chain appears here as **configuration**, not as a dispatch key: the value is used for
    /// capacities and pre-checks (how wide is one signature), never to decide which crypto runs.
    pub const fn primary_for_chain(chain: ChainKind) -> Option<Self> {
        match chain {
            ChainKind::Btc => Some(Self::btc_input_segwit_v0()),
            ChainKind::Eth => Some(Self::ethereum_tx(EcdsaPreimage::EthereumFeeMarket)),
            ChainKind::Xmr => Some(Self::Edwards25519ClsagV2),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_widths_follow_the_output_shape() {
        assert_eq!(SignProtocol::btc_input_segwit_v0().signature_len(), 64);
        assert_eq!(SignProtocol::btc_input_legacy().signature_len(), 64);
        assert_ne!(
            SignProtocol::btc_input_segwit_v0(),
            SignProtocol::btc_input_legacy(),
            "legacy and segwit v0 sign different preimages"
        );
        assert_eq!(
            SignProtocol::ethereum_tx(EcdsaPreimage::EthereumLegacy { chain_id: None })
                .signature_len(),
            65,
            "Ethereum appends the recovery byte"
        );
        assert_eq!(SignProtocol::btc_taproot_keypath().signature_len(), 64);
        assert_eq!(SignProtocol::Edwards25519ClsagV2.signature_len(), 96);
    }

    /// The tests that matter: two tasks that would produce *different bytes for the same message*
    /// must not compare equal. This is what stops the enum from collapsing into "the chain name
    /// with extra steps".
    #[test]
    fn preimages_are_distinct_where_they_must_be() {
        let legacy = SignProtocol::ethereum_tx(EcdsaPreimage::EthereumLegacy { chain_id: Some(1) });
        let legacy_other_chain = SignProtocol::ethereum_tx(EcdsaPreimage::EthereumLegacy {
            chain_id: Some(11155111),
        });
        let fee_market = SignProtocol::ethereum_tx(EcdsaPreimage::EthereumFeeMarket);
        let typed = SignProtocol::ethereum_tx(EcdsaPreimage::EthereumTypedData);
        let personal = SignProtocol::ethereum_tx(EcdsaPreimage::EthereumPersonal);
        let btc = SignProtocol::btc_input_segwit_v0();
        let btc_legacy = SignProtocol::btc_input_legacy();
        let taproot = SignProtocol::btc_taproot_keypath();

        let all = [
            legacy,
            legacy_other_chain,
            fee_market,
            typed,
            personal,
            btc,
            btc_legacy,
            taproot,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "protocols {i} and {j} must be distinguishable");
                }
            }
        }
    }

    #[test]
    fn same_curve_and_scheme_but_different_preimage_is_not_the_same_protocol() {
        // The specific confusion this module exists to prevent: BTC and ETH both run ECDSA over
        // secp256k1, and their preimages have nothing in common.
        let btc = SignProtocol::btc_input_segwit_v0();
        let btc_legacy = SignProtocol::btc_input_legacy();
        let eth = SignProtocol::ethereum_tx(EcdsaPreimage::EthereumPersonal);
        assert_ne!(btc, eth);
        assert_ne!(
            btc_legacy, btc,
            "legacy BTC is a third preimage, not a flavour of segwit v0"
        );
        assert_ne!(btc_legacy, eth);
        assert_eq!(btc.signature_len(), 64);
        assert_eq!(eth.signature_len(), 65);
    }

    #[test]
    fn only_wired_chains_have_a_primary_protocol() {
        assert!(SignProtocol::primary_for_chain(ChainKind::Btc).is_some());
        assert!(SignProtocol::primary_for_chain(ChainKind::Eth).is_some());
        assert!(SignProtocol::primary_for_chain(ChainKind::Xmr).is_some());
        // Library-only chains: the product does not sign for them, so there is no protocol to
        // name — the capability table says "available", this says "not wired".
        for chain in [
            ChainKind::Sol,
            ChainKind::Ada,
            ChainKind::Ar,
            ChainKind::Tron,
            ChainKind::Apt,
            ChainKind::Sui,
            ChainKind::Near,
            ChainKind::Xrp,
        ] {
            assert_eq!(
                SignProtocol::primary_for_chain(chain),
                None,
                "{chain:?} is not a chain this product signs for"
            );
        }
    }
}
