//! TxNormalize: UR payload → TxTemplate
//!
//! **Phase 2.4 fake implementation**: infers ChainKind from the UR type tag and generates a minimal TxTemplate
//! Phase 4 real implementation: full UR payload parsing + ChainKind inference + tx field extraction

use crate::error::Result;
use crate::types::chain_kind::ChainKind;
use crate::ur::ur_encode::UrTypeTag;

extern crate alloc;

/// Transaction template (chain-agnostic)
///
/// After the business module gets a TxTemplate, it dispatches by ChainKind to the matching chain handler
/// Z2.4a (2026-09-24): `payload` borrows the caller's input buffer (C-class policy —
/// the P6.3 HardFault lesson stands: never on the stack; the caller's buffer is the
/// single home, zero copies).
#[derive(Clone, Debug)]
pub struct TxTemplate<'a> {
    pub chain_kind: ChainKind,
    /// raw payload (chain-specific parsing by the business modules)
    pub payload: &'a [u8],
    /// Derivation path (used by business modules to dispatch; distinguishes mainnet/testnet + account)
    pub derivation_path: crate::derivation::path::DerivationPath,
}

/// explicit payload cap: real PSBT 12KB + headroom. Above it raises UrPayloadTooLarge (silent truncation forbidden).
const PAYLOAD_MAX: usize = 16384;

/// UR payload → TxTemplate
///
/// **P1-01 (2026-08-26)**: ChainKind is no longer inferred from the payload's first byte — the type tag
/// Carried by the UR decode layer (`ur:<type>/`); the business layer calls the matching codec by type.
/// The legacy `UrTypeTag::from_bytes` first-byte private tag protocol is deprecated.
pub fn to_template<'a>(type_tag: UrTypeTag, payload: &'a [u8]) -> Result<TxTemplate<'a>> {
    let chain_kind = match type_tag {
        UrTypeTag::CryptoPsbt => ChainKind::Btc,
        UrTypeTag::EthSignRequest => ChainKind::Eth,
        UrTypeTag::CryptoMoneroTx | UrTypeTag::XmrTxUnsigned | UrTypeTag::XmrTxSigned => {
            ChainKind::Xmr
        }
        UrTypeTag::SolanaSignRequest => ChainKind::Sol,
        UrTypeTag::CardanoSignRequest => ChainKind::Ada,
        UrTypeTag::CosmosSignRequest => ChainKind::Cosmos,
        UrTypeTag::Bytes
        | UrTypeTag::CryptoHdKey
        | UrTypeTag::CryptoAccount
        | UrTypeTag::Unknown => {
            return Err(crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::UrPayloadUnknownType,
            ));
        }
    };
    let derivation_path = crate::derivation::path::DerivationPath::parse("m/44'/0'/0'/0/0")
        .map_err(|_| {
            crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::DerivationPathInvalidSyntax,
            )
        })?;
    if payload.len() > PAYLOAD_MAX {
        return Err(crate::error::ShlosiloError::new(
            crate::error::ShlosiloErrorKind::UrPayloadTooLarge,
        ));
    }
    Ok(TxTemplate {
        chain_kind,
        payload,
        derivation_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_template_btc() {
        let result = to_template(UrTypeTag::CryptoPsbt, &[0x58, 0x03, 1, 2, 3]);
        assert!(result.is_ok());
        let template = result.unwrap();
        assert_eq!(template.chain_kind, ChainKind::Btc);
    }

    #[test]
    fn to_template_xmr() {
        let result = to_template(UrTypeTag::CryptoMoneroTx, &[1, 2, 3]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().chain_kind, ChainKind::Xmr);
    }

    #[test]
    fn to_template_unknown_rejected() {
        let result = to_template(UrTypeTag::Unknown, &[99, 1, 2, 3]);
        assert!(result.is_err());
    }

    /// P1-01: the type is decided by the tag; the payload's first byte no longer has special meaning
    #[test]
    fn to_template_type_tag_not_first_byte() {
        // same payload, different tag → different chain
        let btc = to_template(UrTypeTag::CryptoPsbt, &[0x01, 0x02]).unwrap();
        let eth = to_template(UrTypeTag::EthSignRequest, &[0x01, 0x02]).unwrap();
        assert_eq!(btc.chain_kind, ChainKind::Btc);
        assert_eq!(eth.chain_kind, ChainKind::Eth);
    }

    /// P1-01: the payload is fully preserved (including the CBOR wrapper); no first-byte stripping
    #[test]
    fn to_template_payload_preserved() {
        let payload = [0xa2u8, 0x01, 0x02, 0x03];
        let t = to_template(UrTypeTag::EthSignRequest, &payload).unwrap();
        assert_eq!(t.payload, &payload[..]);
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("tx_normalize.rs");
        assert!(source.contains("Phase 2.4"));
        assert!(source.contains("ChainKind"));
    }
}
