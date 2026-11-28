//! Which script a PSBT input spends, and therefore which signing protocol it needs.
//!
//! # Why this is its own module (chain-axis design §5, S10)
//!
//! One BTC PSBT can spend four different script shapes in the same request — P2PKH (legacy),
//! P2SH-wrapped P2WPKH (BIP-49), P2WPKH (BIP-84) and P2TR key path (BIP-86) — and each signs a
//! **different preimage** with a different scheme. The per-input decision therefore has to be one
//! classification, not a cascade of `if`s spread through the signing loop: a cascade is how you
//! end up with a fifth shape falling through to whatever branch happened to be last.
//!
//! Two facts come out of the classification, and they are deliberately separate:
//!
//! * **the protocol** — which preimage and which signature scheme. This is the crypto decision.
//! * **the shape** — which PSBT map slots get written (a legacy input carries no witness; a
//!   P2SH-wrapped one needs its redeem script; a taproot one writes `0x13`). This is assembly.
//!
//! Signing uses the shape to choose the writer and the protocol to know what it is signing; the
//! table below pins that the two never disagree.

use crate::types::sign_protocol::SignProtocol;

/// The script a PSBT input spends, as far as signing is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpentScript {
    /// `76a914…88ac` with our HASH160: legacy P2PKH, SigVersion BASE.
    P2pkh,
    /// `a914{20-byte redeem hash}87` wrapping P2WPKH: BIP-49, BIP-143 preimage.
    P2shP2wpkh,
    /// `0014…`: native segwit v0, BIP-143 preimage.
    P2wpkh,
    /// `5120…`: taproot key path, BIP-341 preimage, Schnorr.
    P2tr,
}

impl SpentScript {
    /// The signing protocol this shape uses.
    ///
    /// `const fn` and total: every shape has exactly one protocol, so a new shape cannot be added
    /// without answering this question.
    pub const fn protocol(self) -> SignProtocol {
        match self {
            Self::P2pkh => SignProtocol::btc_input_legacy(),
            Self::P2shP2wpkh | Self::P2wpkh => SignProtocol::btc_input_segwit_v0(),
            Self::P2tr => SignProtocol::btc_taproot_keypath(),
        }
    }
}

/// Classify the script an input spends.
///
/// `spk` is the previous output's `scriptPubKey`; `pubkey_hash` is HASH160 of the key we derived
/// for this input, which is what makes a P2PKH/P2WPKH match *our* key rather than any key.
///
/// Returns `None` for a shape this signer does not spend (P2WSH, bare multisig, a P2PKH for
/// someone else's key…): the caller answers `PsbtOwnershipMismatch`, because "we cannot describe
/// what this input spends" and "this input is not ours" must not be guessed apart.
///
/// # Taproot
///
/// A P2TR input is recognised by the script alone (`OP_1 PUSH32`). Whether we *own* it is decided
/// later, against the `TAP_BIP32_DERIVATION` record — a different check on a different map slot,
/// which is why it is not attempted here.
/// Is this script a P2TR output key? Script-only, because a taproot input carries its ownership
/// record in `TAP_BIP32_DERIVATION` rather than `BIP32_DERIVATION` — the signing loop has to know
/// it is looking at taproot *before* it derives a key from a record that input does not have.
/// Takes `impl AsRef<[u8]>` rather than `&[u8]`: the caller holds a `Cow<[u8]>` (the PSBT's
/// previous output may be borrowed or owned), and every spelling that coerces a `Cow` into an
/// argument position trips a different clippy lint (`needless_borrow`, `useless_asref`,
/// `redundant_slicing`) while a bare `Cow` does not convert. Accepting `AsRef` removes the
/// coercion — and therefore the argument — entirely.
pub fn is_p2tr(spk: impl AsRef<[u8]>) -> bool {
    let spk = spk.as_ref();
    matches!(spk, [0x51, 0x20, rest @ ..] if rest.len() == 32)
}

pub fn classify(spk: &[u8], pubkey_hash: &[u8; 20]) -> Option<SpentScript> {
    if is_p2tr(spk) {
        return Some(SpentScript::P2tr);
    }
    match spk {
        // OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG, for our key
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash == pubkey_hash => {
            Some(SpentScript::P2pkh)
        }
        // OP_HASH160 PUSH20 <redeem hash> OP_EQUAL — the wrapper is verified against the key by
        // the signer that re-derives the redeem script, not here.
        [0xa9, 0x14, rest @ .., 0x87] if rest.len() == 20 => Some(SpentScript::P2shP2wpkh),
        // OP_0 PUSH20 <hash>, for our key
        [0x00, 0x14, hash @ ..] if hash == pubkey_hash => Some(SpentScript::P2wpkh),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 20] = [0x11; 20];
    const OTHER: [u8; 20] = [0x22; 20];

    fn p2pkh(hash: &[u8; 20]) -> [u8; 25] {
        let mut spk = [0u8; 25];
        spk[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
        spk[3..23].copy_from_slice(hash);
        spk[23..].copy_from_slice(&[0x88, 0xac]);
        spk
    }

    #[test]
    fn each_shape_maps_to_its_own_protocol() {
        let p2wpkh = {
            let mut spk = [0u8; 22];
            spk[..2].copy_from_slice(&[0x00, 0x14]);
            spk[2..].copy_from_slice(&HASH);
            spk
        };
        let p2sh = {
            let mut spk = [0u8; 23];
            spk[..2].copy_from_slice(&[0xa9, 0x14]);
            spk[2..22].copy_from_slice(&OTHER);
            spk[22] = 0x87;
            spk
        };
        let p2tr = {
            let mut spk = [0u8; 34];
            spk[..2].copy_from_slice(&[0x51, 0x20]);
            spk[2..].copy_from_slice(&[0x33; 32]);
            spk
        };

        assert_eq!(classify(&p2pkh(&HASH), &HASH), Some(SpentScript::P2pkh));
        assert_eq!(classify(&p2sh, &HASH), Some(SpentScript::P2shP2wpkh));
        assert_eq!(classify(&p2wpkh, &HASH), Some(SpentScript::P2wpkh));
        assert_eq!(classify(&p2tr, &HASH), Some(SpentScript::P2tr));

        // The protocol table: legacy is its own preimage, the two segwit v0 shapes share BIP-143,
        // taproot is Schnorr. Two shapes may share a protocol; no shape may share one with the
        // wrong family.
        assert_eq!(
            SpentScript::P2pkh.protocol(),
            SignProtocol::btc_input_legacy()
        );
        assert_eq!(
            SpentScript::P2wpkh.protocol(),
            SignProtocol::btc_input_segwit_v0()
        );
        assert_eq!(
            SpentScript::P2shP2wpkh.protocol(),
            SignProtocol::btc_input_segwit_v0()
        );
        assert_eq!(
            SpentScript::P2tr.protocol(),
            SignProtocol::btc_taproot_keypath()
        );
        assert_ne!(
            SpentScript::P2pkh.protocol(),
            SpentScript::P2wpkh.protocol(),
            "legacy and segwit v0 must not share a preimage"
        );
    }

    #[test]
    fn a_p2pkh_for_another_key_is_not_ours() {
        assert_eq!(classify(&p2pkh(&OTHER), &HASH), None);
    }

    #[test]
    fn a_p2wpkh_for_another_key_is_not_ours() {
        let mut spk = [0u8; 22];
        spk[..2].copy_from_slice(&[0x00, 0x14]);
        spk[2..].copy_from_slice(&OTHER);
        assert_eq!(classify(&spk, &HASH), None);
    }

    #[test]
    fn unsupported_shapes_are_refused_not_guessed() {
        // P2WSH (OP_0 PUSH32), bare multisig, and a truncated script: all must be None, so the
        // caller refuses with one code instead of falling into a neighbouring branch.
        let p2wsh = {
            let mut spk = [0u8; 34];
            spk[..2].copy_from_slice(&[0x00, 0x20]);
            spk[2..].copy_from_slice(&[0x44; 32]);
            spk
        };
        assert_eq!(classify(&p2wsh, &HASH), None);
        assert_eq!(classify(&[0x51, 0x21, 0x00], &HASH), None);
        assert_eq!(classify(&[], &HASH), None);
        assert_eq!(classify(&[0x76, 0xa9, 0x14], &HASH), None);
    }
}
