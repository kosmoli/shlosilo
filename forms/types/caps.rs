//! Collection capacity leaves for the zero-heap signing path (Z2.3, 2026-09-24,
//! decision "option 2": leaf collections carry fixed caps; aggregate lists are
//! caller-sized slices — their capacity is a per-appearance deployment parameter,
//! NOT a constant here).
//!
//! Hard = protocol constant (Monero consensus). Soft = v1 working value chosen
//! from measured fixtures + headroom; over-cap input raises an explicit error
//! (silent truncation forbidden) and the value is tunable after the UR-replay /
//! real-wallet validation sweep.

/// Protocol-hard: Monero fixed ring size (post-v13 CLSAG). Never tunable.
/// Z5.3 pool cut: BP+ prove multiexp scratch, in (Scalar, EdwardsPoint)
/// entries. Bound = `2 * padded_pow_of_2(MAX_COMMITMENTS * 64) + 2` = 2*1024+2
/// (the A-terms worst case; WIP L/R need less). Over-cap in the prove chain
/// is an explicit error before any proving starts.
pub const SIGN_WS_BP_TERMS: usize = 2050;

/// Z5.3 D-cut: the Straus scratch byte pool (byte expression of the vendor's
/// `StrausScratch::storage_bytes(SIGN_WS_BP_CHUNK_MAX)`; a pin test asserts the
/// two agree — same source-of-truth discipline as the Z3.3b ws layout).
///
/// T-04 follow-up (2026-09-30): sized for the CHUNK capacity, not the terms
/// bound. The chunked multiexp feeds `multiexp_chunk_terms()` terms at a time
/// (default 36, per-platform deployment), so a terms-cap-sized pool was 57x
/// larger than the live working set (5.77MB -> ~99KB) and pushed the ws past
/// the 8MB PSRAM heap on forgebox ("sign ws: alloc fail (10575072 bytes)").
/// `set_bp_multiexp_chunk_terms` clamps to this cap (a larger chunk would
/// make `StrausScratch::new` fail loudly at prove time).
pub const SIGN_WS_BP_CHUNK_MAX: usize = 36;
pub const SIGN_WS_BP_STRAUS_BYTES: usize =
    SIGN_WS_BP_CHUNK_MAX * (16 * 160) + SIGN_WS_BP_CHUNK_MAX * 256 + 64;
/// CryptoNight-V0 key-derivation scratchpad (algorithm-defined 2MB).
/// T-04 follow-up (2026-09-30): the ws segment is OVERLAID on the
/// bp_straus+bp_wip region (phase time-share — the decrypt key derivation
/// completes before the prove phase; the CN core zeroes the region on every
/// exit path, restoring the carve's documented zero-fill state). The overlay
/// fit is enforced at compile time below and pinned by layout tests.
pub const SIGN_WS_CN_SCRATCH: usize = 1 << 21;

/// T-04 follow-up: the overlay region shared by the CN scratchpad and the
/// straus+wip pair — the larger of the two demands. The wip carve is padded
/// to fill the region (`WipScratch::new` takes "at least" storage).
pub const SIGN_WS_BP_OVERLAY_BYTES: usize =
    if SIGN_WS_CN_SCRATCH > SIGN_WS_BP_STRAUS_BYTES + SIGN_WS_BP_WIP_BYTES {
        SIGN_WS_CN_SCRATCH
    } else {
        SIGN_WS_BP_STRAUS_BYTES + SIGN_WS_BP_WIP_BYTES
    };

/// T-04 follow-up: the overlay must fit the region by construction.
const _: () = assert!(
    SIGN_WS_CN_SCRATCH <= SIGN_WS_BP_OVERLAY_BYTES
        && SIGN_WS_BP_STRAUS_BYTES + SIGN_WS_BP_WIP_BYTES <= SIGN_WS_BP_OVERLAY_BYTES,
    "CN scratchpad overlay must fit the straus+wip region"
);

/// Z5.3 C-cut B: WIP round ping-pong scratch (a/b/g/h double buffers) —
/// byte expression of `WipScratch::storage_bytes(SIGN_WS_BP_TERMS)`.
pub const SIGN_WS_BP_WIP_BYTES: usize = SIGN_WS_BP_TERMS * 960;

/// Z4-7d: PSBT map pool — record pool + payload arena. The map store's home is
/// caller memory (SignWs); `shlosilo_sign_ws_len` reports the capacity
/// (runtime query, never fixed into the ABI). Over-cap is an explicit Err.
pub const SIGN_WS_PSBT_ARENA: usize = 64 * 1024;
pub const SIGN_WS_PSBT_RECS: usize = 128;
/// Z4-7e: BIP32_DERIVATION records per input map (measured: 1 in the fixture;
/// >cap is an explicit Err — single-sig rejects multisig records anyway).
pub const BT_BIP32_RECORDS_MAX: usize = 16;

/// Z5.2b: decompressed generator point element size (curve25519-dalek
/// `EdwardsPoint` repr: 4 x [u64; 5]). Pinned by a static assert in c_abi;
/// the C side sizes table buffers as points * this constant.
pub const SHLOSILO_GENPOINT_SIZE: usize = 160;

/// Z5.2b: per-set generator table storage (deploy constants; pinned ==
/// `generator_table_sizes` runtime query by tests/ffi_gencache_provide.rs —
/// same source-of-truth contract as the Z3.3b ws layout).
pub const SHLOSILO_GENCACHE_G_BYTES: u32 = 163_840;
pub const SHLOSILO_GENCACHE_H_BYTES: u32 = 163_840;
pub const SHLOSILO_GENCACHE_BLOB_BYTES: u32 = 262_144;

pub const RING_MAX: usize = 16;

/// Soft: additional tx keys per source/output (real traffic 1-2).
pub const EXTRA_KEYS_MAX: usize = 8;

/// Soft: `tx_extra` nonce payload bytes (payment IDs are 8/9B).
pub const TX_EXTRA_NONCE_MAX: usize = 32;

/// Soft: `tx_extra` additional pubkeys (subaddress sends; one per output).
pub const TX_EXTRA_PUBKEYS_MAX: usize = 16;

/// Soft: `original` address-string bytes (Monero base58 addresses: standard 95,
/// integrated 106 chars — real traffic never exceeds 106). Over-cap is an
/// explicit EncodingInvalidFormat Err (Z3.1 leaf: the container Vec is gone).
pub const DEST_ORIGINAL_MAX: usize = 106;

// ── Z3.3b sign-workspace deployment caps (single source of truth: the shell,
// the SignWsLayout carve, and the shlosilo_sign_ws_len() query all size from
// these — contract 3 of the C-ABI workspace design). Counts mirror the
// historical shell caps (behavior-identical); tuning is deployment work.

/// Workspace: plaintext scratch == max unsigned-txset plain budget.
pub const SIGN_WS_PLAIN: usize = 16384;
/// Workspace: unsigned-model tx slots.
pub const SIGN_WS_TXES: usize = 8;
/// Workspace: source entries (flat, all txes).
pub const SIGN_WS_SOURCES: usize = 32;
/// Workspace: the retained-leg staging (I13) — the FULL fp-matched retention
/// set for the keystone two-fill map. Mirrors `WalletKiRecord` capacity
/// (pairing-record pool, 64) — a larger retention batch refuses at the sign.
// WP4 (2026-11-02): raised 64 -> 128 alongside the pairing-record cap —
// the keystone-ecosystem scenario (a real wallet's outputs history) crosses
// 64 quickly; the sign workspace lives in PSRAM (ExtMalloc), so the extra
// slots cost heap, not SRAM.
pub const SIGN_WS_RETAINED: usize = 128;
/// Workspace: splitted destinations (flat).
pub const SIGN_WS_SPLITS: usize = 64;
/// Workspace: selected-transfers bytes (flat).
pub const SIGN_WS_SEL: usize = 256;
/// Workspace: tx_extra bytes == max plain budget.
pub const SIGN_WS_EXTRA: usize = 16384;
/// Workspace: model destinations (flat).
pub const SIGN_WS_DESTS: usize = 64;
/// Workspace: subaddress indices (flat).
pub const SIGN_WS_SUBIDX: usize = 256;
/// Workspace: PendingTx slots.
pub const SIGN_WS_PTX: usize = 8;
/// Workspace: signed-tx wire bytes (TX_WIRE_SLOT_MAX per tx).
pub const SIGN_WS_TX_BYTES: usize = 16 * 1024 * 8;
/// Workspace: key images (flat).
/// Raised 32 -> 128 (WP4): the Indexed positional array spans
/// max(selected_transfers)+1 over the wallet's transfer space.
pub const SIGN_WS_KI: usize = 128;
/// Workspace: tx key image records (flat).
/// Raised 128 -> 256 (WP4): the Keyed tail's two-fill union =
/// new outputs (≤100) + retained transfers (≤128).
pub const SIGN_WS_TKI: usize = 256;
/// Workspace: selected-transfers record bytes (flat).
pub const SIGN_WS_SEL_OUT: usize = 256;
/// Workspace: key-image string bytes (67 per source).
pub const SIGN_WS_KSTR: usize = 67 * 32;
/// Workspace: UR decode — decoded-parts slots (FountainWs pool).
pub const UR_WS_DECODED_SLOTS: usize = 256;
/// Workspace: UR decode — work-buffer slots.
pub const UR_WS_BUFFER_SLOTS: usize = 256;
/// Workspace: UR decode — cascade queue slots.
pub const UR_WS_QUEUE_SLOTS: usize = 256;
/// Workspace: UR decode — received-sequence slots (the full fountain sequence
/// space: MAX_TOTAL_FRAMES).
pub const UR_WS_RECEIVED_SLOTS: usize = 4096;

/// Workspace: records-face destinations (flat).
pub const SIGN_WS_RECORD_DESTS: usize = 64;

/// ClsagProof serialized cap: pseudo_out (32) + s[RING_MAX] (32*16) + c1 (32) + D (32).
/// Layout per clsag.rs sign(): `pseudo_out(32) ‖ s[mixin+1] ‖ c1 ‖ D`.
pub const CLSAG_PROOF_MAX: usize = 32 * (RING_MAX + 3);

// === QR transport limits (B-7) =============================================
//
// The two directions are not symmetrical, and treating them as one number is
// how a device ends up able to *collect* a payload it can never *assemble*:
//
// - Inbound (a wallet -> us) is bounded by our **reassembly slots**, not by a
//   memory budget: the fountain decoder completes at `decoded_count >=
//   sequence_count`, and `sequence_count = ceil(消息 / 分片)`. With
//   `UR_WS_DECODED_SLOTS = 256` and the 130-character fragments the Cake family
//   sends by default (bytewords minimal is 4 chars per 2 bytes, so ~65 B of data
//   per part), the ceiling is ~16.6 KiB. That is why
//   `ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN` stays at 16384: raising it
//   without raising the slots produces a session that never completes (progress
//   parks at 99%) - frames are accepted one by one and the request can never be
//   signed.
// - Outbound (us -> a wallet) is ours to choose: we pick the fragment length, so
//   the wallet's decoder - not our slot count - is the limit. 64 KiB covers a
//   29-input spend under the measured size model (722 + 2131·N_in + 711·N_out).

/// Largest signed artifact we emit, and therefore the caller-buffer budget the
/// sign FFI accepts: 64 KiB of payload plus the 512-byte container slack the
/// old `MULTIPART_PAYLOAD_MAX_LEN + 512` shape used.
pub(crate) const SIGN_OUTBOUND_MAX: usize = 64 * 1024 + 512;

#[cfg(test)]
mod transport_limit_pins {
    //! The C side carries these numbers literally (`UR_PAYLOAD_MAX`,
    //! `SIGN_OUT_MAX` in flux/forgebox/src/tasks/product_task.c), so the two
    //! faces are compared here rather than through a `pub` constant: making them
    //! `pub` would export them into shlosilo.h and invite a second source of
    //! truth. `tests/transport_limits.rs` pins the C side and the behaviour.

    #[test]
    fn outbound_cap_is_64k_plus_container_slack() {
        assert_eq!(super::SIGN_OUTBOUND_MAX, 64 * 1024 + 512);
    }
}
