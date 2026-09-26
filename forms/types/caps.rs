//! Collection capacity leaves for the zero-heap signing path (Z2.3, 2026-09-24,
//! decision "选项2": leaf collections carry fixed caps; aggregate lists are
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

/// Z5.3 D-cut: the Straus scratch byte pool (mirrors the vendor's
/// `StrausScratch::storage_bytes(SIGN_WS_BP_TERMS)`; a pin test asserts the
/// two agree — same source-of-truth discipline as the Z3.3b ws layout).
pub const SIGN_WS_BP_STRAUS_BYTES: usize = (SIGN_WS_BP_TERMS * 2816) + 64;

/// Z5.3 C-cut B: WIP round ping-pong scratch (a/b/g/h double buffers) —
/// byte expression of `WipScratch::storage_bytes(SIGN_WS_BP_TERMS)`.
pub const SIGN_WS_BP_WIP_BYTES: usize = SIGN_WS_BP_TERMS * 960;

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
pub const SIGN_WS_KI: usize = 32;
/// Workspace: tx key image records (flat).
pub const SIGN_WS_TKI: usize = 128;
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
