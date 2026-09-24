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
pub const RING_MAX: usize = 16;

/// Soft: additional tx keys per source/output (real traffic 1-2).
pub const EXTRA_KEYS_MAX: usize = 8;

/// Soft: `tx_extra` nonce payload bytes (payment IDs are 8/9B).
pub const TX_EXTRA_NONCE_MAX: usize = 32;

/// Soft: `tx_extra` additional pubkeys (subaddress sends; one per output).
pub const TX_EXTRA_PUBKEYS_MAX: usize = 16;

/// ClsagProof serialized cap: pseudo_out (32) + c1 (32) + s[RING_MAX] (32*16).
pub const CLSAG_PROOF_MAX: usize = 32 + 32 + 32 * RING_MAX;
