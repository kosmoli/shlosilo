//! Chain-specific business modules
//!
//! Phase 5 v4 real implementation
//!
//! Phase 5 v6 addition: BTC P2WPKH full transaction signing
//! Phase 5 v7 addition: ETH EIP-1559 full transaction signing
//!
//! **Chain axis (design note §9.3-2, batch 1)**: each subtree is behind its own
//! additive `chain-*` feature. Turning one off means the module does not exist at
//! all — every dispatch site that could reach it is gated the same way and answers
//! `ChainKindUnsupported` (C-ABI `UnsupportedChainKind`, -10) instead. The features
//! are additive on purpose: any subset compiles, and `default` (which carries all
//! three) is the pre-axis behaviour.

#[cfg(feature = "chain-btc")]
pub mod btc;
#[cfg(feature = "chain-eth")]
pub mod eth;
#[cfg(feature = "chain-xmr")]
pub mod xmr;
