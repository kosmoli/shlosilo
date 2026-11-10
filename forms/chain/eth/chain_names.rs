//! EVM chain id → display name, for the review page.
//!
//! The operator signs a transaction, not a chain id. `chain 1` tells nobody which
//! network they are about to spend on, and a wrong-network send is unrecoverable -
//! so a known chain gets its name next to the id.
//!
//! Every entry is machine-read from the authoritative registry
//! (`https://github.com/ethereum-lists/chains`, `_data/chains/eip155-<id>.json`,
//! fetched 2026-11-11) and the raw snapshot is committed as
//! `tests/fixtures/eip155_chains.json`; a test walks that file and fails if this
//! table drifts from it (no hand-typed names, and no quietly added chain).
//!
//! Ids outside this table are NOT guessed: the review page prints the raw id, which
//! is the only thing we actually know about them.

/// (chain id, name) for the chains this firmware names, lowercase for the ASCII-only
/// device font.
pub const KNOWN_CHAINS: [(u64, &str); 10] = [
    (1, "ethereum mainnet"),
    (10, "op mainnet"),
    (56, "bnb smart chain mainnet"),
    (100, "gnosis"),
    (137, "polygon mainnet"),
    (250, "fantom opera"),
    (324, "zksync mainnet"),
    (8453, "base"),
    (42161, "arbitrum one"),
    (43114, "avalanche c-chain"),
];

/// The display name of `chain_id`, or `None` when this firmware does not know it.
pub fn chain_name(chain_id: u64) -> Option<&'static str> {
    let mut i = 0;
    while i < KNOWN_CHAINS.len() {
        if KNOWN_CHAINS[i].0 == chain_id {
            return Some(KNOWN_CHAINS[i].1);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_are_unique_and_non_empty() {
        for (i, (id, name)) in KNOWN_CHAINS.iter().enumerate() {
            assert!(!name.is_empty(), "chain {id} has no name");
            assert!(
                name.is_ascii()
                    && name.chars().all(|c| c.is_ascii_lowercase()
                        || c == ' '
                        || c.is_ascii_digit()
                        || c == '-'),
                "chain {id} name must be lowercase ASCII: {name}"
            );
            // a review line is 48 chars: "chain <id> <name>"
            assert!(
                name.len() + 12 <= 48,
                "chain {id} name too long for one review line: {name}"
            );
            for (j, (other, _)) in KNOWN_CHAINS.iter().enumerate() {
                if i != j {
                    assert_ne!(id, other, "duplicate chain id {id}");
                }
            }
        }
    }

    #[test]
    fn lookup_and_unknown() {
        assert_eq!(chain_name(1), Some("ethereum mainnet"));
        assert_eq!(chain_name(42161), Some("arbitrum one"));
        // an id we do not know must stay unknown rather than borrow a name
        assert_eq!(chain_name(0), None);
        assert_eq!(chain_name(999_999), None);
        assert_eq!(chain_name(5), None); // goerli: deliberately not named
    }
}
