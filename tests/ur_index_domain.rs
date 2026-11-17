//! Phase 6 pins: the fountain index domain is u16 and its *capacity* is a platform value.
//!
//! Two things must stay separate or the next step silently breaks the device:
//!
//! 1. **Domain** - no `as u8` truncation on a fragment index anywhere. A 300-fragment
//!    session must produce index 299, not 43.
//! 2. **Capacity** - how many source fragments a platform carries (`ur_source_fragments_max`).
//!    Raising it widens the index arrays *and* the alias sampler, so it needs a measured
//!    budget rather than a wish.
#![cfg(feature = "alloc-fallback")]

use shlosilo::encoding::fountain::{IdxKey, IdxSet};

/// Every profile in the tree must fit the domain the sampler was sized for.
#[test]
fn the_index_domain_is_wide_enough_for_the_configured_capacity() {
    let cap = shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX;
    assert!(cap > 0);
    // u16 means 65,536; the sampler and every index array are sized by the cap.
    assert!(
        cap <= u16::MAX as usize,
        "capacity {cap} does not fit the index type"
    );
    // The key set must be able to hold a full-degree equation (degree ≤ fragment count).
    let mut set: IdxSet = heapless::Vec::new();
    for i in 0..cap as u16 {
        set.push(i)
            .expect("a full-degree set must fit the configured capacity");
    }
    assert_eq!(set.len(), cap);
    // ...and the highest index must survive the trip through the dedup key.
    let high = IdxKey::from_indexes(&[(cap - 1) as u16]);
    let other = IdxKey::from_indexes(&[0]);
    assert_ne!(high, other, "index {} collapsed onto index 0", cap - 1);
}

/// The capacity is the profile's, not a hard-coded 256 in the fountain.
#[test]
fn the_capacity_comes_from_the_profile() {
    assert_eq!(
        shlosilo::encoding::fountain::source_fragments_max(),
        shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX
    );
}
