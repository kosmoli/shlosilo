//! Phase 4a workspace pins: the per-input tables live in the caller's buffer now.
//!
//! Three things stopped being free when `rings` / `tx_inputs` / `ring_lens` moved from
//! stack arrays into `SignWs`, and each gets a pin here:
//!
//! 1. **Alignment** — a `&mut [u8]` says nothing about alignment. Every slice the carve
//!    hands out must start on `align_of::<T>()`, whatever offset the caller's buffer has.
//! 2. **Initialisation before read** — the carve owns the "every slot is valid" duty
//!    (rings to zero points, `tx_inputs` to empty inputs, `ring_lens` to 0). A buffer
//!    pre-filled with poison proves nothing is passed through uninitialised.
//! 3. **Disjointness** — the three regions must not overlap the rest of the workspace
//!    (a silent overlap is the classic accounting bug in a byte arena).
// Chain axis: this file drives the xmr surface; without that switch the
// API it uses does not exist.
#![cfg(feature = "chain-xmr")]
#![cfg(feature = "alloc-fallback")]

use monero_ed25519::CompressedPoint;
use shlosilo::business::sign::{carve_sign_ws, SignWsLayout};

/// Carve from a buffer whose base is shifted by `offset` bytes; return the three tables.
fn carve_at(offset: usize) -> (usize, usize, usize, usize) {
    let layout = SignWsLayout::compute();
    let mut backing = std::vec![0xAAu8; layout.total + offset];
    let buf = &mut backing[offset..];
    let ws = carve_sign_ws(buf).expect("carve must succeed");
    let rings_ptr = ws.rings.as_ptr() as usize;
    let tx_ptr = ws.tx_inputs.as_ptr() as usize;
    let lens_ptr = ws.ring_lens.as_ptr() as usize;
    let lens_len = ws.ring_lens.len();
    (rings_ptr, tx_ptr, lens_ptr, lens_len)
}

#[test]
fn tables_are_aligned_for_any_buffer_offset() {
    let ring_align = core::mem::align_of::<
        [(CompressedPoint, CompressedPoint); shlosilo::types::caps::RING_MAX],
    >();
    let tx_align = core::mem::align_of::<shlosilo::chain::xmr::transaction::TxInput>();
    let usize_align = core::mem::align_of::<usize>();
    for offset in 0..4 {
        let (rings, tx, lens, len) = carve_at(offset);
        assert_eq!(rings % ring_align, 0, "rings misaligned at offset {offset}");
        assert_eq!(tx % tx_align, 0, "tx_inputs misaligned at offset {offset}");
        assert_eq!(
            lens % usize_align,
            0,
            "ring_lens misaligned at offset {offset}"
        );
        assert_eq!(len, shlosilo::limits::XMR_INPUTS_MAX);
    }
}

#[test]
fn carve_initialises_every_slot_even_over_poison() {
    let layout = SignWsLayout::compute();
    let mut backing = std::vec![0xAAu8; layout.total];
    let ws = carve_sign_ws(&mut backing).expect("carve");

    // rings: zero points, not the poison pattern.
    let zero = CompressedPoint::from([0u8; 32]);
    for (i, row) in ws.rings.iter().enumerate() {
        for (j, slot) in row.iter().enumerate() {
            assert_eq!(slot.0, zero, "ring[{i}][{j}] not initialised");
            assert_eq!(slot.1, zero, "ring[{i}][{j}] commitment not initialised");
        }
    }
    // tx_inputs: empty offsets + zeroed key image (the signer overwrites what it uses).
    for (i, slot) in ws.tx_inputs.iter().enumerate() {
        assert_eq!(
            slot.key_offsets.len(),
            0,
            "tx_inputs[{i}] offsets not empty"
        );
        assert_eq!(
            slot.key_image, [0u8; 32],
            "tx_inputs[{i}] key image not zeroed"
        );
    }
    // ring_lens: all zero.
    for (i, len) in ws.ring_lens.iter().enumerate() {
        assert_eq!(*len, 0, "ring_lens[{i}] not zeroed");
    }
}

#[test]
fn the_three_regions_do_not_overlap_the_rest_of_the_workspace() {
    let layout = SignWsLayout::compute();
    let mut backing = std::vec![0u8; layout.total];
    let base = backing.as_mut_ptr() as usize;
    let ws = carve_sign_ws(&mut backing).expect("carve");
    let ranges = [
        (
            ws.rings.as_ptr() as usize,
            ws.rings.len() * core::mem::size_of_val(&ws.rings[0]),
            "rings",
        ),
        (
            ws.tx_inputs.as_ptr() as usize,
            core::mem::size_of_val(ws.tx_inputs),
            "tx_inputs",
        ),
        (
            ws.ring_lens.as_ptr() as usize,
            core::mem::size_of_val(ws.ring_lens),
            "ring_lens",
        ),
        // One representative neighbour: the wire slot the signer also writes.
        (ws.tx_bytes.as_ptr() as usize, ws.tx_bytes.len(), "tx_bytes"),
    ];
    for r in ranges {
        assert!(
            r.0 >= base && r.0 + r.1 <= base + layout.total,
            "{} escapes the workspace",
            r.2
        );
    }
    for a in 0..ranges.len() {
        for b in (a + 1)..ranges.len() {
            let (s1, l1, n1) = ranges[a];
            let (s2, l2, n2) = ranges[b];
            assert!(s1 + l1 <= s2 || s2 + l2 <= s1, "{n1} overlaps {n2}");
        }
    }
}

/// The capacity query and the carve come from one computation (contract 3), and the
/// tables are inside it: the total must cover them.
#[test]
fn the_capacity_query_covers_the_input_tables() {
    let layout = SignWsLayout::compute();
    let tables = core::mem::size_of::<
        [(CompressedPoint, CompressedPoint); shlosilo::types::caps::RING_MAX],
    >() * shlosilo::limits::XMR_INPUTS_MAX
        + core::mem::size_of::<shlosilo::chain::xmr::transaction::TxInput>()
            * shlosilo::limits::XMR_INPUTS_MAX
        + core::mem::size_of::<usize>() * shlosilo::limits::XMR_INPUTS_MAX;
    assert!(
        layout.total >= tables,
        "total {} < tables {}",
        layout.total,
        tables
    );
}
