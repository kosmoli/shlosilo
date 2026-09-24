//! Regression tests for the exact transaction-prefix bytes committed to by CLSAG.

use shlosilo::chain::xmr::transaction::{TransactionPrefix, TxExtra, TxInput, TxOutput};

#[test]
fn txin_to_key_consensus_encoding_is_in_prefix_hash_bytes() {
    let prefix = TransactionPrefix::new(
        0,
        vec![TxInput::new(
            heapless::Vec::from_slice(&[5, 7]).unwrap(),
            [0x11; 32],
        )],
        vec![TxOutput::new_tagged(0, [0x22; 32], 0x33)],
        TxExtra::new(),
    );
    let bytes = prefix.serialize();

    assert_eq!(
        &bytes[..8],
        &[2, 0, 1, 0x02, 0, 2, 5, 7],
        "prefix must contain version, unlock time, vin count, txin_to_key tag, amount, and offsets",
    );

    let mut pos = 0;
    let decoded = TransactionPrefix::deserialize(&bytes, &mut pos).unwrap();
    assert_eq!(decoded, prefix);
    assert_eq!(pos, bytes.len());
}
