//! Real unsigned_txset → shlosilo signing → monerod-ready broadcast hex
//! Usage: cargo run --release --example p7_real_sign -- /tmp/test0830_unsigned_txset /tmp/test0830_keys.hex
use shlosilo::chain::xmr::tx_signer::sign_tx_from_construction;
use shlosilo::chain::xmr::unsigned_txset::{decrypt_unsigned_txset, deserialize_unsigned_tx};

fn hex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = std::fs::read(&args[1]).expect("read txset");
    let keys = std::fs::read_to_string(&args[2]).expect("read keys");
    let mut lines = keys.lines().filter(|l| !l.trim().is_empty());
    let spend = hex32(lines.next().unwrap().trim());
    let view = hex32(lines.next().unwrap().trim());

    let plain = decrypt_unsigned_txset(&data, &view).expect("decrypt");
    let mut txes = core::array::from_fn::<
        Option<shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'_>>,
        8,
        _,
    >(|_| None);
    let mut sources =
        core::array::from_fn::<Option<shlosilo::chain::xmr::unsigned_txset::TxSourceEntry>, 32, _>(
            |_| None,
        );
    let mut sd =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut sel = [0usize; 256];
    let mut ex = vec![0u8; plain.len()];
    let mut de =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut su = [0u32; 256];
    let utx = deserialize_unsigned_tx(
        &plain,
        shlosilo::chain::xmr::unsigned_txset::UnsignedTxPools {
            txes: &mut txes,
            sources: &mut sources,
            splitted_dsts: &mut sd,
            selected_transfers: &mut sel,
            extra: &mut ex,
            dests: &mut de,
            subaddr_indices: &mut su,
        },
    )
    .expect("deserialize");
    assert_eq!(utx.txes.len(), 1);
    let tx_data = utx.txes.iter().flatten().next().unwrap();
    println!(
        "signing: {} source(s), ring={}",
        tx_data.sources.len(),
        tx_data
            .sources
            .iter()
            .flatten()
            .next()
            .unwrap()
            .outputs
            .len()
    );

    let mut rng = rand_core::OsRng;
    let bytes = sign_tx_from_construction(tx_data, &spend, &view, &mut rng).expect("sign");
    println!("✓ signed tx: {} bytes, version={}", bytes.len(), bytes[0]);

    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    std::fs::write("/tmp/test0830_signed_tx.hex", &hex).expect("write hex");
    println!("hex written to /tmp/test0830_signed_tx.hex");
}
