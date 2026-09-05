//! Decrypt and parse a real unsigned_txset (from a test0830 watch-only wallet wallet-rpc transfer)
//! Usage: cargo run --example p7_real_unsigned -- /tmp/test0830_unsigned_txset /tmp/test0830_keys.hex
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
    let _spend = hex32(lines.next().unwrap().trim());
    let view = hex32(lines.next().unwrap().trim());

    println!("txset {} bytes", data.len());
    let plain = decrypt_unsigned_txset(&data, &view).expect("decrypt");
    println!(
        "✓ decrypt: {} bytes plaintext (Schnorr sig + ChaCha20-Legacy OK)",
        plain.len()
    );
    let utx = deserialize_unsigned_tx(&plain).expect("deserialize");
    println!("✓ deserialize: {} tx construction data", utx.txes.len());
    for (i, tx) in utx.txes.iter().enumerate() {
        println!(
            "tx[{}]: {} sources, use_rct={}, unlock_time={}",
            i,
            tx.sources.len(),
            tx.use_rct,
            tx.unlock_time
        );
        for (j, s) in tx.sources.iter().enumerate() {
            println!(
                "  source[{}]: amount={} ring={} real_output={}",
                j,
                s.amount,
                s.outputs.len(),
                s.real_output
            );
        }
        println!("  change: amount={}", tx.change_dts.amount);
        for d in &tx.splitted_dsts {
            println!("  dest: amount={}", d.amount);
        }
        println!("  selected_transfers: {:?}", tx.selected_transfers);
    }
}
