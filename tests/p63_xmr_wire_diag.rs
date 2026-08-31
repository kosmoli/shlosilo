//! P1-06 wire 诊断：逐字段用 monero-rs 原语解码，打印 cursor 偏移
use monero::consensus::Decodable;
use std::io::Cursor;

#[test]
#[ignore = "X7: 需外部凭据/env（SHLOSILO_TEST_XMR_*）——缺 env 不再静默计入 passed；跑法: cargo test -- --ignored 并注入 env"]
fn progressive_decode() {
    let Ok(s) = std::env::var("SHLOSILO_SIGNED_TX_IN") else {
        eprintln!("SKIP");
        return;
    };
    let hex = std::fs::read_to_string(&s).unwrap();
    let h = hex.trim();
    let v: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i+2],16).unwrap()).collect();
    let mut c = Cursor::new(&v[..]);

    use monero::consensus::encode::VarInt;
    let version: u64 = <VarInt as Decodable>::consensus_decode(&mut c).unwrap().0;
    eprintln!("version={} pos={}", version, c.position());
    let unlock: u64 = <VarInt as Decodable>::consensus_decode(&mut c).unwrap().0;
    eprintln!("unlock={} pos={}", unlock, c.position());

    // vin count
    let n_in: u64 = <VarInt as Decodable>::consensus_decode(&mut c).unwrap().0;
    eprintln!("vin_count={} pos={}", n_in, c.position());
    let mut ins = Vec::new();
    for _ in 0..n_in {
        match <monero::TxIn as Decodable>::consensus_decode(&mut c) {
            Ok(monero::TxIn::ToKey { amount, key_offsets, k_image }) => {
                eprintln!("  TxIn ok amount={} noffs={} ki[:6]={:?} pos={}",
                    amount.0, key_offsets.len(), &k_image.image.0[..6], c.position());
                ins.push(monero::TxIn::ToKey { amount, key_offsets, k_image });
            }
            Ok(_other) => panic!("TxIn unexpected variant at pos {}", c.position()),
            Err(e) => panic!("TxIn decode FAIL at pos {}: {:?}", c.position(), e),
        }
    }
    let n_out: u64 = <VarInt as Decodable>::consensus_decode(&mut c).unwrap().0;
    eprintln!("vout_count={} pos={}", n_out, c.position());
    for i in 0..n_out {
        match <monero::TxOut as Decodable>::consensus_decode(&mut c) {
            Ok(_) => eprintln!("  TxOut[{}] ok pos={}", i, c.position()),
            Err(e) => panic!("TxOut[{}] decode FAIL at pos {}: {:?}", i, c.position(), e),
        }
    }
    // extra: varint len + bytes
    let extra_len: u64 = <VarInt as Decodable>::consensus_decode(&mut c).unwrap().0;
    eprintln!("extra_len={} pos={}", extra_len, c.position());
    let mut eb = vec![0u8; extra_len as usize];
    std::io::Read::read_exact(&mut c, &mut eb).unwrap();
    eprintln!("extra consumed pos={}", c.position());

    // rct base
    let rtype: u8 = Decodable::consensus_decode(&mut c).unwrap();
    eprintln!("rct_type={} pos={}", rtype, c.position());
    if rtype == 0 {
        eprintln!("non-rct tx done"); return;
    }
    let fee: u64 = <VarInt as Decodable>::consensus_decode(&mut c).unwrap().0;
    eprintln!("fee={} pos={}", fee, c.position());
    // ecdhInfo 无 count
    for i in 0..n_out {
        let mut amt=[0u8;8];
        std::io::Read::read_exact(&mut c, &mut amt).unwrap();
        eprintln!("  ecdh[{}] pos={}", i, c.position());
    }
    for i in 0..n_out {
        let mut m=[0u8;32];
        std::io::Read::read_exact(&mut c, &mut m).unwrap();
        eprintln!("  outPk[{}] pos={}", i, c.position());
    }
    eprintln!("BASE OK, remaining bytes = {}", (v.len() as u64 - c.position()));
}
