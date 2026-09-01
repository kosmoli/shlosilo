//! 打印 fixture ring 全部 16 个 outputs 的 index/dest/mask 与 real_output，
//! 判定 sign 时 ring[real] 是否真的是 real idx。

use shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx;

const PLAIN: &[u8] = include_bytes!("fixtures/txset_plain.bin");

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[test]
#[ignore]
fn diag_ring_full() {
    let cd = deserialize_unsigned_tx(PLAIN).unwrap();
    let src = &cd.txes[0].sources[0];
    {
        let m: String = src.mask.expose().iter().map(|b| format!("{:02x}", b)).collect();
        println!("source.mask (blinding?) = {}", m);
        let rm: String = src.outputs[src.real_output as usize]
            .mask
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!("outputs[real].mask      = {}", rm);
    }
    println!("real_output field = {}", src.real_output);
    for (i, o) in src.outputs.iter().enumerate() {
        println!("out[{:2}] idx={} dest={} mask={}", i, o.index, hexs(&o.dest), hexs(&o.mask));
    }
}
