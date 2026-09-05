//! P63-XMR mask diagnostics: compare the fixture ring mask with the on-chain outPk commitment

use shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx;

const PLAIN: &[u8] = include_bytes!("fixtures/txset_plain.bin");

#[test]
#[ignore]
fn diag_ring_masks() {
    let cd = deserialize_unsigned_tx(PLAIN).unwrap();
    let src = &cd.txes[0].sources[0];
    for (i, o) in src.outputs.iter().enumerate().take(4) {
        println!(
            "out[{}] idx={} dest={} mask={}",
            i,
            o.index,
            hex32(&o.dest),
            hex32(&o.mask)
        );
    }
}

fn hex32(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
