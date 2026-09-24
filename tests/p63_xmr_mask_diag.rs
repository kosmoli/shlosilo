//! P63-XMR mask diagnostics: compare the fixture ring mask with the on-chain outPk commitment

use shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx;

const PLAIN: &[u8] = include_bytes!("fixtures/txset_plain.bin");

#[test]
#[ignore]
fn diag_ring_masks() {
    let mut p_txes = core::array::from_fn::<
        Option<shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'_>>,
        8,
        _,
    >(|_| None);
    let mut p_src =
        core::array::from_fn::<Option<shlosilo::chain::xmr::unsigned_txset::TxSourceEntry>, 32, _>(
            |_| None,
        );
    let mut p_sd =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut p_su = [0u32; 256];
    let cd = deserialize_unsigned_tx(
        PLAIN,
        shlosilo::chain::xmr::unsigned_txset::UnsignedTxPools {
            txes: &mut p_txes,
            sources: &mut p_src,
            splitted_dsts: &mut p_sd,
            selected_transfers: &mut p_sel,
            extra: &mut p_ex,
            dests: &mut p_de,
            subaddr_indices: &mut p_su,
        },
    )
    .unwrap();
    let src = cd
        .txes
        .iter()
        .flatten()
        .next()
        .unwrap()
        .sources
        .iter()
        .flatten()
        .next()
        .unwrap();
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
