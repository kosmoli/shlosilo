//! E-case (large-input) request walker — forensic probe.
//!
//! Run with `TOO_LARGE_FRAMES=<frames file> cargo test --release --test
//! e_case_walker -- --ignored --nocapture`. Reassembles an `xmr-txunsigned`
//! UR capture, decrypts the unsigned container with the TEST2 view key and
//! prints the construction shape plus the predicted signed size against the
//! device caps (SIGN_OUT_MAX 16896 / return-UR budget 16384).

#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::xmr::unsigned_txset::{
    decrypt_unsigned_txset, deserialize_unsigned_tx, UnsignedTxPools,
};
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

const TEST2_VIEW_SK: [u8; 32] = [
    0x8d, 0xea, 0xed, 0xf1, 0x13, 0x7e, 0x24, 0xb9, 0xed, 0x25, 0x38, 0xae, 0x99, 0x53, 0x2f, 0x0f,
    0xf7, 0x71, 0x7c, 0x3c, 0x52, 0xd1, 0x16, 0x9c, 0xb0, 0x06, 0x88, 0x1c, 0x48, 0xa7, 0xbb, 0x04,
];

#[test]
#[ignore]
fn walk_e_case_request() {
    let path = std::env::var("TOO_LARGE_FRAMES").expect("set TOO_LARGE_FRAMES");
    let text = std::fs::read_to_string(&path).expect("frames file");
    let frames: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ur:"))
        .collect();
    println!("frames: {}", frames.len());

    let mut dec = UrMultipartDecoder::new();
    for f in &frames {
        dec.receive_frame(f).expect("frame feeds");
    }
    assert!(dec.complete(), "capture must complete");
    let mut out = vec![0u8; 65536];
    let n = dec.payload_into(&mut out).unwrap().expect("complete");
    out.truncate(n);
    println!("UR payload (encrypted container): {n} bytes");
    println!("head: {:02x?}", &out[..8.min(n)]);

    let plain = decrypt_unsigned_txset(&out, &TEST2_VIEW_SK).expect("decrypt unsigned");
    println!("unsigned plain: {} bytes", plain.len());

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
    let utx = deserialize_unsigned_tx(
        &plain,
        UnsignedTxPools {
            txes: &mut p_txes,
            sources: &mut p_src,
            splitted_dsts: &mut p_sd,
            selected_transfers: &mut p_sel,
            extra: &mut p_ex,
            dests: &mut p_de,
            subaddr_indices: &mut p_su,
        },
    )
    .expect("parse unsigned wire");

    let mut total_in = 0usize;
    let mut total_out = 0usize;
    for slot in utx.txes.iter().flatten() {
        let n_in = slot.sources.iter().flatten().count();
        let n_sel = slot.selected_transfers.len();
        let n_split = slot.splitted_dsts.len();
        let n_dst = slot.dests.len();
        println!(
            "tx: sources(flat)={} selected={} splitted_dsts={} dests={} extra={} unlock={}",
            n_in,
            n_sel,
            n_split,
            n_dst,
            slot.extra.len(),
            slot.unlock_time
        );
        total_in += n_in;
        total_out += n_split;
        let sel: Vec<usize> = slot.selected_transfers.iter().copied().collect();
        println!("  selected_transfers idx: {sel:?}");
        for d in slot.dests.iter() {
            println!(
                "  dest: amount={} sub={} int={} addr={:02x?}...",
                d.amount,
                d.is_subaddress,
                d.is_integrated,
                &d.spend_public_key[..4]
            );
        }
    }
    // Size model fitted on three measured points (cap5 4in2out=10669B plain,
    // 1023-shape 4in4out=12092B plain, E-case 9in2out=21327B plain):
    // plain ≈ 722 + 2131·N_in + 711·N_out (input marginal MEASURED; the older
    // 660·N_in figure was an unidentifiable assumption from 4-input-only data).
    let predicted = 722 + 2131 * total_in + 711 * total_out;
    println!("predicted signed plain ≈ {predicted} B (model 722+2131·{total_in}+711·{total_out})");
    println!(
        "caps: SIGN_OUT_MAX=16896, return-UR budget=16384 -> {}",
        if predicted > 16896 {
            "OVER CAP (expected sign rc=-20)"
        } else if predicted > 16384 {
            "over return-UR budget"
        } else {
            "within caps"
        }
    );
}

const TEST2_ENTROPY: [u8; 32] = [
    0x57, 0xaa, 0x02, 0x25, 0x12, 0xf8, 0x65, 0x0c, 0xb8, 0x1d, 0xd3, 0xc9, 0x6c, 0x90, 0xc8, 0x03,
    0x8f, 0xc7, 0x20, 0x80, 0x3c, 0xdb, 0x50, 0xb2, 0x19, 0x8e, 0x8f, 0xf2, 0x26, 0xed, 0x0f, 0x5e,
];
const TEST2_SPEND_SK: [u8; 32] = [
    0x12, 0x83, 0xcb, 0xd5, 0x3a, 0x57, 0x9f, 0x0e, 0x34, 0x90, 0xf3, 0xd9, 0x97, 0x8d, 0x7d, 0x42,
    0x3f, 0x98, 0x69, 0x23, 0xb3, 0x25, 0xa2, 0x33, 0x45, 0x4f, 0xb9, 0x91, 0xd0, 0xbb, 0x28, 0x0d,
];
const FRESH_ENTROPY: [u8; 32] = [
    0x5c, 0x81, 0xd4, 0xe2, 0x9a, 0x07, 0xb6, 0x3f, 0x18, 0xe5, 0xc0, 0x7d, 0x62, 0xa9, 0x4b, 0x38,
    0xf0, 0xe1, 0xc7, 0x5a, 0x26, 0xd8, 0xb3, 0x94, 0x01, 0xf7, 0xea, 0x2c, 0x5b, 0x6d, 0x83, 0x19,
];

/// Re-sign the captured E-case request and measure the signed container size
/// against SIGN_OUT_MAX 16896 (the device's -20 "request too large").
#[test]
#[ignore]
fn sign_e_case_request() {
    use shlosilo::business::sign::{
        sign_with_entropy_records, wallet_fingerprint, SignInput, WalletKiRecord,
    };
    use shlosilo::entropy::mnemonic::Mnemonic;
    use shlosilo::ur::ur_encode::UrTypeTag;

    let path = std::env::var("TOO_LARGE_FRAMES").expect("set TOO_LARGE_FRAMES");
    let text = std::fs::read_to_string(&path).expect("frames file");
    let mut dec = UrMultipartDecoder::new();
    for l in text.lines().map(str::trim).filter(|l| l.starts_with("ur:")) {
        dec.receive_frame(l).expect("frame feeds");
    }
    assert!(dec.complete(), "capture must complete");
    let mut container = vec![0u8; 65536];
    let n = dec.payload_into(&mut container).unwrap().expect("complete");
    container.truncate(n);

    let spend_pub = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &curve25519_dalek::scalar::Scalar::from_bytes_mod_order(TEST2_SPEND_SK))
        .compress()
        .to_bytes();
    let view_pub = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &curve25519_dalek::scalar::Scalar::from_bytes_mod_order(TEST2_VIEW_SK))
        .compress()
        .to_bytes();
    let fp = wallet_fingerprint(&spend_pub, &view_pub);

    // Re-parse to build a record set covering the full ki_span: derive each
    // selected source's key image (same derivation the signer runs) and fill
    // the remaining span slots with dummies (presence only).
    let plain =
        shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset(&container, &TEST2_VIEW_SK)
            .expect("decrypt unsigned");
    let mut q_txes = core::array::from_fn::<
        Option<shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'_>>,
        8,
        _,
    >(|_| None);
    let mut q_src =
        core::array::from_fn::<Option<shlosilo::chain::xmr::unsigned_txset::TxSourceEntry>, 32, _>(
            |_| None,
        );
    let mut q_sd =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut q_sel = [0usize; 256];
    let mut q_ex = [0u8; 8192];
    let mut q_de =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut q_su = [0u32; 256];
    let utx = shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx(
        &plain,
        UnsignedTxPools {
            txes: &mut q_txes,
            sources: &mut q_src,
            splitted_dsts: &mut q_sd,
            selected_transfers: &mut q_sel,
            extra: &mut q_ex,
            dests: &mut q_de,
            subaddr_indices: &mut q_su,
        },
    )
    .expect("parse unsigned wire");

    let mut ki_by_idx: Vec<(u32, [u8; 32])> = Vec::new();
    let mut max_sel = 0u32;
    for slot in utx.txes.iter().flatten() {
        for (src, &sel) in slot
            .sources
            .iter()
            .flatten()
            .zip(slot.selected_transfers.iter())
        {
            let (ki, _off) = shlosilo::chain::xmr::subaddress::derive_input_from_source(
                &TEST2_VIEW_SK,
                &TEST2_SPEND_SK,
                src,
                slot.subaddr_account,
                &slot.subaddr_indices,
            )
            .expect("derive KI");
            ki_by_idx.push((sel as u32, ki));
            max_sel = max_sel.max(sel as u32);
        }
    }
    let mut records: Vec<WalletKiRecord> = Vec::new();
    for i in 0..=max_sel {
        let ki = ki_by_idx
            .iter()
            .find(|(j, _)| *j == i)
            .map(|(_, k)| *k)
            .unwrap_or([0x42; 32]);
        records.push(WalletKiRecord {
            transfer_idx: i,
            wallet_fp: fp,
            key_image: ki,
            out_pub: [i as u8; 32],
        });
    }

    let m = Mnemonic::from_entropy(&TEST2_ENTROPY).expect("mnemonic");
    let mut sbuf = vec![0u8; 32768];
    match sign_with_entropy_records(
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &container,
        &records,
        &FRESH_ENTROPY,
        &mut sbuf,
    ) {
        Ok(nn) => {
            if let Ok(p) = std::env::var("SHLOSILO_SIGNED_CONTAINER_OUT") {
                std::fs::write(p, &sbuf[..nn]).expect("dump signed container");
            }
            println!(
                "SIGN OK: signed container = {nn} bytes (SIGN_OUT_MAX=16896, return budget=16384)"
            )
        }
        Err(e) => println!("SIGN ERR: {e:?}"),
    }
}
