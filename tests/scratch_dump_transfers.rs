//! SCRATCH dump (2026-10-17): pin the unsigned_tx_set `transfers` segment
//! encoding + verify construction extra round-trip. Temporary — folded into the
//! red pins / fix in the same series.
use shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset;

const TX2_LAB_VIEW_SK: [u8; 32] = [
    0xdb, 0x93, 0xce, 0x63, 0x2d, 0x8d, 0x31, 0xe3, 0x1b, 0xd0, 0xb4, 0xec, 0xbd, 0xbd, 0xb8, 0x33,
    0xca, 0xe8, 0x13, 0x92, 0x8a, 0xf4, 0x02, 0xc5, 0xb7, 0xff, 0xeb, 0x85, 0x76, 0x9c, 0xf0, 0x00,
];

fn read_varint(d: &[u8], off: &mut usize) -> u64 {
    let mut v = 0u64;
    let mut sh = 0;
    loop {
        let b = d[*off];
        *off += 1;
        v |= ((b & 0x7f) as u64) << sh;
        if b & 0x80 == 0 {
            return v;
        }
        sh += 7;
    }
}

fn read_u8(d: &[u8], off: &mut usize) -> u8 {
    let b = d[*off];
    *off += 1;
    b
}

fn take<'a>(d: &'a [u8], off: &mut usize, n: usize) -> &'a [u8] {
    let s = &d[*off..*off + n];
    *off += n;
    s
}

#[ignore = "host tool: dump the fixture transfers segment (findings recorded in TX2_WHITEBOX_REPORT.md section 13)"]
#[test]
fn dump_transfers_segment_and_extra() {
    let enc = include_bytes!("fixtures/tx2_cake_real_unsigned.bin");
    let plain = decrypt_unsigned_txset(enc, &TX2_LAB_VIEW_SK).expect("decrypt");
    println!("plaintext len = {}", plain.len());

    // top: version varint, txes count varint, then per-tx construction data.
    // Walk construction data exactly per read_tx_construction_data field order.
    let d: &[u8] = &plain;
    let mut off = 0usize;
    let ver = read_varint(d, &mut off);
    let n_tx = read_varint(d, &mut off);
    println!("top ver={ver} n_tx={n_tx}");

    for t in 0..n_tx {
        let n_sources = read_varint(d, &mut off);
        println!("  tx{t}: n_sources={n_sources}");
        for s in 0..n_sources {
            let n_out = read_varint(d, &mut off);
            for _ in 0..n_out {
                let _pair_tag = read_u8(d, &mut off);
                let idx = read_varint(d, &mut off);
                let dest = take(d, &mut off, 32);
                let mask = take(d, &mut off, 32);
                if s == 0 {
                    println!(
                        "    src0 out idx={idx} dest={} mask={}",
                        &hex(dest)[..16],
                        &hex(mask)[..16]
                    );
                }
            }
            let real_output = u64::from_le_bytes(take(d, &mut off, 8).try_into().unwrap());
            let real_out_tx_key = take(d, &mut off, 32);
            let n_add = read_varint(d, &mut off);
            for _ in 0..n_add {
                take(d, &mut off, 32);
            }
            let real_output_in_tx_index =
                u64::from_le_bytes(take(d, &mut off, 8).try_into().unwrap());
            let amount = u64::from_le_bytes(take(d, &mut off, 8).try_into().unwrap());
            let rct = read_u8(d, &mut off);
            let mask = take(d, &mut off, 32);
            take(d, &mut off, 32 * 4); // multisig kLRki
            if s == 0 {
                println!(
                    "    src0 real_output={} real_idx={} amount={} rct={} add={} txkey={} mask={}",
                    real_output,
                    real_output_in_tx_index,
                    amount,
                    rct,
                    n_add,
                    &hex(real_out_tx_key)[..16],
                    &hex(mask)[..16]
                );
            }
        }
        // change_dts
        let orig_len = read_varint(d, &mut off);
        let orig = take(d, &mut off, orig_len as usize);
        let ch_amount = read_varint(d, &mut off);
        take(d, &mut off, 64); // spend + view
        let ch_sub = read_u8(d, &mut off);
        let ch_int = read_u8(d, &mut off);
        println!(
            "  tx{t}: change orig_len={} orig='{}' amount={} sub={} int={}",
            orig_len,
            String::from_utf8_lossy(orig),
            ch_amount,
            ch_sub,
            ch_int
        );
        let n_spl = read_varint(d, &mut off);
        for _ in 0..n_spl {
            let ol = read_varint(d, &mut off);
            take(d, &mut off, ol as usize);
            let amt = read_varint(d, &mut off);
            take(d, &mut off, 64);
            let sub = read_u8(d, &mut off);
            let int = read_u8(d, &mut off);
            println!("    splitted dst: amount={amt} sub={sub} int={int}");
        }
        let n_sel = read_varint(d, &mut off);
        let mut sel = Vec::new();
        for _ in 0..n_sel {
            sel.push(read_varint(d, &mut off));
        }
        println!("  tx{t}: selected_transfers={sel:?}");
        let extra_len = read_varint(d, &mut off);
        let extra = take(d, &mut off, extra_len as usize);
        println!(
            "  tx{t}: construction extra_len={} extra={}",
            extra_len,
            &hex(extra)[..extra.len().min(32) * 2]
        );
        let unlock = u64::from_le_bytes(take(d, &mut off, 8).try_into().unwrap());
        let flags = read_u8(d, &mut off);
        let rct_ver = read_varint(d, &mut off);
        let rpt = read_varint(d, &mut off);
        let bp = read_varint(d, &mut off);
        println!("  tx{t}: unlock={unlock} flags={flags} rctcfg=({rct_ver},{rpt},{bp})");
        let n_dst = read_varint(d, &mut off);
        for _ in 0..n_dst {
            let ol = read_varint(d, &mut off);
            take(d, &mut off, ol as usize);
            let amt = read_varint(d, &mut off);
            take(d, &mut off, 64);
            let sub = read_u8(d, &mut off);
            let int = read_u8(d, &mut off);
            println!("    dest: amount={amt} sub={sub} int={int}");
        }
        let sa = u32::from_le_bytes(take(d, &mut off, 4).try_into().unwrap());
        let n_si = read_varint(d, &mut off);
        let mut si = Vec::new();
        for _ in 0..n_si {
            si.push(read_varint(d, &mut off));
        }
        println!("  tx{t}: subaddr_account={sa} subaddr_indices={si:?}");
    }

    // ── remainder = transfers segment ──
    let rest = &d[off..];
    println!(
        "transfers segment offset={off} len={} head={}",
        rest.len(),
        &hex(rest)[..rest.len().min(48) * 2]
    );
    let mut t = 0usize;
    let begin = read_varint(rest, &mut t);
    let end = read_varint(rest, &mut t);
    println!("  begin={begin} end={end}");
    let cnt = read_varint(rest, &mut t);
    println!("  count={cnt}");
    for i in 0..cnt {
        let v = read_varint(rest, &mut t);
        let pubk = take(rest, &mut t, 32);
        let internal_idx = read_varint(rest, &mut t);
        let global_idx = read_varint(rest, &mut t);
        let tx_pub = take(rest, &mut t, 32);
        let flags = read_u8(rest, &mut t);
        let amount = read_varint(rest, &mut t);
        let n_add = read_varint(rest, &mut t);
        for _ in 0..n_add {
            take(rest, &mut t, 32);
        }
        let major = read_varint(rest, &mut t);
        let minor = read_varint(rest, &mut t);
        println!(
            "  etd{i}: v={v} pub={} internal={} global={} txpub={} flags={flags} amount={amount} add={n_add} sub=({major},{minor})",
            &hex(pubk)[..16],
            internal_idx,
            global_idx,
            &hex(tx_pub)[..16]
        );
    }
    println!("  segment consumed {}/{} bytes", t, rest.len());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
