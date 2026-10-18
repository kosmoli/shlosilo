// quick check: display count (payload/200) vs real fountain count ((shell+payload)/200)
#[test]
#[ignore = "host probe"]
fn frag_count_mismatch() {
    use shlosilo::ur::ur_multipart::UrMultipartEncoder;
    for plen in [3600usize, 3700, 3797, 3798, 3799, 3800, 3801, 3937] {
        let payload = vec![0xABu8; plen];
        let enc = UrMultipartEncoder::new("xmr-txsigned", &payload, 200).unwrap();
        let real = enc.fragment_count();
        let display = plen.div_ceil(200);
        println!(
            "payload {plen}: display(g_ur_total)={display} real_fountain={real} {}",
            if real != display { "<-- MISMATCH" } else { "" }
        );
    }
}
