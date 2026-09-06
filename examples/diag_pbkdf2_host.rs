// Throwaway: host timing comparison of the production PBKDF2 path (pbkdf2 crate + sha2
// u64 backend) vs the u32-pair fast path (entropy::pbkdf2_fast), microseconds precision.
use std::time::Instant;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use shlosilo::entropy::pbkdf2_fast::pbkdf2_hmac_sha512;

fn main() {
    let password = [0x11u8; 64];
    let salt = b"mnemonic";
    let mut out = [0u8; 64];
    let mut out2 = [0u8; 64];

    // warmup both paths
    pbkdf2_hmac::<Sha512>(&password, salt, 2048, &mut out);
    pbkdf2_hmac_sha512(&password, salt, 2048, &mut out2);
    assert_eq!(out, out2, "fast path diverges from the pbkdf2 crate");

    let n = 20;
    let t0 = Instant::now();
    for _ in 0..n {
        pbkdf2_hmac::<Sha512>(&password, salt, 2048, &mut out);
    }
    let per_crate = t0.elapsed().as_secs_f64() * 1000.0 / n as f64;

    let t1 = Instant::now();
    for _ in 0..n {
        pbkdf2_hmac_sha512(&password, salt, 2048, &mut out2);
    }
    let per_fast = t1.elapsed().as_secs_f64() * 1000.0 / n as f64;

    println!(
        "PBKDF2-HMAC-SHA512-2048: crate {:.3} ms/run | fast {:.3} ms/run | speedup {:.2}x (host, {} runs)",
        per_crate,
        per_fast,
        per_crate / per_fast,
        n
    );
}
