//! Builds the generators within the Constant Reference String for Bulletproofs(+) at compile-time,
//! allowing apps to solely deserialize them (without having to calculate them).
//!
//! shlosilo patch (2026-09-03): emit compressed bytes + a decompress **loop**.
//! Upstream `vec![decompress(), decompress(), … ×2048]` puts hundreds of KB of
//! EdwardsPoint temporaries on the stack (ForgeBox HardFault 4–5s into first
//! prove_plus). A loop keeps the frame small; the Vec still lands on the heap.

use std::{
    env,
    fs::{remove_file, File},
    io::Write as _,
    path::Path,
};

#[cfg(feature = "compile-time-generators")]
fn generators(prefix: &'static str, path: &str) {
    use curve25519_dalek::EdwardsPoint;

    use monero_bulletproofs_generators::bulletproofs_generators;

    fn serialize_bytes(out: &mut String, points: &[EdwardsPoint]) {
        for generator in points {
            out.extend(format!("        {:?},\n", generator.compress().to_bytes()).chars());
        }
    }

    let generators = bulletproofs_generators(prefix.as_bytes());
    #[allow(non_snake_case)]
    let mut G_str = String::new();
    serialize_bytes(&mut G_str, &generators.G);
    #[allow(non_snake_case)]
    let mut H_str = String::new();
    serialize_bytes(&mut H_str, &generators.H);

    let path = Path::new(&env::var("OUT_DIR").expect("cargo didn't set $OUT_DIR")).join(path);
    let _ = remove_file(&path);
    File::create(&path)
    .expect("failed to create file in $OUT_DIR")
    .write_all(
      format!(
        r#"
          fn decompress_generator_vec(bytes: &[[u8; 32]]) -> std_shims::vec::Vec<curve25519_dalek::EdwardsPoint> {{
            let mut out = std_shims::vec::Vec::with_capacity(bytes.len());
            for b in bytes {{
              out.push(
                curve25519_dalek::edwards::CompressedEdwardsY(*b)
                  .decompress()
                  .expect("generator from build script wasn't on-curve"),
              );
            }}
            out
          }}
          pub(crate) static GENERATORS: LazyLock<Generators> = LazyLock::new(|| {{
            const G_BYTES: &[[u8; 32]] = &[
{G_str}            ];
            const H_BYTES: &[[u8; 32]] = &[
{H_str}            ];
            Generators {{
              G: decompress_generator_vec(G_BYTES),
              H: decompress_generator_vec(H_BYTES),
            }}
          }});
        "#,
      )
      .as_bytes(),
    )
    .expect("couldn't write generated source code to file on disk");
}

#[cfg(not(feature = "compile-time-generators"))]
fn generators(prefix: &'static str, path: &str) {
    let path = Path::new(&env::var("OUT_DIR").expect("cargo didn't set $OUT_DIR")).join(path);
    let _ = remove_file(&path);
    File::create(&path)
        .expect("failed to create file in $OUT_DIR")
        .write_all(
            format!(
                r#"
        pub(crate) static GENERATORS: LazyLock<Generators> = LazyLock::new(|| {{
          monero_bulletproofs_generators::bulletproofs_generators(b"{prefix}")
        }});
      "#,
            )
            .as_bytes(),
        )
        .expect("couldn't write generated source code to file on disk");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    generators("bulletproof", "generators.rs");
    generators("bulletproof_plus", "generators_plus.rs");
}
