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
    let mut f = File::create(&path).expect("failed to create file in $OUT_DIR");
    // Z5.2b: emitted table lengths — the single sizing source of truth for the
    // probe, the provide validation, and the init-time fill check.
    let _ = f.write_all(
        format!(
        "pub(crate) const TABLE_G_LEN: usize = {};\npub(crate) const TABLE_H_LEN: usize = {};\n",
        generators.G.len(),
        generators.H.len(),
      )
        .as_bytes(),
    );
    f.write_all(
      format!(
        r#"
          #[cfg(feature = "alloc-fallback")]
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
          #[cfg(feature = "alloc-fallback")]
          fn rebuild_from_blob(blob: &[u8], n: usize) -> crate::generator_cache_hook::Generators<'static> {{
            // n points x 128 bytes of raw extended coordinates (X, Y, Z, T),
            // all G first, then all H. Coordinates came from validated points.
            let mut g = std_shims::vec::Vec::with_capacity(n / 2);
            let mut h = std_shims::vec::Vec::with_capacity(n / 2);
            let mut buf = [0u8; 128];
            let mut idx = 0;
            for _ in 0..(n / 2) {{
              buf.copy_from_slice(&blob[idx..idx + 128]);
              idx += 128;
              g.push(curve25519_dalek::EdwardsPoint::from_raw_extended_bytes(&buf));
            }}
            for _ in 0..(n / 2) {{
              buf.copy_from_slice(&blob[idx..idx + 128]);
              idx += 128;
              h.push(curve25519_dalek::EdwardsPoint::from_raw_extended_bytes(&buf));
            }}
            crate::generator_cache_hook::Generators {{
              G: crate::generator_cache_hook::leak_vec(g),
              H: crate::generator_cache_hook::leak_vec(h),
            }}
          }}
          // A3 (2026-09-28): the compressed table stays in flash (~64KB);
          // decompression is emplacement into caller-provided gencache
          // storage (once), behind the atomic ready flag. No LazyLock, no
          // 640KB expanded cache in flash, no intermediate Vec.
          pub(crate) fn generators() -> Result<crate::generator_cache_hook::Generators<'static>, crate::generator_cache_hook::InitError> {{
            const G_BYTES: &[[u8; 32]] = &[
{G_str}            ];
            const H_BYTES: &[[u8; 32]] = &[
{H_str}            ];
            let n_points = G_BYTES.len() + H_BYTES.len();
            // ready read first (Acquire): initialized sets borrow directly.
            if let Some(gens) = crate::generator_cache_hook::table_generators(b"{prefix}") {{
              return Ok(gens);
            }}
            // Z5.2: caller-provided decompressed table storage (emplacement).
            if let Some(st) = crate::generator_cache_hook::take_table_storage(b"{prefix}") {{
              if st.g.len() == G_BYTES.len() && st.h.len() == H_BYTES.len() {{
                return crate::generator_cache_hook::init_tables(b"{prefix}", n_points, G_BYTES, H_BYTES, st);
              }}
              return Err(crate::generator_cache_hook::InitError::BlobMismatch);
            }}
            // Transitional fallback (alloc-fallback feature): one-shot
            // decompress into a leaked Vec. Load-hit still honored (persistence
            // works without table storage).
            #[cfg(feature = "alloc-fallback")]
            {{
              if let Some(blob) = crate::generator_cache_hook::try_load_blob(b"{prefix}", n_points) {{
                return Ok(rebuild_from_blob(blob, n_points));
              }}
              let g = decompress_generator_vec(G_BYTES);
              let h = decompress_generator_vec(H_BYTES);
              {{
                let mut blob = std_shims::vec::Vec::with_capacity(n_points * 128);
                for p in g.iter() {{ blob.extend_from_slice(&p.to_raw_extended_bytes()); }}
                for p in h.iter() {{ blob.extend_from_slice(&p.to_raw_extended_bytes()); }}
                crate::generator_cache_hook::try_store_blob(b"{prefix}", &blob);
              }}
              return Ok(crate::generator_cache_hook::Generators {{
                G: crate::generator_cache_hook::leak_vec(g),
                H: crate::generator_cache_hook::leak_vec(h),
              }});
            }}
            #[cfg(not(feature = "alloc-fallback"))]
            Err(crate::generator_cache_hook::InitError::BlobMismatch)
          }}
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
        // Z5.2b: upstream generator sets are definitionally 1024 + 1024.
        pub(crate) const TABLE_G_LEN: usize = 1024;
        pub(crate) const TABLE_H_LEN: usize = 1024;
        // A3: same accessor shape as the compile-time template; this face
        // builds the table through the allocating generators crate and is
        // test/legacy surface.
        #[cfg(feature = "alloc-fallback")]
        pub(crate) fn generators() -> Result<crate::generator_cache_hook::Generators<'static>, crate::generator_cache_hook::InitError> {{
          let ext = monero_bulletproofs_generators::bulletproofs_generators(b"{prefix}");
          assert_eq!(ext.G.len(), TABLE_G_LEN);
          assert_eq!(ext.H.len(), TABLE_H_LEN);
          #[cfg(feature = "alloc-fallback")]
          {{
            return Ok(crate::generator_cache_hook::Generators {{
              G: crate::generator_cache_hook::leak_vec(ext.G),
              H: crate::generator_cache_hook::leak_vec(ext.H),
            }});
          }}
          #[cfg(not(feature = "alloc-fallback"))]
          Err(crate::generator_cache_hook::InitError::BlobMismatch)
        }}
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
