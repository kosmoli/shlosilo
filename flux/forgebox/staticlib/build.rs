//! Host-target guard (audit #16 P2-01).
//!
//! This shim is embedded-only by design: it bundles a PRIMASK
//! critical-section impl and therefore requires `critical-section`'s
//! `restore-state-u8` feature. On a hosted target the core crate's own
//! dependency enables `critical-section/std`, and cargo merges features
//! across the graph - the two `restore-state-*` configurations collide inside
//! critical-section with an obscure `RawRestoreStateInner` redefinition
//! buried under compile errors.
//!
//! Building this shim for a hosted target is not a supported configuration;
//! fail early with the actual reason instead of letting that surface.

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os != "none" {
        eprintln!(
            "error: shlosilo-forgebox is an embedded-only staticlib shim \
             (build for e.g. --target thumbv7em-none-eabihf, as \
             flux/forgebox/build.sh does). Building for a hosted target \
             ('{os}') is not supported: the shim's PRIMASK critical-section \
             impl (restore-state-u8) collides with the host \
             `critical-section/std` feature set."
        );
        std::process::exit(1);
    }
}
