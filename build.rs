//! Build script: embed the current git short hash as SHLOSILO_BUILD_GIT so the
//! smoke-test version line identifies the exact firmware build on-device
//! (flash-verification discipline: the user reads one line to confirm which
//! build is running before trusting its timings). A dirty working tree adds
//! a `-dirty` suffix: a build from uncommitted sources must not wear a clean
//! commit's hash, or two different firmwares share one identity.
//!
//! Watch list: the dirty state must be re-checked whenever ANY source that
//! lands in a firmware changes. Cargo only re-runs this script when the paths
//! below change, and the root package's own files do NOT cover the flux
//! appearance source trees - without the explicit entries, editing (say)
//! flux/pico2/src left the stamp stale and an uncommitted build wore the
//! clean last-commit hash: exactly the confusion this script exists to
//! prevent. (Measured 2026-09-14: the perf-bench firmware built from a dirty
//! tree still said `+15a83ca` with no `-dirty`.)

use std::process::Command;

/// Sources that end up in a produced firmware and can be edited without
/// moving HEAD. Kept as an explicit list because cargo watches nothing by
/// default once any `rerun-if-changed` is emitted.
const WATCH_PATHS: &[&str] = &[
    ".git/logs/HEAD", // commits/checkouts: keeps the hash itself current
    "build.rs",
    "Cargo.toml",
    "forms",          // the core crate source tree
    "vendor",         // vendored crates (patched in tree)
    "flux/pico2/src", // Rust-native appearance
    "flux/pico2/Cargo.toml",
    "flux/pico2/build.rs",
    "flux/forgebox/staticlib", // C-host staticlib shim
    "flux/host-sim/staticlib", // POSIX simulator shim
];

fn main() {
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    let identity = if dirty && git_hash != "unknown" {
        format!("{git_hash}-dirty")
    } else {
        git_hash
    };
    println!("cargo:rustc-env=SHLOSILO_BUILD_GIT={identity}");
    for path in WATCH_PATHS {
        println!("cargo:rerun-if-changed={path}");
    }
}
