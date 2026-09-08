//! Build script: embed the current git short hash as SHLOSILO_BUILD_GIT so the
//! smoke-test version line identifies the exact firmware build on-device
//! (flash-verification discipline: the user reads one line to confirm which
//! build is running before trusting its timings).

use std::process::Command;

fn main() {
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SHLOSILO_BUILD_GIT={git_hash}");
    // Rebuild when HEAD moves so the hash stays current.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=build.rs");
}
