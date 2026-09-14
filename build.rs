//! Build script: embed the current git short hash as SHLOSILO_BUILD_GIT so the
//! smoke-test version line identifies the exact firmware build on-device
//! (flash-verification discipline: the user reads one line to confirm which
//! build is running before trusting its timings). A dirty working tree adds
//! a `-dirty` suffix: a build from uncommitted sources must not wear a clean
//! commit's hash, or two different firmwares share one identity.

use std::process::Command;

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
    // Rebuild when HEAD moves so the hash stays current.
    // Track the git reflog: it changes on every commit/checkout, unlike .git/HEAD
    // (a symref whose content only changes on branch switches).
    println!("cargo:rerun-if-changed=.git/logs/HEAD");
    println!("cargo:rerun-if-changed=build.rs");
}
