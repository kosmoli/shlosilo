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
    "limits",                  // platform resource profiles (generated consts)
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
    emit_limits();
}

/// Platform resource profiles (`limits/<profile>.toml`) -> `$OUT_DIR/limits_generated.rs`.
///
/// Selection: `SHLOSILO_LIMITS=<profile>`. A build for a bare-metal target MUST name
/// a profile - defaulting to `host` there would silently compile the host's ceilings
/// into a device that cannot honour them. Host/test builds default to `host`.
///
/// Parsing is deliberately minimal (sections and `key = value` lines): the files are
/// ours, the schema check below is the real gate, and pulling a TOML dependency into a
/// build script that also runs for `thumbv7em` targets is not worth it.
fn emit_limits() {
    const KEYS: &[&str] = &[
        "bt_tx_inputs_max",
        "bt_tx_outputs_max",
        "psbt_maps_max",
        "ur_ws_decoded_slots",
        "ur_ws_buffer_slots",
        "ur_ws_queue_slots",
        "ur_ws_received_slots",
        "ur_payload_max",
        "sign_ws_bp_chunk_max",
    ];
    println!("cargo:rerun-if-env-changed=SHLOSILO_LIMITS");

    let target = std::env::var("TARGET").unwrap_or_default();
    let bare_metal = target.contains("none-eabi") || target.contains("none-eabihf");
    let profile = match std::env::var("SHLOSILO_LIMITS") {
        Ok(p) if !p.is_empty() => p,
        _ if bare_metal => panic!(
            "SHLOSILO_LIMITS is required for bare-metal target {target}:              pass --profile <name> to the build script (host is not a valid default here)"
        ),
        _ => "host".to_string(),
    };
    // Whitelist: never interpolate an environment value straight into a path.
    const PROFILES: &[&str] = &[
        "host",
        "tiny-test",
        "stress-test",
        "pico2",
        "forgebox",
        "luckyfox",
    ];
    if !PROFILES.contains(&profile.as_str()) {
        panic!("unknown SHLOSILO_LIMITS profile {profile:?}; expected one of {PROFILES:?}");
    }

    let path = format!("limits/{profile}.toml");
    println!("cargo:rerun-if-changed={path}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));

    let mut values: Vec<(&str, u64)> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{path}: expected `key = value`, got {line:?}"));
        let key = k.trim();
        let value: u64 = v
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{path}: {key} is not an integer"));
        let known = KEYS
            .iter()
            .find(|k2| **k2 == key)
            .unwrap_or_else(|| panic!("{path}: unknown limits key {key:?} (schema: {KEYS:?})"));
        assert!(
            values.iter().all(|(k2, _)| k2 != known),
            "{path}: duplicate key {key}"
        );
        assert!(value > 0, "{path}: {key} must be > 0");
        values.push((known, value));
    }
    for key in KEYS {
        assert!(
            values.iter().any(|(k, _)| k == key),
            "{path}: missing key {key}"
        );
    }

    let get = |name: &str| -> u64 {
        *values
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
            .expect("schema check above guarantees presence")
    };

    // Cross-key sanity: the inbound payload ceiling cannot exceed what the part
    // domain can deliver (255 parts' worth of the largest fragment we accept).
    // Getting this wrong is how a device ends up collecting a payload it can never
    // assemble (B-7, 2026-11-15).
    let payload_max = get("ur_payload_max");
    let assembled_max = get("ur_ws_decoded_slots") * 240;
    assert!(
        payload_max <= assembled_max,
        "{path}: ur_payload_max ({payload_max}) exceeds what {} decoded slots can assemble at 240 B/part ({assembled_max})",
        get("ur_ws_decoded_slots")
    );
    let maps_min = 1 + get("bt_tx_inputs_max") + get("bt_tx_outputs_max");
    assert!(
        get("psbt_maps_max") >= maps_min,
        "{path}: psbt_maps_max ({}) must be >= 1 + inputs + outputs ({maps_min})",
        get("psbt_maps_max")
    );

    let mut out = String::from(
        "// @generated by build.rs from limits/*.toml - do not edit.
         // Platform resource ceilings; see the limits-knob design note.
",
    );
    out.push_str(&format!("pub const PROFILE: &str = \"{profile}\";\n"));
    for (key, value) in &values {
        let name = key.to_uppercase();
        out.push_str(&format!("pub const {name}: usize = {value};\n"));
    }
    // Derived, never configured twice.
    out.push_str(
        "pub const PSBT_MAPS_MIN: usize = 1 + BT_TX_INPUTS_MAX + BT_TX_OUTPUTS_MAX;\n\
         pub const ASSEMBLED_PAYLOAD_MAX: usize = UR_WS_DECODED_SLOTS * 240;\n",
    );

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(format!("{out_dir}/limits_generated.rs"), out)
        .expect("write limits_generated.rs");
    println!("cargo:warning=limits profile: {profile}");
}
