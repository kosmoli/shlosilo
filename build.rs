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
        "ur_ws_decoded_slots",
        "ur_ws_buffer_slots",
        "ur_ws_queue_slots",
        "ur_ws_received_slots",
        "ur_payload_max",
        "ur_encode_fragment_len",
        "ur_inbound_fragment_max",
        "ur_source_fragments_max",
        "sign_ws_bp_chunk_max",
        "pairing_records_max",
        "xmr_inputs_max",
        "c_header",
        "psram_budget_bytes",
        "stack_budget_bytes",
    ];
    println!("cargo:rerun-if-env-changed=SHLOSILO_LIMITS");
    // The budget report states where it was computed: a host report is not a device
    // report, because `size_of::<usize>()` differs.
    println!(
        "cargo:rustc-env=SHLOSILO_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    );

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
        if key == "c_header" {
            assert!(value <= 1, "{path}: c_header is a flag (0 or 1)");
        } else {
            assert!(value > 0, "{path}: {key} must be > 0");
        }
        values.push((known, value));
    }
    for key in KEYS {
        assert!(
            values.iter().any(|(k, _)| k == key),
            "{path}: missing key {key}"
        );
    }

    // PSBT map count is derived, never configured: the parser holds one map per
    // global/input/output record and nothing else, so the ceiling is exactly
    // 1 + inputs + outputs. A profile that shrinks the input ceiling gets the smaller
    // map array for free instead of carrying a stale hand-computed number.
    let (bt_in, bt_out) = (
        *values
            .iter()
            .find(|(k, _)| *k == "bt_tx_inputs_max")
            .map(|(_, v)| v)
            .expect("schema check above guarantees presence"),
        *values
            .iter()
            .find(|(k, _)| *k == "bt_tx_outputs_max")
            .map(|(_, v)| v)
            .expect("schema check above guarantees presence"),
    );
    values.push(("psbt_maps_max", 1 + bt_in + bt_out));

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
    // The outbound frame is spelled as bytewords (2 chars per byte) inside a
    // `ur:<type>/<n>-<m>/<text>` wrapper; the carrier's frame buffer is 1024 chars.
    // A fragment that cannot render is a device-side truncation, so refuse it here.
    let encode_fragment_len = get("ur_encode_fragment_len");
    if encode_fragment_len == 0 || encode_fragment_len > 480 {
        panic!(
            "{path}: ur_encode_fragment_len ({encode_fragment_len}) must be 1..=480 (bytewords at 2 chars/byte inside the carrier's 1024-char frame buffer)"
        );
    }
    // Inbound fragment ceiling: the equation arena is buffer_slots x this, and an
    // oversized part is refused rather than truncated. It must cover our own outbound
    // fragment length (the same `Part` wire type carries both directions) and stay at or
    // below the hard 2 KiB wire cap.
    let inbound_frag = get("ur_inbound_fragment_max");
    if inbound_frag < encode_fragment_len || inbound_frag > 2048 {
        panic!(
            "{path}: ur_inbound_fragment_max ({inbound_frag}) must be between ur_encode_fragment_len ({encode_fragment_len}) and 2048"
        );
    }
    // The payload ceiling must be *reachable*: a 64 KiB payload at the configured fragment
    // length needs ceil(payload/fragment) source fragments, and a profile that cannot
    // represent that many cannot emit its own maximum (or decode a peer's real request).
    let payload_max_pending = *values
        .iter()
        .find(|(k, _)| *k == "ur_payload_max")
        .map(|(_, v)| v)
        .expect("schema check above guarantees presence");
    let needed_fragments = payload_max_pending.div_ceil(encode_fragment_len);
    if needed_fragments > get("ur_source_fragments_max") {
        panic!(
            "{path}: ur_payload_max ({payload_max_pending}) at ur_encode_fragment_len ({encode_fragment_len}) needs {needed_fragments} source fragments, but ur_source_fragments_max is {}",
            get("ur_source_fragments_max")
        );
    }
    let payload_max = get("ur_payload_max");
    let assembled_max = get("ur_ws_decoded_slots") * 240;
    assert!(
        payload_max <= assembled_max,
        "{path}: ur_payload_max ({payload_max}) exceeds what {} decoded slots can assemble at 240 B/part ({assembled_max})",
        get("ur_ws_decoded_slots")
    );
    // PSBT map count is derived, never configured: the parser holds one map per
    // global/input/output record and nothing else, so the ceiling is exactly
    // 1 + inputs + outputs. A profile that shrinks the input ceiling gets the smaller
    // map array for free instead of carrying a stale hand-computed number.

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

    // Identity of the effective configuration: FNV-1a 64 over the canonical
    // "v1|profile|key=value..." text. Not a security boundary - it exists so a Rust
    // staticlib and a C translation unit built from different profiles cannot be linked
    // into one firmware without saying so.
    let mut canonical = format!("v1|{profile}");
    for (key, value) in &values {
        canonical.push_str(&format!("|{key}={value}"));
    }
    let mut fingerprint: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in canonical.as_bytes() {
        fingerprint ^= u64::from(*byte);
        fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
    }
    out.push_str(&format!(
        "pub const LIMITS_FINGERPRINT: u64 = 0x{fingerprint:016x};\n"
    ));

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(format!("{out_dir}/limits_generated.rs"), out)
        .expect("write limits_generated.rs");

    // C projection: only a carrier whose platform layer is C asks for it. This is a
    // one-way projection of the Rust ceilings - never the source of truth - and it is
    // written into that carrier's own artifact directory, so two profiles can never
    // overwrite each other's header (a Rust/C capacity mismatch is an FFI buffer-length
    // mismatch, not a cosmetic problem).
    if get("c_header") == 1 {
        let mut h = String::from(
            "/* @generated by build.rs from limits/*.toml - do not edit.\n\
             * Projection of the Rust limits module for a C platform layer.\n */\n",
        );
        h.push_str("#ifndef SHLOSILO_LIMITS_H\n#define SHLOSILO_LIMITS_H\n\n");
        h.push_str(&format!("#define SHLOSILO_LIMITS_PROFILE \"{profile}\"\n"));
        h.push_str(&format!(
            "#define SHLOSILO_LIMITS_FINGERPRINT 0x{fingerprint:016x}ULL\n"
        ));
        for (key, value) in &values {
            h.push_str(&format!(
                "#define SHLOSILO_LIMITS_{} {value}\n",
                key.to_uppercase()
            ));
        }
        h.push_str("\n#endif /* SHLOSILO_LIMITS_H */\n");

        let carrier_dir = "flux/forgebox/shlosilo";
        std::fs::create_dir_all(carrier_dir).expect("create carrier include dir");
        std::fs::write(format!("{carrier_dir}/shlosilo_limits.h"), &h)
            .expect("write shlosilo_limits.h into the carrier tree");
        std::fs::write(format!("{out_dir}/shlosilo_limits.h"), &h)
            .expect("write shlosilo_limits.h into OUT_DIR");
    }

    println!("cargo:warning=limits profile: {profile}");
}
