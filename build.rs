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
    let dirty_list = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let identity = if !dirty_list.is_empty() && git_hash != "unknown" {
        // Say WHAT was dirty, not just that something was: this string is what a delivered
        // image wears on its footer, and "why did this build say -dirty" is unanswerable
        // after the fact without the list (a real image once read -dirty for a clean commit
        // because something touched the tree between the Rust and C identity windows).
        println!(
            "cargo:warning=shlosilo identity is dirty; git saw: {}",
            dirty_list.replace('\n', "; ")
        );
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
        "review_lines_max",
        "eip712_types_max",
        "eip712_type_fields_max",
        "eip712_name_bytes",
        "eip712_depth_max",
        "eip712_nodes_max",
        "eip712_encode_type_bytes",
        "eip712_arena_bytes",
        "eip712_display_bytes",
        "sign_ws_bp_chunk_max",
        "sign_bp_chunk_terms",
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
    // Chain-axis matrix profiles (`chainaxes-<combo>`): generated by
    // `scripts/check_chain_axes.sh` from `host.toml` with only the `[chains]` block
    // rewritten, so the matrix can build each combination against a profile that
    // *agrees* with it (the cross-check below refuses a mismatch in either direction).
    // The name gate is a whitelist of SHAPES as well as names: lowercase/digits/'-'
    // only, so an environment value still cannot become a path.
    let derived_chainaxes = profile.starts_with("chainaxes-")
        && profile
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !PROFILES.contains(&profile.as_str()) && !derived_chainaxes {
        panic!("unknown SHLOSILO_LIMITS profile {profile:?}; expected one of {PROFILES:?}");
    }

    let path = format!("limits/{profile}.toml");
    println!("cargo:rerun-if-changed={path}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));

    let mut values: Vec<(&str, u64)> = Vec::new();
    // Chain capability list (`[chains]`). Batch 1 of the chain axis keeps this file
    // the single source of truth for "which chains does this profile claim", and the
    // cross-check below makes the claim verifiable instead of aspirational.
    let mut chains: Vec<(&str, bool)> = Vec::new();
    const CHAIN_KEYS: &[&str] = &["btc", "eth", "xmr"];
    // Limits keys that are only meaningful for one chain: required while that chain is
    // on, allowed to be absent while it is off (a chain-less profile should not have to
    // carry another chain's ceilings). Everything else stays unconditional.
    const CHAIN_REQUIRED_KEYS: &[(&str, &str)] = &[
        ("bt_tx_inputs_max", "btc"),
        ("bt_tx_outputs_max", "btc"),
        ("xmr_inputs_max", "xmr"),
        ("pairing_records_max", "xmr"),
    ];
    let mut section = "";
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = match name {
                "limits" => "limits",
                "chains" => "chains",
                _ => panic!("{path}: unknown section [{name}] (schema: [limits], [chains])"),
            };
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{path}: expected `key = value`, got {line:?}"));
        let key = k.trim();
        if section == "chains" {
            let chain = CHAIN_KEYS.iter().find(|c| **c == key).unwrap_or_else(|| {
                panic!("{path}: unknown [chains] key {key:?} (schema: {CHAIN_KEYS:?})")
            });
            let on = match v.trim() {
                "true" => true,
                "false" => false,
                other => panic!("{path}: [chains] {key} must be true or false, got {other:?}"),
            };
            assert!(
                chains.iter().all(|(c, _)| c != chain),
                "{path}: duplicate [chains] key {key}"
            );
            chains.push((chain, on));
            continue;
        }
        assert!(
            section == "limits",
            "{path}: key {key:?} appears outside a section (a TOML section header is required)"
        );
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
    // The capability list must exist and be complete: a missing chain is an unstated
    // claim, and "unstated" is what this file exists to rule out.
    for chain in CHAIN_KEYS {
        assert!(
            chains.iter().any(|(c, _)| c == chain),
            "{path}: missing [chains] key {chain} (schema: {CHAIN_KEYS:?})"
        );
    }
    let chain_on = |name: &str| -> bool {
        chains
            .iter()
            .find(|(c, _)| *c == name)
            .map(|(_, on)| *on)
            .expect("schema check above guarantees presence")
    };
    // BIDIRECTIONAL cross-check against the compiled feature set.
    //
    // build.rs does not participate in dependency resolution (design note §2) and must
    // not: it only reads the features cargo already decided on and refuses a profile
    // whose claim contradicts the build. Both directions matter — "declared on but not
    // compiled" ships an image whose profile promises a chain it cannot sign, and
    // "compiled but declared off" leaves chain code in an image whose capability list
    // says it is absent (the size/symbol accounting would then be a lie).
    for (chain, feature) in [
        ("btc", "CHAIN_BTC"),
        ("eth", "CHAIN_ETH"),
        ("xmr", "CHAIN_XMR"),
    ] {
        let declared = chain_on(chain);
        let compiled = std::env::var_os(format!("CARGO_FEATURE_{feature}")).is_some();
        assert_eq!(
            declared,
            compiled,
            "{path}: [chains] {chain} = {declared} but cargo feature {} is {} \
             (declared-on needs the feature in the build's feature set; declared-off needs it out)",
            feature.to_lowercase().replace('_', "-"),
            if compiled { "on" } else { "off" }
        );
    }
    for key in KEYS {
        if CHAIN_REQUIRED_KEYS
            .iter()
            .any(|(k, c)| k == key && !chain_on(c))
        {
            // Chain off: this ceiling has no owner in the build, so it may be absent.
            continue;
        }
        assert!(
            values.iter().any(|(k, _)| k == key),
            "{path}: missing key {key}"
        );
    }

    // PSBT map count is derived, never configured: the parser holds one map per
    // global/input/output record and nothing else, so the ceiling is exactly
    // 1 + inputs + outputs. A profile that shrinks the input ceiling gets the smaller
    // map array for free instead of carrying a stale hand-computed number.
    // Absent while `btc` is off (the schema above allows it then): the PSBT ceilings are
    // derived as 0, i.e. "this build holds no PSBT records". Nothing that reads them is
    // compiled on such a face; the constants still exist so the projection stays total.
    let bt_opt = |name: &str| -> u64 {
        values
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };
    let (bt_in, bt_out) = (bt_opt("bt_tx_inputs_max"), bt_opt("bt_tx_outputs_max"));
    values.push(("psbt_maps_max", 1 + bt_in + bt_out));
    // PSBT key-value records are DERIVED too. The old flat 128 refused the real 43-input
    // Sparrow request with "request too large" while its bytes fit comfortably - the
    // record count, not the byte count, ran out. A measured probe (host, real fixture)
    // shows 9 records per input is still short and 24 clears it, so the ceiling carries
    // 24 per input plus 8 per output (outputs carry redeem/witness-script/derivation)
    // with headroom; the cost is 16 B per record in PSRAM.
    values.push(("psbt_recs_max", 24 * bt_in + 8 * bt_out + 32));
    // The arena holds the request bytes PLUS what signing appends to each input map
    // (final_scriptSig, final_scriptWitness): 61,138 B request + 43 x ~110 B of final
    // fields overran a flat 64 KiB. Derived so the two can never drift apart again.
    let payload_cap = *values
        .iter()
        .find(|(k, _)| *k == "ur_payload_max")
        .map(|(_, v)| v)
        .expect("schema check above guarantees presence");
    values.push(("psbt_arena_bytes", payload_cap + 16 * 1024));
    // The signed artifact is the request PLUS the fields signing appends, so its cap
    // follows the same headroom: the real 43-input request goes 61,138 -> 65,671 B, only
    // 377 B short of the old flat 64 KiB + 512. Same derivation as the arena.
    values.push(("sign_output_bytes", payload_cap + 16 * 1024));
    // The JSON document budget for EIP-712 typed data is DERIVED from the inbound
    // payload ceiling, never configured separately: a document larger than what the
    // transport can deliver is not a limit anyone can reach, and a profile that
    // shrinks the transport (tiny-test) must shrink the parser with it. The 16 KiB
    // figure is the shared cap the alloc parser and the pool both enforce; the
    // derived value is the smaller of the two.
    let eip712_json_bytes_max = payload_cap.min(16 * 1024);
    values.push(("eip712_json_bytes_max", eip712_json_bytes_max));

    let get = |name: &str| -> u64 {
        values
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };

    // Cross-key sanity: the per-call multiexp chunk may not exceed the ceiling the
    // straus scratch region is sized from - a bigger chunk would make
    // `StrausScratch::new` fail at prove time, i.e. a profile-only error that would
    // surface as a runtime encoding error on the device.
    assert!(
        get("sign_bp_chunk_terms") <= get("sign_ws_bp_chunk_max"),
        "profile {profile}: sign_bp_chunk_terms ({}) must be <= sign_ws_bp_chunk_max ({})",
        get("sign_bp_chunk_terms"),
        get("sign_ws_bp_chunk_max")
    );

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
    // EIP-712 container budgets size both the pool workspace and the parser's
    // per-record ceilings. A profile that pushes one past what a record field can
    // hold would not fail on the device — it would truncate a count or an index, so
    // the domain is asserted here where the profile is read.
    let eip712_types = get("eip712_types_max");
    assert!(
        (1..=64).contains(&eip712_types),
        "{path}: eip712_types_max ({eip712_types}) must be 1..=64 (the encodeType walk tracks visited types in a u64 bitmap)"
    );
    let eip712_type_fields = get("eip712_type_fields_max");
    assert!(
        (1..=255).contains(&eip712_type_fields),
        "{path}: eip712_type_fields_max ({eip712_type_fields}) must be 1..=255 (Eip712Type::n_fields is a u8)"
    );
    let eip712_name_bytes = get("eip712_name_bytes");
    assert!(
        (1..=255).contains(&eip712_name_bytes),
        "{path}: eip712_name_bytes ({eip712_name_bytes}) must be 1..=255 (name and type-string lengths are u8)"
    );
    let eip712_nodes = get("eip712_nodes_max");
    assert!(
        (1..=65535).contains(&eip712_nodes),
        "{path}: eip712_nodes_max ({eip712_nodes}) must be 1..=65535 (node child indices are u16)"
    );
    let eip712_depth = get("eip712_depth_max");
    assert!(
        (1..=32).contains(&eip712_depth),
        "{path}: eip712_depth_max ({eip712_depth}) must be 1..=32 (a value tree cannot nest deeper than the JSON syntax it arrives in)"
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
    // Chain capability list, projected from the profile's `[chains]` block (chain axis,
    // §9.3-1). Rust-only on purpose: it is the DECLARATION the cross-check above just
    // verified against the compiled features, so a query can state what this profile
    // claims. It is deliberately not part of `LIMITS_FINGERPRINT` (the tracked C
    // `shlosilo_limits.h` pins that value; the feature set is already identified by the
    // build itself) and it is not projected into the C header.
    for (chain, const_name) in [
        ("btc", "CHAIN_BTC"),
        ("eth", "CHAIN_ETH"),
        ("xmr", "CHAIN_XMR"),
    ] {
        out.push_str(&format!(
            "pub const {const_name}: bool = {};\n",
            chain_on(chain)
        ));
    }
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
