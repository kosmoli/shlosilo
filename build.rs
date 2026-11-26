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
//!
//! Chain axis, batch 2 (design note 「链轴积木化」 §9.3-ter / §9.3-quater): this
//! script does exactly two things and nothing else -
//!
//! 1. **limits schema / derivations / fingerprint** (`limits/<profile>.toml` →
//!    `$OUT_DIR/limits_generated.rs`). The `[chains]` block is GONE from those
//!    files (L1): a limits profile describes resource ceilings only, and a file
//!    that still carries one is a hard error below.
//! 2. **declaration vs build cross-check.** A build manifest (`builds/<name>.toml`)
//!    is a *declaration*; the cargo `chain-*` features are the *mechanism*. The
//!    wrapper (`scripts/build_declared.sh`) exports `SHLOSILO_CHAINS=<csv>` and this
//!    script compares it against the compiled `CARGO_FEATURE_CHAIN_*` set:
//!    - no `SHLOSILO_CHAINS` (a bare `cargo build/test`) ⇒ no check at all. The
//!      looseness comes from the ABSENCE of a declaration, never from a switch (L3:
//!      `role` decides purpose and receipt rights, never strictness);
//!    - `SHLOSILO_CHAINS` present ⇒ **strict equality**. A mismatch is a build
//!      error in both directions: a declared chain must be compiled in (an image
//!      that promises what it cannot sign) and an undeclared chain must not be
//!      (extra parsers/crypto/signing logic change the audit surface of a signer -
//!      "development convenience" does not get to relax the delivery face).
//!      The check has to live HERE rather than in the wrapper: a wrapper can stop a
//!      human from forgetting a feature, but only `CARGO_FEATURE_*` sees the feature
//!      set **after unification**, which is what catches a transitive dependency
//!      turning a chain on behind everyone's back.
//!
//! The two identities are different questions and are never merged:
//! - `LIMITS_FINGERPRINT` (FNV-1a 64): the resource ceilings. A Rust↔C
//!   accidental-mismatch tripwire; not cryptographic, not an attestation.
//! - `BUILD_FINGERPRINT` (SHA-256 over a versioned canonical encoding, see
//!   [`canonical_build_encoding`]): the whole build identity - limits content, the
//!   ACTUAL chain set, target, HEAD, Cargo.lock digest, rustc version, role and this
//!   script's own digest. Projected into Rust AND into the C header, and queryable
//!   over the C ABI, so the C side can check "the chains I think I compiled against"
//!   against "the chains inside the library I just linked".
//!   It does NOT take the FNV value as input (L4: a non-cryptographic digest must not
//!   feed a cryptographic one).

use std::process::Command;

use sha2::{Digest, Sha256};

/// Sources that end up in a produced firmware and can be edited without
/// moving HEAD. Kept as an explicit list because cargo watches nothing by
/// default once any `rerun-if-changed` is emitted.
const WATCH_PATHS: &[&str] = &[
    ".git/logs/HEAD", // commits/checkouts: keeps the hash itself current
    "build.rs",
    "Cargo.toml",
    "Cargo.lock",     // BUILD_FINGERPRINT input (dependency identity)
    "forms",          // the core crate source tree
    "vendor",         // vendored crates (patched in tree)
    "flux/pico2/src", // Rust-native appearance
    "flux/pico2/Cargo.toml",
    "flux/pico2/build.rs",
    "flux/forgebox/staticlib",   // C-host staticlib shim
    "flux/host-sim/staticlib",   // POSIX simulator shim
    "limits",                    // platform resource profiles (generated consts)
    "builds",                    // build manifests (declarations; digest goes in the receipt)
    "scripts/build_declared.sh", // the wrapper's digest is a BUILD_FINGERPRINT input
];

/// The chain-axis vocabulary, in the one canonical order every projection uses:
/// the C header, `SHLOSILO_CHAINS`, the Rust constants and this file agree on it.
/// (`(name, CARGO_FEATURE suffix)`.)
const CHAINS: &[(&str, &str)] = &[
    ("btc", "CHAIN_BTC"),
    ("eth", "CHAIN_ETH"),
    ("xmr", "CHAIN_XMR"),
];

/// Roles a build may declare. `delivery` is the only one allowed to produce a
/// receipt (L3/L6) - and the only one this script holds to a clean working tree.
const ROLES: &[&str] = &["delivery", "development", "test", "benchmark"];

/// Version of the [`canonical_build_encoding`] layout. Bump it when the field
/// set or its order changes: a fingerprint is only comparable inside one schema.
const BUILD_FINGERPRINT_SCHEMA: u32 = 1;

fn main() {
    let git_hash =
        git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty_list = git(&["status", "--porcelain"]).unwrap_or_default();
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
    emit_limits(&identity, &dirty_list);
}

/// One line of `git <args>` output, or `None` when git is unusable.
fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Digest of a file as lowercase hex, or `None` when it cannot be read.
fn sha256_file(path: &str) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes))
}

/// The chain set the compiler ACTUALLY resolved, in canonical order.
///
/// Read from `CARGO_FEATURE_CHAIN_*`, i.e. the feature set after unification for
/// this crate - the only place where a transitively-enabled chain is visible.
fn compiled_chains() -> Vec<&'static str> {
    CHAINS
        .iter()
        .filter(|(_, feature)| std::env::var_os(format!("CARGO_FEATURE_{feature}")).is_some())
        .map(|(name, _)| *name)
        .collect()
}

/// The chain set a build manifest DECLARED (`SHLOSILO_CHAINS`, exported by
/// `scripts/build_declared.sh`), or `None` for a bare cargo build.
///
/// Empty/unset means "no declaration" (the dev face). Malformed input is an error,
/// not a silent fallback: a typo in the wrapper must not switch the strict check off.
fn declared_chains() -> Option<Vec<&'static str>> {
    let raw = match std::env::var("SHLOSILO_CHAINS") {
        Ok(raw) if !raw.trim().is_empty() => raw,
        _ => return None,
    };
    let mut out: Vec<&'static str> = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let name = CHAINS
            .iter()
            .find(|(name, _)| *name == token)
            .map(|(name, _)| *name)
            .unwrap_or_else(|| {
                panic!(
                    "SHLOSILO_CHAINS declares unknown chain {token:?}; known chains are {:?}",
                    CHAINS.iter().map(|(n, _)| *n).collect::<Vec<_>>()
                )
            });
        assert!(
            !out.contains(&name),
            "SHLOSILO_CHAINS lists {name} twice ({raw:?})"
        );
        out.push(name);
    }
    assert!(
        !out.is_empty(),
        "SHLOSILO_CHAINS is set but names no chain (raw {raw:?}); a manifest declares at least one"
    );
    Some(out)
}

fn csv(chains: &[&str]) -> String {
    if chains.is_empty() {
        "none".to_string()
    } else {
        chains.join(",")
    }
}

/// Append one `name=value` line, refusing a newline in either half: that is what
/// makes the field boundaries unambiguous without a length prefix.
fn push_field(out: &mut String, name: &str, value: &str) {
    assert!(
        !name.contains('\n') && !value.contains('\n'),
        "canonical build encoding field contains a newline: {name}={value:?}"
    );
    out.push_str(name);
    out.push('=');
    out.push_str(value);
    out.push('\n');
}

/// Versioned canonical encoding of everything `BUILD_FINGERPRINT` commits to.
///
/// Shape (UTF-8, every line LF-terminated, `name=value`, fixed order, no value may
/// contain a newline):
///
/// ```text
/// shlosilo-build-fingerprint/1        <- schema/domain tag, always the first line
/// schema_version=1
/// limits_profile=<profile>
/// limits.<KEY>=<value>                <- one line per limits key, ASCII-sorted by key
/// chains=<canonical csv>              <- the ACTUAL compiled set ("none" if empty)
/// target=<TARGET triple>
/// git_head=<40 hex | unknown>
/// tree_state=<clean | dirty>
/// cargo_lock_sha256=<64 hex | absent>
/// rustc=<rustc --version, one line>
/// build_role=<role | unspecified>
/// build_script_sha256=<64 hex>
/// wrapper_sha256=<64 hex | absent>
/// ```
///
/// `BUILD_FINGERPRINT_SHA256` is SHA-256 over exactly these bytes; the text is also
/// written to `$OUT_DIR/build_fingerprint.canon.txt`, so the published hex can be
/// re-derived with `sha256sum` alone - a fingerprint nobody can recompute is a claim,
/// not a fact. The FNV limits fingerprint is deliberately NOT an input (L4).
#[allow(clippy::too_many_arguments)]
fn canonical_build_encoding(
    profile: &str,
    values: &[(&str, u64)],
    chains: &[&str],
    target: &str,
    git_head: &str,
    tree_state: &str,
    cargo_lock_sha: &str,
    rustc: &str,
    role: &str,
    build_script_sha: &str,
    wrapper_sha: &str,
) -> String {
    // Fixed order: sorted by key, never the file's own line order (a profile rewrite
    // that only moves lines must not move the fingerprint).
    let mut limits: Vec<(&str, u64)> = values.to_vec();
    limits.sort_by(|a, b| a.0.cmp(b.0));

    let mut out = String::new();
    out.push_str(&format!(
        "shlosilo-build-fingerprint/{BUILD_FINGERPRINT_SCHEMA}\n"
    ));
    push_field(
        &mut out,
        "schema_version",
        &BUILD_FINGERPRINT_SCHEMA.to_string(),
    );
    push_field(&mut out, "limits_profile", profile);
    for (key, value) in &limits {
        push_field(&mut out, &format!("limits.{key}"), &value.to_string());
    }
    push_field(&mut out, "chains", &csv(chains));
    push_field(&mut out, "target", target);
    push_field(&mut out, "git_head", git_head);
    push_field(&mut out, "tree_state", tree_state);
    push_field(&mut out, "cargo_lock_sha256", cargo_lock_sha);
    push_field(&mut out, "rustc", rustc);
    push_field(&mut out, "build_role", role);
    push_field(&mut out, "build_script_sha256", build_script_sha);
    push_field(&mut out, "wrapper_sha256", wrapper_sha);
    out
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
fn emit_limits(identity: &str, dirty_list: &str) {
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
    // Chain axis batch 2: the declaration pair. Both are exported by
    // `scripts/build_declared.sh`; a bare cargo build sets neither.
    println!("cargo:rerun-if-env-changed=SHLOSILO_CHAINS");
    println!("cargo:rerun-if-env-changed=SHLOSILO_BUILD_ROLE");
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
    let mut section = "";
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = match name {
                "limits" => "limits",
                // L1: a limits profile describes RESOURCE CEILINGS only. The chain set
                // is a build declaration (`builds/<name>.toml`); keeping it here
                // re-coupled two orthogonal axes and forced one file per chain subset.
                "chains" => panic!(
                    "{path}: `[chains]` does not belong in a limits profile any more (chain \
                     axis L1). Declare the chain set in a build manifest instead - \
                     builds/<name>.toml with a `[chains]` table - and build through \
                     `scripts/build_declared.sh <manifest>`. Limits files carry resource \
                     ceilings only."
                ),
                _ => panic!("{path}: unknown section [{name}] (schema: [limits])"),
            };
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{path}: expected `key = value`, got {line:?}"));
        let key = k.trim();
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

    // ---- build role (L3: purpose + receipt rights, never strictness) --------
    let role = match std::env::var("SHLOSILO_BUILD_ROLE") {
        Ok(r) if !r.trim().is_empty() => {
            let r = r.trim().to_string();
            // A typo must not silently downgrade a delivery build to "unspecified".
            assert!(
                ROLES.contains(&r.as_str()),
                "unknown SHLOSILO_BUILD_ROLE {r:?}; expected one of {ROLES:?}"
            );
            r
        }
        _ => "unspecified".to_string(),
    };

    // ---- chain declaration vs compiled feature set (batch 2) ----------------
    //
    // `compiled` is what this crate will actually contain; `declared` is what the
    // build manifest asked for. Strict equality whenever a declaration exists (L3):
    // the permissive direction ("declared ⊆ compiled") only ever belonged to the
    // no-declaration dev face, which needs no check at all.
    let compiled = compiled_chains();
    if let Some(declared) = declared_chains() {
        if declared != compiled {
            panic!(
                "chain axis mismatch (limits profile {profile}, build role {role}):\n\
                 - declared chains = [{}]  (SHLOSILO_CHAINS, from the build manifest)\n\
                 - compiled chains = [{}]  (CARGO_FEATURE_CHAIN_* after feature unification)\n\
                 A declared chain must be compiled in, and an undeclared chain must not be:\n\
                 extra parsers/crypto/signing logic change the audit surface of a signer, so\n\
                 the delivery face has no \"superset is fine\" direction. Fix the manifest or\n\
                 the build's --features; a bare `cargo build` (no manifest) is the only\n\
                 unchecked face.",
                csv(&declared),
                csv(&compiled)
            );
        }
    }
    let chain_on = |name: &str| -> bool { compiled.contains(&name) };
    // Limits keys that are only meaningful for one chain: required exactly while that
    // chain is compiled in, absent-allowed otherwise (a BTC-less build should not have
    // to carry another chain's ceilings). Everything else stays unconditional.
    const CHAIN_REQUIRED_KEYS: &[(&str, &str)] = &[
        ("bt_tx_inputs_max", "btc"),
        ("bt_tx_outputs_max", "btc"),
        ("xmr_inputs_max", "xmr"),
        ("pairing_records_max", "xmr"),
    ];
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
    // hold would not fail on the device - it would truncate a count or an index, so
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

    // ---- the build identity ------------------------------------------------
    let tree_state = if dirty_list.is_empty() {
        "clean"
    } else {
        "dirty"
    };
    // L4 (`HEAD ≠ source`): a delivery build must be reproducible from the commit it
    // names, so a dirty tree is refused outright rather than recorded as a footnote.
    // The wrapper refuses first (before cargo starts); this is the same rule at the
    // layer that cannot be bypassed by calling cargo by hand.
    if role == "delivery" {
        assert!(
            dirty_list.is_empty(),
            "role=delivery refuses a dirty working tree (L4): HEAD would not be the source \
             that was built. git sees:\n{dirty_list}\n\
             Commit or stash the changes, or declare the manifest with role=test/development \
             (those never produce a receipt)."
        );
    }

    let git_head = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let cargo_lock_sha = sha256_file("Cargo.lock").unwrap_or_else(|| "absent".to_string());
    let build_script_sha =
        sha256_file("build.rs").expect("BUILD_FINGERPRINT needs this script's own digest");
    let wrapper_sha =
        sha256_file("scripts/build_declared.sh").unwrap_or_else(|| "absent".to_string());
    let rustc_version = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().replace('\n', " "))
        .unwrap_or_else(|| "unknown".to_string());

    let target_field = if target.is_empty() {
        "unknown"
    } else {
        &target
    };
    let canonical = canonical_build_encoding(
        &profile,
        &values,
        &compiled,
        target_field,
        &git_head,
        tree_state,
        &cargo_lock_sha,
        &rustc_version,
        &role,
        &build_script_sha,
        &wrapper_sha,
    );
    let build_fingerprint_sha = sha256_hex(canonical.as_bytes());
    // The 64-bit projection (Rust constant + C macro + FFI return): the first 8 bytes
    // of the SHA-256, big-endian. 64 bits are plenty for a build-consistency tripwire,
    // and it keeps the C comparison in the same shape as `shlosilo_limits_fingerprint`.
    let build_fingerprint_u64 = u64::from_str_radix(&build_fingerprint_sha[..16], 16)
        .expect("a sha256 hex prefix is 16 hex digits");
    let chain_mask: u32 = CHAINS
        .iter()
        .enumerate()
        .filter(|(_, (name, _))| chain_on(name))
        .map(|(bit, _)| 1u32 << bit)
        .sum();

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    // The canonical bytes travel with the generated constants so the fingerprint can be
    // re-derived independently: `sha256sum build_fingerprint.canon.txt` must equal
    // BUILD_FINGERPRINT_SHA256.
    std::fs::write(format!("{out_dir}/build_fingerprint.canon.txt"), &canonical)
        .expect("write build_fingerprint.canon.txt");

    let mut out = String::from(
        "// @generated by build.rs from limits/*.toml - do not edit.
         // Platform resource ceilings; see the limits-knob design note.
",
    );
    out.push_str(&format!("pub const PROFILE: &str = \"{profile}\";\n"));
    // The chain set of THIS build: read from the compiled features, not from a limits
    // file (batch 2 / L1). `CHAIN_*` keeps the batch-1 constant names so anything that
    // already queries them keeps working.
    for (chain, const_name) in CHAINS {
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
    // into one firmware without saying so. Unchanged by batch 2 on purpose: it commits
    // to the resource ceilings only, and it is NOT an input to BUILD_FINGERPRINT (L4).
    let mut canonical_fnv = format!("v1|{profile}");
    for (key, value) in &values {
        canonical_fnv.push_str(&format!("|{key}={value}"));
    }
    let mut fingerprint: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in canonical_fnv.as_bytes() {
        fingerprint ^= u64::from(*byte);
        fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
    }
    out.push_str(&format!(
        "pub const LIMITS_FINGERPRINT: u64 = 0x{fingerprint:016x};\n"
    ));
    // The build identity (L4/L5): what this build IS, not just which ceilings it holds.
    out.push_str(&format!(
        "/// SHA-256 over the versioned canonical build encoding (schema {BUILD_FINGERPRINT_SCHEMA}).\n\
         /// Re-derivable: `sha256sum $OUT_DIR/build_fingerprint.canon.txt`.\n\
         pub const BUILD_FINGERPRINT_SHA256: &str = \"{build_fingerprint_sha}\";\n\
         /// First 8 bytes of [`BUILD_FINGERPRINT_SHA256`], big-endian (C-ABI projection).\n\
         pub const BUILD_FINGERPRINT: u64 = 0x{build_fingerprint_u64:016x};\n\
         /// The chain set this build actually compiled, in canonical order (btc,eth,xmr).\n\
         pub const BUILD_CHAINS: &str = \"{}\";\n\
         /// The same set as a bitmask: btc = 1, eth = 2, xmr = 4.\n\
         pub const BUILD_CHAIN_MASK: u32 = {chain_mask};\n\
         /// The declared build role ({ROLES:?}); only `delivery` may produce a receipt.\n\
         pub const BUILD_ROLE: &str = \"{role}\";\n\
         /// The target triple the fingerprint was computed for.\n\
         pub const BUILD_TARGET: &str = \"{target_field}\";\n",
        csv(&compiled)
    ));

    std::fs::write(format!("{out_dir}/limits_generated.rs"), out)
        .expect("write limits_generated.rs");

    // ---------------------------------------------------------------- C side --
    // The identity block is generated once here and written verbatim to two places:
    //   * `$OUT_DIR/shlosilo_build_identity.h` - always. Any C host (the POSIX
    //     simulator included) can compare the header it compiled against with the
    //     library it linked.
    //   * `shlosilo_limits.h` - only when the carrier asks for the limits projection
    //     (`c_header = 1`), which is the header the product carrier already includes.
    // The `#ifndef` guard makes including both legal and keeps the values single
    // (a second, drifting copy is exactly what a projection must not become).
    let mut id = String::from(
        "/* @generated by build.rs - do not edit.\n\
         * Build identity: the chain set this library ACTUALLY compiled, and the\n\
         * BUILD_FINGERPRINT over (schema, limits, chains, target, HEAD, Cargo.lock,\n\
         * rustc, role). Compare it against the linked library with\n\
         *   shlosilo_build_fingerprint_ffi()   -> SHLOSILO_BUILD_FINGERPRINT\n\
         *   shlosilo_build_chain_mask_ffi()    -> SHLOSILO_BUILD_CHAIN_MASK\n\
         * A mismatch means the header and the library came from different builds.\n */\n\
         #ifndef SHLOSILO_BUILD_IDENTITY_H\n#define SHLOSILO_BUILD_IDENTITY_H\n\n\
         #ifndef SHLOSILO_BUILD_IDENTITY_DEFINED\n#define SHLOSILO_BUILD_IDENTITY_DEFINED 1\n",
    );
    id.push_str(&format!("#define SHLOSILO_BUILD_PROFILE \"{profile}\"\n"));
    id.push_str(&format!("#define SHLOSILO_BUILD_ROLE \"{role}\"\n"));
    id.push_str(&format!(
        "#define SHLOSILO_BUILD_TARGET \"{target_field}\"\n"
    ));
    id.push_str(&format!(
        "#define SHLOSILO_BUILD_CHAINS \"{}\"\n",
        csv(&compiled)
    ));
    id.push_str(&format!(
        "#define SHLOSILO_BUILD_CHAIN_MASK {chain_mask}u\n"
    ));
    for (chain, _) in CHAINS {
        id.push_str(&format!(
            "#define SHLOSILO_BUILD_CHAIN_{} {}\n",
            chain.to_uppercase(),
            u8::from(chain_on(chain))
        ));
    }
    id.push_str(&format!(
        "#define SHLOSILO_BUILD_FINGERPRINT 0x{build_fingerprint_u64:016x}ULL\n"
    ));
    id.push_str(&format!(
        "#define SHLOSILO_BUILD_FINGERPRINT_SHA256 \"{build_fingerprint_sha}\"\n"
    ));
    id.push_str(
        "#endif /* SHLOSILO_BUILD_IDENTITY_DEFINED */\n\n#endif /* SHLOSILO_BUILD_IDENTITY_H */\n",
    );
    std::fs::write(format!("{out_dir}/shlosilo_build_identity.h"), &id)
        .expect("write shlosilo_build_identity.h");

    // Machine-readable identity for the wrapper's receipt (L6). Written here so the
    // receipt quotes the SAME values the library carries instead of re-deriving them
    // from a second place - a receipt that recomputes identity is a second source.
    let identity_txt = format!(
        "version_string=v{}-poc4+{identity}\n\
         limits_profile={profile}\n\
         build_role={role}\n\
         build_target={target_field}\n\
         chains={}\n\
         chain_mask={chain_mask}\n\
         build_fingerprint_sha256={build_fingerprint_sha}\n\
         build_fingerprint_u64=0x{build_fingerprint_u64:016x}\n\
         limits_fingerprint=0x{fingerprint:016x}\n\
         git_head={git_head}\n\
         tree_state={tree_state}\n",
        std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into()),
        csv(&compiled)
    );
    std::fs::write(format!("{out_dir}/build_identity.txt"), identity_txt)
        .expect("write build_identity.txt");

    // C projection of the ceilings: only a carrier whose platform layer is C asks for
    // it. This is a one-way projection of the Rust ceilings - never the source of
    // truth - and it is written into that carrier's own artifact directory, so two
    // profiles can never overwrite each other's header (a Rust/C capacity mismatch is
    // an FFI buffer-length mismatch, not a cosmetic problem).
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
        // The build identity rides the same header (design note §9.3-ter): the C side
        // must be able to check the chain set it assumes against the compiled one.
        h.push('\n');
        h.push_str(&id);
        h.push_str("\n#endif /* SHLOSILO_LIMITS_H */\n");

        let carrier_dir = "flux/forgebox/shlosilo";
        std::fs::create_dir_all(carrier_dir).expect("create carrier include dir");
        std::fs::write(format!("{carrier_dir}/shlosilo_limits.h"), &h)
            .expect("write shlosilo_limits.h into the carrier tree");
        std::fs::write(format!("{carrier_dir}/shlosilo_build_identity.h"), &id)
            .expect("write shlosilo_build_identity.h into the carrier tree");
        std::fs::write(format!("{out_dir}/shlosilo_limits.h"), &h)
            .expect("write shlosilo_limits.h into OUT_DIR");
    }

    println!(
        "cargo:warning=build identity: limits profile {profile}, chains [{}], role {role}, \
         BUILD_FINGERPRINT {}",
        csv(&compiled),
        &build_fingerprint_sha[..16]
    );
}
