//! Task 4 test 4 — 无持久化 code-face proof: a source-level grep over the
//! keysource module asserting no persistence / allocation surface.
//!
//! Threat model: key material lives in RAM only; a powered-down device holds
//! zero key material. That forbids flash/filesystem writes on the key path —
//! and (Z6) heap allocation in the key path (no `Box`/`Vec`/`String`).
//!
//! This lives in `tests/` (not `src/`) on purpose: the assertion strings must
//! not appear inside the sources being scanned.

/// Sources scanned: the whole keysource module.
const SOURCES: &[(&str, &str)] = &[
    ("src/lib.rs", include_str!("../src/lib.rs")),
    (
        "src/keysource/mod.rs",
        include_str!("../src/keysource/mod.rs"),
    ),
    (
        "src/keysource/ffi.rs",
        include_str!("../src/keysource/ffi.rs"),
    ),
    (
        "src/keysource/qr.rs",
        include_str!("../src/keysource/qr.rs"),
    ),
];

/// Forbidden tokens: persistence APIs (flash/fs) and heap allocation roots.
const FORBIDDEN: &[&str] = &[
    // persistence (filesystem / file writes)
    "std::fs",
    "std::io",
    "fs::",
    "fopen",
    "fwrite",
    "File::",
    "OpenOptions",
    "write_all",
    "remove_file",
    "create_dir",
    "set_len",
    // flash / storage device words in CODE positions
    "flash_write",
    "flash_read",
    "sd_write",
    "sd_read",
    // heap allocation roots (Z6 zero-heap key path)
    "Box::",
    "Vec::",
    "String::",
    "alloc::",
    "vec![",
    "to_vec",
    "into_boxed",
];

#[test]
fn keysource_code_face_has_no_persistence_or_allocation() {
    for (path, src) in SOURCES {
        for token in FORBIDDEN {
            assert!(
                !src.contains(token),
                "{path} must stay persistence/alloc-free — found `{token}`"
            );
        }
    }
}

#[test]
fn keysource_is_no_std() {
    // The flux key path must compile without std — the crate root declares it.
    assert!(
        SOURCES[0].1.contains("#![no_std]"),
        "flux/keysource must remain a no_std crate"
    );
}
