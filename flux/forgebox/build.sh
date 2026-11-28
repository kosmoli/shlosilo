#!/bin/bash
# =============================================================================
# forgebox appearance build (MH1903 + FreeRTOS + LVGL, C host)
#
# This is a "flux" appearance: it owns the hardware-facing side (drivers, RTOS
# tasks, UI, flash/SD) and consumes the shlosilo *forms* static library — the
# cargo crate at the repository root — through the generated C ABI.
#
# The static library and the C header are BUILD INPUTS, not tracked files:
#   target/.../libshlosilo.a  -> shlosilo/libshlosilo.a   (stripped)
#   <repo root>/shlosilo.h    -> shlosilo/shlosilo.h      (after a sync gate)
# Both are produced here from source so they can never drift from forms.
#
# Signing (the final step producing build/forgebox.bin) is optional and runs
# only when the local `forgebox` CLI and ~/.forgebox/keys/private.pem exist;
# without them the build still succeeds with the unsigned intermediate. See
# README.md ("Build") - neither tool nor key is vendored in the repository.
# =============================================================================

set -e
set -o pipefail

# Parallelism: size it to the machine. The hardcoded -j16 this replaces
# oversubscribed GitHub's 4-vCPU runners 4x, which costs more than it buys.
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

# Cross toolchain: pinned, not whatever apt happens to have. The Ubuntu package
# is unpinned (a runner image update silently changes the compiler that builds
# the firmware) and two distributions of the SAME version produce different
# images - arm-none-eabi-gcc 14.2.1 from Ubuntu and from xPack differ by ~4.4 kB
# on this tree - so local builds and CI must use the same one. See
# docs/toolchain.md; SHLOSILO_ARM_TOOLCHAIN points at an unpacked copy and
# SHLOSILO_ARM_TOOLCHAIN_STRICT=1 turns a mismatch into an error.
PINNED_TOOLCHAIN_VERSION="14.2.1"
PINNED_TOOLCHAIN="${SHLOSILO_ARM_TOOLCHAIN:-${HOME}/.local/toolchains/gnu-arm}"
if [[ -x "${PINNED_TOOLCHAIN}/bin/arm-none-eabi-gcc" ]]; then
    export PATH="${PINNED_TOOLCHAIN}/bin:${PATH}"
    TC_LINE="$(arm-none-eabi-gcc --version | head -1)"
    echo "toolchain: ${TC_LINE}"
    if [[ "${TC_LINE}" != *" ${PINNED_TOOLCHAIN_VERSION} "* ]] || [[ "${TC_LINE}" != *"xPack"* ]]; then
        echo "toolchain: expected the pinned xPack ${PINNED_TOOLCHAIN_VERSION} (docs/toolchain.md)" >&2
        if [[ "${SHLOSILO_ARM_TOOLCHAIN_STRICT:-0}" == "1" ]]; then
            exit 1
        fi
    fi
else
    echo "toolchain: UNPINNED system arm-none-eabi-gcc ($(arm-none-eabi-gcc --version | head -1))" >&2
    echo "toolchain: install the pinned one - see docs/toolchain.md" >&2
    if [[ "${SHLOSILO_ARM_TOOLCHAIN_STRICT:-0}" == "1" ]]; then
        exit 1
    fi
fi

# Resolve paths regardless of the caller's cwd.
cd "$(dirname "${BASH_SOURCE[0]}")"
APP_ROOT="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

# Build outputs. The two overrides exist so a probe flavor (the SE-isolation gate) can build
# without clobbering the canonical artifacts: same source tree, different build/staticlib dirs.
BUILD_FOLDER="${SHLOSILO_FORGEBOX_BUILD_DIR:-$APP_ROOT/build}"
SHLOSILO_DIR="${SHLOSILO_FORGEBOX_STATICLIB_DIR:-$APP_ROOT/shlosilo}"
BUILD_SIMULATOR_FOLDER="$APP_ROOT/build_simulator"
TOOLS_FOLDER="$APP_ROOT/tools"
MAKE_OAT_FILE_PATH="${TOOLS_FOLDER}/ota_file_maker"
MAKE_PADDING_FILE_PATH="${TOOLS_FOLDER}/padding_bin_file"
ASTYLE_PATH="${TOOLS_FOLDER}/AStyle.sh"
LANGUAGE_PATH="$APP_ROOT/src/ui/lv_i18n"
LANGUAGE_SCRIPT="python3 data_loader.py"

# ---- shlosilo (forms) build configuration for this appearance ----
# The feature set for the staticlib build (diagnostic FFI features) and the
# C-host runtime hooks live in flux/forgebox/staticlib/.
SHLOSILO_TARGET="${SHLOSILO_TARGET:-thumbv7em-none-eabihf}"

# ---- key-supply module switch (design 密钥供给 §11) ----
# SHLOSILO_WITH_SE=0 builds the plate-only flavor: the SE key-supply module is left out on BOTH
# sides of the ABI - the Rust `se` feature (--no-default-features: no SeKeySource, no SE FFI
# entries in the keep table) and the C SE source set + its call sites (CMake
# -DSHLOSILO_WITH_SE=OFF). ONE variable drives both on purpose: the C product entry calls the
# Rust SE glue and the C keystore sits under it, so a half-switched build either fails to link
# or ships a module the carrier cannot use.
SHLOSILO_WITH_SE="${SHLOSILO_WITH_SE:-1}"
case "$SHLOSILO_WITH_SE" in
    1) SE_CMAKE=ON ;;
    0) SE_CMAKE=OFF ;;
    *) echo "SHLOSILO_WITH_SE must be 0 or 1 (got '$SHLOSILO_WITH_SE')" >&2; exit 1 ;;
esac
echo "key supply: $( [[ "$SE_CMAKE" == ON ]] && echo "plate + SE (SHLOSILO_WITH_SE=1)" || echo "plate only (SHLOSILO_WITH_SE=0)" )"

# ---- chain set (pool #99) ----
# Same one-variable-drives-both-halves rule as the key-supply switch above: the staticlib's
# cargo features AND the C host's `-DSHLOSILO_CHAIN_*` declaration come from here, because a host
# that declares a different set than the archive carries either cannot call what it links
# (harmless) or fails at the link (loud) - but only if the two halves are derived together.
# Default = the three-chain product face, so a plain `build.sh` is unchanged.
if [[ "${build_options[btc_only]}" == true ]]; then
    SHLOSILO_CHAINS="btc"
else
    SHLOSILO_CHAINS="${SHLOSILO_CHAINS:-btc,eth,xmr}"
fi
case "$SHLOSILO_CHAINS" in
    btc|eth|xmr|btc,eth|xmr,btc|btc,eth,xmr) ;;
    *) echo "SHLOSILO_CHAINS must be a comma list of btc/eth/xmr (got '$SHLOSILO_CHAINS')" >&2; exit 1 ;;
esac
CHAIN_CARGO_FLAGS=()
if [[ "$SHLOSILO_CHAINS" != "btc,eth,xmr" || "$SHLOSILO_WITH_SE" != 1 ]]; then
    _feats=()
    [[ "$SHLOSILO_WITH_SE" == 1 ]] && _feats+=("se")
    IFS=',' read -r -a _chain_list <<< "$SHLOSILO_CHAINS"
    for _c in "${_chain_list[@]}"; do _feats+=("chain-$_c"); done
    _feat_str="$(IFS=,; echo "${_feats[*]}")"
    CHAIN_CARGO_FLAGS=(--no-default-features --features "$_feat_str")
fi
echo "chain axis: declaring ${SHLOSILO_CHAINS} (staticlib features: ${CHAIN_CARGO_FLAGS[*]:-default})"

# forgebox CLI (firmware signing) lives in the Hermes node bin on the dev box.
if [[ -d "$HOME/.hermes/node/bin" ]]; then
    export PATH="$HOME/.hermes/node/bin:$PATH"
fi

declare -A build_options=(
    ["log"]=false
    ["copy"]=false
    ["production"]=false
    ["screen"]=false
    ["debug"]=false
    ["format"]=false
    ["release"]=false
    ["rebuild"]=false
    ["btc_only"]=false
    ["cypherpunk"]=false
    ["simulator"]=false
    ["language"]=false
    ["clean"]=false
    ["no_sign"]=false
    ["smoke"]=false
)

for arg in "$@"; do
    if [[ "$arg" == "format" ]]; then
        pushd "$TOOLS_FOLDER"
        echo "Formatting files..."
        bash "$ASTYLE_PATH"
        popd
    else
        echo "Building with option: $arg"
        build_options["$arg"]=true
    fi
done

echo "Building with options: ${build_options[@]}"

# -----------------------------------------------------------------------------
# shlosilo (forms) staticlib + header
# -----------------------------------------------------------------------------
build_shlosilo() {
    local lib="$REPO_ROOT/target/$SHLOSILO_TARGET/release/libshlosilo.a"

    echo "=== shlosilo staticlib: cargo build -p shlosilo-forgebox ($SHLOSILO_TARGET) ${CHAIN_CARGO_FLAGS[*]:-} ==="
    # The keep-table must be current BEFORE the build: it is what keeps every
    # C-ABI entry point reachable through LTO. A new entry point without a
    # regenerated table would otherwise fail late, at the C link.
    ( cd "$REPO_ROOT" && python3 scripts/gen_ffi_keep.py --check ) || exit 1
    # The core crate is rlib-only; the staticlib is bundled by the
    # flux/forgebox/staticlib shim package, so no other consumer of the crate
    # is ever forced through a staticlib unit.
    ( cd "$REPO_ROOT" && SHLOSILO_LIMITS=forgebox cargo build -p shlosilo-forgebox \
        "${CHAIN_CARGO_FLAGS[@]}" --release --target "$SHLOSILO_TARGET" )
    mkdir -p "$SHLOSILO_DIR"
    arm-none-eabi-strip --strip-debug "$lib" -o "$SHLOSILO_DIR/libshlosilo.a"
    echo "    staticlib -> $SHLOSILO_DIR/libshlosilo.a ($(stat -c%s "$SHLOSILO_DIR/libshlosilo.a") bytes)"

    echo "=== shlosilo C header sync gate (cbindgen regen must equal tracked) ==="
    bash "$REPO_ROOT/scripts/check_header.sh"
    cp "$REPO_ROOT/shlosilo.h" "$SHLOSILO_DIR/shlosilo.h"
    # The limits projection is written by the CORE crate's build.rs into the canonical carrier
    # dir, so a probe flavor (its own SHLOSILO_DIR) has to take its copy from there - same
    # profile, same content, separate file, so the two flavors can never read each other's.
    # An ordinary build already IS that dir, and cp refuses to copy a file onto itself.
    if [[ "$SHLOSILO_DIR" != "$APP_ROOT/shlosilo" ]]; then
        cp "$APP_ROOT/shlosilo/shlosilo_limits.h" "$SHLOSILO_DIR/shlosilo_limits.h"
    fi
    echo "    header OK (tracked == regen)"
}

# -----------------------------------------------------------------------------
# firmware identity assertion
# -----------------------------------------------------------------------------
# The screen carries TWO identity strings and they are computed at DIFFERENT times:
#   * `shlosilo v0.5.0-poc4+<hash>[-dirty]` — the Rust core, baked when cargo compiles
#     (`build.rs`, at the start of build_shlosilo);
#   * `fw v1.0.0 <hash>[-dirty]`            — the C side, baked when cmake configures
#     (CMakeLists.txt reads `git status --porcelain`).
# Both must name this commit and agree about dirtiness. One delivered image already wore
# `-dirty` on the C line for a clean commit because something dirtied the tree between the
# two windows, and nothing caught it — the receipt then claimed the image was clean. This
# assertion turns that class of mismatch into a build failure instead of a footer nobody
# reads twice.
assert_firmware_identity() {
    local elf="$BUILD_FOLDER/mh1903.elf"
    local id_h="$BUILD_FOLDER/fw_identity.h"
    [[ -f "$elf" && -f "$id_h" ]] || { echo "identity: missing $elf or $id_h" >&2; exit 1; }
    local head_short rust_id c_id
    head_short="$(git -C "$REPO_ROOT" rev-parse --short=7 HEAD)"
    rust_id="$(strings "$elf" | grep -oE 'v0\.5\.0-poc4\+[0-9a-z-]+' | head -1)"
    rust_id="${rust_id#v0.5.0-poc4+}"
    c_id="$(sed -n 's/^#define FIRMWARE_GIT_HASH "\(.*\)"$/\1/p' "$id_h")"
    if [[ -z "$rust_id" || -z "$c_id" ]]; then
        echo "identity: could not read the strings (rust='$rust_id' c='$c_id')" >&2
        exit 1
    fi
    if [[ "${rust_id%-dirty}" != "$head_short" || "${c_id%-dirty}" != "$head_short" ]]; then
        echo "identity: expected both strings to name ${head_short}; got rust='$rust_id' c='$c_id'" >&2
        exit 1
    fi
    if [[ "$rust_id" != "$c_id" ]]; then
        echo "identity: the two strings disagree (rust='$rust_id' c='$c_id')." >&2
        echo "identity: they are baked at different times, so a dirty tree in between shows up" >&2
        echo "identity: here. Rebuild from a clean tree, or make both windows see the same state." >&2
        exit 1
    fi
    echo "    identity: rust='$rust_id' c='$c_id' (HEAD ${head_short})"
}

if [[ "${build_options[rebuild]}" == true ]]; then
    if [[ -d "$BUILD_FOLDER" ]]; then
        rm -rf "$BUILD_FOLDER"
    fi
    ( cd "$REPO_ROOT" && cargo clean --target "$SHLOSILO_TARGET" ) || true
fi

mkdir -p "$BUILD_FOLDER"

if [[ ! -f "$BUILD_FOLDER/padding_bin_file.py" ]]; then
    cp "$MAKE_PADDING_FILE_PATH/padding_bin_file.py" "$BUILD_FOLDER/padding_bin_file.py"
fi

# Build the forms staticlib + sync the header BEFORE cmake configure: the
# CMakeLists checks for libshlosilo.a at configure time.
build_shlosilo

execute_build() {
    if [[ "${build_options[language]}" == true ]]; then
        pushd "$LANGUAGE_PATH"
        $LANGUAGE_SCRIPT
        popd
    fi

    cmake_parm=""
    # Same pinning rule as SMOKE_SCREEN below: pass the key-supply flavor EXPLICITLY on every
    # configure, or a bare re-configure reuses whatever the cache holds and silently builds the
    # other flavor. SHLOSILO_PATH is a cache variable for the same reason as the dirs above -
    # the probe flavor consumes its own copy of libshlosilo.a, never the canonical one.
    cmake_parm="${cmake_parm} -DSHLOSILO_WITH_SE=${SE_CMAKE}"
    cmake_parm="${cmake_parm} -DSHLOSILO_PATH=${SHLOSILO_DIR}"
    # C objects are the long pole of this build (FreeRTOS + LVGL + vendor libs,
    # a full rebuild per CI run). When a compiler cache is installed, route the
    # C/ASM compile steps through it; nothing changes when it is absent.
    if command -v ccache >/dev/null 2>&1; then
        export CCACHE_BASEDIR="${REPO_ROOT}"
        export CCACHE_NOHASHDIR=true
        cmake_parm="${cmake_parm} -DCMAKE_C_COMPILER_LAUNCHER=ccache"
        cmake_parm="${cmake_parm} -DCMAKE_ASM_COMPILER_LAUNCHER=ccache"
    fi
    if [[ "${build_options[production]}" == true ]]; then
        cmake_parm="${cmake_parm} -DBUILD_PRODUCTION=true"
    fi
    # The chain set reaches CMake as a declaration the header guards consume; the old
    # `-DBTC_ONLY=true` was read by nothing and a `build.sh btc_only` silently produced the
    # three-chain product.
    cmake_parm="${cmake_parm} -DSHLOSILO_CHAINS=$(echo "$SHLOSILO_CHAINS" | tr ',' ';')"
    if [[ "${build_options[cypherpunk]}" == true ]]; then
        cmake_parm="${cmake_parm} -DCYBERPUNK=true"
    fi
    if [[ "${build_options[screen]}" == true ]]; then
        cmake_parm="${cmake_parm} -DENABLE_SCREEN_SHOT=true"
    fi
    if [[ "${build_options[smoke]}" == true ]]; then
        cmake_parm="${cmake_parm} -DSMOKE_SCREEN=true"
    else
        # Explicit OFF: a bare configure REUSES a cached SMOKE_SCREEN=true
        # from a previous `build.sh smoke` and silently builds the smoke
        # flavor (bit-identical image - caught twice by sha). Pin the flavor
        # on every configure.
        cmake_parm="${cmake_parm} -DSMOKE_SCREEN=false"
    fi
    if [[ "${build_options[debug]}" == true ]]; then
        cmake_parm="${cmake_parm} -DDEBUG_MEMORY=true"
    fi

    # Field-diagnosis flavor: SHLOSILO_SIGN_FAIL_HEX=1 in the environment turns
    # on the raw-code line on the result page (see CMakeLists SIGN_FAIL_HEX).
    if [[ "${SHLOSILO_SIGN_FAIL_HEX:-0}" != "0" ]]; then
        cmake_parm="${cmake_parm} -DSIGN_FAIL_HEX=true"
    fi

    if [[ "${build_options[simulator]}" == true ]]; then
        mkdir -p "$BUILD_SIMULATOR_FOLDER"
        pushd "$BUILD_SIMULATOR_FOLDER"
        cmake -G "Unix Makefiles" -DBUILD_TYPE=Simulator $cmake_parm ..
        make -j"${JOBS}"
        popd
    else
        pushd "$BUILD_FOLDER"
        cmake -G "Unix Makefiles" $cmake_parm ..
        if [[ "${build_options[log]}" == true ]]; then
            make -j"${JOBS}" > makefile.log 2>&1
        else
            make -j"${JOBS}"
        fi
        # padding is built into this script on purpose: mh1903.bin -> mh1903_full.bin
        # (4K alignment + APP_END magic). Never pad again by hand after this.
        python3 padding_bin_file.py mh1903.bin
        popd
        assert_firmware_identity
    fi

    # ---- sign: single fwdata-layer image ready for the SD card ----
    if [[ "${build_options[simulator]}" != true && "${build_options[no_sign]}" != true ]]; then
        local local_key="$HOME/.forgebox/keys/private.pem"
        if command -v forgebox >/dev/null 2>&1 && [[ -f "$local_key" ]]; then
            echo "=== signing firmware (forgebox sign) ==="
            forgebox sign --s "$BUILD_FOLDER/mh1903_full.bin" \
                          --d "$BUILD_FOLDER/forgebox.bin" \
                          --key "$local_key"
            echo "    flashable image: build/forgebox.bin ($(stat -c%s "$BUILD_FOLDER/forgebox.bin") bytes)"
            echo "    sha256: $(sha256sum "$BUILD_FOLDER/forgebox.bin" | cut -d' ' -f1)"
        else
            echo "NOTE: forgebox CLI or signing key not found - skipped signing."
            echo "      Manual: forgebox sign --s build/mh1903_full.bin --d build/forgebox.bin --key ~/.forgebox/keys/private.pem"
        fi
    fi

    if [[ "${build_options[copy]}" == true ]]; then
        echo "Generating pillar.bin file..."
        pushd "$MAKE_OAT_FILE_PATH"
        echo "Generating OTA files..."
        bash make_ota_file.sh "$(pwd)/build/pillar.bin"
        bash make_ota_file.sh "$(pwd)/build/forgebox.bin"
        bash make_ota_file.sh "F:/pillar.bin"
        popd
    elif [[ "${build_options[release]}" == true ]]; then
        pushd "$MAKE_OAT_FILE_PATH"
        echo "Generating release files..."
        bash make_ota_file.sh "$(pwd)/build/pillar.bin"
        bash make_ota_file.sh "$(pwd)/build/forgebox.bin"
        popd
    elif [[ "${build_options[simulator]}" == true ]]; then
        ./build/simulator.exe
    fi
}

execute_build
