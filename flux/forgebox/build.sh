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
# =============================================================================

set -e
set -o pipefail

# Resolve paths regardless of the caller's cwd.
cd "$(dirname "${BASH_SOURCE[0]}")"
APP_ROOT="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

BUILD_FOLDER="$APP_ROOT/build"
BUILD_SIMULATOR_FOLDER="$APP_ROOT/build_simulator"
TOOLS_FOLDER="$APP_ROOT/tools"
MAKE_OAT_FILE_PATH="${TOOLS_FOLDER}/ota_file_maker"
MAKE_PADDING_FILE_PATH="${TOOLS_FOLDER}/padding_bin_file"
ASTYLE_PATH="${TOOLS_FOLDER}/AStyle.sh"
LANGUAGE_PATH="$APP_ROOT/src/ui/lv_i18n"
LANGUAGE_SCRIPT="python3 data_loader.py"

# ---- shlosilo (forms) build configuration for this appearance ----
SHLOSILO_TARGET="${SHLOSILO_TARGET:-thumbv7em-none-eabihf}"
SHLOSILO_FEATURES="${SHLOSILO_FEATURES:-generator-cache-ffi,cn-timing-ffi,tx-phase-timing-ffi,device-timing,perf-bench-ffi}"

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

    echo "=== shlosilo forms: cargo build ($SHLOSILO_TARGET) ==="
    ( cd "$REPO_ROOT" && cargo build --release --target "$SHLOSILO_TARGET" \
        --no-default-features --features "$SHLOSILO_FEATURES" --lib )
    arm-none-eabi-strip --strip-debug "$lib" -o "$APP_ROOT/shlosilo/libshlosilo.a"
    echo "    staticlib -> shlosilo/libshlosilo.a ($(stat -c%s "$APP_ROOT/shlosilo/libshlosilo.a") bytes)"

    echo "=== shlosilo C header sync gate (cbindgen regen must equal tracked) ==="
    ( cd "$REPO_ROOT" && cbindgen --config cbindgen.toml --crate shlosilo \
        --output "$BUILD_FOLDER/shlosilo_regen.h" ) >/dev/null
    if ! diff -q "$BUILD_FOLDER/shlosilo_regen.h" "$REPO_ROOT/shlosilo.h" >/dev/null; then
        echo "ERROR: tracked shlosilo.h differs from cbindgen output."
        echo "       Regenerate and commit shlosilo.h before building this host."
        diff "$BUILD_FOLDER/shlosilo_regen.h" "$REPO_ROOT/shlosilo.h" | head -20
        exit 1
    fi
    cp "$REPO_ROOT/shlosilo.h" "$APP_ROOT/shlosilo/shlosilo.h"
    echo "    header OK (tracked == regen)"
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
    if [[ "${build_options[production]}" == true ]]; then
        cmake_parm="${cmake_parm} -DBUILD_PRODUCTION=true"
    fi
    if [[ "${build_options[btc_only]}" == true ]]; then
        cmake_parm="${cmake_parm} -DBTC_ONLY=true"
    fi
    if [[ "${build_options[cypherpunk]}" == true ]]; then
        cmake_parm="${cmake_parm} -DCYBERPUNK=true"
    fi
    if [[ "${build_options[screen]}" == true ]]; then
        cmake_parm="${cmake_parm} -DENABLE_SCREEN_SHOT=true"
    fi
    if [[ "${build_options[debug]}" == true ]]; then
        cmake_parm="${cmake_parm} -DDEBUG_MEMORY=true"
    fi

    if [[ "${build_options[simulator]}" == true ]]; then
        mkdir -p "$BUILD_SIMULATOR_FOLDER"
        pushd "$BUILD_SIMULATOR_FOLDER"
        cmake -G "Unix Makefiles" -DBUILD_TYPE=Simulator $cmake_parm ..
        make -j16
        popd
    else
        pushd "$BUILD_FOLDER"
        cmake -G "Unix Makefiles" $cmake_parm ..
        if [[ "${build_options[log]}" == true ]]; then
            make -j16 > makefile.log 2>&1
        else
            make -j16
        fi
        # padding is built into this script on purpose: mh1903.bin -> mh1903_full.bin
        # (4K alignment + APP_END magic). Never pad again by hand after this.
        python3 padding_bin_file.py mh1903.bin
        popd
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
