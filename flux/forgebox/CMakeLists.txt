set(CMAKE_SYSTEM_NAME Generic)
cmake_minimum_required(VERSION 3.10)

set(BUILD_ENVIRONMENT "DEBUG")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g2 -ggdb")
set(CMAKE_C_FLAGS_RELEASE "-O3")

# Must include firmware.cmake before project() to set up compiler
include(firmware.cmake)

project(mh1903)

# GCC 14 promotes several legacy Keystone-driver warnings to hard errors
# (implicit-function-declaration, implicit-int, ...); the same sources
# compiled as warnings on GCC 13.2.1 - environment drift, not a code
# regression. Relax them back to warnings on GCC >= 14 only: GCC 13 (the
# CI image) rejects some of the -Wno-error= flag NAMES outright. This must
# run after project(): CMAKE_C_COMPILER_VERSION is only known once the
# compiler is detected, and firmware.cmake runs before project().
if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 14)
  add_compile_options(
    -Wno-error=implicit-function-declaration
    -Wno-error=implicit-int
    -Wno-error=declaration-missing-parameter-type
    -Wno-error=incompatible-pointer-types)
endif()

# ====== screen ownership switch (product UI vs smoke diagnostics) ======
# OFF (default): boot into the product UI (direct-write renderer; no LVGL).
# ON:  boot into the LVGL smoke diagnostics screen (build.sh smoke).
option(SMOKE_SCREEN "boot into the LVGL smoke diagnostics screen" OFF)

# ====== key-supply module switch (design 密钥供给 §11) ======
# ON (default): plate scan AND the secure-element path (two parallel, replaceable key sources -
# this board carries ATECC608B + DS28S60). OFF: plate only - the keystore data plane, its SE
# transport, both SE drivers and the dev console battery are dropped from the source set, and
# every C call site is gated on the same macro.
# build.sh drives this together with the Rust `se` feature (--no-default-features) from ONE
# variable, SHLOSILO_WITH_SE; the pair is verified below against the static library's symbols.
option(SHLOSILO_WITH_SE "include the secure-element key-supply module" ON)
if(SMOKE_SCREEN AND NOT SHLOSILO_WITH_SE)
    message(FATAL_ERROR "key supply: the smoke diagnostics screen routes the SE console to the panel (shlosilo_smoke_task.c calls SeSmokeSetLog, which lives in the SE source set), so SMOKE_SCREEN=1 cannot be combined with SHLOSILO_WITH_SE=OFF yet. A plate-only carrier brings its own smoke screen.")
endif()

# Field-diagnosis flavor (off in every reference build): append the raw
# sign-failure code in hex to the result page. The shipping vocabulary carries
# class words only; when a code has no entry, "unknown code" is undiagnosable on
# the one channel a device has - the screen. Same precedent as
# SHLOSILO_QR_TYPE_HEX. Enable with SHLOSILO_SIGN_FAIL_HEX=1 in build.sh's env.
option(SIGN_FAIL_HEX "append the raw failure code to the result page" OFF)
if(SIGN_FAIL_HEX)
  add_compile_options(-DSHLOSILO_SIGN_FAIL_HEX=1)
endif()

set(COMMON_DEFINITIONS
    USE_STDPERIPH_DRIVER
    USE_FULL_ASSERT
    ARM_MATH_CM4
    __TARGET_FPU_VFP
    NDEBUG
    ATCA_HAL_I2C
)

# Include paths
set(EXTERNAL_INCLUDE_PATH
    external
    external/FreeRTOS
    external/FreeRTOS/Source/include
    external/FreeRTOS/Source/portable/GCC/ARM_CM4F
    external/FreeRTOS/CMSIS_RTOS_V2
    external/lvgl
    external/lvgl/src
    external/lvgl/src/core
    external/lvgl/src/draw
    external/lvgl/src/extra
    external/lvgl/src/font
    external/lvgl/src/hal
    external/lvgl/src/misc
    external/lvgl/src/widgets
    external/qrcodegen
    external/mh1903_lib/MHSCPU_Driver/inc
    external/mh1903_lib/Device/MegaHunt/mhscpu/Include
    external/mh1903_lib/CMSIS/Include
    external/cryptoauthlib/lib
)

set(SRC_INCLUDE_PATH
    src
    src/config
    src/tasks
    src/driver
    src/diag
    src/keystore
    src/crypto
    src/ui
    src/ram
    src/utils
)

set(INCLUDE_DIR
    ${SRC_INCLUDE_PATH}
    ${EXTERNAL_INCLUDE_PATH}
)

# ====== shlosilo (Rust staticlib) integration ======
# PoC 3: shlosilo Rust business-library integration
# - libshlosilo.a is produced by `shlosilo-poc4 cargo build --release`
# - debug info already stripped with arm-none-eabi-strip
# - called from FreeRTOS tasks through the C ABI (src/tasks/shlosilo_smoke_task.c)
# A cache variable, not a fixed path: a probe flavor (SHLOSILO_WITH_SE=0) consumes its own copy
# so it can never feed the canonical library to a differently-configured C build.
set(SHLOSILO_PATH "${CMAKE_CURRENT_SOURCE_DIR}/shlosilo" CACHE PATH "dir holding libshlosilo.a + shlosilo.h")
if(EXISTS "${SHLOSILO_PATH}/libshlosilo.a")
    message(STATUS "shlosilo: integrating libshlosilo.a from ${SHLOSILO_PATH}")
    list(APPEND INCLUDE_DIR "${SHLOSILO_PATH}")
list(APPEND INCLUDE_DIR "external/mh1903_lib/MHSCPU_Driver/inc/cryptlib")
list(APPEND INCLUDE_DIR "external/mh1903_lib/ctaes")
else()
    message(WARNING "shlosilo: libshlosilo.a not found at ${SHLOSILO_PATH}, skipping integration")
endif()

# ---- key-supply flavor consistency (the switch has two halves; they must agree) ----
# The Rust static library either carries the SE FFI face or it does not, and the C source set
# must be configured to match. Asking the artifact instead of trusting the flag pair is what
# makes a half-switched build impossible to ship: SE C sources without the Rust SE face fail
# at the link, and the Rust SE face with no C caller would ship a dead module.
if(EXISTS "${SHLOSILO_PATH}/libshlosilo.a")
    execute_process(
        COMMAND ${CROSS_COMPILE_PREFIX}-nm "${SHLOSILO_PATH}/libshlosilo.a"
        OUTPUT_VARIABLE SHLOSILO_LIB_SYMBOLS ERROR_QUIET)
    if(SHLOSILO_LIB_SYMBOLS MATCHES "shlosilo_keysource_se_open_ffi")
        set(SHLOSILO_LIB_HAS_SE TRUE)
    else()
        set(SHLOSILO_LIB_HAS_SE FALSE)
    endif()
    if(SHLOSILO_LIB_HAS_SE AND NOT SHLOSILO_WITH_SE)
        message(FATAL_ERROR "key supply: SHLOSILO_WITH_SE=OFF, but ${SHLOSILO_PATH}/libshlosilo.a carries the SE FFI face. Rebuild the staticlib with --no-default-features (build.sh does both halves from SHLOSILO_WITH_SE).")
    elseif(NOT SHLOSILO_LIB_HAS_SE AND SHLOSILO_WITH_SE)
        message(FATAL_ERROR "key supply: SHLOSILO_WITH_SE=ON, but ${SHLOSILO_PATH}/libshlosilo.a has no SE FFI face. Rebuild the staticlib WITHOUT --no-default-features.")
    endif()
    message(STATUS "key supply: staticlib SE face = ${SHLOSILO_LIB_HAS_SE}, source set SE = ${SHLOSILO_WITH_SE}")
endif()

# ---- chain axis on the C surface (pool #99) ----
# shlosilo.h guards chain-specific declarations behind `#if defined(SHLOSILO_CHAIN_*)` (cbindgen
# `[defines]`), so this host must DECLARE the chain set it links against. One variable drives
# both halves, the same shape the key-supply switch above uses: build.sh derives the staticlib
# feature set and this declaration from SHLOSILO_CHAINS.
#
# Verification is deliberately asymmetric, and says so rather than implying coverage it lacks:
# XMR is the only chain with chain-exclusive entry points (shlosilo_xmr_pairing_ffi and the
# generator-cache pair), so the archive can confirm or refute that half in BOTH directions.
# BTC and ETH carry no exclusive symbol, so their declaration is taken on trust - inventing a
# check that cannot see them would only manufacture confidence. The loud signal for a wrong
# BTC/ETH declaration is the C build itself: a declaration that is too narrow hides a prototype
# the host calls (compile error), one that is too wide hides nothing and links.
set(SHLOSILO_CHAINS "btc;eth;xmr" CACHE STRING "chain set this C host declares")
foreach(_chain ${SHLOSILO_CHAINS})
    if(NOT _chain MATCHES "^(btc|eth|xmr)$")
        message(FATAL_ERROR "chain axis: unknown chain '${_chain}' in SHLOSILO_CHAINS='${SHLOSILO_CHAINS}' (expected btc, eth and/or xmr)")
    endif()
    string(TOUPPER "${_chain}" _chain_upper)
    add_compile_options(-DSHLOSILO_CHAIN_${_chain_upper}=1)
    message(STATUS "chain axis: declaring SHLOSILO_CHAIN_${_chain_upper}")
endforeach()

if(EXISTS "${SHLOSILO_PATH}/libshlosilo.a")
    if(SHLOSILO_LIB_SYMBOLS MATCHES "shlosilo_xmr_pairing_ffi")
        set(SHLOSILO_LIB_HAS_XMR TRUE)
    else()
        set(SHLOSILO_LIB_HAS_XMR FALSE)
    endif()
    list(FIND SHLOSILO_CHAINS "xmr" _xmr_declared)
    if(_xmr_declared GREATER -1 AND NOT SHLOSILO_LIB_HAS_XMR)
        message(FATAL_ERROR "chain axis: SHLOSILO_CHAINS declares xmr, but ${SHLOSILO_PATH}/libshlosilo.a has no XMR FFI face. Rebuild the staticlib with chain-xmr (build.sh derives it from SHLOSILO_CHAINS).")
    elseif(_xmr_declared EQUAL -1 AND SHLOSILO_LIB_HAS_XMR)
        message(FATAL_ERROR "chain axis: SHLOSILO_CHAINS does not declare xmr, but ${SHLOSILO_PATH}/libshlosilo.a carries the XMR FFI face - either the archive was built for more chains than this host declares, or the header guards now hide a surface that exists. Rebuild the staticlib without chain-xmr.")
    endif()
    if(_xmr_declared GREATER -1)
        set(_xmr_declared_txt "yes")
    else()
        set(_xmr_declared_txt "no")
    endif()
    message(STATUS "chain axis: staticlib XMR face = ${SHLOSILO_LIB_HAS_XMR}, xmr declared = ${_xmr_declared_txt}")
endif()

# LVGL source files (smoke diagnostics only; the product UI does not use LVGL)
if(SMOKE_SCREEN)
    file(GLOB_RECURSE LVGL
        "external/lvgl/src/core/*.c"
        "external/lvgl/src/draw/*.c"
        "external/lvgl/src/hal/*.c"
        "external/lvgl/src/misc/*.c"
        "external/lvgl/src/widgets/*.c"
        "external/lvgl/src/extra/*.c"
        "external/lvgl/src/font/*.c"
    )
else()
    set(LVGL "")
endif()

# FreeRTOS source files
file(GLOB_RECURSE FREERTOS
    "external/FreeRTOS/Source/croutine.c"
    "external/FreeRTOS/Source/event_groups.c"
    "external/FreeRTOS/Source/list.c"
    "external/FreeRTOS/Source/queue.c"
    "external/FreeRTOS/Source/stream_buffer.c"
    "external/FreeRTOS/Source/tasks.c"
    "external/FreeRTOS/Source/timers.c"
    "external/FreeRTOS/Source/portable/GCC/ARM_CM4F/port.c"
    "external/FreeRTOS/CMSIS_RTOS_V2/cmsis_os2.c"
    "external/FreeRTOS/Source/portable/MemMang/heap_4.c"
    "external/FreeRTOS/rtos_expand.c"
)

# MH1903 driver source files
aux_source_directory(external/mh1903_lib/MHSCPU_Driver/src/ MH1903_DRIVER)
# The vendored mhscpu_qspi.c (keystone's proven QSPI flash driver, needed by the BP+
# generator cache backend) is wrapped in #ifdef BUILD_PRODUCTION upstream — compile it
# with the define regardless of the global BUILD_ENVIRONMENT.
set_source_files_properties(external/mh1903_lib/MHSCPU_Driver/src/mhscpu_qspi.c
    PROPERTIES COMPILE_DEFINITIONS BUILD_PRODUCTION)

set(APP_SRC
    src/main.c
    shlosilo/embedded_alloc_glue.c

    src/driver/drv_sys.c
    src/driver/drv_uart.c
    src/driver/drv_psram.c
    src/driver/drv_lcd_bright.c
    src/driver/drv_parallel8080.c
    src/driver/drv_ili9806.c
    src/driver/drv_nt35510.c
    src/driver/hal_lcd.c
    src/driver/drv_aw32001.c
    src/driver/drv_battery.c
    src/driver/drv_spi.c
    src/driver/drv_gd25qxx.c
    src/driver/drv_i2c_io.c
    src/ram/psram_heap_4.c
    src/ram/user_memory.c
    src/ram/hardfault_diag.c
    src/diag/crash_record.c
    src/diag/crash_store.c
    src/diag/crash_blackbox.c
    src/diag/crash_noinit.c
    src/driver/hal_touch.c
    src/driver/drv_i2c.c
    src/driver/drv_exti.c
    src/driver/exti_stubs.c
    src/driver/hardware_version.c
    src/driver/drv_cst3xx.c
    src/driver/drv_cst726.c
    src/driver/drv_ft6336.c
    src/driver/drv_gsl1691.c
    src/utils/assert.c
    src/utils/user_delay.c
    src/utils/user_utils.c
    src/config/version.c
    src/driver/drv_power.c
    src/driver/low_power.c
    src/flash/xmr_gen_cache_flash.c
    external/mh1903_lib/ctaes/ctaes.c

    # Crypto primitives + the TRNG/OTP/MPU drivers the keystore is assembled from. They stay in
    # EVERY flavor: err_code/log_print are used tree-wide, and the primitives are shared (a
    # plate-only build strips the unused ones via --gc-sections instead of source-set surgery,
    # so the keystore can come back without touching this list).
    src/crypto/sha256.c
    src/crypto/sha512.c
    src/crypto/hmac.c
    src/crypto/hash_and_salt.c
    src/driver/drv_trng.c
    src/driver/drv_otp.c
    src/driver/drv_mpu.c
    src/utils/err_code.c
    src/utils/log_print.c
)

# ---- key-supply: the SE module's C side (design 密钥供给 §11) ----
# The dependency edge is one-way and tight, which is why this is a clean cut: keystore.c is the
# only consumer of se_manager.c, se_manager.c the only consumer of both SE drivers, and
# se_smoke.c (the dev console battery: 'se unlock/lock', provisioning, SE self-checks) the only
# consumer of keystore.h. Once the C call sites in product_task.c are gated on the same macro,
# nothing in the tree references them.
if(SHLOSILO_WITH_SE)
    list(APPEND APP_SRC
        # keystore data plane (keystone3-parity, the C side of the key supply)
        src/keystore/keystore.c
        src/keystore/se_manager.c
        # SE comm face (Task 7): ATECC608B / DS28S60 drivers + the dev console battery
        # (se_smoke.c, hardware safety gate inside) + its utils.
        # drv_spi_io.c is the GPIO-bitbang SPI the DS28S60 rides on (its absence was hidden by
        # the same --gc-sections gap that hid the console).
        src/driver/drv_atecc608b.c
        src/driver/drv_ds28s60.c
        src/driver/drv_spi_io.c
        src/tasks/se_smoke.c
    )

    # ATECC608B driver library: vendored from keystone3-firmware external/
    # (same provenance as the keystore port; keystone3's own CMake builds this
    # exact file set -- atca core + calib + host + crypto + hashes + hal).
    # The file set is COMPILE INPUT (goes into objsrc), NOT an include path:
    # the old `list(APPEND INCLUDE_DIR ${CRYPTOAUTHLIB_SRC})` fed ~40 source
    # file paths to the include-dir list (a "not a directory" warning per file)
    # and the library was never compiled at all -- nothing referenced it while
    # the SE console plane was stripped by --gc-sections, so the link gap was
    # invisible. keystone3's chain is ${cryptoauthlib} -> ${EXTERNAL} ->
    # ${objsrc}; this glob is the same end (appended to objsrc below).
    file(GLOB_RECURSE CRYPTOAUTHLIB_SRC
        external/cryptoauthlib/lib/atca_basic.c
        external/cryptoauthlib/lib/atca_cfgs.c
        external/cryptoauthlib/lib/atca_debug.c
        external/cryptoauthlib/lib/atca_device.c
        external/cryptoauthlib/lib/atca_helpers.c
        external/cryptoauthlib/lib/atca_iface.c
        external/cryptoauthlib/lib/atca_utils_sizes.c
        external/cryptoauthlib/lib/calib/*.c
        external/cryptoauthlib/lib/host/atca_host.c
        external/cryptoauthlib/lib/crypto/*.c
        external/cryptoauthlib/lib/crypto/hashes/*.c
        external/cryptoauthlib/lib/hal/*.c
    )
else()
    set(CRYPTOAUTHLIB_SRC "")
    message(STATUS "key supply: plate only - the SE module is out of the source set")
endif()

# Screen ownership: exactly one renderer per build owns the panel.
if(SMOKE_SCREEN)
    list(APPEND APP_SRC
        src/tasks/helloworld_task.c
        src/tasks/shlosilo_smoke_task.c
        src/ui/imgDevLogo.c
        src/ui/openSansEnTitle.c
        src/ui/openSansEnText.c
    )
else()
    list(APPEND APP_SRC
        src/tasks/product_task.c
        src/ui/shlosilo_ui.c
        src/ui/ui_wrap.c
        src/ui/ui_qr.c
        src/ui/ui_font.c
        src/driver/drv_qrdecode.c
        src/driver/qr_selftest.c
        external/qrcodegen/qrcodegen.c
    )
endif()

# ====== firmware identity (shown on the product UI footer) ======
# git short hash at configure time; an uncommitted tree gets a -dirty suffix.
set(FW_GIT_HASH "nogit")
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short=7 HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE FW_GIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    execute_process(COMMAND ${GIT_EXECUTABLE} status --porcelain
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../..
        OUTPUT_VARIABLE FW_GIT_DIRTY OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(FW_GIT_DIRTY)
        set(FW_GIT_HASH "${FW_GIT_HASH}-dirty")
        # Record WHAT was dirty: this suffix reaches the product screen, and a footer reading
        # "-dirty" for a clean commit is unanswerable after the fact without the list.
        string(REPLACE "\n" "; " FW_GIT_DIRTY_LIST "${FW_GIT_DIRTY}")
        message(WARNING "firmware identity is dirty; git saw: ${FW_GIT_DIRTY_LIST}")
    endif()
endif()
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/fw_identity.h
    "#define FIRMWARE_GIT_HASH \"${FW_GIT_HASH}\"\n")
list(APPEND INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR})
message(STATUS "forgebox firmware identity: ${FW_GIT_HASH}")

set(objsrc
    ${MH1903_DRIVER}
    ${APP_SRC}
    ${FREERTOS}
    ${LVGL}
    ${CRYPTOAUTHLIB_SRC}
    external/mh1903_lib/Device/MegaHunt/mhscpu/Source/GCC/startup_mhscpu.s
)

# Append shlosilo static library to objsrc (after APP_SRC)
if(EXISTS "${SHLOSILO_PATH}/libshlosilo.a")
    list(APPEND objsrc "${SHLOSILO_PATH}/libshlosilo.a")
endif()

add_executable(${PROJECT_NAME}.elf ${objsrc})
if(SMOKE_SCREEN)
    list(APPEND COMMON_DEFINITIONS SMOKE_SCREEN=1)
endif()
# Presence-style define (same idiom as SMOKE_SCREEN above): defined exactly when the SE source
# set is in the build, so the C call sites in product_task.c can never reference a translation
# unit that is not there - SE call sites without their source file fail loudly at the link
# instead of silently shipping as a stub. build.sh sets both halves together.
if(SHLOSILO_WITH_SE)
    list(APPEND COMMON_DEFINITIONS SHLOSILO_WITH_SE=1)
endif()

# Field-diagnosis switch (2026-11-04): draw the decoded UR type token as hex on
# the scan page. Default OFF; build a one-off diagnostic image with
#   cmake ... -DQR_TYPE_HEX_DIAG=ON
# (the production flavour must never print payload-derived text).
option(QR_TYPE_HEX_DIAG "Dump the decoded UR type token as hex on the scan page" OFF)
if(QR_TYPE_HEX_DIAG)
    list(APPEND COMMON_DEFINITIONS SHLOSILO_QR_TYPE_HEX=1)
endif()
target_compile_definitions(${PROJECT_NAME}.elf PRIVATE ${COMMON_DEFINITIONS})
target_include_directories(${PROJECT_NAME}.elf PRIVATE ${INCLUDE_DIR})

# Link shlosilo static library (must come AFTER target creation so link order is correct)
if(EXISTS "${SHLOSILO_PATH}/libshlosilo.a")
    target_link_libraries(${PROJECT_NAME}.elf "${SHLOSILO_PATH}/libshlosilo.a")
endif()

# QR decode library (product flavor only: camera + closed-source decode lib)
if(NOT SMOKE_SCREEN)
    target_link_libraries(${PROJECT_NAME}.elf
        "${CMAKE_CURRENT_SOURCE_DIR}/external/mh1903_lib/MHSCPU_Driver/lib/MH1903_QRDecodeLib.a")
endif()

target_link_libraries(${PROJECT_NAME}.elf m)

set(ELF_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.elf)
set(HEX_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.hex)
set(BIN_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.bin)

add_custom_command(TARGET "${PROJECT_NAME}.elf" POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -Obinary ${ELF_FILE} ${BIN_FILE}
    COMMAND ${CMAKE_OBJCOPY} -Oihex ${ELF_FILE} ${HEX_FILE}
    COMMENT "Building ${PROJECT_NAME}.bin and ${PROJECT_NAME}.hex"

    COMMAND ${CMAKE_COMMAND} -E copy ${HEX_FILE} "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.hex"
    COMMAND ${CMAKE_COMMAND} -E copy ${BIN_FILE} "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.bin"

    COMMAND ${CMAKE_SIZE} --format=berkeley ${PROJECT_NAME}.elf ${PROJECT_NAME}.hex
    COMMENT "Building ${PROJECT_NAME}.bin and ${PROJECT_NAME}.hex; Invoking: Cross ARM GNU Print Size"
)