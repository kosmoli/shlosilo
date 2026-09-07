set(CMAKE_SYSTEM_NAME Generic)
cmake_minimum_required(VERSION 3.10)

set(BUILD_ENVIRONMENT "DEBUG")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g2 -ggdb")
set(CMAKE_C_FLAGS_RELEASE "-O3")

# Must include firmware.cmake before project() to set up compiler
include(firmware.cmake)

project(mh1903)

set(COMMON_DEFINITIONS
    USE_STDPERIPH_DRIVER
    USE_FULL_ASSERT
    ARM_MATH_CM4
    __TARGET_FPU_VFP
    NDEBUG
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
    external/mh1903_lib/MHSCPU_Driver/inc
    external/mh1903_lib/Device/MegaHunt/mhscpu/Include
    external/mh1903_lib/CMSIS/Include
)

set(SRC_INCLUDE_PATH
    src
    src/config
    src/tasks
    src/driver
    src/ram
    src/utils
)

set(INCLUDE_DIR
    ${SRC_INCLUDE_PATH}
    ${EXTERNAL_INCLUDE_PATH}
)

# ====== shlosilo (Rust staticlib) integration ======
# PoC 3: shlosilo Rust 业务库集成
# - libshlosilo.a 由 shlosilo-poc3 cargo build --release 产出
# - 已用 arm-none-eabi-strip 删 debug info
# - 通过 C-ABI 给 FreeRTOS task 调用（src/tasks/shlosilo_smoke_task.c）
set(SHLOSILO_PATH "${CMAKE_CURRENT_SOURCE_DIR}/shlosilo")
if(EXISTS "${SHLOSILO_PATH}/libshlosilo.a")
    message(STATUS "shlosilo: integrating libshlosilo.a from ${SHLOSILO_PATH}")
    list(APPEND INCLUDE_DIR "${SHLOSILO_PATH}")
list(APPEND INCLUDE_DIR "external/mh1903_lib/MHSCPU_Driver/inc/cryptlib")
list(APPEND INCLUDE_DIR "external/mh1903_lib/ctaes")
else()
    message(WARNING "shlosilo: libshlosilo.a not found at ${SHLOSILO_PATH}, skipping integration")
endif()

# LVGL source files
file(GLOB_RECURSE LVGL
    "external/lvgl/src/core/*.c"
    "external/lvgl/src/draw/*.c"
    "external/lvgl/src/hal/*.c"
    "external/lvgl/src/misc/*.c"
    "external/lvgl/src/widgets/*.c"
    "external/lvgl/src/extra/*.c"
    "external/lvgl/src/font/*.c"
)

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
    src/tasks/helloworld_task.c

    src/tasks/shlosilo_smoke_task.c
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
    src/driver/drv_i2c_io.c
    src/ram/psram_heap_4.c
    src/ram/user_memory.c
    src/utils/assert.c
    src/utils/user_delay.c
    src/utils/user_utils.c
    src/config/version.c
    src/driver/drv_power.c
    src/driver/low_power.c
    src/flash/xmr_gen_cache_flash.c
    external/mh1903_lib/ctaes/ctaes.c
    src/ui/imgDevLogo.c
    src/ui/openSansEnTitle.c
    src/ui/openSansEnText.c
)

set(objsrc
    ${MH1903_DRIVER}
    ${APP_SRC}
    ${FREERTOS}
    ${LVGL}
    external/mh1903_lib/Device/MegaHunt/mhscpu/Source/GCC/startup_mhscpu.s
)

# Append shlosilo static library to objsrc (after APP_SRC)
if(EXISTS "${SHLOSILO_PATH}/libshlosilo.a")
    list(APPEND objsrc "${SHLOSILO_PATH}/libshlosilo.a")
endif()

add_executable(${PROJECT_NAME}.elf ${objsrc})
target_compile_definitions(${PROJECT_NAME}.elf PRIVATE ${COMMON_DEFINITIONS})
target_include_directories(${PROJECT_NAME}.elf PRIVATE ${INCLUDE_DIR})

# Link shlosilo static library (must come AFTER target creation so link order is correct)
if(EXISTS "${SHLOSILO_PATH}/libshlosilo.a")
    target_link_libraries(${PROJECT_NAME}.elf "${SHLOSILO_PATH}/libshlosilo.a")
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