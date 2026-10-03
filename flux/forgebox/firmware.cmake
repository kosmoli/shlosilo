set(CROSS_COMPILE_PREFIX arm-none-eabi)
set(CMAKE_C_COMPILER ${CROSS_COMPILE_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${CROSS_COMPILE_PREFIX}-g++)
set(CMAKE_ASM_COMPILER ${CROSS_COMPILE_PREFIX}-gcc)
set(CMAKE_OBJCOPY ${CROSS_COMPILE_PREFIX}-objcopy)
set(CMAKE_OBJDUMP ${CROSS_COMPILE_PREFIX}-objdump)
set(CMAKE_SIZE ${CROSS_COMPILE_PREFIX}-size)
set(MCU cortex-m4)
set(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/mh1903b.ld)
set(ARCH_FLAGS "-mcpu=${MCU} -mthumb -mlittle-endian")
set(MCU_FLAGS "${ARCH_FLAGS} -Os -mfloat-abi=hard -mfpu=fpv4-sp-d16")
# GCC 14 promotes several legacy Keystone-driver warnings to hard errors;
# GCC 13 (CI image) does not and rejects some of the -Wno-error= flag names.
# Probe each flag and add only the ones this compiler accepts.
include(CheckCCompilerFlag)
set(GCC14_RELAX_FLAGS "")
foreach(_flag
    -Wno-error=implicit-function-declaration
    -Wno-error=implicit-int
    -Wno-error=declaration-missing-parameter-type
    -Wno-error=incompatible-pointer-types)
  string(MAKE_C_IDENTIFIER "ok${_flag}" _var)
  check_c_compiler_flag("${_flag}" ${_var})
  if(${_var})
    list(APPEND GCC14_RELAX_FLAGS ${_flag})
  endif()
endforeach()
set(CMAKE_C_FLAGS "${MCU_FLAGS} -Wall -Wno-unknown-pragmas -Wno-format -g ${GCC14_RELAX_FLAGS}")
set(CMAKE_CXX_FLAGS "${MCU_FLAGS} -Wall -Wno-unknown-pragmas -Wno-format -g")

set_property(SOURCE external/mh1903_lib/Device/MegaHunt/mhscpu/Source/GCC/startup_mhscpu.s PROPERTY LANGUAGE C)

set(CMAKE_EXE_LINKER_FLAGS " -T ${LINKER_SCRIPT} -Wl,-Map=mh1903.map,--cref -lm -mcpu=${MCU} --specs=nano.specs -specs=nosys.specs -nostartfiles -Wl,--gc-sections -u _printf_float -u _scanf_float")
