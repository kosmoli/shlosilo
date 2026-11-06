# Cross toolchain (pinned)

The forgebox appearance is a C host for the Rust core, so it is built with an
`arm-none-eabi` GCC. **Which** one matters, and it must be the same one
everywhere.

## Why it is pinned

`apt install gcc-arm-none-eabi` installs whatever the distribution ships at that
moment. That has two problems:

1. **It is unpinned.** A runner-image or distro update changes the compiler that
   builds the firmware without anybody deciding to change it. Local and CI can
   silently drift apart.
2. **Same version, different binary.** Measured on this tree, building the same
   commit with `arm-none-eabi-gcc 14.2.1`:

   | source | image | sha256 |
   |---|---|---|
   | Ubuntu (apt) | 976,428 B | `d2306a70…` |
   | xPack release | 972,058 B | `545c3677…` |

   The ~4.4 kB difference comes from how each distribution configures
   newlib/multilib. A CI gate that compiles with a different toolchain than the
   one producing shipped images can hide (or invent) breakage on either side.

So both CI and local builds use the same pinned upstream release.

## Pinned release

| field | value |
|---|---|
| project | https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack |
| version | `v14.2.1-1.1` |
| asset | `xpack-arm-none-eabi-gcc-14.2.1-1.1-linux-x64.tar.gz` |
| tarball sha256 | `ed8c7d207a85d00da22b90cf80ab3b0b2c7600509afadf6b7149644e9d4790a6` |
| `arm-none-eabi-gcc --version` first line | `arm-none-eabi-gcc (xPack GNU Arm Embedded GCC x86_64) 14.2.1 20241119` |

The tarball ships a `.sha` file next to it; verify before unpacking.

## Install (local)

```sh
mkdir -p ~/.local/toolchains
cd ~/.local/toolchains
base=https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack/releases/download/v14.2.1-1.1
curl -fL -o armtc.tar.gz       "$base/xpack-arm-none-eabi-gcc-14.2.1-1.1-linux-x64.tar.gz"
curl -fL -o armtc.tar.gz.sha   "$base/xpack-arm-none-eabi-gcc-14.2.1-1.1-linux-x64.tar.gz.sha"
echo "$(awk '{print $1}' armtc.tar.gz.sha)  armtc.tar.gz" | sha256sum -c -
mkdir -p gnu-arm && tar -xzf armtc.tar.gz -C gnu-arm --strip-components=1
rm -f armtc.tar.gz armtc.tar.gz.sha
~/.local/toolchains/gnu-arm/bin/arm-none-eabi-gcc --version | head -1
```

`flux/forgebox/build.sh` picks that path up automatically and prints which
toolchain it used. Override the location with `SHLOSILO_ARM_TOOLCHAIN=/path`, and
set `SHLOSILO_ARM_TOOLCHAIN_STRICT=1` to turn "wrong or missing pinned toolchain"
into a hard error (CI does this).

Nothing else needs the cross toolchain: `cargo` builds the Rust core and the
pico2 image with their own targets.

## What this does not change

Images built before the switch keep their hashes; the pin only fixes what future
builds use. The firmware identity string (`v0.5.0-poc4+<git7>`) still comes from
git, so the sha of a given commit can change **once** when the toolchain changes
— that is expected, and the identity line, not the sha, is the anchor for "which
build is on the device".
