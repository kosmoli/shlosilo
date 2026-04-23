# ForgeBox Hello World

## Overview

This repository contains a minimal Hello World firmware example for ForgeBox. It is a small starting point for building and running your first firmware image on the device.

## Getting Started

### Local Build Requirements

- ARM GCC Toolchain (arm-none-eabi-gcc)
- CMake 3.10 or later
- Rust toolchain
- `bindgen-cli`
- `cbindgen`

On macOS:

#### macOS

```bash
brew install armmbed/formulae/arm-none-eabi-gcc
rustup install nightly-2025-05-01
rustup target add thumbv7em-none-eabihf
cargo install bindgen-cli
cargo install cbindgen
```

### Build Locally

```bash
python3 build.py -e production
```

### Build With Docker

If you prefer not to install the toolchain locally:

```bash
docker build --target builder -t forgebox-helloworld-builder .
```

To copy the generated files out of the image:

```bash
container_id=$(docker create forgebox-helloworld-builder)
docker cp "$container_id":/forgebox-helloworld/build ./build
docker rm "$container_id"
```

### Output Files

After a successful build, you should see:

- `mh1903.elf`
- `mh1903.bin`
- `mh1903.hex`
- `mh1903_full.bin`

### Flashing

Use `forgebox-cli` to sign the `mh1903_full.bin` firmware image, then copy the signed package to an SD card and load it onto your ForgeBox.


## License

See `LICENSE.md` for details.

## Contact

For support or inquiries, please contact us at eng@keyst.one
