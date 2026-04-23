FROM ubuntu:22.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /forgebox-helloworld

RUN apt-get update \
    && apt-get install -y --no-install-recommends -o Acquire::Retries=5 \
        binutils-arm-none-eabi \
        ca-certificates \
        cmake \
        gcc-arm-none-eabi \
        libnewlib-arm-none-eabi \
        libstdc++-arm-none-eabi-newlib \
        make \
        python-is-python3 \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt

RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python3 build.py

FROM scratch AS artifacts

COPY --from=builder /forgebox-helloworld/build/mh1903.bin /build/mh1903.bin
COPY --from=builder /forgebox-helloworld/build/mh1903.hex /build/mh1903.hex
COPY --from=builder /forgebox-helloworld/build/mh1903.elf /build/mh1903.elf
COPY --from=builder /forgebox-helloworld/build/mh1903_full.bin /build/mh1903_full.bin
