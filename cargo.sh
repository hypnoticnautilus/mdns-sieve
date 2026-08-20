#!/usr/bin/env bash
# Wrapper to run cargo inside a docker container without installing Rust locally
set -e

# Default to standard rust image
IMAGE="rust:1.85-slim"

# If cross-compiling is requested, use the musl-cross image
if [[ "$*" == *"--target aarch64-unknown-linux-musl"* ]]; then
    IMAGE="messense/rust-musl-cross:aarch64-musl"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="aarch64-unknown-linux-musl-gcc"
    export CC_aarch64_unknown_linux_musl="aarch64-unknown-linux-musl-gcc"
fi

USER_ID=$(id -u)
GROUP_ID=$(id -g)

# Create a local cache directory so cargo doesn't redownload crates every run
mkdir -p .cargo_cache

# Run cargo inside docker, mounting the current directory and setting the user to match the host
docker run --rm \
    --user "$USER_ID:$GROUP_ID" \
    -v "$(pwd):/usr/src/myapp" \
    -w /usr/src/myapp \
    -e CARGO_HOME=/usr/src/myapp/.cargo_cache \
    -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER" \
    -e CC_aarch64_unknown_linux_musl="$CC_aarch64_unknown_linux_musl" \
    "$IMAGE" cargo "$@"
