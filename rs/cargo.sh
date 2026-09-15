#!/usr/bin/env bash
# Wrapper to run cargo inside a docker container without installing Rust locally
set -e

IMAGE="rust:1.85-slim"
DOCKER_ENV=()

# Extract target triple if provided (--target <triple> or --target=<triple>)
TARGET=""
prev_arg=""
for arg in "$@"; do
    if [[ "$prev_arg" == "--target" ]]; then
        TARGET="$arg"
    elif [[ "$arg" == --target=* ]]; then
        TARGET="${arg#--target=}"
    fi
    prev_arg="$arg"
done

# If cross-compiling for musl, dynamically resolve image and environment variables
if [[ "$TARGET" =~ .*linux-musl.* ]]; then
    # Map target triple to messense/rust-musl-cross tag (e.g., aarch64-unknown-linux-musl -> aarch64-musl)
    MUSL_ARCH=$(echo "$TARGET" | sed -E 's/-unknown-linux-/-/')
    IMAGE="messense/rust-musl-cross:${MUSL_ARCH}"

    TARGET_UPPER=$(echo "$TARGET" | tr '[:lower:]' '[:upper:]' | tr '-' '_')
    TARGET_LOWER=$(echo "$TARGET" | tr '-' '_')

    DOCKER_ENV+=(-e "CARGO_TARGET_${TARGET_UPPER}_LINKER=${TARGET}-gcc")
    DOCKER_ENV+=(-e "CC_${TARGET_LOWER}=${TARGET}-gcc")
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
    "${DOCKER_ENV[@]}" \
    "$IMAGE" cargo "$@"
