#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$(pwd)"
ARCH=""
KEY_FILE=""

usage() {
    echo "Usage: $0 [-a arch] [-o outdir] [-k privkey] <path-to-binary>"
    echo "Example: $0 -o ./build/apks -k .local/keys/packaging.rsa rs/target/aarch64-unknown-linux-musl/release/mdns-sieve"
    exit 1
}

# Parse options using getopts
while getopts "a:o:k:h" opt; do
    case "$opt" in
        a) ARCH="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        k) KEY_FILE="$OPTARG" ;;
        h)
            echo "Usage: $0 [-a arch] [-o outdir] [-k privkey] <path-to-binary>"
            exit 0
            ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

BINARY="$1"

if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at '${BINARY}'" >&2
    usage
fi

# Resolve absolute paths for mounting
mkdir -p "$OUTPUT_DIR"
ABS_OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
ABS_BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"

echo "Building APK for binary: $BINARY, Output: $ABS_OUTPUT_DIR)"

BUILD_ARGS=""
if [ -n "$ARCH" ]; then
    BUILD_ARGS="$BUILD_ARGS -a $ARCH"
fi
BUILD_ARGS="$BUILD_ARGS -o /output"

DOCKER_KEY_MOUNT=""
if [ -n "$KEY_FILE" ]; then
    if [ ! -f "$KEY_FILE" ]; then
        echo "Error: Key file not found at '${KEY_FILE}'" >&2
        exit 1
    fi
    ABS_KEY_FILE="$(cd "$(dirname "$KEY_FILE")" && pwd)/$(basename "$KEY_FILE")"
    DOCKER_KEY_MOUNT="-v $ABS_KEY_FILE:/tmp/packaging.rsa:ro"
    BUILD_ARGS="$BUILD_ARGS -k /tmp/packaging.rsa"
fi

docker run --rm \
    -v "$PROJECT_DIR:/project" \
    -v "$ABS_BINARY:/tmp/mdns-sieve-bin:ro" \
    $DOCKER_KEY_MOUNT \
    -v "$ABS_OUTPUT_DIR:/output" \
    -w /project \
    alpine:latest \
    /project/pkg/apk/build.sh $BUILD_ARGS /tmp/mdns-sieve-bin

echo "Done! Generated files in $OUTPUT_DIR:"
ls -lh "$ABS_OUTPUT_DIR/"
