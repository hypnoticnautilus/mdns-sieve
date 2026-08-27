#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$(pwd)"
ARCH=""

usage() {
    echo "Usage: $0 [-a arch] [-o outdir] <path-to-binary>"
    echo "Example: $0 -o ./build/apks rs/target/aarch64-unknown-linux-musl/release/mdns-sieve"
    exit 1
}

# Parse options using getopts
while getopts "a:o:h" opt; do
    case "$opt" in
        a) ARCH="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h)
            echo "Usage: $0 [-a arch] [-o outdir] <path-to-binary>"
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

docker run --rm \
    -v "$PROJECT_DIR:/project" \
    -v "$ABS_BINARY:/tmp/mdns-sieve-bin:ro" \
    -v "$ABS_OUTPUT_DIR:/output" \
    -w /project \
    alpine:latest \
    /project/pkg/apk/build.sh $BUILD_ARGS /tmp/mdns-sieve-bin

echo "Done! Generated files in $OUTPUT_DIR:"
ls -lh "$ABS_OUTPUT_DIR/"
