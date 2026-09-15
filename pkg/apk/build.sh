#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$(pwd)"
ARCH=""
KEY_FILE=""

usage() {
    echo "Usage: $0 [-a arch] [-o outdir] [-k privkey] <path-to-binary>"
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

# Install required build tools (including file for arch detection)
apk add --no-cache alpine-sdk doas file

# Detect architecture from binary if not provided via -a
if [ -z "$ARCH" ]; then
    INFO=$(file -b "$BINARY" 2>/dev/null || true)
    case "$INFO" in
        *aarch64*|*AArch64*|*ARM\ aarch64*)
            ARCH="aarch64" ;;
        *x86-64*|*x86_64*)
            ARCH="x86_64" ;;
        *ARM*|*arm*)
            ARCH="armv7" ;;
        *80386*|*i386*|*i686*)
            ARCH="x86" ;;
        *RISC-V*|*riscv64*)
            ARCH="riscv64" ;;
        *)
            echo "Error: Could not auto-detect architecture from binary info: '$INFO'"
            exit 1
    esac
fi

echo "Packaging for Alpine architecture: $ARCH"
echo "Output directory: $OUTPUT_DIR"

# Copy binary into $startdir (SCRIPT_DIR)
cp "$BINARY" "$SCRIPT_DIR/mdns-sieve"
chmod 755 "$SCRIPT_DIR/mdns-sieve"

# Configure builder user
adduser -D -G abuild builder || true
mkdir -p /etc/doas.d
echo 'permit nopass :abuild' > /etc/doas.d/abuild.conf

# Setup abuild key
if [ -n "$KEY_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "Using provided RSA signing key: $KEY_FILE"
    mkdir -p /home/builder/.abuild
    KEY_NAME="mdns-sieve-packaging"
    cp "$KEY_FILE" "/home/builder/.abuild/${KEY_NAME}.rsa"
    chmod 600 "/home/builder/.abuild/${KEY_NAME}.rsa"
    openssl rsa -in "/home/builder/.abuild/${KEY_NAME}.rsa" -pubout -out "/home/builder/.abuild/${KEY_NAME}.rsa.pub"
    mkdir -p /etc/apk/keys
    cp "/home/builder/.abuild/${KEY_NAME}.rsa.pub" /etc/apk/keys/
    echo "PACKAGER_PRIVKEY=\"/home/builder/.abuild/${KEY_NAME}.rsa\"" > /home/builder/.abuild/abuild.conf
    chown -R builder:abuild /home/builder/.abuild
else
    echo "Generating ephemeral RSA signing key..."
    su builder -c 'abuild-keygen -a -i -n'
fi

# Fix permissions on package workspace for builder user
chown -R builder:abuild "$SCRIPT_DIR"

# Build packages as builder user for target architecture
cd "$SCRIPT_DIR"
su builder -c "CARCH=$ARCH abuild -r -f"

# Copy generated APKs, index, and public keys to output directory
mkdir -p "$OUTPUT_DIR"
find /home/builder/packages -type f -name "*.apk" -exec cp {} "$OUTPUT_DIR/" \;
find /home/builder/packages -type f -name "APKINDEX.tar.gz" -exec cp {} "$OUTPUT_DIR/" \;

# Prevent accumulation of old keys by deleting previous ones
rm -f "$OUTPUT_DIR"/*.rsa.pub
cp /home/builder/.abuild/*.rsa.pub "$OUTPUT_DIR/" 2>/dev/null || true

# Clean up copied build binary from source dir
rm -f "$SCRIPT_DIR/mdns-sieve"

echo "APKs and signing key successfully created in $OUTPUT_DIR"
