#!/bin/sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR=$(dirname "$SCRIPT_DIR")

HOST="${1:-pi3.home}"

set -x

echo "Building Rust binary for deployment..."
(cd "$PROJECT_DIR/rs" && ../cargo.sh build --release --target aarch64-unknown-linux-musl)

echo "Copying config..."
scp "$SCRIPT_DIR/config.yaml" "$HOST:/etc/mdns-sieve.yaml"

echo "Stopping service if running..."
ssh "$HOST" "rc-service mdns-sieve stop || true"

echo "Copying binary and setting up service..."
scp "$PROJECT_DIR/rs/target/aarch64-unknown-linux-musl/release/mdns-sieve" "$HOST:/usr/local/bin/mdns-sieve"
scp "$PROJECT_DIR/deploy/openrc/mdns-sieve" "$HOST:/tmp/mdns-sieve-openrc"

ssh "$HOST" << 'EOF'
  set -e
  if [ ! -f "/etc/init.d/mdns-sieve" ]; then
    echo "Installing OpenRC service..."
    mv /tmp/mdns-sieve-openrc /etc/init.d/mdns-sieve
    chmod +x /etc/init.d/mdns-sieve
    rc-update add mdns-sieve default
  else
    mv /tmp/mdns-sieve-openrc /etc/init.d/mdns-sieve
    chmod +x /etc/init.d/mdns-sieve
  fi
  rc-service mdns-sieve start
EOF

echo "Deployment complete!"
