#!/bin/sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR=$(dirname "$SCRIPT_DIR")

HOST="$1"
HOST_PY="$2"
HOST_CONFIG="$3"

TD="$(mktemp -d)"
trap "rm -rf \"$TD\"" EXIT
python3 -m pip wheel --no-deps -w "$TD" "$PROJECT_DIR"/py
python3 -m pip wheel --no-deps -w "$TD" "$PROJECT_DIR"/py-gui
TD2="$(ssh "$HOST" mktemp -d)"
scp "$TD"/*.whl "$HOST:$TD2"

scp "$SCRIPT_DIR/config.yaml" "$HOST:$HOST_CONFIG"

ssh "$HOST" sh <<EOF
set -e
trap "rm -rf \"$TD2\"" EXIT
"$HOST_PY" -m pip uninstall -y mdns-sieve mdns-sieve-gui
"$HOST_PY" -m pip install -f "$TD2" mdns-sieve mdns-sieve-gui
pkill -fe mdns_sieve.main || true
pkill -fe mdns_sieve_gui.main || true
rc-service mdns-sieve restart
rc-service mdns-sieve-gui restart
EOF
