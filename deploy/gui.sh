#!/bin/sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR=$(dirname "$SCRIPT_DIR")

HOST="$1"
HOST_PY="$2"
HOST_CONFIG="$3"

TD="$(mktemp -d)"
trap "rm -rf \"$TD\"" EXIT
python3 -m pip wheel --no-deps -w "$TD" "$PROJECT_DIR"/py-gui

TD2="$(ssh "$HOST" mktemp -d)"
scp "$TD"/*.whl "$HOST:$TD2"

ssh "$HOST" sh <<EOF
set -e
trap "rm -rf \"$TD\"" EXIT
"$HOST_PY" -m pip uninstall -y mdns-sieve-gui
"$HOST_PY" -m pip install -f "$TD2" mdns-sieve-gui
pkill -fe mdns_sieve_gui.main || true
nohup "$HOST_PY" -m mdns_sieve_gui.main -c "$HOST_CONFIG" > /var/log/mdns-sieve-gui.log 2>&1 < /dev/null &
EOF
