#!/bin/bash
set -euo pipefail

# --- Always run from test/ root for path consistency ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$TEST_DIR"

SCRIPTS_DIR="$TEST_DIR/scripts"
OTA_FETCH_BIN="$TEST_DIR/../build/ota-fetch"
CONFIG_PATH="$TEST_DIR/etc/ota_fetch/ota_fetch.conf"
INBOX_DIR="$TEST_DIR/var/lib/ota_fetch/inbox"
CURRENT_DIR="$TEST_DIR/var/lib/ota_fetch/current"
INBOX_MANIFEST="$INBOX_DIR/manifest.json"
CURRENT_MANIFEST="$CURRENT_DIR/manifest.json"
SERVER_ROOT="$TEST_DIR/server"
BASE_MANIFEST="$SERVER_ROOT/manifest_base.json"
PORT=8443

# Utility: hash file or print error
hash_file() {
    if [[ -f "$1" ]]; then
        sha256sum "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

set_manifest_version() {
    local version="$1"
    local manifest="$2"
    jq --arg ver "$version" '.manifest_version = $ver' "$BASE_MANIFEST" > "$manifest"
    cd "$SCRIPTS_DIR"
    python3 sign_manifest.py
    cd "$TEST_DIR"
}

cleanup() {
    echo "Stopping HTTPS server (PID $SERVER_PID)"
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "Starting local HTTPS (mTLS) test server on port $PORT"
python3 "$SCRIPTS_DIR/https_server.py" "$PORT" &
SERVER_PID=$!


set_manifest_version "8.8.8-test" "$SERVER_ROOT/manifest.json"

echo "Cleaning current and inbox directories..."
rm -f "$INBOX_DIR"/*.json "$CURRENT_DIR"/*.json

echo "===== FIRST ota-fetch RUN (should apply update) ====="
"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --oneshot

# Confirm manifest from server is applied and moved to current
SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")
CUR_HASH=$(hash_file "$CURRENT_MANIFEST")
if [[ "$SERVER_HASH" == "$CUR_HASH" ]]; then
    echo "[OK] Manifest unchanged after first run."
else
    echo "[FAIL] Manifest hash changed unexpectedly after first run."
    exit 1
fi

echo "===== SECOND ota-fetch RUN (should do nothing) ====="
"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --oneshot

# Confirm manifest from server remains in current
SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")
CUR_HASH=$(hash_file "$CURRENT_MANIFEST")
if [[ "$SERVER_HASH" == "$CUR_HASH" ]]; then
    echo "[OK] Manifest unchanged after second run."
else
    echo "[FAIL] Manifest hash changed unexpectedly after second run."
    exit 1
fi

echo "===== MODIFY MANIFEST TO SIMULATE NEW UPDATE ====="
# Make a copy, bump version, sign it
set_manifest_version "9.9.9-test" "$SERVER_ROOT/manifest.json"

"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --oneshot

# Confirm manifest from server is applied and moved to current
SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")
CUR_HASH=$(hash_file "$CURRENT_MANIFEST")
if [[ "$SERVER_HASH" == "$CUR_HASH" ]]; then
    echo "[OK] New manifest applied and matches server version."
else
    echo "[FAIL] Manifest hash changed unexpectedly after third run."
    exit 1
fi

echo "===== ALL TESTS PASSED ====="
exit 0
