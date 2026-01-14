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
SIGNER_KEY_TYPE="${SIGNER_KEY_TYPE:-}"
PAYLOAD_DEFAULT="$SERVER_ROOT/default/h4-bundle.raucb"
PAYLOAD_GW="$SERVER_ROOT/h4-gw/h4-gw-bundle.raucb"
PAYLOAD_VISION="$SERVER_ROOT/h4-vision/h4-vision-bundle.raucb"
DAEMON_PID=""
DAEMON_LOG="$TEST_DIR/var/log/ota_fetch_daemon.log"

if [[ -n "$SIGNER_KEY_TYPE" ]]; then
    echo "Regenerating test keys with signer type: $SIGNER_KEY_TYPE"
    python3 "$SCRIPTS_DIR/gen_test_keys.py" --signer-type "$SIGNER_KEY_TYPE"
fi

prepare_payloads() {
    mkdir -p "$(dirname "$PAYLOAD_DEFAULT")" "$(dirname "$PAYLOAD_GW")" "$(dirname "$PAYLOAD_VISION")"

    if [[ ! -f "$PAYLOAD_DEFAULT" ]]; then
        printf "ota-fetch test bundle\n" > "$PAYLOAD_DEFAULT"
    fi
    if [[ ! -f "$PAYLOAD_GW" ]]; then
        cp "$PAYLOAD_DEFAULT" "$PAYLOAD_GW"
    fi
    if [[ ! -f "$PAYLOAD_VISION" ]]; then
        cp "$PAYLOAD_DEFAULT" "$PAYLOAD_VISION"
    fi
}

payload_hash() {
    sha256sum "$1" | awk '{print $1}'
}

payload_size() {
    stat -c %s "$1"
}

# Utility: hash file or print error
hash_file() {
    if [[ -f "$1" ]]; then
        sha256sum "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

wait_for_manifest_hash() {
    local expected_hash="$1"
    local timeout_sec="$2"
    local elapsed=0
    while (( elapsed < timeout_sec )); do
        if [[ "$(hash_file "$CURRENT_MANIFEST")" == "$expected_hash" ]]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

set_manifest_version() {
    local version="$1"
    local manifest="$2"
    local hash
    local size
    hash=$(payload_hash "$PAYLOAD_DEFAULT")
    size=$(payload_size "$PAYLOAD_DEFAULT")
    jq --arg ver "$version" --arg hash "$hash" --argjson size "$size" \
        '.manifest_version = $ver
         | .releases[].files[].sha256 = $hash
         | .releases[].files[].size = $size' \
        "$BASE_MANIFEST" > "$manifest"
    cd "$SCRIPTS_DIR"
    python3 sign_manifest.py
    cd "$TEST_DIR"
}

cleanup() {
    if [[ -n "$DAEMON_PID" ]]; then
        echo "Stopping ota-fetch daemon (PID $DAEMON_PID)"
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    echo "Stopping HTTPS server (PID $SERVER_PID)"
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "Starting local HTTPS (mTLS) test server on port $PORT"
prepare_payloads
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

echo "===== DAEMON MODE TEST (UPDATE INTERVAL) ====="
PAYLOAD_NAME=$(jq -r '.releases[] | select(.device_id=="default") | .files[0].filename' "$BASE_MANIFEST")
if [[ -z "$PAYLOAD_NAME" || "$PAYLOAD_NAME" == "null" ]]; then
    echo "[FAIL] Could not determine default payload filename."
    exit 1
fi
INBOX_PAYLOAD="$INBOX_DIR/$PAYLOAD_NAME"
rm -f "$INBOX_PAYLOAD"

mkdir -p "$(dirname "$DAEMON_LOG")"
"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --daemon >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

sleep 2

SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")
CUR_HASH=$(hash_file "$CURRENT_MANIFEST")
if [[ "$SERVER_HASH" == "$CUR_HASH" ]]; then
    echo "[OK] Daemon idle while up to date."
else
    echo "[FAIL] Daemon changed manifest while up to date."
    exit 1
fi
if [[ -e "$INBOX_PAYLOAD" ]]; then
    echo "[FAIL] Daemon downloaded payload while up to date."
    exit 1
fi
echo "[OK] Daemon did not download payload while up to date."

set_manifest_version "10.10.10-test" "$SERVER_ROOT/manifest.json"
SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")

if wait_for_manifest_hash "$SERVER_HASH" 10; then
    echo "[OK] Daemon applied new manifest within interval."
else
    echo "[FAIL] Daemon did not apply new manifest in time."
    exit 1
fi
if [[ -f "$INBOX_PAYLOAD" ]]; then
    echo "[OK] Daemon downloaded payload for update."
else
    echo "[FAIL] Daemon did not download payload for update."
    exit 1
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

echo "===== ALL TESTS PASSED ====="
exit 0
