#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OTA_FETCH_BIN="$SCRIPT_DIR/../build/ota-fetch"
CONFIG_PATH="$SCRIPT_DIR/etc/ota_fetch/ota_fetch.conf"
INBOX_PATH="test/var/lib/ota_fetch/inbox/manifest.json"
SERVER_ROOT="$SCRIPT_DIR/server"
PORT=8080

echo "Starting local HTTP test server on port $PORT"
cd "$SERVER_ROOT"
python3 -m http.server $PORT > /dev/null 2>&1 &
SERVER_PID=$!

# Give server time to start
sleep 1

echo "Cleaning inbox directory..."
rm -f "$INBOX_PATH"

echo "Running ota-fetch"
"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --oneshot

echo "Validating result..."
if [[ -f "$INBOX_PATH" ]]; then
    echo "Manifest downloaded successfully"
    jq . "$INBOX_PATH"
    STATUS=0
else
    echo "Manifest not found in inbox"
    STATUS=1
fi

echo "Stopping HTTP server (PID $SERVER_PID)"
if kill "$SERVER_PID" 2>/dev/null; then
    echo "Stopped HTTP server (PID $SERVER_PID)"
else
    echo "HTTP server already exited"
fi

exit $STATUS

