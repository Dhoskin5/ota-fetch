#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 KERNEL FORGE LLC

import http.server
import ssl
import sys
import os
from pathlib import Path

# Always resolve paths relative to the test root (parent of scripts/)
SCRIPT_DIR = Path(__file__).resolve().parent
TEST_ROOT = SCRIPT_DIR.parent

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443

SERVER_ROOT = TEST_ROOT / "server"
CA_CERT = TEST_ROOT / "private/rootCA.crt"
SERVER_CERT = TEST_ROOT / "server/server.crt"
SERVER_KEY = TEST_ROOT / "server/server.key"

def env_truthy(name):
    value = os.getenv(name, "")
    return value.lower() in ("1", "true", "yes", "on")

ENABLE_HTTP_LOG = env_truthy("OTA_FETCH_HTTP_LOG")


class TestHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        if not ENABLE_HTTP_LOG:
            return
        super().log_message(format, *args)

httpd = http.server.HTTPServer(('127.0.0.1', PORT), TestHTTPRequestHandler)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(cafile=str(CA_CERT))
context.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

os.chdir(str(SERVER_ROOT))

print("Serving from directory:", SERVER_ROOT)
print("CA_CERT:", CA_CERT)
print("SERVER_CERT:", SERVER_CERT)
print("SERVER_KEY:", SERVER_KEY)

print(f"HTTPS server with mTLS running on https://127.0.0.1:{PORT}/ serving directory: {SERVER_ROOT}")
httpd.serve_forever()
