# ota-fetch

[![CI](https://github.com/Dhoskin5/ota-fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/Dhoskin5/ota-fetch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

*A lightweight C tool to securely fetch and verify OTA updates on embedded Linux systems.*

## Introduction

**ota-fetch** is an over-the-air update fetching utility designed for embedded Linux devices. It provides a minimal, secure, and production-ready mechanism to download update payloads via HTTPS using mutual TLS (mTLS), verify their authenticity and integrity, and integrate with higher-level update frameworks like RAUC.

## Key Features

- Secure HTTPS and mutual TLS (mTLS) via libcurl
- Manifest validation using OpenSSL signature verification
- SHA-256 payload integrity checking
- One-shot and daemon modes for flexible update policies
- Embedded-friendly: small footprint, minimal dependencies
- Designed for integration with RAUC, meta-mu, and future update frameworks

## Getting Started

### Prerequisites

Install the required packages:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake \
  libcurl4-openssl-dev libssl-dev libcjson-dev \
  jq python3 python3-pip
```

### Build Instructions

```bash
git clone https://github.com/Dhoskin5/ota-fetch.git
cd ota-fetch
cmake -B build -S .
cmake --build build
```

### Configuration

`ota-fetch` uses a config file located by default at:

```
/etc/ota-fetch/ota-fetch.conf
```

Sample fields in the config file:

```ini
server_url = https://updates.example.com
ca_cert = /etc/ota-fetch/ca.pem
client_cert = /etc/ota-fetch/client.crt
client_key = /etc/ota-fetch/client.key
connect_timeout = 5
retry_attempts = 3
inbox_manifest_dir = /var/lib/ota_fetch/inbox
current_manifest_dir = /var/lib/ota_fetch/current
log_file = /var/log/ota-fetch.log
```

### Running ota-fetch

```bash
./ota-fetch --oneshot
./ota-fetch --daemon
./ota-fetch --config=/path/to/your.conf
```

## Testing

A full integration test is available using a local HTTPS server.

Run the test scripts:

```bash
cd test/scripts
chmod +x *.sh
python3 gen_test_keys.py
./run-fetch-test.sh
```

### CI/CD

GitHub Actions CI is defined in `.github/workflows/ota-fetch.yml` and includes:

- Dependency installation
- Build using CMake
- mTLS integration test with a local HTTPS server
- Automated key/cert generation
- Manifest signing and verification

## Project Structure

```
ota-fetch/
├── src/                # Main source files
├── include/            # (Optional) headers
├── test/               # Scripts, keys, test manifest
├── docs/               # Doxygen-generated documentation
├── CMakeLists.txt
└── README.md
```

### Documentation

Build with Doxygen:

```bash
doxygen Doxyfile
```

HTML output will be in the `docs/html/` directory.

## Contributing

This project is developed as part of a professional embedded portfolio to demonstrate best practices in secure update systems.

## License

This project is primarily licensed under the [MIT License](LICENSE),
with additional third-party components under their own terms.

### Third-Party Licenses

This project includes third-party software. See the [`licenses/`](licenses/) directory for details.

- [inih](https://github.com/benhoyt/inih) — BSD 3-Clause License

---

With a secure update mechanism like ota-fetch in place, your embedded devices can safely receive updates in the field, reducing the risk of unauthorized firmware and ensuring reliability. We hope this tool proves useful in your projects, happy updating!
