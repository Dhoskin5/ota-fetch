# Contributing

Thanks for your interest in improving ota-fetch.

## Build

Dependencies (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake \
  libcurl4-openssl-dev libssl-dev libcjson-dev
```

Build:

```bash
cmake -B build -S .
cmake --build build
```

## Tests

Integration tests use a local HTTPS server with mTLS.

Dependencies:

```bash
sudo apt-get install -y jq python3 python3-pip
python3 -m pip install cryptography
```

Run:

```bash
cd test/scripts
chmod +x *.sh
python3 gen_test_keys.py
./run-fetch-test.sh
```

## Style and expectations

- C99, keep changes minimal and focused.
- Prefer clear error handling and unambiguous logs.
- Maintain Doxygen comments for public headers and core modules.
- Use underscores in directory names; hyphens are reserved for executables.
