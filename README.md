<h1 align="center"> Project PQXDH </h1>

## Overview

**Post-Quantum Extended Diffie–Hellman (PQXDH)** is a cryptographic protocol
designed to resist “harvest now, decrypt later” attacks. It extends the ideas of
X3DH with a post-quantum key encapsulation mechanism while retaining classical
elliptic-curve authentication.

The protocol is described in the
[Signal PQXDH specification](https://signal.org/docs/specifications/pqxdh/).
It targets asynchronous messaging: Bob can publish prekeys while offline, and
Alice can use a server-provided prekey bundle to establish a shared secret and
send an encrypted initial message.

This project provides an experimental C library implementing the current
published PQXDH specification (revision 3) with this concrete parameter set:

- **ML-KEM-1024** through liboqs for the post-quantum contribution;
- **XEd25519** through libxeddsa and **X25519** through libsodium;
- **HKDF-SHA-256** through OpenSSL for session-key derivation;
- **AES-256-GCM** for authenticated encryption.

> [!WARNING]
> This implementation has not received an independent security audit and is not
> an implementation of the Signal Messenger wire protocol. PQXDH specifies a
> handshake, not Signal's surrounding message format or server API. This code is
> intended for education, experimentation, protocol review, and integration
> testing—not production secrets. The precise parameter profile is documented in
> [docs/PROTOCOL.md](docs/PROTOCOL.md).

### Why PQXDH?

PQXDH strengthens the initial asynchronous handshake against passive quantum
adversaries. A recorded exchange cannot be decrypted later solely by breaking
the classical elliptic-curve component: the attacker must also defeat the
post-quantum KEM contribution.

Authentication in revision 3 remains classical. Applications must authenticate
identity-key fingerprints through a trusted channel and should transition from
the initial session key to a suitable post-PQXDH ratcheting protocol.

## Key Features

- Hybrid X25519 and ML-KEM-1024 session-key agreement.
- Signed Bob prekey bundles with optional one-time X25519 prekeys.
- One-time or last-resort ML-KEM prekey state.
- AES-256-GCM encryption of the initial payload.
- Deterministic, bounded network encoding and decoding.
- Message identifiers and an in-memory replay tracker.
- Explicit secret-cleanup helpers.
- Static or shared library builds.
- CMake package and pkg-config metadata for downstream projects.
- Tests, sanitizers, fuzzing, Linux containers, and Windows CI.

---

## How It Works

1. **Key generation and publication**
   - Bob generates identity material, a signed X25519 prekey, an optional
     one-time X25519 prekey, and an ML-KEM-1024 prekey.
   - Bob signs the published signed-prekey and KEM material.

2. **Initial key exchange**
   - Alice verifies Bob's bundle.
   - Alice performs three X25519 exchanges, plus a fourth when an X25519
     one-time prekey is available.
   - Alice encapsulates an ML-KEM shared secret.
   - All classical and post-quantum secrets are combined with HKDF-SHA-256.

3. **Initial encryption**
   - Alice encrypts the initial payload with AES-256-GCM.
   - Bob derives the same key, authenticates and decrypts the payload, records
     the message identifier, and erases consumed one-time private keys.

---

## Project Structure

```plaintext
PQXDH
├── .github/workflows/     # Linux and Windows continuous integration
├── cmake/                 # Installed CMake package configuration
├── docs/                  # Protocol profile and conformance notes
├── fuzz/                  # libFuzzer targets
├── liboqs/                # Pinned liboqs Git submodule
├── libxeddsa/             # Pinned XEd25519 Git submodule
├── CMakeLists.txt         # Primary library build and installation
├── Makefile               # Lightweight Unix build
├── alpine.dockerfile      # Alpine build/test image
├── debian.dockerfile      # Debian build/test image
├── pqxdh.c                # Protocol implementation
├── pqxdh.h                # Public C API
├── run-alpine.sh          # Alpine dependency/build helper
├── run-debian.sh          # Debian dependency/build helper
├── run-windows.ps1        # Windows MSVC/vcpkg build helper
├── SECURITY.md            # Security policy
├── test_pqxdh.c           # Unit and integration tests
└── vcpkg.json             # Windows dependency manifest
```

## Prerequisites

- A C11 compiler;
- CMake 3.20 or newer, or GNU Make on Unix;
- OpenSSL 3.0 or newer;
- libsodium;
- liboqs with ML-KEM-1024 enabled.
- libxeddsa (included as a pinned submodule).

Initialize the pinned dependency before building:

```sh
git submodule update --init --recursive
```

## Building on Debian or Ubuntu

The helper installs system dependencies and installs a minimal liboqs build
under `/usr/local`, so it requires `sudo`:

```sh
chmod +x run-debian.sh
./run-debian.sh
```

## Building on Alpine Linux

```sh
chmod +x run-alpine.sh
./run-alpine.sh
```

## Building on Windows

Install Visual Studio 2022 with the **Desktop development with C++** workload,
CMake, PowerShell 7, and [vcpkg](https://github.com/microsoft/vcpkg). Then:

```powershell
$env:VCPKG_ROOT = "C:\src\vcpkg"
.\run-windows.ps1 -Configuration Release -Triplet x64-windows
```

The script initializes libxeddsa, restores OpenSSL, libsodium, and liboqs from
`vcpkg.json`, builds the library with MSVC, and runs CTest. ARM64 is also supported when its Visual Studio
toolchain is installed:

```powershell
.\run-windows.ps1 -Configuration Release -Triplet arm64-windows
```

To install the resulting library:

```powershell
.\run-windows.ps1 -Configuration Release `
  -InstallPrefix "C:\Program Files\PQXDH" -Install
```

The native Windows liboqs vcpkg port uses dynamic linkage. Applications must
ship its runtime DLLs and the other vcpkg runtime dependencies.

## Manual CMake Build

When dependencies are already installed:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The Make build remains available on Unix-like systems:

```sh
make test
```

## Running in Docker

Initialize the Git submodule, then build and run either image:

```sh
docker build -f debian.dockerfile -t pqxdh-debian .
docker run --rm pqxdh-debian

docker build -f alpine.dockerfile -t pqxdh-alpine .
docker run --rm pqxdh-alpine
```

The current suite contains eight tests covering initialization, bundle
authentication, end-to-end agreement, network encoding, replay rejection,
AES-GCM integrity, one-time-key consumption, and operation without an X25519
one-time prekey.

## Validation Results

The following checks were executed successfully on the current source tree:

| Environment or check | Result |
| --- | --- |
| GNU Make build and test suite | **8/8 passed** |
| CMake and CTest release build | **8/8 passed** |
| AddressSanitizer and UndefinedBehaviorSanitizer | **8/8 passed** |
| Debian Bookworm Docker image | **Build passed, 8/8 tests passed** |
| Alpine 3.22 Docker image | **Build passed, 8/8 tests passed** |
| Static library installation | **Passed** |
| Shared library installation and SONAME | **Passed** |
| External CMake consumer using `PQXDH::pqxdh` | **Passed** |
| pkg-config consumer metadata | **Passed** |
| Clang/libFuzzer target | **Built; 1,000-run smoke test passed** |
| Windows MSVC and vcpkg | **Configured in CI; pending first pushed run** |

The Windows result is deliberately marked as pending: native MSVC execution
requires a Windows runner. The workflow in `.github/workflows/ci.yml` will build
and run the same test suite on `windows-2025` whenever the changes are pushed or
a pull request is opened.

## Using PQXDH as a Library

Install it to a chosen prefix:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/desired/prefix
cmake --build build --parallel
cmake --install build
```

Consume it from CMake:

```cmake
find_package(pqxdh 0.3 CONFIG REQUIRED)
target_link_libraries(my_application PRIVATE PQXDH::pqxdh)
```

Or with pkg-config on supported Unix systems:

```sh
cc application.c $(pkg-config --cflags --libs pqxdh)
```

The main entry points are:

- `pqxdh_generate_alice_keys`;
- `pqxdh_generate_pre_key_bundle`;
- `pqxdh_alice_create_initial_message`;
- `pqxdh_bob_process_initial_message`;
- `pqxdh_encode_initial_message`;
- `pqxdh_decode_initial_message`.

Call the matching `pqxdh_clear_*` helpers when sensitive objects are no longer
needed. Applications must serialize access to Bob's private bundle and persist
one-time-key consumption transactionally.

## Fuzzing

```sh
CC=clang cmake -S . -B build-fuzz \
  -DPQXDH_BUILD_TESTS=OFF -DPQXDH_BUILD_FUZZERS=ON
cmake --build build-fuzz --parallel
./build-fuzz/fuzz_decode_initial_message corpus/
```

## Contributing

Contributions are welcome. Changes to cryptographic behavior should include
tests, precise protocol documentation, and clear compatibility implications.

Security problems should be reported privately as described in
[SECURITY.md](SECURITY.md).

## License

This project is licensed under the [MIT License](LICENSE).
