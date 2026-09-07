<h1 align="center"> Project PQXDH </h1>

## Overview

**Post-Quantum Extended Diffie–Hellman (PQXDH)** is an asynchronous key-agreement
protocol designed to resist “harvest now, decrypt later” attacks. It extends
X3DH with a post-quantum key encapsulation mechanism while retaining classical
elliptic-curve authentication.

The protocol is defined by Signal in the
[PQXDH specification](https://signal.org/docs/specifications/pqxdh/). PQXDH lets
Alice establish a shared secret and send encrypted initial data while Bob is
offline, using a prekey bundle previously published by Bob.

This project is a C reimplementation of the currently published **PQXDH
revision 3** protocol with the following concrete profile:

- **ML-KEM-1024** through liboqs for the post-quantum contribution;
- **X25519** through libsodium for classical Diffie–Hellman;
- **XEd25519** through libxeddsa for identity signatures;
- **HKDF-SHA-256** through OpenSSL for session-key derivation;
- **AES-256-GCM** for authenticated encryption of the initial payload.

I've tried to stay as close as possible to the specification while keeping the
implementation understandable, testable, and reusable as a C library. The
chosen encodings and other profile details are documented in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

> [!WARNING]
> This is experimental cryptographic software. It has not received an
> independent security audit and must not protect production secrets. It
> implements the PQXDH handshake, not Signal Messenger's complete wire protocol,
> server, Double Ratchet, or application.

### Why PQXDH?

Classical public-key cryptography is vulnerable to sufficiently powerful
quantum computers. An adversary can already record encrypted traffic and hope
to decrypt it later. PQXDH mixes a classical X25519 contribution with an
ML-KEM contribution so that breaking X25519 in the future is not sufficient to
recover the initial session key.

PQXDH revision 3 still uses classical authentication. Users must authenticate
identity-key fingerprints through a trusted channel, and an active quantum
attacker is outside the authentication guarantee of this revision.

## Key Features

- Hybrid X25519 and ML-KEM-1024 session establishment.
- Curve25519 identity keys and randomized XEd25519 signatures.
- Signed classical and post-quantum prekeys.
- Optional one-time X25519 prekeys.
- One-time or last-resort ML-KEM prekey state.
- AES-256-GCM authenticated encryption.
- Bounded, deterministic initial-message encoding.
- Message identifiers and replay rejection.
- Explicit helpers for erasing sensitive state.
- Static and shared C library builds.
- CMake package and pkg-config integration.
- Unit tests, sanitizers, fuzzing, Docker builds, and CI.

---

## How It Works

1. **Key generation and publication**
   - Bob generates a Curve25519 identity key, a signed X25519 prekey, an
     optional one-time X25519 prekey, and an ML-KEM-1024 prekey.
   - Bob signs `EncodeEC(SPK_B)` and `EncodeKEM(PQPK_B)` with XEd25519.

2. **Key exchange**
   - Alice verifies Bob's signatures.
   - Alice creates an ephemeral X25519 key and computes DH1, DH2, and DH3.
   - DH4 is added when a one-time curve prekey is available.
   - Alice encapsulates a post-quantum shared secret with ML-KEM-1024.

3. **Key derivation**
   - The X25519 outputs and ML-KEM shared secret are concatenated in the order
     required by PQXDH revision 3.
   - HKDF-SHA-256 derives a 32-byte session key using a zero salt and the
     profile-specific `info` string.

4. **Initial encryption**
   - Alice encrypts the initial payload with AES-256-GCM.
   - The encoded Alice and Bob identity keys are authenticated as associated
     data.
   - Bob repeats the derivation, authenticates the payload, rejects replays,
     and erases consumed one-time private keys.

PQXDH establishes the initial secret only. A complete messenger should feed
that secret into a post-PQXDH ratcheting protocol and use a distinct key for
each later message.

---

## Project Structure

```plaintext
PQXDH
├── .github/workflows/     # Linux and Windows continuous integration
├── cmake/                 # Installed CMake package configuration
├── docs/                  # Protocol profile and conformance notes
├── fuzz/                  # libFuzzer target
├── liboqs/                # Pinned ML-KEM implementation (Git submodule)
├── libxeddsa/             # Pinned XEd25519 implementation (Git submodule)
├── CMakeLists.txt         # Main build, test, and installation definition
├── Makefile               # Lightweight Unix build
├── alpine.dockerfile      # Alpine build and test image
├── debian.dockerfile      # Debian build and test image
├── pqxdh.c                # Protocol implementation
├── pqxdh.h                # Public C API
├── run-alpine.sh          # Alpine setup helper
├── run-debian.sh          # Debian/Ubuntu setup helper
├── run-windows.ps1        # Windows MSVC/vcpkg helper
├── SECURITY.md            # Security policy and limitations
├── test_pqxdh.c           # Unit and integration tests
└── vcpkg.json             # Windows dependency manifest
```

## Prerequisites

- Git with submodule support;
- a C11 compiler;
- CMake 3.20 or newer, or GNU Make on Unix;
- OpenSSL 3.0 or newer;
- libsodium;
- liboqs built with ML-KEM-1024 enabled;
- libxeddsa, included as a pinned submodule.

Clone or initialize the repository recursively:

```sh
git clone --recursive https://github.com/Aur3ns/PQXDH.git
cd PQXDH
```

For an existing checkout:

```sh
git submodule update --init --recursive
```

## Building on Debian or Ubuntu

The helper installs the required system packages, builds the pinned minimal
liboqs configuration, builds PQXDH, and runs the tests:

```sh
chmod +x run-debian.sh
./run-debian.sh
```

## Building on Alpine Linux

```sh
chmod +x run-alpine.sh
./run-alpine.sh
```

## Manual CMake Build

When the dependencies are already installed:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Build a shared library with:

```sh
cmake -S . -B build-shared \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON
cmake --build build-shared --parallel
```

The Make build remains available on Unix-like systems:

```sh
make test
```

## Running in Docker

```sh
docker build -f debian.dockerfile -t pqxdh-debian .
docker run --rm pqxdh-debian

docker build -f alpine.dockerfile -t pqxdh-alpine .
docker run --rm pqxdh-alpine
```

## Building on Windows

Install Visual Studio with the **Desktop development with C++** workload,
CMake, Git, PowerShell, and [vcpkg](https://github.com/microsoft/vcpkg). Then:

```powershell
$env:VCPKG_ROOT = "C:\src\vcpkg"
.\run-windows.ps1 -Configuration Release -Triplet x64-windows
```

An ARM64 triplet is also accepted when the matching Visual Studio toolchain is
installed:

```powershell
.\run-windows.ps1 -Configuration Release -Triplet arm64-windows
```

> [!NOTE]
> The Windows workflow currently reaches the MSVC link stage but still fails to
> link the embedded libxeddsa objects. Linux, Debian Docker, and Alpine Docker
> builds pass. Windows support therefore remains work in progress rather than a
> validated platform.

## Expected Test Output

```plaintext
[1/8] Initialization and key uniqueness...
    PASS
[2/8] Bundle verification and tampering...
    PASS
[3/8] End-to-end Alice/Bob key agreement...
    PASS
[4/8] Network encoding and decoding...
    PASS
[5/8] Replay rejection...
    PASS
[6/8] AES-256-GCM integrity...
    PASS
[7/8] One-time key consumption...
    PASS
[8/8] Exchange without a curve one-time prekey...
    PASS

Result: 8/8 tests passed.
```

## Validation Status

| Environment or check | Current result |
| --- | --- |
| GNU Make | 8/8 tests passed |
| CMake Release, static library | 8/8 tests passed |
| CMake Release, shared library | 8/8 tests passed |
| ASan and UBSan | 8/8 tests passed |
| Debian Bookworm container | Build passed, 8/8 tests passed |
| Alpine 3.22 container | Build passed, 8/8 tests passed |
| Installed static library consumer | Passed |
| Clang/libFuzzer smoke run | Passed |
| GitHub CI, Ubuntu GCC and Clang | Passed |
| GitHub CI, Windows MSVC | Link failure under investigation |

These checks test implementation behavior, memory-safety instrumentation, and
build portability. They are not a cryptographic proof, an independent audit, or
an official Signal interoperability test.

## Using PQXDH as a Library

Install the library to a chosen prefix:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/desired/prefix
cmake --build build --parallel
cmake --install build
```

Consume it from CMake:

```cmake
find_package(pqxdh 0.3 CONFIG REQUIRED)
target_link_libraries(my_application PRIVATE PQXDH::pqxdh)
```

Or with pkg-config on Unix-like systems:

```sh
cc application.c $(pkg-config --cflags --libs pqxdh)
```

The main entry points are:

- `pqxdh_generate_alice_keys`;
- `pqxdh_generate_pre_key_bundle`;
- `pqxdh_verify_pre_key_bundle`;
- `pqxdh_alice_create_initial_message`;
- `pqxdh_bob_process_initial_message`;
- `pqxdh_encode_initial_message`;
- `pqxdh_decode_initial_message`.

Call the matching `pqxdh_clear_*` helpers when sensitive values are no longer
needed. Applications must persist identity keys, replay state, and one-time-key
consumption safely and transactionally.

## Fuzzing

```sh
CC=clang cmake -S . -B build-fuzz \
  -DPQXDH_BUILD_TESTS=OFF \
  -DPQXDH_BUILD_FUZZERS=ON
cmake --build build-fuzz --parallel
./build-fuzz/fuzz_decode_initial_message corpus/
```

## Roadmap

The next application target is an educational Android messenger using this
library through the Android NDK. Nearby devices would exchange encrypted data
over Bluetooth Low Energy, with a classical X3DH control profile and the PQXDH
profile measured under the same conditions. Direct peer-to-peer messaging comes
first; multi-hop mesh routing is a later extension.

Planned work includes:

- persistent identities and fingerprint/QR verification;
- explicit alerts for authentication failure, replay, and identity changes;
- a per-message symmetric key chain after PQXDH;
- Android client and Bluetooth transport;
- a classical X3DH comparison implementation;
- reproducible latency, bandwidth, memory, and optional energy benchmarks;
- a documented threat model and source-level audit.

## Contributing

Feel free to open an issue or pull request. Changes to cryptographic behavior
should include tests, precise protocol documentation, and clear compatibility
and security implications.

Security problems should be reported privately as described in
[SECURITY.md](SECURITY.md).

## License

This project is licensed under the [MIT License](LICENSE).
