<h1 align="center"> Project PQXDH </h1>

## Overview

**Post-Quantum Extended Diffie–Hellman (PQXDH)** is a cryptographic protocol designed to resist attacks from quantum computers. It is an evolution of the traditional **Diffie–Hellman key exchange**, extended with support for post-quantum algorithms to address the growing concerns around quantum threats.

According to the documentation, that you can find at this link : <https://signal.org/docs/specifications/pqxdh/>

PQXDH establishes a shared secret key between two parties who mutually authenticate each other based on public keys. PQXDH provides post-quantum forward secrecy and a form of cryptographic deniability but still relies on the hardness of the discrete log problem for mutual authentication in this revision of the protocol.

PQXDH is designed for asynchronous settings where one user (“Bob”) is offline but has published some information to a server. Another user (“Alice”) wants to use that information to send encrypted data to Bob, and also establish a shared secret key for future communication.

This project implements a hybrid PQXDH protocol in **C**, combining:

- **Kyber** (Post-Quantum Key Encapsulation Mechanism - KEM).
- **Ed25519/Curve25519** (Classical signature and Diffie–Hellman algorithms).
- **AES-GCM** for authenticated encryption.

I've tried to get as close as possible to the specifications of the document

### Why PQXDH?

Developed as an enhanced extension of the **X3DH protocol** (used in Signal Messenger), PQXDH addresses the vulnerabilities of classical cryptography to quantum attacks. It ensures **long-term confidentiality** by protecting against "harvest now, decrypt later" attacks, where an adversary captures encrypted communications to decrypt them in the future using quantum computers.

The protocol was first introduced by **Ehren Kret** and **Rolfe Schmidt** and is now integrated into the Signal protocol to future-proof secure messaging.

## Key Features

- **Post-Quantum Security:** Integrates the Kyber algorithm for quantum-resistant key encapsulation.
- **Backward Compatibility:** Combines traditional cryptographic methods with quantum-resistant techniques.
- **Authenticated Encryption:** Uses AES-GCM for confidentiality and message integrity.
- **Nonce Management:** Protects against replay attacks by tracking unique nonces.

---

## How It Works

1. **Key Generation:**
   - Bob generates Kyber keys (post-quantum), Ed25519 identity keys, and ephemeral Curve25519 keys.
   - Bob signs his ephemeral keys and shares a pre-key bundle with Alice.

2. **Key Exchange:**
   - Alice verifies Bob's pre-keys, encapsulates a shared secret using Kyber, and performs multiple Diffie–Hellman (DH) operations.
   - A final shared key is derived using SHAKE256 (a post-quantum secure key derivation function).

3. **Encryption/Decryption:**
   - Alice encrypts messages using AES-GCM with the derived shared key.
   - Bob decrypts and validates the message's authenticity.

---

## Project Structure

```plaintext
PQXDH
├── liboqs/                # Quantum-safe cryptographic algorithm library
├── .dockerignore          # The Docker equivalent of .gitignore
├── .gitattributes         # Tells Git to checkout and push certain files with certain line endings
├── .gitmodules            # Organizes project submodules for Git to interpret
├── alpine.dockerfile      # Dockerfile built on top of the alpine image
├── debian.dockerfile      # Dockerfile built on top of the debian-slim image
├── LICENSE                # Project license
├── Makefile               # Makefile for automating compilation
├── pqxdh.c                # Implementation of PQXDH functions
├── pqxdh.h                # Header file with structures and function prototypes
├── README.md              # The explanatory file you're currently reading
├── run-alpine.sh          # Script to install dependencies and build the project in an Alpine environment
├── run-debian.sh          # Script to install dependencies and build the project in a Debian environment
└── test_pqxdh.c           # Unit tests for validating protocol correctness
```

## Prerequisites

Choose an installer that matches your operating system.
Using the Alpine installer as an example, first compile the project:

```bash
chmod +x run-alpine.sh
./run-alpine.sh
```

Then, execute the testing binary:

```bash
./test_pqxdh
```

***Expected Output***
If everything is working correctly, you should see the following output:

```plaintext
Test Key Initialization: PASS
Test KEM Encapsulation/Decapsulation: PASS
Derived key successfully
Test Diffie-Hellman and Initial Message: PASS
Encryption/Decryption Test:
AES Key: <hexadecimal key>
Nonce Used: <nonce>
Decrypted Text: Secret message for testing
Encryption/Decryption Test: PASS
```

## Running in Docker

Using the Alpine Dockerfile as an example, first build the image:

```shell
docker build -f ./alpine.dockerfile -t pqdxh-alpine .
```

Then, run a container from that image:

```shell
docker run pqdxh-alpine
```

***Expected Output***
If everything is working correctly, you should see the following output:

```plaintext
Test Key Initialization: PASS
Test KEM Encapsulation/Decapsulation: PASS
Derived key successfully
Test Diffie-Hellman and Initial Message: PASS
Encryption/Decryption Test:
AES Key: <hexadecimal key>
Nonce Used: <nonce>
Decrypted Text: Secret message for testing
Encryption/Decryption Test: PASS
```

## Contributing

Feel free to open a pull request or create an issue in this repository.

## License

This project is licensed under the [MIT License](./LICENSE).
