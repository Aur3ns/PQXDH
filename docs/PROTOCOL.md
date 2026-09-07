# Protocol profile and conformance

This library implements a concrete parameter profile of revision 3 of the
[Signal PQXDH specification](https://signal.org/docs/specifications/pqxdh/)
(2023-05-24, last updated 2024-01-23):

1. Bob publishes an identity key, a signed X25519 prekey, an optional one-time
   X25519 prekey, and a signed ML-KEM-1024 key.
2. Alice verifies the signed bundle, computes DH1 through DH3 and optional DH4,
   encapsulates an ML-KEM shared secret, and derives a 32-byte session key.
3. Alice encrypts an initial payload and Bob repeats the derivation, authenticates
   the ciphertext, consumes one-time private keys, and records its message ID.

## Concrete profile

- Identity keys: Curve25519 keys in XEdDSA's canonical sign-bit form.
- Identity signatures: randomized XEd25519 using libxeddsa; every signature gets
  a fresh 64-byte random `Z` value as required by the XEdDSA specification.
- Diffie-Hellman: X25519 using libsodium.
- Post-quantum KEM: ML-KEM-1024 using liboqs.
- KDF: HKDF-SHA-256 through OpenSSL EVP.
- Initial-message AEAD: AES-256-GCM with a random 96-bit nonce.
- Key and message identifiers: SHA-256.
- Wire integers: unsigned big-endian values.

`EncodeEC` is byte `0x05` followed by the 32-byte little-endian X25519
u-coordinate. `EncodeKEM` is byte `0x0a` followed by the ML-KEM-1024 public-key
encoding. Their ranges are therefore disjoint.

The KDF input is exactly `0xff * 32 || DH1 || DH2 || DH3 [|| DH4] || SS`, with
a 32-byte zero salt. Its info value is
`PQXDH_CURVE25519_SHA-256_ML-KEM-1024`. The AEAD associated data is exactly
`EncodeEC(IK_A) || EncodeEC(IK_B)`. ML-KEM binds its public key into the
ciphertext, so PQXDH does not require appending `EncodeKEM(PQPK_B)` to AD.

## Scope and interoperability

The cryptographic transcript follows PQXDH revision 3. The specification leaves
algorithm identifiers, key identifiers, the concrete AEAD, and the unambiguous
initial-message container to implementers; those choices form this project's
wire profile. Consequently it will interoperate with another implementation of
this same profile, but not directly with Signal Messenger/libsignal's complete
wire protocol. No official cross-implementation PQXDH vectors are currently
published, so conformance is tested structurally and end-to-end rather than
claimed from an official vector suite. Applications must authenticate identity
fingerprints over a separate trusted channel.

## State and concurrency

`PrivateKeyBundle` and `ReplayTracker` are mutable protocol state. The caller
must serialize access to them and persist one-time-key consumption before
acknowledging a successfully processed message. The in-memory replay tracker is
bounded and is a convenience mechanism, not a durable replay database.
