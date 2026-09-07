#include "pqxdh.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

/* libxeddsa's public header marks calls as dllimport on Windows unless BUILD
 * is defined. Its object files are embedded directly into pqxdh, so these are
 * local definitions rather than imports. Keep the workaround scoped to this
 * header instead of leaking libxeddsa's generic BUILD macro to other headers.
 */
#if defined(_WIN32) && !defined(BUILD)
#define BUILD
#define PQXDH_UNDEFINE_XEDDSA_BUILD
#endif
#include <xeddsa.h>
#if defined(PQXDH_UNDEFINE_XEDDSA_BUILD)
#undef PQXDH_UNDEFINE_XEDDSA_BUILD
#undef BUILD
#endif

#define PQXDH_EC_ENCODING_TAG 0x05U
#define PQXDH_KEM_ENCODING_TAG 0x0aU
#define PQXDH_HKDF_INFO_LABEL "PQXDH_CURVE25519_SHA-256_ML-KEM-1024"

#define PQXDH_SIGNATURE_DATA_MAX_BYTES 2048U
#define PQXDH_ASSOCIATED_DATA_MAX_BYTES 4096U
#define PQXDH_HKDF_PREFIX_BYTES 32U
#define PQXDH_SHA256_BYTES 32U

/* ------------------------------------------------------------------------- */
/* Internal utilities                                                        */
/* ------------------------------------------------------------------------- */

/* Securely wipe sensitive data from memory.
 * sodium_memzero() is used so the compiler cannot optimize the erase away.
 */
static void secure_zero(void *buffer, size_t length)
{
    if (buffer != NULL && length > 0U) {
        sodium_memzero(buffer, length);
    }
}

/* Append a raw byte sequence to a bounded output buffer.
 * The offset is advanced only when the complete input fits.
 */
static int append_bytes(
    uint8_t *output,
    size_t output_capacity,
    size_t *offset,
    const uint8_t *input,
    size_t input_length
)
{
    if (output == NULL || offset == NULL ||
        (input == NULL && input_length > 0U)) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (*offset > output_capacity ||
        input_length > output_capacity - *offset) {
        return PQXDH_ERROR_BUFFER_TOO_SMALL;
    }

    if (input_length > 0U) {
        memcpy(output + *offset, input, input_length);
        *offset += input_length;
    }

    return PQXDH_SUCCESS;
}

/* Append one unsigned byte to the serialized output buffer. */
static int append_u8(
    uint8_t *output,
    size_t output_capacity,
    size_t *offset,
    uint8_t value
)
{
    return append_bytes(output, output_capacity, offset, &value, 1U);
}

/* Append a 32-bit unsigned integer in big-endian network byte order. */
static int append_u32_be(
    uint8_t *output,
    size_t output_capacity,
    size_t *offset,
    uint32_t value
)
{
    const uint8_t encoded[4] = {
        (uint8_t) ((value >> 24U) & 0xffU),
        (uint8_t) ((value >> 16U) & 0xffU),
        (uint8_t) ((value >> 8U) & 0xffU),
        (uint8_t) (value & 0xffU)
    };

    return append_bytes(output, output_capacity, offset, encoded, sizeof(encoded));
}

/* Read a fixed number of bytes from a bounded input buffer.
 * The offset is advanced only when enough encoded data remains.
 */
static int read_bytes(
    const uint8_t *input,
    size_t input_length,
    size_t *offset,
    uint8_t *output,
    size_t output_length
)
{
    if (input == NULL || offset == NULL ||
        (output == NULL && output_length > 0U)) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (*offset > input_length || output_length > input_length - *offset) {
        return PQXDH_ERROR_ENCODING;
    }

    if (output_length > 0U) {
        memcpy(output, input + *offset, output_length);
        *offset += output_length;
    }

    return PQXDH_SUCCESS;
}

/* Read one unsigned byte from the encoded message. */
static int read_u8(
    const uint8_t *input,
    size_t input_length,
    size_t *offset,
    uint8_t *value
)
{
    return read_bytes(input, input_length, offset, value, 1U);
}

/* Read a 32-bit unsigned integer encoded in big-endian byte order. */
static int read_u32_be(
    const uint8_t *input,
    size_t input_length,
    size_t *offset,
    uint32_t *value
)
{
    uint8_t encoded[4];
    int status;

    if (value == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    status = read_bytes(input, input_length, offset, encoded, sizeof(encoded));
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    *value = ((uint32_t) encoded[0] << 24U) |
             ((uint32_t) encoded[1] << 16U) |
             ((uint32_t) encoded[2] << 8U) |
             (uint32_t) encoded[3];

    return PQXDH_SUCCESS;
}

/* Compute a SHA-256 digest with the OpenSSL EVP interface.
 * The output buffer is wiped if hashing fails.
 */
static int sha256_digest(
    const uint8_t *input,
    size_t input_length,
    uint8_t output[PQXDH_SHA256_BYTES]
)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned int digest_length = 0U;
    int status = PQXDH_ERROR_KDF;

    if (output == NULL || (input == NULL && input_length > 0U)) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return PQXDH_ERROR_MEMORY;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto cleanup;
    }

    if (input_length > 0U &&
        EVP_DigestUpdate(ctx, input, input_length) != 1) {
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(ctx, output, &digest_length) != 1 ||
        digest_length != PQXDH_SHA256_BYTES) {
        goto cleanup;
    }

    status = PQXDH_SUCCESS;

cleanup:
    EVP_MD_CTX_free(ctx);

    if (status != PQXDH_SUCCESS) {
        secure_zero(output, PQXDH_SHA256_BYTES);
    }

    return status;
}

/* Return 1 only when every byte in the supplied buffer is zero. */
static int bytes_are_zero(const uint8_t *input, size_t input_length)
{
    uint8_t accumulator = 0U;

    if (input == NULL) {
        return 0;
    }

    for (size_t i = 0U; i < input_length; ++i) {
        accumulator |= input[i];
    }

    return accumulator == 0U;
}

/* Check whether a message identifier is already present in the replay tracker.
 * sodium_memcmp() is used for fixed-length comparisons.
 */
static int replay_contains(
    const ReplayTracker *tracker,
    const uint8_t message_id[PQXDH_MESSAGE_ID_BYTES]
)
{
    size_t count;

    if (tracker == NULL || message_id == NULL) {
        return 0;
    }

    count = tracker->count;
    if (count > PQXDH_MAX_REPLAY_ENTRIES) {
        count = PQXDH_MAX_REPLAY_ENTRIES;
    }

    for (size_t i = 0U; i < count; ++i) {
        if (sodium_memcmp(
                tracker->used_message_ids[i],
                message_id,
                PQXDH_MESSAGE_ID_BYTES
            ) == 0) {
            return 1;
        }
    }

    return 0;
}

/* Generate a fresh X25519 key pair.
 * The private scalar is generated with libsodium's cryptographic RNG.
 */
static int generate_x25519_keypair(
    uint8_t public_key[PQXDH_X25519_PUBLIC_BYTES],
    uint8_t private_key[PQXDH_X25519_PRIVATE_BYTES]
)
{
    if (public_key == NULL || private_key == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    randombytes_buf(private_key, PQXDH_X25519_PRIVATE_BYTES);

    if (crypto_scalarmult_curve25519_base(public_key, private_key) != 0) {
        secure_zero(private_key, PQXDH_X25519_PRIVATE_BYTES);
        secure_zero(public_key, PQXDH_X25519_PUBLIC_BYTES);
        return PQXDH_ERROR_DIFFIE_HELLMAN;
    }

    return PQXDH_SUCCESS;
}

/* Generate an X25519 identity scalar in XEdDSA's canonical sign-bit form. */
static int generate_identity_keypair(uint8_t public_key[32], uint8_t private_key[32])
{
    randombytes_buf(private_key, 32U);
    priv_to_curve25519_pub(public_key, private_key);
    return bytes_are_zero(public_key, 32U) ? PQXDH_ERROR_RANDOM : PQXDH_SUCCESS;
}

static int xeddsa_sign_key(uint8_t signature[64], const uint8_t private_key[32],
                           const uint8_t *message, size_t message_length)
{
    uint8_t nonce[64];
    uint8_t signing_scalar[32];

    if (message_length > UINT32_MAX) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }
    priv_force_sign(signing_scalar, private_key, false);
    randombytes_buf(nonce, sizeof(nonce));
    ed25519_priv_sign(signature, signing_scalar, message,
                      (uint32_t) message_length, nonce);
    secure_zero(nonce, sizeof(nonce));
    secure_zero(signing_scalar, sizeof(signing_scalar));
    return PQXDH_SUCCESS;
}

static int xeddsa_verify_key(const uint8_t signature[64], const uint8_t public_key[32],
                             const uint8_t *message, size_t message_length)
{
    uint8_t ed_public[32];
    int result;

    if (message_length > UINT32_MAX) {
        return PQXDH_ERROR_SIGNATURE;
    }
    curve25519_pub_to_ed25519_pub(ed_public, public_key, false);
    result = ed25519_verify(signature, ed_public, message, (uint32_t) message_length);
    secure_zero(ed_public, sizeof(ed_public));
    return result == 0 ? PQXDH_SUCCESS : PQXDH_ERROR_SIGNATURE;
}

/* Compute one X25519 Diffie-Hellman shared secret. */
static int pqxdh_x25519(
    uint8_t output[PQXDH_X25519_PUBLIC_BYTES],
    const uint8_t private_key[PQXDH_X25519_PRIVATE_BYTES],
    const uint8_t public_key[PQXDH_X25519_PUBLIC_BYTES]
)
{
    if (output == NULL || private_key == NULL || public_key == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (crypto_scalarmult_curve25519(output, private_key, public_key) != 0) {
        secure_zero(output, PQXDH_X25519_PUBLIC_BYTES);
        return PQXDH_ERROR_DIFFIE_HELLMAN;
    }

    return PQXDH_SUCCESS;
}

/* Verify that the configured ML-KEM algorithm is enabled in liboqs. */
static int create_kem(void)
{
    if (OQS_KEM_alg_is_enabled(PQXDH_KEM_ALGORITHM) != 1) {
        return PQXDH_ERROR_INITIALIZATION;
    }

    return PQXDH_SUCCESS;
}

/* Encapsulate a post-quantum shared secret with Bob's ML-KEM public key.
 * The resulting ciphertext is sent to Bob as part of the initial message.
 */
static int kem_encapsulate(
    const uint8_t public_key[PQXDH_KEM_PUBLIC_KEY_BYTES],
    uint8_t ciphertext[PQXDH_KEM_CIPHERTEXT_BYTES],
    uint8_t shared_secret[PQXDH_KEM_SHARED_SECRET_BYTES]
)
{
    OQS_KEM *kem = NULL;
    int status = PQXDH_ERROR_KEM;

    if (public_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    kem = OQS_KEM_new(PQXDH_KEM_ALGORITHM);
    if (kem == NULL) {
        return PQXDH_ERROR_KEM;
    }

    if (kem->length_public_key != PQXDH_KEM_PUBLIC_KEY_BYTES ||
        kem->length_ciphertext != PQXDH_KEM_CIPHERTEXT_BYTES ||
        kem->length_shared_secret != PQXDH_KEM_SHARED_SECRET_BYTES) {
        status = PQXDH_ERROR_INITIALIZATION;
        goto cleanup;
    }

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) !=
        OQS_SUCCESS) {
        goto cleanup;
    }

    status = PQXDH_SUCCESS;

cleanup:
    OQS_KEM_free(kem);

    if (status != PQXDH_SUCCESS) {
        secure_zero(ciphertext, PQXDH_KEM_CIPHERTEXT_BYTES);
        secure_zero(shared_secret, PQXDH_KEM_SHARED_SECRET_BYTES);
    }

    return status;
}

/* Recover the post-quantum shared secret using Bob's ML-KEM private key. */
static int kem_decapsulate(
    const uint8_t private_key[PQXDH_KEM_PRIVATE_KEY_BYTES],
    const uint8_t ciphertext[PQXDH_KEM_CIPHERTEXT_BYTES],
    uint8_t shared_secret[PQXDH_KEM_SHARED_SECRET_BYTES]
)
{
    OQS_KEM *kem = NULL;
    int status = PQXDH_ERROR_KEM;

    if (private_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    kem = OQS_KEM_new(PQXDH_KEM_ALGORITHM);
    if (kem == NULL) {
        return PQXDH_ERROR_KEM;
    }

    if (kem->length_secret_key != PQXDH_KEM_PRIVATE_KEY_BYTES ||
        kem->length_ciphertext != PQXDH_KEM_CIPHERTEXT_BYTES ||
        kem->length_shared_secret != PQXDH_KEM_SHARED_SECRET_BYTES) {
        status = PQXDH_ERROR_INITIALIZATION;
        goto cleanup;
    }

    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, private_key) !=
        OQS_SUCCESS) {
        goto cleanup;
    }

    status = PQXDH_SUCCESS;

cleanup:
    OQS_KEM_free(kem);

    if (status != PQXDH_SUCCESS) {
        secure_zero(shared_secret, PQXDH_KEM_SHARED_SECRET_BYTES);
    }

    return status;
}

/* ------------------------------------------------------------------------- */
/* Pre-key signatures                                                        */
/* ------------------------------------------------------------------------- */

/* Sig(IK_B, EncodeEC(SPK_B), Z_SPK), per PQXDH revision 3. */
static int build_signed_prekey_signature_data(
    const PreKeyBundle *bundle,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
)
{
    size_t offset = 0U;
    int status;

    if (bundle == NULL || output == NULL || output_length == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    status = append_u8(output, output_capacity, &offset, PQXDH_EC_ENCODING_TAG);
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    status = append_bytes(
        output,
        output_capacity,
        &offset,
        bundle->signed_prekey_public,
        sizeof(bundle->signed_prekey_public)
    );
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    *output_length = offset;
    return PQXDH_SUCCESS;
}

/* Sig(IK_B, EncodeKEM(PQPK_B), Z_PQPK), per PQXDH revision 3. */
static int build_kem_signature_data(
    const PreKeyBundle *bundle,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
)
{
    size_t offset = 0U;
    int status;

    if (bundle == NULL || output == NULL || output_length == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    status = append_u8(output, output_capacity, &offset, PQXDH_KEM_ENCODING_TAG);
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    status = append_bytes(
        output,
        output_capacity,
        &offset,
        bundle->kem_public,
        sizeof(bundle->kem_public)
    );
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    *output_length = offset;
    return PQXDH_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Transcript and KDF                                                        */
/* ------------------------------------------------------------------------- */

/* AD = EncodeEC(IK_A) || EncodeEC(IK_B). ML-KEM binds its public key. */
static int build_associated_data(
    const PreKeyBundle *bob_bundle,
    const InitialMessage *message,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
)
{
    size_t offset = 0U;
    int status;

    if (bob_bundle == NULL || message == NULL ||
        output == NULL || output_length == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    status = append_u8(output, output_capacity, &offset, PQXDH_EC_ENCODING_TAG);
    if (status == PQXDH_SUCCESS)
        status = append_bytes(output, output_capacity, &offset,
                              message->alice_identity_public, 32U);
    if (status == PQXDH_SUCCESS)
        status = append_u8(output, output_capacity, &offset, PQXDH_EC_ENCODING_TAG);
    if (status == PQXDH_SUCCESS)
        status = append_bytes(output, output_capacity, &offset,
                              bob_bundle->identity_public, 32U);
    if (status != PQXDH_SUCCESS) return status;

    *output_length = offset;
    return PQXDH_SUCCESS;
}

/* Derive the final 256-bit session key with HKDF-SHA-256.
 * Classical X25519 shared secrets and the ML-KEM shared secret are combined,
 * then bound to a hash of the authenticated transcript.
 */
static int derive_session_key(
    const uint8_t dh1[PQXDH_X25519_PUBLIC_BYTES],
    const uint8_t dh2[PQXDH_X25519_PUBLIC_BYTES],
    const uint8_t dh3[PQXDH_X25519_PUBLIC_BYTES],
    const uint8_t *dh4,
    bool uses_one_time_prekey,
    const uint8_t kem_shared_secret[PQXDH_KEM_SHARED_SECRET_BYTES],
    uint8_t session_key[PQXDH_SESSION_KEY_BYTES]
)
{
    uint8_t ikm[
        PQXDH_HKDF_PREFIX_BYTES +
        (4U * PQXDH_X25519_PUBLIC_BYTES) +
        PQXDH_KEM_SHARED_SECRET_BYTES
    ];
    const uint8_t info[] = PQXDH_HKDF_INFO_LABEL;
    const uint8_t salt[PQXDH_SHA256_BYTES] = {0};
    EVP_PKEY_CTX *ctx = NULL;
    size_t ikm_length = 0U;
    size_t output_length = PQXDH_SESSION_KEY_BYTES;
    int status = PQXDH_ERROR_KDF;

    if (dh1 == NULL || dh2 == NULL || dh3 == NULL ||
        kem_shared_secret == NULL || session_key == NULL ||
        (uses_one_time_prekey && dh4 == NULL)) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    memset(ikm, 0xff, PQXDH_HKDF_PREFIX_BYTES);
    ikm_length = PQXDH_HKDF_PREFIX_BYTES;

    memcpy(ikm + ikm_length, dh1, PQXDH_X25519_PUBLIC_BYTES);
    ikm_length += PQXDH_X25519_PUBLIC_BYTES;

    memcpy(ikm + ikm_length, dh2, PQXDH_X25519_PUBLIC_BYTES);
    ikm_length += PQXDH_X25519_PUBLIC_BYTES;

    memcpy(ikm + ikm_length, dh3, PQXDH_X25519_PUBLIC_BYTES);
    ikm_length += PQXDH_X25519_PUBLIC_BYTES;

    if (uses_one_time_prekey) {
        memcpy(ikm + ikm_length, dh4, PQXDH_X25519_PUBLIC_BYTES);
        ikm_length += PQXDH_X25519_PUBLIC_BYTES;
    }

    memcpy(
        ikm + ikm_length,
        kem_shared_secret,
        PQXDH_KEM_SHARED_SECRET_BYTES
    );
    ikm_length += PQXDH_KEM_SHARED_SECRET_BYTES;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (ctx == NULL) {
        status = PQXDH_ERROR_MEMORY;
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(
            ctx,
            EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND
        ) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(
            ctx,
            salt,
            (int) sizeof(salt)
        ) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(
            ctx,
            ikm,
            (int) ikm_length
        ) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx,
            info,
            (int) (sizeof(info) - 1U)
        ) <= 0 ||
        EVP_PKEY_derive(ctx, session_key, &output_length) <= 0 ||
        output_length != PQXDH_SESSION_KEY_BYTES) {
        status = PQXDH_ERROR_KDF;
        goto cleanup;
    }

    status = PQXDH_SUCCESS;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    secure_zero(ikm, sizeof(ikm));

    if (status != PQXDH_SUCCESS) {
        secure_zero(session_key, PQXDH_SESSION_KEY_BYTES);
    }

    return status;
}

/* ------------------------------------------------------------------------- */
/* Internal message encoding                                                 */
/* ------------------------------------------------------------------------- */

/* Serialize every InitialMessage field except message_id.
 * This deterministic representation is hashed to compute the message identifier.
 */
static int serialize_initial_message_prefix(
    const InitialMessage *message,
    uint8_t *encoded,
    size_t encoded_capacity,
    size_t *encoded_length
)
{
    size_t offset = 0U;
    int status;

    if (message == NULL || encoded == NULL || encoded_length == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (message->ciphertext_len < PQXDH_AEAD_TAG_BYTES ||
        message->ciphertext_len > PQXDH_MAX_INITIAL_CIPHERTEXT_BYTES ||
        message->ciphertext_len > UINT32_MAX) {
        return PQXDH_ERROR_ENCODING;
    }

    status = append_u8(encoded, encoded_capacity, &offset, message->version);
    if (status != PQXDH_SUCCESS) {
        return status;
    }

#define SERIALIZE_FIELD(field)                                                \
    do {                                                                      \
        status = append_bytes(                                                \
            encoded, encoded_capacity, &offset, (field), sizeof(field)        \
        );                                                                    \
        if (status != PQXDH_SUCCESS) {                                        \
            return status;                                                    \
        }                                                                     \
    } while (0)

    SERIALIZE_FIELD(message->alice_identity_public);
    SERIALIZE_FIELD(message->alice_ephemeral_public);
    SERIALIZE_FIELD(message->signed_prekey_id);

    status = append_u8(
        encoded,
        encoded_capacity,
        &offset,
        message->uses_one_time_prekey ? 1U : 0U
    );
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    SERIALIZE_FIELD(message->one_time_prekey_id);
    SERIALIZE_FIELD(message->kem_id);
    SERIALIZE_FIELD(message->kem_ciphertext);
    SERIALIZE_FIELD(message->nonce);

    status = append_u32_be(
        encoded,
        encoded_capacity,
        &offset,
        (uint32_t) message->ciphertext_len
    );
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    status = append_bytes(
        encoded,
        encoded_capacity,
        &offset,
        message->ciphertext,
        message->ciphertext_len
    );
    if (status != PQXDH_SUCCESS) {
        return status;
    }

#undef SERIALIZE_FIELD

    *encoded_length = offset;
    return PQXDH_SUCCESS;
}

/* Compute the SHA-256 identifier of the serialized initial message.
 * The identifier is later used for integrity validation and replay detection.
 */
static int compute_initial_message_id(
    const InitialMessage *message,
    uint8_t output[PQXDH_MESSAGE_ID_BYTES]
)
{
    uint8_t encoded[PQXDH_MAX_ENCODED_INITIAL_MESSAGE_BYTES];
    size_t encoded_length = 0U;
    int status;

    status = serialize_initial_message_prefix(
        message,
        encoded,
        sizeof(encoded),
        &encoded_length
    );
    if (status != PQXDH_SUCCESS) {
        secure_zero(encoded, sizeof(encoded));
        return status;
    }

    status = sha256_digest(encoded, encoded_length, output);
    secure_zero(encoded, sizeof(encoded));
    return status;
}

/* Validate the structural and cryptographic consistency of an initial message.
 * This checks protocol version, lengths, optional fields and message identifier.
 */
static int validate_initial_message(const InitialMessage *message)
{
    uint8_t expected_id[PQXDH_MESSAGE_ID_BYTES];
    int status;

    if (message == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (message->version != PQXDH_PROTOCOL_VERSION ||
        message->ciphertext_len < PQXDH_AEAD_TAG_BYTES ||
        message->ciphertext_len > PQXDH_MAX_INITIAL_CIPHERTEXT_BYTES) {
        return PQXDH_ERROR_ENCODING;
    }

    if (!message->uses_one_time_prekey &&
        !bytes_are_zero(
            message->one_time_prekey_id,
            sizeof(message->one_time_prekey_id)
        )) {
        return PQXDH_ERROR_ENCODING;
    }

    if (bytes_are_zero(message->alice_identity_public,
                       sizeof(message->alice_identity_public)) ||
        bytes_are_zero(message->alice_ephemeral_public,
                       sizeof(message->alice_ephemeral_public))) {
        return PQXDH_ERROR_ENCODING;
    }

    status = compute_initial_message_id(message, expected_id);
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    if (sodium_memcmp(
            expected_id,
            message->message_id,
            sizeof(expected_id)
        ) != 0) {
        secure_zero(expected_id, sizeof(expected_id));
        return PQXDH_ERROR_ENCODING;
    }

    secure_zero(expected_id, sizeof(expected_id));
    return PQXDH_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

/* Initialize the cryptographic dependencies required by this implementation. */
int pqxdh_init(void)
{
    if (xeddsa_init() < 0) {
        return PQXDH_ERROR_INITIALIZATION;
    }

    return create_kem();
}

/* Compute a stable SHA-256 identifier for a public pre-key. */
int pqxdh_compute_key_id(
    const uint8_t *key,
    size_t key_len,
    uint8_t key_id[PQXDH_KEY_ID_BYTES]
)
{
    if (key == NULL || key_len == 0U || key_id == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    return sha256_digest(key, key_len, key_id);
}

/* Generate Alice's long-term Curve25519 identity key. */
int pqxdh_generate_alice_keys(AliceKeyBundle *alice)
{
    int status;

    if (alice == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    memset(alice, 0, sizeof(*alice));

    status = pqxdh_init();
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    status = generate_identity_keypair(alice->identity_public,
                                       alice->identity_private);
    if (status != PQXDH_SUCCESS) {
        pqxdh_clear_alice_keys(alice);
        return status;
    }

    alice->initialized = true;
    return PQXDH_SUCCESS;
}

/* Generate Bob's complete public/private pre-key state.
 * This creates the identity key, signed X25519 pre-key, one-time X25519 pre-key,
 * ML-KEM-1024 pre-key, identifiers, and signatures published to Alice.
 */
int pqxdh_generate_pre_key_bundle(
    PreKeyBundle *public_bundle,
    PrivateKeyBundle *private_bundle
)
{
    OQS_KEM *kem = NULL;
    uint8_t signature_data[PQXDH_SIGNATURE_DATA_MAX_BYTES];
    size_t signature_data_length = 0U;
    int status;

    if (public_bundle == NULL || private_bundle == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    memset(public_bundle, 0, sizeof(*public_bundle));
    memset(private_bundle, 0, sizeof(*private_bundle));
    memset(signature_data, 0, sizeof(signature_data));

    status = pqxdh_init();
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = generate_identity_keypair(public_bundle->identity_public,
                                       private_bundle->identity_private);
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = generate_x25519_keypair(
        public_bundle->signed_prekey_public,
        private_bundle->signed_prekey_private
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = generate_x25519_keypair(
        public_bundle->one_time_prekey_public,
        private_bundle->one_time_prekey_private
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    public_bundle->has_one_time_prekey = true;
    private_bundle->has_one_time_prekey = true;
    private_bundle->one_time_prekey_used = false;

    status = pqxdh_compute_key_id(
        public_bundle->signed_prekey_public,
        sizeof(public_bundle->signed_prekey_public),
        public_bundle->signed_prekey_id
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = pqxdh_compute_key_id(
        public_bundle->one_time_prekey_public,
        sizeof(public_bundle->one_time_prekey_public),
        public_bundle->one_time_prekey_id
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    kem = OQS_KEM_new(PQXDH_KEM_ALGORITHM);
    if (kem == NULL) {
        status = PQXDH_ERROR_KEM;
        goto cleanup;
    }

    if (kem->length_public_key != PQXDH_KEM_PUBLIC_KEY_BYTES ||
        kem->length_secret_key != PQXDH_KEM_PRIVATE_KEY_BYTES) {
        status = PQXDH_ERROR_INITIALIZATION;
        goto cleanup;
    }

    if (OQS_KEM_keypair(
            kem,
            public_bundle->kem_public,
            private_bundle->kem_private
        ) != OQS_SUCCESS) {
        status = PQXDH_ERROR_KEM;
        goto cleanup;
    }

    public_bundle->kem_is_one_time = true;
    private_bundle->kem_is_one_time = true;
    private_bundle->kem_key_used = false;

    status = pqxdh_compute_key_id(
        public_bundle->kem_public,
        sizeof(public_bundle->kem_public),
        public_bundle->kem_id
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = build_signed_prekey_signature_data(
        public_bundle,
        signature_data,
        sizeof(signature_data),
        &signature_data_length
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = xeddsa_sign_key(public_bundle->signed_prekey_signature,
                             private_bundle->identity_private,
                             signature_data, signature_data_length);
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    secure_zero(signature_data, sizeof(signature_data));
    signature_data_length = 0U;

    status = build_kem_signature_data(
        public_bundle,
        signature_data,
        sizeof(signature_data),
        &signature_data_length
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = xeddsa_sign_key(public_bundle->kem_signature,
                             private_bundle->identity_private,
                             signature_data, signature_data_length);
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    public_bundle->initialized = true;
    private_bundle->initialized = true;
    status = PQXDH_SUCCESS;

cleanup:
    OQS_KEM_free(kem);
    secure_zero(signature_data, sizeof(signature_data));

    if (status != PQXDH_SUCCESS) {
        memset(public_bundle, 0, sizeof(*public_bundle));
        pqxdh_clear_private_key_bundle(private_bundle);
    }

    return status;
}

/* Verify the integrity and authenticity of Bob's public pre-key bundle.
 * Public-key identifiers, identity conversion, and Ed25519 signatures are checked
 * before Alice is allowed to use the bundle.
 */
int pqxdh_verify_pre_key_bundle(const PreKeyBundle *bundle)
{
    uint8_t expected_id[PQXDH_KEY_ID_BYTES];
    uint8_t signature_data[PQXDH_SIGNATURE_DATA_MAX_BYTES];
    size_t signature_data_length = 0U;
    int status;

    if (bundle == NULL || !bundle->initialized) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    memset(expected_id, 0, sizeof(expected_id));
    memset(signature_data, 0, sizeof(signature_data));

    status = pqxdh_compute_key_id(
        bundle->signed_prekey_public,
        sizeof(bundle->signed_prekey_public),
        expected_id
    );
    if (status != PQXDH_SUCCESS ||
        sodium_memcmp(
            expected_id,
            bundle->signed_prekey_id,
            sizeof(expected_id)
        ) != 0) {
        status = PQXDH_ERROR_SIGNATURE;
        goto cleanup;
    }

    if (bundle->has_one_time_prekey) {
        status = pqxdh_compute_key_id(
            bundle->one_time_prekey_public,
            sizeof(bundle->one_time_prekey_public),
            expected_id
        );
        if (status != PQXDH_SUCCESS ||
            sodium_memcmp(
                expected_id,
                bundle->one_time_prekey_id,
                sizeof(expected_id)
            ) != 0) {
            status = PQXDH_ERROR_SIGNATURE;
            goto cleanup;
        }
    } else if (!bytes_are_zero(
                   bundle->one_time_prekey_public,
                   sizeof(bundle->one_time_prekey_public)
               ) ||
               !bytes_are_zero(
                   bundle->one_time_prekey_id,
                   sizeof(bundle->one_time_prekey_id)
               )) {
        status = PQXDH_ERROR_SIGNATURE;
        goto cleanup;
    }

    status = pqxdh_compute_key_id(
        bundle->kem_public,
        sizeof(bundle->kem_public),
        expected_id
    );
    if (status != PQXDH_SUCCESS ||
        sodium_memcmp(expected_id, bundle->kem_id, sizeof(expected_id)) != 0) {
        status = PQXDH_ERROR_SIGNATURE;
        goto cleanup;
    }

    status = build_signed_prekey_signature_data(
        bundle,
        signature_data,
        sizeof(signature_data),
        &signature_data_length
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = xeddsa_verify_key(bundle->signed_prekey_signature,
                               bundle->identity_public,
                               signature_data, signature_data_length);
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    secure_zero(signature_data, sizeof(signature_data));
    signature_data_length = 0U;

    status = build_kem_signature_data(
        bundle,
        signature_data,
        sizeof(signature_data),
        &signature_data_length
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = xeddsa_verify_key(bundle->kem_signature,
                               bundle->identity_public,
                               signature_data, signature_data_length);
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = PQXDH_SUCCESS;

cleanup:
    secure_zero(expected_id, sizeof(expected_id));
    secure_zero(signature_data, sizeof(signature_data));
    return status;
}

/* Encrypt and authenticate a message with AES-256-GCM.
 * The function generates a fresh nonce and appends the authentication tag
 * directly after the encrypted payload.
 */
int encrypt_message(
    const uint8_t key[PQXDH_SESSION_KEY_BYTES],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *associated_data,
    size_t associated_data_len,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_len,
    uint8_t nonce[PQXDH_AEAD_NONCE_BYTES]
)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int output_length = 0;
    int final_length = 0;
    size_t required_capacity;
    int status = PQXDH_ERROR_ENCRYPTION;

    if (key == NULL || ciphertext == NULL || ciphertext_len == NULL ||
        nonce == NULL || (plaintext == NULL && plaintext_len > 0U) ||
        (associated_data == NULL && associated_data_len > 0U)) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (plaintext_len > SIZE_MAX - PQXDH_AEAD_TAG_BYTES) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    required_capacity = plaintext_len + PQXDH_AEAD_TAG_BYTES;
    if (ciphertext_capacity < required_capacity) {
        return PQXDH_ERROR_BUFFER_TOO_SMALL;
    }

    if (plaintext_len > INT_MAX || associated_data_len > INT_MAX) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    *ciphertext_len = 0U;

    if (RAND_bytes(nonce, (int) PQXDH_AEAD_NONCE_BYTES) != 1) {
        return PQXDH_ERROR_RANDOM;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return PQXDH_ERROR_MEMORY;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            (int) PQXDH_AEAD_NONCE_BYTES,
            NULL
        ) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }

    if (associated_data_len > 0U &&
        EVP_EncryptUpdate(
            ctx,
            NULL,
            &output_length,
            associated_data,
            (int) associated_data_len
        ) != 1) {
        goto cleanup;
    }

    output_length = 0;
    if (plaintext_len > 0U &&
        EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &output_length,
            plaintext,
            (int) plaintext_len
        ) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + output_length,
            &final_length
        ) != 1) {
        goto cleanup;
    }

    *ciphertext_len = (size_t) output_length + (size_t) final_length;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            (int) PQXDH_AEAD_TAG_BYTES,
            ciphertext + *ciphertext_len
        ) != 1) {
        goto cleanup;
    }

    *ciphertext_len += PQXDH_AEAD_TAG_BYTES;
    status = PQXDH_SUCCESS;

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    if (status != PQXDH_SUCCESS) {
        secure_zero(ciphertext, required_capacity);
        secure_zero(nonce, PQXDH_AEAD_NONCE_BYTES);
        *ciphertext_len = 0U;
    }

    return status;
}

/* Authenticate and decrypt an AES-256-GCM ciphertext.
 * Authentication failure causes the plaintext buffer to be wiped.
 */
int decrypt_message(
    const uint8_t key[PQXDH_SESSION_KEY_BYTES],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[PQXDH_AEAD_NONCE_BYTES],
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *tag;
    size_t encrypted_length;
    uint8_t dummy_output[1] = {0U};
    int output_length = 0;
    int final_length = 0;
    int status = PQXDH_ERROR_DECRYPTION;

    if (key == NULL || ciphertext == NULL || nonce == NULL ||
        plaintext_len == NULL ||
        (associated_data == NULL && associated_data_len > 0U)) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (ciphertext_len < PQXDH_AEAD_TAG_BYTES) {
        return PQXDH_ERROR_DECRYPTION;
    }

    encrypted_length = ciphertext_len - PQXDH_AEAD_TAG_BYTES;

    if ((plaintext == NULL && encrypted_length > 0U) ||
        plaintext_capacity < encrypted_length) {
        return PQXDH_ERROR_BUFFER_TOO_SMALL;
    }

    if (encrypted_length > INT_MAX || associated_data_len > INT_MAX) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    *plaintext_len = 0U;
    tag = ciphertext + encrypted_length;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return PQXDH_ERROR_MEMORY;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            (int) PQXDH_AEAD_NONCE_BYTES,
            NULL
        ) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }

    if (associated_data_len > 0U &&
        EVP_DecryptUpdate(
            ctx,
            NULL,
            &output_length,
            associated_data,
            (int) associated_data_len
        ) != 1) {
        goto cleanup;
    }

    output_length = 0;
    if (encrypted_length > 0U &&
        EVP_DecryptUpdate(
            ctx,
            plaintext,
            &output_length,
            ciphertext,
            (int) encrypted_length
        ) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            (int) PQXDH_AEAD_TAG_BYTES,
            (void *) tag
        ) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext != NULL ? plaintext + output_length : dummy_output,
            &final_length
        ) != 1) {
        goto cleanup;
    }

    *plaintext_len = (size_t) output_length + (size_t) final_length;
    status = PQXDH_SUCCESS;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    secure_zero(dummy_output, sizeof(dummy_output));

    if (status != PQXDH_SUCCESS) {
        if (plaintext != NULL && encrypted_length > 0U) {
            secure_zero(plaintext, encrypted_length);
        }
        *plaintext_len = 0U;
    }

    return status;
}

/* Execute Alice's side of the initial PQXDH exchange.
 * Alice verifies Bob's bundle, generates an ephemeral X25519 key, performs the
 * classical DH computations, encapsulates with ML-KEM, derives a session key,
 * encrypts the first payload, and computes the final message identifier.
 */
int pqxdh_alice_create_initial_message(
    const AliceKeyBundle *alice,
    const PreKeyBundle *bob_bundle,
    const uint8_t *plaintext,
    size_t plaintext_len,
    InitialMessage *initial_message,
    uint8_t session_key[PQXDH_SESSION_KEY_BYTES]
)
{
    uint8_t ephemeral_private[PQXDH_X25519_PRIVATE_BYTES];
    uint8_t dh1[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t dh2[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t dh3[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t dh4[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t kem_shared_secret[PQXDH_KEM_SHARED_SECRET_BYTES];
    uint8_t associated_data[PQXDH_ASSOCIATED_DATA_MAX_BYTES];
    size_t associated_data_length = 0U;
    int status;

    if (alice == NULL || bob_bundle == NULL || initial_message == NULL ||
        session_key == NULL || !alice->initialized ||
        (plaintext == NULL && plaintext_len > 0U)) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (plaintext_len > PQXDH_MAX_INITIAL_PLAINTEXT_BYTES) {
        return PQXDH_ERROR_BUFFER_TOO_SMALL;
    }

    memset(initial_message, 0, sizeof(*initial_message));
    memset(ephemeral_private, 0, sizeof(ephemeral_private));
    memset(dh1, 0, sizeof(dh1));
    memset(dh2, 0, sizeof(dh2));
    memset(dh3, 0, sizeof(dh3));
    memset(dh4, 0, sizeof(dh4));
    memset(kem_shared_secret, 0, sizeof(kem_shared_secret));
    memset(associated_data, 0, sizeof(associated_data));
    secure_zero(session_key, PQXDH_SESSION_KEY_BYTES);

    /* Authenticate Bob's published pre-key bundle before using any key material. */
    status = pqxdh_verify_pre_key_bundle(bob_bundle);
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    initial_message->version = PQXDH_PROTOCOL_VERSION;
    memcpy(
        initial_message->alice_identity_public,
        alice->identity_public,
        sizeof(initial_message->alice_identity_public)
    );
    memcpy(
        initial_message->signed_prekey_id,
        bob_bundle->signed_prekey_id,
        sizeof(initial_message->signed_prekey_id)
    );

    initial_message->uses_one_time_prekey =
        bob_bundle->has_one_time_prekey;

    if (initial_message->uses_one_time_prekey) {
        memcpy(
            initial_message->one_time_prekey_id,
            bob_bundle->one_time_prekey_id,
            sizeof(initial_message->one_time_prekey_id)
        );
    }

    memcpy(
        initial_message->kem_id,
        bob_bundle->kem_id,
        sizeof(initial_message->kem_id)
    );

    /* Generate Alice's ephemeral X25519 key pair for this handshake only. */
    status = generate_x25519_keypair(
        initial_message->alice_ephemeral_public,
        ephemeral_private
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* DH1: Alice identity key with Bob's signed pre-key. */
    status = pqxdh_x25519(
        dh1,
        alice->identity_private,
        bob_bundle->signed_prekey_public
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* DH2: Alice ephemeral key with Bob's identity key. */
    status = pqxdh_x25519(
        dh2,
        ephemeral_private,
        bob_bundle->identity_public
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* DH3: Alice ephemeral key with Bob's signed pre-key. */
    status = pqxdh_x25519(
        dh3,
        ephemeral_private,
        bob_bundle->signed_prekey_public
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* DH4 is included only when Bob supplied an unused one-time pre-key. */
    if (initial_message->uses_one_time_prekey) {
        status = pqxdh_x25519(
            dh4,
            ephemeral_private,
            bob_bundle->one_time_prekey_public
        );
        if (status != PQXDH_SUCCESS) {
            goto cleanup;
        }
    }

    /* Add the post-quantum ML-KEM contribution to the hybrid handshake. */
    status = kem_encapsulate(
        bob_bundle->kem_public,
        initial_message->kem_ciphertext,
        kem_shared_secret
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = build_associated_data(
        bob_bundle,
        initial_message,
        associated_data,
        sizeof(associated_data),
        &associated_data_length
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* Combine all classical and post-quantum secrets into one session key. */
    status = derive_session_key(
        dh1,
        dh2,
        dh3,
        initial_message->uses_one_time_prekey ? dh4 : NULL,
        initial_message->uses_one_time_prekey,
        kem_shared_secret,
        session_key
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* Encrypt the initial application payload with the newly derived key. */
    status = encrypt_message(
        session_key,
        plaintext,
        plaintext_len,
        associated_data,
        associated_data_length,
        initial_message->ciphertext,
        sizeof(initial_message->ciphertext),
        &initial_message->ciphertext_len,
        initial_message->nonce
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* Finalize the message with a deterministic identifier used for replay checks. */
    status = compute_initial_message_id(
        initial_message,
        initial_message->message_id
    );

cleanup:
    secure_zero(ephemeral_private, sizeof(ephemeral_private));
    secure_zero(dh1, sizeof(dh1));
    secure_zero(dh2, sizeof(dh2));
    secure_zero(dh3, sizeof(dh3));
    secure_zero(dh4, sizeof(dh4));
    secure_zero(kem_shared_secret, sizeof(kem_shared_secret));
    secure_zero(associated_data, sizeof(associated_data));

    if (status != PQXDH_SUCCESS) {
        pqxdh_clear_initial_message(initial_message);
        pqxdh_clear_session_key(session_key);
    }

    return status;
}

/* Execute Bob's side of the initial PQXDH exchange.
 * Bob validates the message, rejects replays or reused one-time keys, reproduces
 * the DH and ML-KEM secrets, derives the same session key, authenticates and
 * decrypts the payload, then consumes the one-time private keys.
 */
int pqxdh_bob_process_initial_message(
    const PreKeyBundle *bob_public_bundle,
    PrivateKeyBundle *bob_private_bundle,
    const InitialMessage *initial_message,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len,
    uint8_t session_key[PQXDH_SESSION_KEY_BYTES],
    ReplayTracker *replay_tracker
)
{
    uint8_t dh1[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t dh2[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t dh3[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t dh4[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t kem_shared_secret[PQXDH_KEM_SHARED_SECRET_BYTES];
    uint8_t associated_data[PQXDH_ASSOCIATED_DATA_MAX_BYTES];
    size_t associated_data_length = 0U;
    int status;

    if (bob_public_bundle == NULL || bob_private_bundle == NULL ||
        initial_message == NULL || plaintext_len == NULL ||
        session_key == NULL || replay_tracker == NULL ||
        !bob_private_bundle->initialized) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    *plaintext_len = 0U;
    secure_zero(session_key, PQXDH_SESSION_KEY_BYTES);
    memset(dh1, 0, sizeof(dh1));
    memset(dh2, 0, sizeof(dh2));
    memset(dh3, 0, sizeof(dh3));
    memset(dh4, 0, sizeof(dh4));
    memset(kem_shared_secret, 0, sizeof(kem_shared_secret));
    memset(associated_data, 0, sizeof(associated_data));

    /* Revalidate the public bundle so the local public/private state remains trusted. */
    status = pqxdh_verify_pre_key_bundle(bob_public_bundle);
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* Reject malformed or internally inconsistent messages before cryptographic use. */
    status = validate_initial_message(initial_message);
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* Reject an initial message that has already been processed. */
    if (replay_contains(replay_tracker, initial_message->message_id)) {
        status = PQXDH_ERROR_REPLAY;
        goto cleanup;
    }

    if (sodium_memcmp(
            initial_message->signed_prekey_id,
            bob_public_bundle->signed_prekey_id,
            PQXDH_KEY_ID_BYTES
        ) != 0 ||
        sodium_memcmp(
            initial_message->kem_id,
            bob_public_bundle->kem_id,
            PQXDH_KEY_ID_BYTES
        ) != 0) {
        status = PQXDH_ERROR_KEY_NOT_FOUND;
        goto cleanup;
    }

    if (initial_message->uses_one_time_prekey) {
        if (!bob_public_bundle->has_one_time_prekey ||
            !bob_private_bundle->has_one_time_prekey ||
            sodium_memcmp(
                initial_message->one_time_prekey_id,
                bob_public_bundle->one_time_prekey_id,
                PQXDH_KEY_ID_BYTES
            ) != 0) {
            status = PQXDH_ERROR_KEY_NOT_FOUND;
            goto cleanup;
        }

        if (bob_private_bundle->one_time_prekey_used) {
            status = PQXDH_ERROR_KEY_ALREADY_USED;
            goto cleanup;
        }
    }

    if (bob_private_bundle->kem_is_one_time &&
        bob_private_bundle->kem_key_used) {
        status = PQXDH_ERROR_KEY_ALREADY_USED;
        goto cleanup;
    }

    status = pqxdh_x25519(
        dh1,
        bob_private_bundle->signed_prekey_private,
        initial_message->alice_identity_public
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = pqxdh_x25519(
        dh2,
        bob_private_bundle->identity_private,
        initial_message->alice_ephemeral_public
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = pqxdh_x25519(
        dh3,
        bob_private_bundle->signed_prekey_private,
        initial_message->alice_ephemeral_public
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    if (initial_message->uses_one_time_prekey) {
        status = pqxdh_x25519(
            dh4,
            bob_private_bundle->one_time_prekey_private,
            initial_message->alice_ephemeral_public
        );
        if (status != PQXDH_SUCCESS) {
            goto cleanup;
        }
    }

    /* Recover the same post-quantum shared secret created by Alice. */
    status = kem_decapsulate(
        bob_private_bundle->kem_private,
        initial_message->kem_ciphertext,
        kem_shared_secret
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = build_associated_data(
        bob_public_bundle,
        initial_message,
        associated_data,
        sizeof(associated_data),
        &associated_data_length
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = derive_session_key(
        dh1,
        dh2,
        dh3,
        initial_message->uses_one_time_prekey ? dh4 : NULL,
        initial_message->uses_one_time_prekey,
        kem_shared_secret,
        session_key
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    /* Authenticate the transcript-bound ciphertext before accepting the payload. */
    status = decrypt_message(
        session_key,
        initial_message->ciphertext,
        initial_message->ciphertext_len,
        associated_data,
        associated_data_length,
        initial_message->nonce,
        plaintext,
        plaintext_capacity,
        plaintext_len
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    status = pqxdh_replay_check_and_mark(
        replay_tracker,
        initial_message->message_id
    );
    if (status != PQXDH_SUCCESS) {
        goto cleanup;
    }

    if (initial_message->uses_one_time_prekey) {
        bob_private_bundle->one_time_prekey_used = true;
        secure_zero(
            bob_private_bundle->one_time_prekey_private,
            sizeof(bob_private_bundle->one_time_prekey_private)
        );
    }

    if (bob_private_bundle->kem_is_one_time) {
        bob_private_bundle->kem_key_used = true;
        secure_zero(
            bob_private_bundle->kem_private,
            sizeof(bob_private_bundle->kem_private)
        );
    }

    status = PQXDH_SUCCESS;

cleanup:
    secure_zero(dh1, sizeof(dh1));
    secure_zero(dh2, sizeof(dh2));
    secure_zero(dh3, sizeof(dh3));
    secure_zero(dh4, sizeof(dh4));
    secure_zero(kem_shared_secret, sizeof(kem_shared_secret));
    secure_zero(associated_data, sizeof(associated_data));

    if (status != PQXDH_SUCCESS) {
        if (plaintext != NULL && plaintext_capacity > 0U) {
            secure_zero(plaintext, plaintext_capacity);
        }
        *plaintext_len = 0U;
        pqxdh_clear_session_key(session_key);
    }

    return status;
}

/* Encode an InitialMessage into a deterministic platform-independent format.
 * Fixed-width integer fields use network byte order.
 */
int pqxdh_encode_initial_message(
    const InitialMessage *message,
    uint8_t *encoded,
    size_t encoded_capacity,
    size_t *encoded_len
)
{
    size_t prefix_length = 0U;
    int status;

    if (message == NULL || encoded == NULL || encoded_len == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    status = validate_initial_message(message);
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    status = serialize_initial_message_prefix(
        message,
        encoded,
        encoded_capacity,
        &prefix_length
    );
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    status = append_bytes(
        encoded,
        encoded_capacity,
        &prefix_length,
        message->message_id,
        sizeof(message->message_id)
    );
    if (status != PQXDH_SUCCESS) {
        return status;
    }

    *encoded_len = prefix_length;
    return PQXDH_SUCCESS;
}

/* Decode a serialized InitialMessage and validate its complete structure.
 * Extra bytes, malformed lengths, and inconsistent identifiers are rejected.
 */
int pqxdh_decode_initial_message(
    const uint8_t *encoded,
    size_t encoded_len,
    InitialMessage *message
)
{
    size_t offset = 0U;
    uint8_t bool_value = 0U;
    uint32_t ciphertext_length = 0U;
    int status;

    if (encoded == NULL || message == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    memset(message, 0, sizeof(*message));

    status = read_u8(encoded, encoded_len, &offset, &message->version);
    if (status != PQXDH_SUCCESS) {
        goto fail;
    }

#define DECODE_FIELD(field)                                                   \
    do {                                                                      \
        status = read_bytes(                                                  \
            encoded, encoded_len, &offset, (field), sizeof(field)             \
        );                                                                    \
        if (status != PQXDH_SUCCESS) {                                        \
            goto fail;                                                        \
        }                                                                     \
    } while (0)

    DECODE_FIELD(message->alice_identity_public);
    DECODE_FIELD(message->alice_ephemeral_public);
    DECODE_FIELD(message->signed_prekey_id);

    status = read_u8(encoded, encoded_len, &offset, &bool_value);
    if (status != PQXDH_SUCCESS || bool_value > 1U) {
        status = PQXDH_ERROR_ENCODING;
        goto fail;
    }
    message->uses_one_time_prekey = bool_value == 1U;

    DECODE_FIELD(message->one_time_prekey_id);
    DECODE_FIELD(message->kem_id);
    DECODE_FIELD(message->kem_ciphertext);
    DECODE_FIELD(message->nonce);

    status = read_u32_be(
        encoded,
        encoded_len,
        &offset,
        &ciphertext_length
    );
    if (status != PQXDH_SUCCESS ||
        ciphertext_length < PQXDH_AEAD_TAG_BYTES ||
        ciphertext_length > PQXDH_MAX_INITIAL_CIPHERTEXT_BYTES) {
        status = PQXDH_ERROR_ENCODING;
        goto fail;
    }

    message->ciphertext_len = (size_t) ciphertext_length;

    status = read_bytes(
        encoded,
        encoded_len,
        &offset,
        message->ciphertext,
        message->ciphertext_len
    );
    if (status != PQXDH_SUCCESS) {
        goto fail;
    }

    DECODE_FIELD(message->message_id);

#undef DECODE_FIELD

    if (offset != encoded_len) {
        status = PQXDH_ERROR_ENCODING;
        goto fail;
    }

    status = validate_initial_message(message);
    if (status != PQXDH_SUCCESS) {
        goto fail;
    }

    return PQXDH_SUCCESS;

fail:
    pqxdh_clear_initial_message(message);
    return status;
}

/* Reset a replay tracker to an empty state. */
void pqxdh_replay_tracker_init(ReplayTracker *tracker)
{
    if (tracker != NULL) {
        memset(tracker, 0, sizeof(*tracker));
    }
}

/* Reject a previously seen message identifier or record a new one.
 * When the fixed tracker is full, the oldest entry is discarded.
 */
int pqxdh_replay_check_and_mark(
    ReplayTracker *tracker,
    const uint8_t message_id[PQXDH_MESSAGE_ID_BYTES]
)
{
    if (tracker == NULL || message_id == NULL) {
        return PQXDH_ERROR_INVALID_ARGUMENT;
    }

    if (replay_contains(tracker, message_id)) {
        return PQXDH_ERROR_REPLAY;
    }

    if (tracker->count > PQXDH_MAX_REPLAY_ENTRIES) {
        pqxdh_replay_tracker_init(tracker);
    }

    if (tracker->count == PQXDH_MAX_REPLAY_ENTRIES) {
        memmove(
            tracker->used_message_ids[0],
            tracker->used_message_ids[1],
            (PQXDH_MAX_REPLAY_ENTRIES - 1U) * PQXDH_MESSAGE_ID_BYTES
        );
        tracker->count = PQXDH_MAX_REPLAY_ENTRIES - 1U;
    }

    memcpy(
        tracker->used_message_ids[tracker->count],
        message_id,
        PQXDH_MESSAGE_ID_BYTES
    );
    ++tracker->count;

    return PQXDH_SUCCESS;
}

/* Securely erase Alice's private and public key state. */
void pqxdh_clear_alice_keys(AliceKeyBundle *alice)
{
    if (alice != NULL) {
        secure_zero(alice, sizeof(*alice));
    }
}

/* Securely erase Bob's complete private pre-key state. */
void pqxdh_clear_private_key_bundle(PrivateKeyBundle *private_bundle)
{
    if (private_bundle != NULL) {
        secure_zero(private_bundle, sizeof(*private_bundle));
    }
}

/* Securely erase an InitialMessage structure from memory. */
void pqxdh_clear_initial_message(InitialMessage *message)
{
    if (message != NULL) {
        secure_zero(message, sizeof(*message));
    }
}

/* Securely erase a derived session key. */
void pqxdh_clear_session_key(
    uint8_t session_key[PQXDH_SESSION_KEY_BYTES]
)
{
    if (session_key != NULL) {
        secure_zero(session_key, PQXDH_SESSION_KEY_BYTES);
    }
}

/* Convert a PQXDH status code into a short human-readable English message. */
const char *pqxdh_status_string(int status)
{
    switch (status) {
        case PQXDH_SUCCESS:
            return "success";
        case PQXDH_ERROR_INVALID_ARGUMENT:
            return "invalid argument";
        case PQXDH_ERROR_INITIALIZATION:
            return "cryptographic initialization failed";
        case PQXDH_ERROR_MEMORY:
            return "memory allocation failed";
        case PQXDH_ERROR_RANDOM:
            return "random generation failed";
        case PQXDH_ERROR_SIGNATURE:
            return "invalid signature or bundle";
        case PQXDH_ERROR_DIFFIE_HELLMAN:
            return "Diffie-Hellman computation failed";
        case PQXDH_ERROR_KEM:
            return "ML-KEM operation failed";
        case PQXDH_ERROR_KDF:
            return "key derivation failed";
        case PQXDH_ERROR_ENCRYPTION:
            return "encryption failed";
        case PQXDH_ERROR_DECRYPTION:
            return "decryption or authentication failed";
        case PQXDH_ERROR_REPLAY:
            return "message already processed";
        case PQXDH_ERROR_KEY_NOT_FOUND:
            return "pre-key not found";
        case PQXDH_ERROR_KEY_ALREADY_USED:
            return "one-time pre-key already consumed";
        case PQXDH_ERROR_BUFFER_TOO_SMALL:
            return "buffer too small";
        case PQXDH_ERROR_ENCODING:
            return "invalid message encoding";
        default:
            return "unknown error";
    }
}

const char *pqxdh_version_string(void)
{
    return "0.3.0";
}
