#ifndef PQXDH_H
#define PQXDH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include <oqs/kem_ml_kem.h>
#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(OQS_ENABLE_KEM_ml_kem_1024)
#error "PQXDH requires liboqs to be built with ML-KEM-1024 enabled"
#endif

#define PQXDH_PROTOCOL_VERSION 2U
#define PQXDH_VERSION_MAJOR 0U
#define PQXDH_VERSION_MINOR 3U
#define PQXDH_VERSION_PATCH 0U
#define PQXDH_SESSION_KEY_BYTES 32U
#define PQXDH_KEY_ID_BYTES 32U
#define PQXDH_MESSAGE_ID_BYTES 32U
#define PQXDH_AEAD_NONCE_BYTES 12U
#define PQXDH_AEAD_TAG_BYTES 16U
#define PQXDH_MAX_INITIAL_PLAINTEXT_BYTES 1024U
#define PQXDH_MAX_INITIAL_CIPHERTEXT_BYTES \
    (PQXDH_MAX_INITIAL_PLAINTEXT_BYTES + PQXDH_AEAD_TAG_BYTES)
#define PQXDH_MAX_ENCODED_INITIAL_MESSAGE_BYTES 4096U
#define PQXDH_MAX_REPLAY_ENTRIES 100U
#define PQXDH_KEM_ALGORITHM OQS_KEM_alg_ml_kem_1024
#define PQXDH_KEM_PUBLIC_KEY_BYTES OQS_KEM_ml_kem_1024_length_public_key
#define PQXDH_KEM_PRIVATE_KEY_BYTES OQS_KEM_ml_kem_1024_length_secret_key
#define PQXDH_KEM_CIPHERTEXT_BYTES OQS_KEM_ml_kem_1024_length_ciphertext
#define PQXDH_KEM_SHARED_SECRET_BYTES OQS_KEM_ml_kem_1024_length_shared_secret
#define PQXDH_IDENTITY_PUBLIC_BYTES 32U
#define PQXDH_IDENTITY_PRIVATE_BYTES 32U
#define PQXDH_SIGNATURE_BYTES 64U
#define PQXDH_X25519_PUBLIC_BYTES crypto_scalarmult_curve25519_BYTES
#define PQXDH_X25519_PRIVATE_BYTES crypto_scalarmult_curve25519_SCALARBYTES

typedef enum {
    PQXDH_SUCCESS = 0,
    PQXDH_ERROR_INVALID_ARGUMENT = -1,
    PQXDH_ERROR_INITIALIZATION = -2,
    PQXDH_ERROR_MEMORY = -3,
    PQXDH_ERROR_RANDOM = -4,
    PQXDH_ERROR_SIGNATURE = -5,
    PQXDH_ERROR_DIFFIE_HELLMAN = -6,
    PQXDH_ERROR_KEM = -7,
    PQXDH_ERROR_KDF = -8,
    PQXDH_ERROR_ENCRYPTION = -9,
    PQXDH_ERROR_DECRYPTION = -10,
    PQXDH_ERROR_REPLAY = -11,
    PQXDH_ERROR_KEY_NOT_FOUND = -12,
    PQXDH_ERROR_KEY_ALREADY_USED = -13,
    PQXDH_ERROR_BUFFER_TOO_SMALL = -14,
    PQXDH_ERROR_ENCODING = -15
} PqxdhStatus;

typedef struct {
    uint8_t identity_public[PQXDH_IDENTITY_PUBLIC_BYTES];
    uint8_t identity_private[PQXDH_IDENTITY_PRIVATE_BYTES];
    bool initialized;
} AliceKeyBundle;

typedef struct {
    uint8_t identity_public[PQXDH_IDENTITY_PUBLIC_BYTES];
    uint8_t signed_prekey_public[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t signed_prekey_signature[PQXDH_SIGNATURE_BYTES];
    uint8_t signed_prekey_id[PQXDH_KEY_ID_BYTES];
    bool has_one_time_prekey;
    uint8_t one_time_prekey_public[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t one_time_prekey_id[PQXDH_KEY_ID_BYTES];
    uint8_t kem_public[PQXDH_KEM_PUBLIC_KEY_BYTES];
    uint8_t kem_signature[PQXDH_SIGNATURE_BYTES];
    uint8_t kem_id[PQXDH_KEY_ID_BYTES];
    bool kem_is_one_time;
    bool initialized;
} PreKeyBundle;

typedef struct {
    uint8_t identity_private[PQXDH_IDENTITY_PRIVATE_BYTES];
    uint8_t signed_prekey_private[PQXDH_X25519_PRIVATE_BYTES];
    bool has_one_time_prekey;
    bool one_time_prekey_used;
    uint8_t one_time_prekey_private[PQXDH_X25519_PRIVATE_BYTES];
    uint8_t kem_private[PQXDH_KEM_PRIVATE_KEY_BYTES];
    bool kem_is_one_time;
    bool kem_key_used;
    bool initialized;
} PrivateKeyBundle;

typedef struct {
    uint8_t version;
    uint8_t alice_identity_public[PQXDH_IDENTITY_PUBLIC_BYTES];
    uint8_t alice_ephemeral_public[PQXDH_X25519_PUBLIC_BYTES];
    uint8_t signed_prekey_id[PQXDH_KEY_ID_BYTES];
    bool uses_one_time_prekey;
    uint8_t one_time_prekey_id[PQXDH_KEY_ID_BYTES];
    uint8_t kem_id[PQXDH_KEY_ID_BYTES];
    uint8_t kem_ciphertext[PQXDH_KEM_CIPHERTEXT_BYTES];
    uint8_t nonce[PQXDH_AEAD_NONCE_BYTES];
    uint8_t ciphertext[PQXDH_MAX_INITIAL_CIPHERTEXT_BYTES];
    size_t ciphertext_len;
    uint8_t message_id[PQXDH_MESSAGE_ID_BYTES];
} InitialMessage;

typedef struct {
    uint8_t used_message_ids[PQXDH_MAX_REPLAY_ENTRIES][PQXDH_MESSAGE_ID_BYTES];
    size_t count;
} ReplayTracker;

int pqxdh_init(void);
int pqxdh_generate_alice_keys(AliceKeyBundle *alice);
int pqxdh_generate_pre_key_bundle(PreKeyBundle *public_bundle, PrivateKeyBundle *private_bundle);
int pqxdh_verify_pre_key_bundle(const PreKeyBundle *bundle);
int pqxdh_alice_create_initial_message(const AliceKeyBundle *alice, const PreKeyBundle *bob_bundle, const uint8_t *plaintext, size_t plaintext_len, InitialMessage *initial_message, uint8_t session_key[PQXDH_SESSION_KEY_BYTES]);
int pqxdh_bob_process_initial_message(const PreKeyBundle *bob_public_bundle, PrivateKeyBundle *bob_private_bundle, const InitialMessage *initial_message, uint8_t *plaintext, size_t plaintext_capacity, size_t *plaintext_len, uint8_t session_key[PQXDH_SESSION_KEY_BYTES], ReplayTracker *replay_tracker);
int encrypt_message(const uint8_t key[PQXDH_SESSION_KEY_BYTES], const uint8_t *plaintext, size_t plaintext_len, const uint8_t *associated_data, size_t associated_data_len, uint8_t *ciphertext, size_t ciphertext_capacity, size_t *ciphertext_len, uint8_t nonce[PQXDH_AEAD_NONCE_BYTES]);
int decrypt_message(const uint8_t key[PQXDH_SESSION_KEY_BYTES], const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *associated_data, size_t associated_data_len, const uint8_t nonce[PQXDH_AEAD_NONCE_BYTES], uint8_t *plaintext, size_t plaintext_capacity, size_t *plaintext_len);
int pqxdh_encode_initial_message(const InitialMessage *message, uint8_t *encoded, size_t encoded_capacity, size_t *encoded_len);
int pqxdh_decode_initial_message(const uint8_t *encoded, size_t encoded_len, InitialMessage *message);
int pqxdh_compute_key_id(const uint8_t *key, size_t key_len, uint8_t key_id[PQXDH_KEY_ID_BYTES]);
void pqxdh_replay_tracker_init(ReplayTracker *tracker);
int pqxdh_replay_check_and_mark(ReplayTracker *tracker, const uint8_t message_id[PQXDH_MESSAGE_ID_BYTES]);
void pqxdh_clear_alice_keys(AliceKeyBundle *alice);
void pqxdh_clear_private_key_bundle(PrivateKeyBundle *private_bundle);
void pqxdh_clear_initial_message(InitialMessage *message);
void pqxdh_clear_session_key(uint8_t session_key[PQXDH_SESSION_KEY_BYTES]);
const char *pqxdh_status_string(int status);
const char *pqxdh_version_string(void);

#ifdef __cplusplus
}
#endif

#endif
