#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "pqxdh.h"

/* Assert that a boolean condition is true.
 * If the condition fails, print the file, line number, and failed expression,
 * then stop the current test by returning 0.
 */
#define TEST_ASSERT(condition)                                                \
    do {                                                                      \
        if (!(condition)) {                                                   \
            fprintf(                                                          \
                stderr,                                                       \
                "    assertion failed at %s:%d: %s\n",                                 \
                __FILE__,                                                     \
                __LINE__,                                                     \
                #condition                                                    \
            );                                                                \
            return 0;                                                         \
        }                                                                     \
    } while (0)

/* Assert that a function returns the expected PQXDH status code.
 * On failure, print both the actual and expected status values and messages.
 */
#define TEST_ASSERT_STATUS(expression, expected)                              \
    do {                                                                      \
        const int actual_status = (expression);                               \
        if (actual_status != (expected)) {                                    \
            fprintf(                                                          \
                stderr,                                                       \
                "    unexpected status at %s:%d: %s (%d), expected %s (%d)\n", \
                __FILE__,                                                     \
                __LINE__,                                                     \
                pqxdh_status_string(actual_status),                           \
                actual_status,                                                \
                pqxdh_status_string(expected),                                \
                expected                                                      \
            );                                                                \
            return 0;                                                         \
        }                                                                     \
    } while (0)

/* Generic function pointer type used for all test functions.
 * Each test returns 1 on success and 0 on failure.
 */
typedef int (*TestFunction)(void);

/* Represents one test entry in the test suite.
 * "name" is displayed to the user and "function" points to the test itself.
 */
typedef struct {
    const char *name;
    TestFunction function;
} TestCase;

/* Generate a fresh Alice identity and Bob pre-key bundle.
 * This helper is reused by tests that need a complete cryptographic setup.
 */
static int setup_keys(
    AliceKeyBundle *alice,
    PreKeyBundle *bob_public,
    PrivateKeyBundle *bob_private
)
{
    if (pqxdh_generate_alice_keys(alice) != PQXDH_SUCCESS) {
        return 0;
    }

    if (pqxdh_generate_pre_key_bundle(bob_public, bob_private) !=
        PQXDH_SUCCESS) {
        pqxdh_clear_alice_keys(alice);
        return 0;
    }

    return 1;
}

/* Verify that independent key generations produce different public keys.
 * This checks Alice identity keys, Bob identity keys, and Bob ML-KEM public keys.
 */
static int test_initialization_and_unique_keys(void)
{
    AliceKeyBundle alice1;
    AliceKeyBundle alice2;
    PreKeyBundle bob1_public;
    PreKeyBundle bob2_public;
    PrivateKeyBundle bob1_private;
    PrivateKeyBundle bob2_private;

    TEST_ASSERT_STATUS(pqxdh_init(), PQXDH_SUCCESS);
    TEST_ASSERT(setup_keys(&alice1, &bob1_public, &bob1_private));
    TEST_ASSERT(setup_keys(&alice2, &bob2_public, &bob2_private));

    TEST_ASSERT(sodium_memcmp(
        alice1.signing_public,
        alice2.signing_public,
        sizeof(alice1.signing_public)
    ) != 0);

    TEST_ASSERT(sodium_memcmp(
        bob1_public.identity_signing_public,
        bob2_public.identity_signing_public,
        sizeof(bob1_public.identity_signing_public)
    ) != 0);

    TEST_ASSERT(sodium_memcmp(
        bob1_public.kem_public,
        bob2_public.kem_public,
        sizeof(bob1_public.kem_public)
    ) != 0);

    pqxdh_clear_alice_keys(&alice1);
    pqxdh_clear_alice_keys(&alice2);
    pqxdh_clear_private_key_bundle(&bob1_private);
    pqxdh_clear_private_key_bundle(&bob2_private);

    return 1;
}

/* Verify that a valid Bob pre-key bundle is accepted.
 * Then modify signed public data and confirm that signature verification fails.
 */
static int test_bundle_verification_and_tampering(void)
{
    PreKeyBundle public_bundle;
    PrivateKeyBundle private_bundle;
    PreKeyBundle tampered;

    TEST_ASSERT_STATUS(
        pqxdh_generate_pre_key_bundle(&public_bundle, &private_bundle),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        pqxdh_verify_pre_key_bundle(&public_bundle),
        PQXDH_SUCCESS
    );

    tampered = public_bundle;
    tampered.signed_prekey_public[0] ^= 0x01U;

    TEST_ASSERT_STATUS(
        pqxdh_verify_pre_key_bundle(&tampered),
        PQXDH_ERROR_SIGNATURE
    );

    tampered = public_bundle;
    tampered.kem_public[0] ^= 0x01U;

    TEST_ASSERT_STATUS(
        pqxdh_verify_pre_key_bundle(&tampered),
        PQXDH_ERROR_SIGNATURE
    );

    pqxdh_clear_private_key_bundle(&private_bundle);
    return 1;
}

/* Perform a complete Alice-to-Bob PQXDH exchange.
 * The test checks successful decryption, matching session keys, and consumption
 * of Bob's one-time elliptic and post-quantum pre-keys.
 */
static int test_end_to_end_key_agreement(void)
{
    static const uint8_t plaintext[] =
        "This is a real PQXDH initial message.";

    AliceKeyBundle alice;
    PreKeyBundle bob_public;
    PrivateKeyBundle bob_private;
    InitialMessage message;
    ReplayTracker tracker;

    uint8_t alice_session_key[PQXDH_SESSION_KEY_BYTES];
    uint8_t bob_session_key[PQXDH_SESSION_KEY_BYTES];
    uint8_t decrypted[PQXDH_MAX_INITIAL_PLAINTEXT_BYTES];
    size_t decrypted_length = 0U;

    TEST_ASSERT(setup_keys(&alice, &bob_public, &bob_private));
    pqxdh_replay_tracker_init(&tracker);

    TEST_ASSERT_STATUS(
        pqxdh_alice_create_initial_message(
            &alice,
            &bob_public,
            plaintext,
            sizeof(plaintext) - 1U,
            &message,
            alice_session_key
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        pqxdh_bob_process_initial_message(
            &bob_public,
            &bob_private,
            &message,
            decrypted,
            sizeof(decrypted),
            &decrypted_length,
            bob_session_key,
            &tracker
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT(decrypted_length == sizeof(plaintext) - 1U);
    TEST_ASSERT(sodium_memcmp(
        decrypted,
        plaintext,
        decrypted_length
    ) == 0);

    TEST_ASSERT(sodium_memcmp(
        alice_session_key,
        bob_session_key,
        sizeof(alice_session_key)
    ) == 0);

    TEST_ASSERT(bob_private.one_time_prekey_used);
    TEST_ASSERT(bob_private.kem_key_used);

    pqxdh_clear_session_key(alice_session_key);
    pqxdh_clear_session_key(bob_session_key);
    pqxdh_clear_initial_message(&message);
    pqxdh_clear_alice_keys(&alice);
    pqxdh_clear_private_key_bundle(&bob_private);
    sodium_memzero(decrypted, sizeof(decrypted));

    return 1;
}

/* Encode an InitialMessage into its network representation and decode it back.
 * The decoded message must remain valid, preserve its identifier, and still
 * produce the same session key and plaintext when processed by Bob.
 */
static int test_network_encoding_round_trip(void)
{
    static const uint8_t plaintext[] = "Serialized message.";

    AliceKeyBundle alice;
    PreKeyBundle bob_public;
    PrivateKeyBundle bob_private;
    InitialMessage original;
    InitialMessage decoded;
    ReplayTracker tracker;

    uint8_t encoded[PQXDH_MAX_ENCODED_INITIAL_MESSAGE_BYTES];
    size_t encoded_length = 0U;
    uint8_t alice_session_key[PQXDH_SESSION_KEY_BYTES];
    uint8_t bob_session_key[PQXDH_SESSION_KEY_BYTES];
    uint8_t decrypted[PQXDH_MAX_INITIAL_PLAINTEXT_BYTES];
    size_t decrypted_length = 0U;

    TEST_ASSERT(setup_keys(&alice, &bob_public, &bob_private));
    pqxdh_replay_tracker_init(&tracker);

    TEST_ASSERT_STATUS(
        pqxdh_alice_create_initial_message(
            &alice,
            &bob_public,
            plaintext,
            sizeof(plaintext) - 1U,
            &original,
            alice_session_key
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        pqxdh_encode_initial_message(
            &original,
            encoded,
            sizeof(encoded),
            &encoded_length
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT(encoded_length > 0U);

    TEST_ASSERT_STATUS(
        pqxdh_decode_initial_message(encoded, encoded_length, &decoded),
        PQXDH_SUCCESS
    );

    TEST_ASSERT(decoded.ciphertext_len == original.ciphertext_len);
    TEST_ASSERT(sodium_memcmp(
        decoded.message_id,
        original.message_id,
        sizeof(decoded.message_id)
    ) == 0);

    TEST_ASSERT_STATUS(
        pqxdh_bob_process_initial_message(
            &bob_public,
            &bob_private,
            &decoded,
            decrypted,
            sizeof(decrypted),
            &decrypted_length,
            bob_session_key,
            &tracker
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT(decrypted_length == sizeof(plaintext) - 1U);
    TEST_ASSERT(sodium_memcmp(
        decrypted,
        plaintext,
        decrypted_length
    ) == 0);

    TEST_ASSERT(sodium_memcmp(
        alice_session_key,
        bob_session_key,
        sizeof(alice_session_key)
    ) == 0);

    TEST_ASSERT_STATUS(
        pqxdh_decode_initial_message(
            encoded,
            encoded_length - 1U,
            &decoded
        ),
        PQXDH_ERROR_ENCODING
    );

    pqxdh_clear_session_key(alice_session_key);
    pqxdh_clear_session_key(bob_session_key);
    pqxdh_clear_initial_message(&original);
    pqxdh_clear_initial_message(&decoded);
    pqxdh_clear_alice_keys(&alice);
    pqxdh_clear_private_key_bundle(&bob_private);
    sodium_memzero(encoded, sizeof(encoded));
    sodium_memzero(decrypted, sizeof(decrypted));

    return 1;
}

/* Process the same initial message twice.
 * The first attempt must succeed and the second must be rejected as a replay.
 */
static int test_replay_rejection(void)
{
    static const uint8_t plaintext[] = "Non-replayable message.";

    AliceKeyBundle alice;
    PreKeyBundle bob_public;
    PrivateKeyBundle bob_private;
    InitialMessage message;
    ReplayTracker tracker;

    uint8_t alice_session_key[PQXDH_SESSION_KEY_BYTES];
    uint8_t bob_session_key[PQXDH_SESSION_KEY_BYTES];
    uint8_t decrypted[PQXDH_MAX_INITIAL_PLAINTEXT_BYTES];
    size_t decrypted_length = 0U;

    TEST_ASSERT(setup_keys(&alice, &bob_public, &bob_private));
    pqxdh_replay_tracker_init(&tracker);

    TEST_ASSERT_STATUS(
        pqxdh_alice_create_initial_message(
            &alice,
            &bob_public,
            plaintext,
            sizeof(plaintext) - 1U,
            &message,
            alice_session_key
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        pqxdh_bob_process_initial_message(
            &bob_public,
            &bob_private,
            &message,
            decrypted,
            sizeof(decrypted),
            &decrypted_length,
            bob_session_key,
            &tracker
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        pqxdh_bob_process_initial_message(
            &bob_public,
            &bob_private,
            &message,
            decrypted,
            sizeof(decrypted),
            &decrypted_length,
            bob_session_key,
            &tracker
        ),
        PQXDH_ERROR_REPLAY
    );

    pqxdh_clear_session_key(alice_session_key);
    pqxdh_clear_session_key(bob_session_key);
    pqxdh_clear_initial_message(&message);
    pqxdh_clear_alice_keys(&alice);
    pqxdh_clear_private_key_bundle(&bob_private);
    sodium_memzero(decrypted, sizeof(decrypted));

    return 1;
}

/* Test AES-256-GCM independently from the PQXDH handshake.
 * A valid ciphertext must decrypt correctly, while a modified authentication
 * tag or an undersized ciphertext must be rejected.
 */
static int test_aead_integrity(void)
{
    static const uint8_t plaintext[] = "AES-GCM integrity";
    static const uint8_t associated_data[] = "Authenticated context";

    uint8_t key[PQXDH_SESSION_KEY_BYTES];
    uint8_t nonce[PQXDH_AEAD_NONCE_BYTES];
    uint8_t ciphertext[sizeof(plaintext) + PQXDH_AEAD_TAG_BYTES];
    uint8_t decrypted[sizeof(plaintext)];
    size_t ciphertext_length = 0U;
    size_t decrypted_length = 0U;

    randombytes_buf(key, sizeof(key));

    TEST_ASSERT_STATUS(
        encrypt_message(
            key,
            plaintext,
            sizeof(plaintext) - 1U,
            associated_data,
            sizeof(associated_data) - 1U,
            ciphertext,
            sizeof(ciphertext),
            &ciphertext_length,
            nonce
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        decrypt_message(
            key,
            ciphertext,
            ciphertext_length,
            associated_data,
            sizeof(associated_data) - 1U,
            nonce,
            decrypted,
            sizeof(decrypted),
            &decrypted_length
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT(decrypted_length == sizeof(plaintext) - 1U);
    TEST_ASSERT(sodium_memcmp(
        decrypted,
        plaintext,
        decrypted_length
    ) == 0);

    ciphertext[ciphertext_length - 1U] ^= 0x01U;

    TEST_ASSERT_STATUS(
        decrypt_message(
            key,
            ciphertext,
            ciphertext_length,
            associated_data,
            sizeof(associated_data) - 1U,
            nonce,
            decrypted,
            sizeof(decrypted),
            &decrypted_length
        ),
        PQXDH_ERROR_DECRYPTION
    );

    TEST_ASSERT_STATUS(
        decrypt_message(
            key,
            ciphertext,
            PQXDH_AEAD_TAG_BYTES - 1U,
            associated_data,
            sizeof(associated_data) - 1U,
            nonce,
            decrypted,
            sizeof(decrypted),
            &decrypted_length
        ),
        PQXDH_ERROR_DECRYPTION
    );

    sodium_memzero(key, sizeof(key));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(ciphertext, sizeof(ciphertext));
    sodium_memzero(decrypted, sizeof(decrypted));

    return 1;
}

/* Verify one-time pre-key consumption.
 * After Bob processes the first initial message, a second initial message that
 * reuses the same one-time keys must be rejected.
 */
static int test_second_message_rejected_after_one_time_keys(void)
{
    static const uint8_t plaintext1[] = "First message";
    static const uint8_t plaintext2[] = "Second message";

    AliceKeyBundle alice;
    PreKeyBundle bob_public;
    PrivateKeyBundle bob_private;
    InitialMessage message1;
    InitialMessage message2;
    ReplayTracker tracker;

    uint8_t alice_key1[PQXDH_SESSION_KEY_BYTES];
    uint8_t alice_key2[PQXDH_SESSION_KEY_BYTES];
    uint8_t bob_key[PQXDH_SESSION_KEY_BYTES];
    uint8_t decrypted[PQXDH_MAX_INITIAL_PLAINTEXT_BYTES];
    size_t decrypted_length = 0U;

    TEST_ASSERT(setup_keys(&alice, &bob_public, &bob_private));
    pqxdh_replay_tracker_init(&tracker);

    TEST_ASSERT_STATUS(
        pqxdh_alice_create_initial_message(
            &alice,
            &bob_public,
            plaintext1,
            sizeof(plaintext1) - 1U,
            &message1,
            alice_key1
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        pqxdh_bob_process_initial_message(
            &bob_public,
            &bob_private,
            &message1,
            decrypted,
            sizeof(decrypted),
            &decrypted_length,
            bob_key,
            &tracker
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        pqxdh_alice_create_initial_message(
            &alice,
            &bob_public,
            plaintext2,
            sizeof(plaintext2) - 1U,
            &message2,
            alice_key2
        ),
        PQXDH_SUCCESS
    );

    TEST_ASSERT_STATUS(
        pqxdh_bob_process_initial_message(
            &bob_public,
            &bob_private,
            &message2,
            decrypted,
            sizeof(decrypted),
            &decrypted_length,
            bob_key,
            &tracker
        ),
        PQXDH_ERROR_KEY_ALREADY_USED
    );

    pqxdh_clear_session_key(alice_key1);
    pqxdh_clear_session_key(alice_key2);
    pqxdh_clear_session_key(bob_key);
    pqxdh_clear_initial_message(&message1);
    pqxdh_clear_initial_message(&message2);
    pqxdh_clear_alice_keys(&alice);
    pqxdh_clear_private_key_bundle(&bob_private);
    sodium_memzero(decrypted, sizeof(decrypted));

    return 1;
}

/* Run every test in sequence, print a compact result for each test,
 * and return a non-zero exit status if at least one test fails.
 */
int main(void)
{
    static const TestCase tests[] = {
        {
            "Initialization and key uniqueness",
            test_initialization_and_unique_keys
        },
        {
            "Bundle verification and tampering",
            test_bundle_verification_and_tampering
        },
        {
            "End-to-end Alice/Bob key agreement",
            test_end_to_end_key_agreement
        },
        {
            "Network encoding and decoding",
            test_network_encoding_round_trip
        },
        {
            "Replay rejection",
            test_replay_rejection
        },
        {
            "AES-256-GCM integrity",
            test_aead_integrity
        },
        {
            "One-time key consumption",
            test_second_message_rejected_after_one_time_keys
        }
    };

    size_t passed = 0U;
    const size_t total = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0U; i < total; ++i) {
        printf("[%zu/%zu] %s...\n", i + 1U, total, tests[i].name);

        if (tests[i].function()) {
            printf("    PASS\n");
            ++passed;
        } else {
            printf("    FAIL\n");
        }
    }

    printf("\nResult: %zu/%zu tests passed.\n", passed, total);
    return passed == total ? 0 : 1;
}