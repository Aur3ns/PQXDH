#ifndef PQXDH_H
#define PQXDH_H

#include <oqs/oqs.h>
#include <sodium.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define AES_KEY_BYTES 32
#define AES_NONCE_BYTES 12
#define SHAKE256_OUTPUT_BYTES 32
#define MAX_USED_OPKS 100

// Structure pour suivre les nonces utilisés et détecter les relectures
typedef struct {
    unsigned char used_nonces[MAX_USED_OPKS][AES_NONCE_BYTES];
    int count;
} NonceTracker;

// Structure représentant un ensemble de pré-clés pour Bob
typedef struct {
    unsigned char ik[crypto_sign_PUBLICKEYBYTES]; // Clé publique d'identité
    unsigned char spk[crypto_scalarmult_curve25519_BYTES]; // Pré-clé secondaire publique
    unsigned char opk[crypto_scalarmult_curve25519_BYTES]; // Autre pré-clé secondaire publique
    unsigned char spk_sig[crypto_sign_BYTES]; // Signature de la pré-clé spk
    unsigned char opk_sig[crypto_sign_BYTES]; // Signature de la pré-clé opk
    unsigned char spk_id[SHA256_DIGEST_LENGTH]; // Identifiant unique pour spk
    unsigned char opk_id[SHA256_DIGEST_LENGTH]; // Identifiant unique pour opk
    OQS_KEM *pqkem; // Structure pour l'encapsulation KEM post-quantique
    unsigned char pqkem_public[OQS_KEM_kyber_1024_length_public_key]; // Clé publique Kyber
    unsigned char pqkem_ct[OQS_KEM_kyber_1024_length_ciphertext]; // Chiffrement encapsulé Kyber
    unsigned char shared_secret_bytes[OQS_KEM_kyber_1024_length_shared_secret]; // Secret partagé Kyber
} PreKeyBundle;

// Structure regroupant les clés privées de Bob
typedef struct {
    unsigned char ik[crypto_sign_SECRETKEYBYTES]; // Clé privée d'identité
    unsigned char spk[crypto_sign_SECRETKEYBYTES]; // Pré-clé secondaire privée
    unsigned char opk[crypto_sign_SECRETKEYBYTES]; // Autre pré-clé secondaire privée
    unsigned char pqkem_private[OQS_KEM_kyber_1024_length_secret_key]; // Clé privée Kyber
} PrivateKeyBundle;

// Structure pour le message initial envoyé par Alice
typedef struct {
    unsigned char ik[crypto_sign_PUBLICKEYBYTES]; // Clé publique d'identité d'Alice
    unsigned char ed[crypto_scalarmult_curve25519_BYTES]; // Clé publique éphémère d'Alice
    unsigned char ct[OQS_KEM_kyber_1024_length_ciphertext]; // Chiffrement encapsulé de Kyber
    unsigned char ect[1024]; // Message chiffré avec AES-GCM
    unsigned char nonce[AES_NONCE_BYTES]; // Nonce pour AES-GCM
    unsigned char signature[crypto_sign_BYTES]; // Signature du message initial
} InitialMessage;

// Fonctions de génération et de gestion des pré-clés
void init_pre_key_bundle(PreKeyBundle *pkb, PrivateKeyBundle *skb);
void compute_key_id(const unsigned char *key, size_t key_len, unsigned char *id);

// Fonctions pour l'encapsulation et la décapsulation KEM
int kem_encapsulate(PreKeyBundle *pkb, unsigned char *shared_secret);
int kem_decapsulate(PrivateKeyBundle *skb, unsigned char *shared_secret, const unsigned char *ct);

// Calculs Diffie-Hellman pour générer des secrets partagés
int diffie_hellman(unsigned char *result, const unsigned char *sk, const unsigned char *pk);
int alice_handle_pre_key(PreKeyBundle *pkb, PrivateKeyBundle *skb, InitialMessage *initial_message);

// Fonctions pour le chiffrement et déchiffrement AES-GCM avec données associées
int encrypt_message(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *associated_data, size_t ad_len,
                    unsigned char *ciphertext, unsigned char *nonce);
int decrypt_message(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *associated_data, size_t ad_len,
                    const unsigned char *nonce, unsigned char *plaintext, NonceTracker *tracker);

// Fonctions pour le suivi et la gestion des nonces
int is_nonce_used(NonceTracker *tracker, const unsigned char *nonce);
void mark_nonce_used(NonceTracker *tracker, const unsigned char *nonce);

// Fonction pour dériver une clé avec SHAKE256
void derive_key_shake256(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len);

#endif // PQXDH_H
