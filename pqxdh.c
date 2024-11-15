#include "pqxdh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Fonction pour générer un nonce sécurisé
void generate_nonce(unsigned char *nonce, size_t size) {
    if (RAND_bytes(nonce, size) != 1) {
        fprintf(stderr, "Erreur : génération de nonce échouée\n");
        exit(EXIT_FAILURE);
    }
}

// Fonction pour calculer un identifiant unique par hachage SHA-256
void compute_key_id(const unsigned char *key, size_t key_len, unsigned char *id) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erreur : échec d'allocation pour EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, key, key_len);
    EVP_DigestFinal_ex(mdctx, id, NULL);
    EVP_MD_CTX_free(mdctx);
}

// Fonction pour vérifier si un nonce a déjà été utilisé
int is_nonce_used(NonceTracker *tracker, const unsigned char *nonce) {
    for (int i = 0; i < tracker->count; i++) {
        if (memcmp(tracker->used_nonces[i], nonce, AES_NONCE_BYTES) == 0) {
            return 1; // Nonce déjà utilisé
        }
    }
    return 0;
}

// Fonction pour marquer un nonce comme utilisé
void mark_nonce_used(NonceTracker *tracker, const unsigned char *nonce) {
    if (tracker->count < MAX_USED_OPKS) {
        memcpy(tracker->used_nonces[tracker->count], nonce, AES_NONCE_BYTES);
        tracker->count++;
    } else {
        fprintf(stderr, "Erreur : limite des nonces utilisés atteinte\n");
        exit(EXIT_FAILURE);
    }
}

// Fonction pour SHAKE256 pour dériver une clé
void derive_key_shake256(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erreur : échec d'allocation pour EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }
    EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(mdctx, input, input_len);
    EVP_DigestFinalXOF(mdctx, output, output_len);
    EVP_MD_CTX_free(mdctx);
}

int encrypt_message(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *associated_data, size_t ad_len,
                    unsigned char *ciphertext, unsigned char *nonce) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Erreur : échec d'initialisation de EVP_CIPHER_CTX\n");
        return -1;
    }

    int len, ciphertext_len;

    generate_nonce(nonce, AES_NONCE_BYTES);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        fprintf(stderr, "Erreur : échec d'initialisation AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (ad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, associated_data, ad_len) != 1) {
        fprintf(stderr, "Erreur : échec d'ajout des données associées\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Erreur : échec du chiffrement AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Erreur : échec de la finalisation AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + ciphertext_len) != 1) {
        fprintf(stderr, "Erreur : échec de récupération du tag GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += 16;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int decrypt_message(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *associated_data, size_t ad_len,
                    const unsigned char *nonce, unsigned char *plaintext, NonceTracker *tracker) {
    if (tracker && is_nonce_used(tracker, nonce)) {
        fprintf(stderr, "Erreur : tentative de réutilisation du nonce détectée\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Erreur : échec d'initialisation de EVP_CIPHER_CTX\n");
        return -1;
    }

    int len, plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        fprintf(stderr, "Erreur : échec d'initialisation AES-GCM pour le déchiffrement\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (ad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &len, associated_data, ad_len) != 1) {
        fprintf(stderr, "Erreur : échec de la vérification des données associées\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(ciphertext + ciphertext_len - 16)) != 1) {
        fprintf(stderr, "Erreur : échec de la configuration du tag GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len -= 16;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Erreur : échec du déchiffrement AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "Erreur : déchiffrement AES-GCM invalide (données corrompues ?)\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    if (tracker) mark_nonce_used(tracker, nonce);
    return plaintext_len;
}


// Initialisation des pré-clés et des clés privées
void init_pre_key_bundle(PreKeyBundle *pkb, PrivateKeyBundle *skb) {
    crypto_sign_keypair(pkb->ik, skb->ik);
    crypto_sign_keypair(pkb->spk, skb->spk);
    crypto_sign_keypair(pkb->opk, skb->opk);

    crypto_sign_detached(pkb->spk_sig, NULL, pkb->spk, crypto_scalarmult_curve25519_BYTES, skb->ik);
    crypto_sign_detached(pkb->opk_sig, NULL, pkb->opk, crypto_scalarmult_curve25519_BYTES, skb->ik);

    compute_key_id(pkb->spk, crypto_scalarmult_curve25519_BYTES, pkb->spk_id);
    compute_key_id(pkb->opk, crypto_scalarmult_curve25519_BYTES, pkb->opk_id);

    pkb->pqkem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!pkb->pqkem) {
        fprintf(stderr, "Erreur : échec d'initialisation de Kyber KEM\n");
        exit(EXIT_FAILURE);
    }
    OQS_KEM_keypair(pkb->pqkem, pkb->pqkem_public, skb->pqkem_private);
}

// Fonction principale de l'échange de clés
int alice_handle_pre_key(PreKeyBundle *pkb, PrivateKeyBundle *skb, InitialMessage *initial_message) {
    unsigned char dh1[crypto_scalarmult_BYTES], dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES], dh4[crypto_scalarmult_BYTES];

    if (crypto_scalarmult_curve25519(dh1, skb->spk, pkb->spk) != 0 ||
        crypto_scalarmult_curve25519(dh2, skb->opk, pkb->ik) != 0 ||
        crypto_scalarmult_curve25519(dh3, skb->spk, pkb->opk) != 0 ||
        crypto_scalarmult_curve25519(dh4, skb->opk, pkb->spk) != 0) {
        fprintf(stderr, "Erreur : échec des calculs Diffie-Hellman\n");
        return -1;
    }

    unsigned char key_material[AES_KEY_BYTES];
    unsigned char input[sizeof(dh1) + sizeof(dh2) + sizeof(dh3) + sizeof(dh4) + sizeof(pkb->shared_secret_bytes)];
    memcpy(input, dh1, sizeof(dh1));
    memcpy(input + sizeof(dh1), dh2, sizeof(dh2));
    memcpy(input + sizeof(dh1) + sizeof(dh2), dh3, sizeof(dh3));
    memcpy(input + sizeof(dh1) + sizeof(dh2) + sizeof(dh3), dh4, sizeof(dh4));
    memcpy(input + sizeof(dh1) + sizeof(dh2) + sizeof(dh3) + sizeof(dh4), pkb->shared_secret_bytes, sizeof(pkb->shared_secret_bytes));

    derive_key_shake256(input, sizeof(input), key_material, AES_KEY_BYTES);
    printf("Clé dérivée avec succès\n");
    return 0;
}
