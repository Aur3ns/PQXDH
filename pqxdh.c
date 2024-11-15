#include "pqxdh.h"

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

// Fonction pour stocker le nonce utilisé
void mark_nonce_used(NonceTracker *tracker, const unsigned char *nonce) {
    if (tracker->count < MAX_USED_OPKS) {
        memcpy(tracker->used_nonces[tracker->count], nonce, AES_NONCE_BYTES);
        tracker->count++;
    }
}

// Fonction pour SHAKE256 pour dériver la clé
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

// Fonction principale de l'échange de clés
int alice_handle_pre_key(PreKeyBundle *pkb, PrivateKeyBundle *skb, InitialMessage *initial_message) {
    // Vérification des signatures des pré-clés
    if (crypto_sign_verify_detached(pkb->spk_sig, pkb->spk, crypto_scalarmult_curve25519_BYTES, pkb->ik) != 0) {
        fprintf(stderr, "Erreur : signature SPK invalide\n");
        return -1;
    }
    if (crypto_sign_verify_detached(pkb->opk_sig, pkb->opk, crypto_scalarmult_curve25519_BYTES, pkb->ik) != 0) {
        fprintf(stderr, "Erreur : signature OPK invalide\n");
        return -1;
    }

    // Calcul des DH
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];
    unsigned char dh4[crypto_scalarmult_BYTES];

    if (crypto_scalarmult_curve25519(dh1, skb->spk, pkb->spk) != 0 ||
        crypto_scalarmult_curve25519(dh2, skb->opk, pkb->ik) != 0 ||
        crypto_scalarmult_curve25519(dh3, skb->spk, pkb->opk) != 0 ||
        crypto_scalarmult_curve25519(dh4, skb->opk, pkb->spk) != 0) {
        fprintf(stderr, "Erreur : échec des calculs Diffie-Hellman\n");
        return -1;
    }

    // Concaténation des DH et dérivation de clé
    unsigned char key_material[AES_KEY_BYTES];
    unsigned char input[sizeof(dh1) + sizeof(dh2) + sizeof(dh3) + sizeof(dh4) + sizeof(pkb->shared_secret_bytes)];
    memcpy(input, dh1, sizeof(dh1));
    memcpy(input + sizeof(dh1), dh2, sizeof(dh2));
    memcpy(input + sizeof(dh1) + sizeof(dh2), dh3, sizeof(dh3));
    memcpy(input + sizeof(dh1) + sizeof(dh2) + sizeof(dh3), dh4, sizeof(dh4));
    memcpy(input + sizeof(dh1) + sizeof(dh2) + sizeof(dh3) + sizeof(dh4), pkb->shared_secret_bytes, sizeof(pkb->shared_secret_bytes));

    derive_key_shake256(input, sizeof(input), key_material, AES_KEY_BYTES);

    // Clé dérivée avec succès
    return 0;
}

int main() {
    PreKeyBundle pkb;
    PrivateKeyBundle skb;
    InitialMessage initial_message;

    init_pre_key_bundle(&pkb, &skb);

    if (alice_handle_pre_key(&pkb, &skb, &initial_message) == 0) {
        printf("Échange de clés réussi.\n");
    } else {
        printf("Échec de l'échange de clés.\n");
    }

    return 0;
}
