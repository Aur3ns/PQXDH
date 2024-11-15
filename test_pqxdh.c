#include <stdio.h>
#include <string.h>
#include "pqxdh.h" // Le fichier .h de votre implémentation PQXDH

void test_key_initialization() {
    PreKeyBundle pkb1, pkb2;
    PrivateKeyBundle skb1, skb2;

    init_pre_key_bundle(&pkb1, &skb1);
    init_pre_key_bundle(&pkb2, &skb2);

    // Vérification que les clés publiques sont différentes
    if (memcmp(pkb1.ik, pkb2.ik, sizeof(pkb1.ik)) != 0) {
        printf("Test d'initialisation des clés : PASS\n");
    } else {
        printf("Test d'initialisation des clés : FAIL\n");
    }
}

void test_kem_encapsulation_decapsulation() {
    PreKeyBundle pkb;
    PrivateKeyBundle skb;

    init_pre_key_bundle(&pkb, &skb);

    unsigned char ss_enc[OQS_KEM_kyber_1024_length_shared_secret];
    unsigned char ss_dec[OQS_KEM_kyber_1024_length_shared_secret];
    OQS_KEM_encaps(pkb.pqkem, pkb.pqkem_ct, ss_enc, pkb.pqkem_public);
    OQS_KEM_decaps(pkb.pqkem, ss_dec, pkb.pqkem_ct, skb.pqkem_private);

    if (memcmp(ss_enc, ss_dec, sizeof(ss_enc)) == 0) {
        printf("Test KEM encapsulation/décapsulation : PASS\n");
    } else {
        printf("Test KEM encapsulation/décapsulation : FAIL\n");
    }
}

void test_diffie_hellman() {
    PreKeyBundle pkb;
    PrivateKeyBundle skb;
    InitialMessage initial_message;

    init_pre_key_bundle(&pkb, &skb);

    if (alice_handle_pre_key(&pkb, &skb, &initial_message) == 0) {
        printf("Test Diffie-Hellman et message initial : PASS\n");
    } else {
        printf("Test Diffie-Hellman et message initial : FAIL\n");
    }
}

void test_encryption_decryption() {
    printf("Début du test de chiffrement/déchiffrement\n");

    unsigned char key[AES_KEY_BYTES];
    RAND_bytes(key, AES_KEY_BYTES);

    unsigned char plaintext[] = "Ceci est un message de test.";
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    unsigned char nonce[AES_NONCE_BYTES];
    unsigned char associated_data[] = "Données associées";

    printf("Clé AES : ");
    for (int i = 0; i < AES_KEY_BYTES; i++) printf("%02x", key[i]);
    printf("\n");

    printf("Chiffrement en cours...\n");
    int ciphertext_len = encrypt_message(key, plaintext, strlen((char *)plaintext),
                                         associated_data, sizeof(associated_data),
                                         ciphertext, nonce);

    if (ciphertext_len < 0) {
        printf("Erreur lors du chiffrement\n");
        return;
    }

    printf("Nonce utilisé : ");
    for (int i = 0; i < AES_NONCE_BYTES; i++) printf("%02x", nonce[i]);
    printf("\n");

    printf("Données associées (chiffrement) : %s\n", associated_data);

    printf("Déchiffrement en cours...\n");
    NonceTracker tracker = {0};
    int decrypted_len = decrypt_message(key, ciphertext, ciphertext_len,
                                        associated_data, sizeof(associated_data),
                                        nonce, decrypted, &tracker);

    if (decrypted_len >= 0) {
        decrypted[decrypted_len] = '\0';
        printf("Texte déchiffré : %s\n", decrypted);
    } else {
        printf("Erreur de déchiffrement\n");
    }

    printf("Données associées (déchiffrement) : %s\n", associated_data);

    if (strcmp((char *)plaintext, (char *)decrypted) == 0) {
        printf("Test chiffrement/déchiffrement : PASS\n");
    } else {
        printf("Test chiffrement/déchiffrement : FAIL\n");
    }

    printf("Fin du test de chiffrement/déchiffrement\n");
}

int main() {
    test_key_initialization();
    test_kem_encapsulation_decapsulation();
    test_diffie_hellman();
    test_encryption_decryption();

    return 0;
}
