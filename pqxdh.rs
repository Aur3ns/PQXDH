use aes_gcm::aead::{Aead, Nonce}; // AES-GCM pour le chiffrement authentifié
use aes_gcm::{Aes256Gcm, Key};    // AES-256-GCM
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use pqcrypto::kem::kyber1024::{KeyEncapsulation, PublicKey as pqcPublicKey}; // Post-quantum KEM
use rand::rngs::OsRng;
use sha3::{Digest, Shake256};
use std::collections::HashSet; // Pour suivre les nonces utilisés (protection contre rejouage)
use std::error::Error;

const AES_KEY_BYTES: usize = 32; // Taille de la clé AES 256 bits

type Aes256Key = Key<Aes256Gcm>;
type AesNonce = Nonce<Aes256Gcm>;

struct PreKeyBundle {
    ik: PublicKey,
    spk: ed25519_compact::x25519::PublicKey,
    opk: ed25519_compact::x25519::PublicKey,
    spk_sig: Signature,
    opk_sig: Signature,
    pqkem: Box<dyn KeyEncapsulation>,
    pqkem_ct: Vec<u8>,
    used_opks: HashSet<Vec<u8>>, // Suivi des pré-clés uniques utilisées
}

struct PrivateKeyBundle {
    ik: SecretKey,
    spk: SecretKey,
    opk: SecretKey,
    pqkem: Box<dyn KeyEncapsulation>,
}

struct InitialMessage {
    ik: PublicKey,
    ed: ed25519_compact::x25519::PublicKey,
    ct: Vec<u8>,
    ect: Vec<u8>,
    nonce: Nonce<Aes256Gcm>,
    signature: Signature,
}

// Fonction de génération de RNG sécurisé
fn secure_rng() -> OsRng {
    OsRng
}

// Chiffrement AES-GCM avec gestion des erreurs
fn encrypt_message(
    key: &Aes256Key,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, Nonce<Aes256Gcm>), Box<dyn Error>> {
    let cipher = Aes256Gcm::new(key);
    let mut rng = secure_rng();
    let nonce = Aes256Gcm::generate_nonce(&mut rng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("Erreur lors du chiffrement AES : {:?}", e).into())?;

    Ok((ciphertext, nonce))
}

// Déchiffrement AES-GCM avec gestion des erreurs
fn decrypt_message(
    key: &Aes256Key,
    initial_message: &InitialMessage,
    received_nonces: &mut HashSet<Vec<u8>>, // Protection contre rejouage
) -> Result<String, Box<dyn Error>> {
    let cipher = Aes256Gcm::new(key);

    // Protection contre rejouage : vérification du nonce unique
    if received_nonces.contains(&initial_message.nonce.to_vec()) {
        return Err("Erreur : Tentative de rejouage détectée".into());
    }
    received_nonces.insert(initial_message.nonce.to_vec()); // Ajout du nonce à la liste des nonces reçus

    let plaintext = cipher
        .decrypt(&initial_message.nonce, &initial_message.ect)
        .map_err(|e| format!("Erreur lors du déchiffrement AES : {:?}", e))?;

    String::from_utf8(plaintext).map_err(|_| "Erreur de conversion du texte en clair".into())
}

impl PreKeyBundle {
    fn new() -> Result<(PreKeyBundle, PrivateKeyBundle), Box<dyn Error>> {
        let bob_ik = KeyPair::generate();
        let bob_spk_ed25519 = KeyPair::generate();
        let bob_opk_ed25519 = KeyPair::generate();
        let bob_spk = ed25519_compact::x25519::PublicKey::from_ed25519(&bob_spk_ed25519.pk)?;
        let bob_opk = ed25519_compact::x25519::PublicKey::from_ed25519(&bob_opk_ed25519.pk)?;

        let spk_sig = bob_ik.sk.sign(bob_spk.as_ref(), Some(Noise::default()));
        let opk_sig = bob_ik.sk.sign(bob_opk.as_ref(), Some(Noise::default()));

        let mut rng = secure_rng();
        let bob_pqkem = pqcrypto::kem::kyber1024::keypair(&mut rng).map_err(|_| "Erreur lors de la génération des clés KEM")?;
        let (ct, _) = bob_pqkem.public.encapsulate().map_err(|_| "Erreur lors de l'encapsulation KEM")?;

        let pre_key_bundle = PreKeyBundle {
            ik: bob_ik.pk,
            spk: bob_spk,
            opk: bob_opk,
            spk_sig,
            opk_sig,
            pqkem: Box::new(bob_pqkem.public),
            pqkem_ct: ct,
            used_opks: HashSet::new(), // Initialisation du suivi des pré-clés uniques utilisées
        };

        let private_key_bundle = PrivateKeyBundle {
            ik: bob_ik.sk,
            spk: bob_spk_ed25519.sk,
            opk: bob_opk_ed25519.sk,
            pqkem: Box::new(bob_pqkem.private),
        };

        Ok((pre_key_bundle, private_key_bundle))
    }

    // Marquer la pré-clé unique comme utilisée
    fn mark_opk_used(&mut self) -> Result<(), &'static str> {
        if self.used_opks.contains(self.opk.as_ref()) {
            return Err("Erreur : Pré-clé unique déjà utilisée");
        }
        self.used_opks.insert(self.opk.as_ref().to_vec());
        Ok(())
    }
}

impl InitialMessage {
    fn alice_handle_pre_key(
        pkb: &mut PreKeyBundle, // Modification pour marquer la pré-clé utilisée
        skb: &PrivateKeyBundle,
    ) -> Result<InitialMessage, Box<dyn Error>> {
        // Vérification des signatures
        pkb.ik.verify(pkb.spk.as_ref(), &pkb.spk_sig)
            .map_err(|_| "Signature SPK invalide")?;
        pkb.ik.verify(pkb.opk.as_ref(), &pkb.opk_sig)
            .map_err(|_| "Signature OPK invalide")?;

        // Marquer la pré-clé unique comme utilisée (empêcher réutilisation)
        pkb.mark_opk_used()?;

        let mut rng = secure_rng();
        let (ct, ss) = pkb.pqkem.encapsulate().map_err(|_| "Erreur lors de l'encapsulation KEM")?;

        let bob_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&pkb.ik)?;
        let alice_ed_ik = KeyPair::generate();
        let alice_ik = ed25519_compact::x25519::SecretKey::from_ed25519(&alice_ed_ik.sk)?;
        let alice_ek = ed25519_compact::x25519::KeyPair::generate();

        let dh1 = pkb.spk.dh(&alice_ik).map_err(|_| "Erreur DH1")?;
        let dh2 = bob_ik_x25519.dh(&alice_ek.sk).map_err(|_| "Erreur DH2")?;
        let dh3 = pkb.spk.dh(&alice_ek.sk).map_err(|_| "Erreur DH3")?;
        let dh4 = pkb.opk.dh(&alice_ek.sk).map_err(|_| "Erreur DH4")?;

        let sum = [
            dh1.as_slice(),
            dh2.as_slice(),
            dh3.as_slice(),
            dh4.as_slice(),
            ss.as_slice(),
        ]
        .concat();

        let mut key_material: [u8; AES_KEY_BYTES] = [0; AES_KEY_BYTES];
        derive_key_shake256(&sum, &mut key_material);

        let key = Key::<Aes256Gcm>::from_slice(&key_material);
        let (ciphertext, nonce) = encrypt_message(key, &[], &[])?;

        let message_data = [
            pkb.ik.as_ref(),
            pkb.spk.as_ref(),
            pkb.opk.as_ref(),
            &ct,
            &ciphertext,
            &nonce.to_bytes(),
        ]
        .concat();
        let signature = skb.ik.sign(&message_data, Some(Noise::default()));

        Ok(InitialMessage {
            ik: alice_ed_ik.pk,
            ed: alice_ek.pk,
            ct,
            ect: ciphertext,
            nonce,
            signature,
        })
    }
}

// Fonction de dérivation de clé via SHAKE256
fn derive_key_shake256(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    hasher.finalize(output);
}

fn main() -> Result<(), Box<dyn Error>> {
    let (mut bob_key_bundle, private_key_bundle) = PreKeyBundle::new()?; // Ajout de mut pour gérer les pré-clés utilisées
    let initial_message = InitialMessage::alice_handle_pre_key(&mut bob_key_bundle, &private_key_bundle)?;

    // Création d'un ensemble pour les nonces reçus (protection contre rejouage)
    let mut received_nonces = HashSet::new();

    // Exemple : déchiffrement (message fictif, à adapter à votre implémentation)
    let plaintext = decrypt_message(
        &Key::<Aes256Gcm>::from_slice(&[0u8; AES_KEY_BYTES]), // Clé fictive ici
        &initial_message,
        &mut received_nonces,
    )?;

    println!("Message déchiffré : {}", plaintext);
    Ok(())
}
