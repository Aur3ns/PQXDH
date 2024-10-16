use aria_gcm::aead::{Aead, Nonce};
use aria_gcm::{AeadCore, Aria256Gcm, Key};
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use pqc_kem::{KeyEncapsulation, PublicKey as pqcPublicKey};
use rand::rngs::OsRng;
use sha3::{Digest, Shake256};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read, Write};

const ARIA_KEY_BYTES: usize = 32;
type Aria256Key = Key<Aria256Gcm>;
type AriaNonce = Nonce<Aria256Gcm>;

struct PreKeyBundle {
    ik: PublicKey,
    spk: ed25519_compact::x25519::PublicKey,
    opk: ed25519_compact::x25519::PublicKey,
    spk_sig: Signature,
    opk_sig: Signature,
    pqkem: Box<dyn KeyEncapsulation>,
    pqkem_ct: Vec<u8>,
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
    nonce: Nonce<Aria256Gcm>,
    signature: Signature,
}

// Fonction de génération de RNG sécurisé
fn secure_rng() -> OsRng {
    OsRng
}

// Amélioration : meilleure gestion des erreurs pour le chiffrement avec ARIA
fn encrypt_file(
    key: &Aria256Key,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, Nonce<Aria256Gcm>), Box<dyn Error>> {
    let cipher = Aria256Gcm::new(key);
    let mut rng = secure_rng();
    let nonce = Aria256Gcm::generate_nonce(&mut rng);

    let ciphertext = cipher
        .encrypt(&nonce, associated_data, plaintext)
        .map_err(|e| format!("Erreur lors du chiffrement ARIA : {:?}", e))?;

    Ok((ciphertext, nonce))
}

// Amélioration : meilleure gestion des erreurs pour le déchiffrement avec ARIA
fn decrypt_file(
    key: &Aria256Key,
    nonce: &Nonce<Aria256Gcm>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Aria256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Erreur lors du déchiffrement : {:?}", e))?;

    Ok(plaintext)
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
        let bob_pqkem = pqc_kem::keypair(&mut rng).map_err(|_| "Erreur lors de la génération des clés KEM")?;
        let (ct, _) = bob_pqkem.public.encapsulate().map_err(|_| "Erreur lors de l'encapsulation KEM")?;

        let pre_key_bundle = PreKeyBundle {
            ik: bob_ik.pk,
            spk,
            opk,
            spk_sig,
            opk_sig,
            pqkem: Box::new(bob_pqkem.public),
            pqkem_ct: ct,
        };

        let private_key_bundle = PrivateKeyBundle {
            ik: bob_ik.sk,
            spk: bob_spk_ed25519.sk,
            opk: bob_opk_ed25519.sk,
            pqkem: Box::new(bob_pqkem.private),
        };

        Ok((pre_key_bundle, private_key_bundle))
    }
}

impl InitialMessage {
    fn alice_handle_pre_key(
        pkb: &PreKeyBundle,
        skb: &PrivateKeyBundle,
        file_path: &str,
    ) -> Result<InitialMessage, Box<dyn Error>> {
        // Vérification des signatures
        pkb.ik.verify(pkb.spk.as_ref(), &pkb.spk_sig)
            .map_err(|_| "Signature SPK invalide")?;
        pkb.ik.verify(pkb.opk.as_ref(), &pkb.opk_sig)
            .map_err(|_| "Signature OPK invalide")?;

        // Lire le contenu du fichier à chiffrer
        let plaintext = fs::read(file_path).map_err(|e| format!("Erreur lors de la lecture du fichier : {:?}", e))?;

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

        let mut key_material: [u8; ARIA_KEY_BYTES] = [0; ARIA_KEY_BYTES];
        derive_key_shake256(&sum, &mut key_material);

        let key: &Aria256Key = &Key::<Aria256Gcm>::clone_from_slice(&key_material);
        let (ciphertext, nonce) = encrypt_file(key, &plaintext, &[])?;

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

// Gestion sécurisée des fichiers reçus par Bob
fn bob_handle_initial_message(
    im: &InitialMessage,
    skb: &PrivateKeyBundle,
    pkb: &PreKeyBundle,
    output_file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let alice_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&im.ik)?;
    let bob_ik_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.ik)?;
    let bob_opk_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.opk)?;
    let bob_spk_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.spk)?;

    let ss: [u8; pqc_kem::KYBER_SSBYTES] = pkb.pqkem.decapsulate(&im.ct)
        .map_err(|_| "Erreur lors de la décapsulation KEM")?;

    let dh1 = alice_ik_x25519.dh(&bob_spk_x25519)?;
    let dh2 = im.ed.dh(&bob_ik_x25519)?;
    let dh3 = im.ed.dh(&bob_spk_x25519)?;
    let dh4 = im.ed.dh(&bob_opk_x25519)?;
    let sum = [
        dh1.as_slice(),
        dh2.as_slice(),
        dh3.as_slice(),
        dh4.as_slice(),
        ss.as_slice(),
    ]
    .concat();

    let mut key_material: [u8; ARIA_KEY_BYTES] = [0; ARIA_KEY_BYTES];
    derive_key_shake256(&sum, &mut key_material);

    let key: &Aria256Key = &Key::<Aria256Gcm>::clone_from_slice(&key_material);
    let plaintext = decrypt_file(key, &im.nonce, im.ect.as_ref())?;

    // Écrire le fichier déchiffré
    let mut output_file = File::create(output_file_path)
        .map_err(|e| format!("Erreur lors de la création du fichier de sortie : {:?}", e))?;
    output_file.write_all(&plaintext)
        .map_err(|e| format!("Erreur lors de l'écriture dans le fichier : {:?}", e))?;

    println!("Fichier déchiffré avec succès et enregistré sous : {}", output_file_path);

    Ok(())
}

// Fonction de dérivation de clé via SHAKE256
fn derive_key_shake256(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    hasher.finalize(output);
}

fn main() -> Result<(), Box<dyn Error>> {
    let (bob_key_bundle, private_key_bundle) = PreKeyBundle::new()?;
    
    // Remplacez "chemin/vers/votre/fichier.txt" par le chemin de votre fichier à chiffrer
    let initial_message = InitialMessage::alice_handle_pre_key(&bob_key_bundle, &private_key_bundle, "chemin/vers/votre/fichier.txt")?;
    
    // Remplacez "chemin/vers/fichier_dechiffre.txt" par le chemin où vous souhaitez enregistrer le fichier déchiffré
    bob_handle_initial_message(&initial_message, &private_key_bundle, &bob_key_bundle, "chemin/vers/fichier_dechiffre.txt")?;

    Ok(())
}
