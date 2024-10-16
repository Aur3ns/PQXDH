use aria_gcm::aead::{Aead, Nonce};
use aria_gcm::{AeadCore, Aria256Gcm, Key};
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use pqc_kem::{KeyEncapsulation, PublicKey as pqcPublicKey};
use rand::rngs::OsRng;
use sha3::{Digest, Shake256};
use std::error::Error;

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
fn encrypt_message(
    key: &Aria256Key,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Aria256Gcm::new(key);
    let mut rng = secure_rng();
    let nonce = Aria256Gcm::generate_nonce(&mut rng);

    cipher
        .encrypt(&nonce, associated_data, plaintext)
        .map_err(|e| format!("Erreur lors du chiffrement ARIA : {:?}", e).into())
}

// Amélioration : meilleure gestion des erreurs pour le déchiffrement avec ARIA
fn decrypt_message(
    key: &Aria256Key,
    initial_message: &InitialMessage,
) -> Result<String, Box<dyn Error>> {
    let cipher = Aria256Gcm::new(key);

    let plaintext = cipher
        .decrypt(&initial_message.nonce, &initial_message.ect)
        .map_err(|e| format!("Erreur lors du déchiffrement ARIA : {:?}", e))?;

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
    ) -> Result<InitialMessage, Box<dyn Error>> {
        // Vérification des signatures
        pkb.ik.verify(pkb.spk.as_ref(), &pkb.spk_sig)
            .map_err(|_| "Signature SPK invalide")?;
        pkb.ik.verify(pkb.opk.as_ref(), &pkb.opk_sig)
            .map_err(|_| "Signature OPK invalide")?;

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
        let cipher = Aria256Gcm::new(key);
        let nonce = Aria256Gcm::generate_nonce(&mut secure_rng());

        let associated_data = [pkb.ik.as_ref(), pkb.spk.as_ref(), pkb.opk.as_ref()].concat();

        // Demande de message à l'utilisateur
        println!("Veuillez entrer le message à chiffrer :");
        let mut user_message = String::new();
        std::io::stdin().read_line(&mut user_message)?;
        let user_message = user_message.trim_end();

        let ciphertext = cipher
            .encrypt(&nonce, &associated_data, user_message.as_bytes())
            .map_err(|e| format!("Erreur lors du chiffrement ARIA : {}", e))?;

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

// Gestion sécurisée des messages reçus par Bob
fn bob_handle_initial_message(
    im: &InitialMessage,
    skb: &PrivateKeyBundle,
    pkb: &PreKeyBundle,
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
    let cipher = Aria256Gcm::new(key);

    // Tentative de déchiffrement
    let plaintext = cipher
        .decrypt(&im.nonce, im.ect.as_ref())
        .map_err(|e| format!("Erreur lors du déchiffrement : {}", e))?;

    let plaintext_str = String::from_utf8_lossy(&plaintext);
    println!("Message déchiffré : {}", plaintext_str);

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
    let initial_message = InitialMessage::alice_handle_pre_key(&bob_key_bundle, &private_key_bundle)?;
    bob_handle_initial_message(&initial_message, &private_key_bundle, &bob_key_bundle)?;

    Ok(())
}
