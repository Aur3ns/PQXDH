use aria_gcm::aead::{Aead, Nonce};
use aria_gcm::{AeadCore, Aria256Gcm, Key};
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use hkdf::Hkdf;
use pqc_kyber::{decapsulate, encapsulate, keypair, PublicKey as pqcPublicKey};
use rand::rngs::OsRng;
use sha2::Sha512;

// Définition de la taille de la clé Aria256Gcm
const ARIA_KEY_BYTES: usize = 32;
type Aria256Key = Key<Aria256Gcm>;
type AriaNonce = Nonce<Aria256Gcm>;

// Structure représentant le bundle de clés prépartagées
struct PreKeyBundle {
    ik: PublicKey,
    spk: ed25519_compact::x25519::PublicKey,
    opk: ed25519_compact::x25519::PublicKey,
    spk_sig: Signature,
    opk_sig: Signature,
    pqkem: pqcPublicKey,
    pqkem_sig: Signature,
}

// Structure représentant le bundle de clés privées
struct PrivateKeyBundle {
    ik: SecretKey,
    spk: SecretKey,
    opk: SecretKey,
    pqkem: Keypair,
}

// Structure représentant le message initial échangé entre Alice et Bob
struct InitialMessage {
    ik: PublicKey,
    ed: ed25519_compact::x25519::PublicKey,
    ct: [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES],
    ect: Vec<u8>,
    nonce: Nonce<Aria256Gcm>,
    signature: Signature, // Signature pour l'authenticité du message
}

// Fonction principale
fn main() {
    // Générer un bundle de clés prépartagées pour Bob
    let bob_key_bundle = PreKeyBundle::new();
    // Générer le message initial à envoyer par Alice
    let initial_message = InitialMessage::alice_handle_pre_key(&bob_key_bundle.0, &bob_key_bundle.1);
    // Traiter le message initial du point de vue de Bob
    bob_handle_initial_message(&initial_message, &bob_key_bundle.1);
}

// Fonction pour obtenir un générateur de nombres aléatoires sécurisé
fn secure_rng() -> OsRng {
    OsRng
}

// Fonction pour chiffrer un message avec Aria256Gcm
fn encrypt_message(key: &Aria256Key, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = Aria256Gcm::new(key);
    let mut rng = secure_rng();
    let nonce = Aria256Gcm::generate_nonce(&mut rng);

    cipher
        .encrypt(&nonce, associated_data, plaintext)
        .map_err(|_| "Error during ARIA encryption")
}

// Fonction pour déchiffrer un message avec Aria256Gcm
fn decrypt_message(key: &Aria256Key, initial_message: &InitialMessage) -> Result<String, &'static str> {
    let cipher = Aria256Gcm::new(key);

    cipher
        .decrypt(&initial_message.nonce, &initial_message.ect)
        .map_err(|_| "Error during ARIA decryption")
        .and_then(|plaintext| String::from_utf8(plaintext).map_err(|_| "Error converting plaintext to string"))
}

// Implémentation des méthodes pour la structure PreKeyBundle
impl PreKeyBundle {
    // Méthode pour générer un nouveau bundle de clés prépartagées
    fn new() -> (PreKeyBundle, PrivateKeyBundle) {
        // Générer les paires de clés nécessaires
        let bob_ik = KeyPair::generate();
        let bob_spk_ed25519 = KeyPair::generate();
        let bob_opk_ed25519 = KeyPair::generate();
        let bob_spk = ed25519_compact::x25519::PublicKey::from_ed25519(&bob_spk_ed25519.pk).unwrap();
        let bob_opk = ed25519_compact::x25519::PublicKey::from_ed25519(&bob_opk_ed25519.pk).unwrap();
        
        // Signer les clés publiques avec la clé privée de l'identité de Bob
        let spk_sig = bob_ik.sk.sign(bob_spk.as_ref(), Some(Noise::default()));
        let opk_sig = bob_ik.sk.sign(bob_opk.as_ref(), Some(Noise::default()));
        
        // Générer une paire de clés pour le protocole pqc_kyber
        let mut rng = rand::thread_rng();
        let bob_pqkem = keypair(&mut rng).unwrap();
        let pqkem_sig = bob_ik.sk.sign(bob_pqkem.public.as_ref(), Some(Noise::default()));

        // Créer le bundle de clés prépartagées
        let pre_key_bundle = PreKeyBundle {
            ik: bob_ik.pk,
            spk: bob_spk,
            opk: bob_opk,
            spk_sig,
            opk_sig,
            pqkem: bob_pqkem.public,
            pqkem_sig,
        };

        // Créer le bundle de clés privées correspondant
        let private_key_bundle = PrivateKeyBundle {
            ik: bob_ik.sk,
            spk: bob_spk_ed25519.sk,
            opk: bob_opk_ed25519.sk,
            pqkem: bob_pqkem,
        };

        (pre_key_bundle, private_key_bundle)
    }
}

// Implémentation des méthodes pour la structure InitialMessage
impl InitialMessage {
    // Méthode pour qu'Alice génère un message initial
    fn alice_handle_pre_key(pkb: &PreKeyBundle, skb: &PrivateKeyBundle) -> Result<InitialMessage, &'static str> {
        // Vérifier les signatures des clés publiques dans le bundle
        if let Err(e) = pkb.ik.verify(pkb.spk.as_ref(), &pkb.spk_sig) {
            panic!("Error: {}", e)
        }
        if let Err(e) = pkb.ik.verify(pkb.opk.as_ref(), &pkb.opk_sig) {
            panic!("Error: {}", e)
        }
        if let Err(e) = pkb.ik.verify(pkb.pqkem.as_ref(), &pkb.pqkem_sig) {
            panic!("Error: {}", e)
        }

        // Générer des données pour encapsuler avec le protocole pqc_kyber
        let mut rng = rand::thread_rng();
        let (ct, ss): (
            [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES],
            [u8; pqc_kyber::KYBER_SSBYTES],
        ) = encapsulate(&pkb.pqkem, &mut rng).unwrap();

        // Convertir la clé publique d'Alice au format x25519
        let bob_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&pkb.ik).unwrap();

        // Générer des paires de clés pour le protocole Noise
        let alice_ed_ik = KeyPair::generate();
        let alice_ik = ed25519_compact::x25519::SecretKey::from_ed25519(&alice_ed_ik.sk).unwrap();
        let alice_ek = ed25519_compact::x25519::KeyPair::generate();
        
        // Calculer les échanges de clés Diffie-Hellman
        let dh1 = pkb.spk.dh(&alice_ik).unwrap();
        let dh2 = bob_ik_x25519.dh(&alice_ek.sk).unwrap();
        let dh3 = pkb.spk.dh(&alice_ek.sk).unwrap();
        let dh4 = pkb.opk.dh(&alice_ek.sk).unwrap();
        
        // Concaténer les résultats pour HKDF
        let sum = [
            dh1.as_slice(),
            dh2.as_slice(),
            dh3.as_slice(),
            dh4.as_slice(),
            ss.as_slice(),
        ]
        .concat();
        
        // Dérivation de clé via HKDF
        let sk = Hkdf::<Sha512>::new(None, sum.as_slice());
        let mut key_material: [u8; ARIA_KEY_BYTES] = [0; ARIA_KEY_BYTES];
        let data = "alice".as_bytes();
        sk.expand(data, &mut key_material).map_err(|_| "Error during key expansion")?;

        // Créer la clé Aria256Gcm
        let key: &Aria256Key = &Key::<Aria256Gcm>::clone_from_slice(&key_material);
        let cipher = Aria256Gcm::new(key);

        // Générer un nonce pour Aria256Gcm
        let nonce = Aria256Gcm::generate_nonce(&mut secure_rng());
        
        // Préparer les données associées pour Aria256Gcm
        let associated_data = [pkb.ik.as_ref(), pkb.spk.as_ref(), pkb.opk.as_ref()].concat();
        
        // Chiffrer le message avec Aria256Gcm
        let ciphertext = cipher
            .encrypt(&nonce, &associated_data, b"totally secret first message".as_ref())
            .map_err(|e| format!("Error during ARIA encryption: {}", e))
            .unwrap();

        // Ajouter la signature du message pour l'authenticité
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

        // Créer et retourner le message initial
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

// Fonction pour traiter le message initial du point de vue de Bob
fn bob_handle_initial_message(im: &InitialMessage, skb: &PrivateKeyBundle) {
    // Convertir la clé publique d'Alice au format x25519
    let alice_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&im.ik).unwrap();

    // Extraire les clés privées de Bob
    let bob_ik_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.ik).unwrap();
    let bob_opk_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.opk).unwrap();
    let bob_spk_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.spk).unwrap();

    // Récupérer la clé partagée et le matériel de clé
    let ss: [u8; pqc_kyber::KYBER_SSBYTES] = decapsulate(&im.ct, &skb.pqkem.secret).unwrap();
    let dh1 = alice_ik_x25519.dh(&bob_spk_x25519).unwrap();
    let dh2 = im.ed.dh(&bob_ik_x25519).unwrap();
    let dh3 = im.ed.dh(&bob_spk_x25519).unwrap();
    let dh4 = im.ed.dh(&bob_opk_x25519).unwrap();
    let sum = [
        dh1.as_slice(),
        dh2.as_slice(),
        dh3.as_slice(),
        dh4.as_slice(),
        ss.as_slice(),
    ]
    .concat();

    // Dérivation de clé via HKDF
    let sk = Hkdf::<Sha512>::new(None, sum.as_slice());
    let mut key: [u8; ARIA_KEY_BYTES] = [0; ARIA_KEY_BYTES];
    let data = "alice".as_bytes();
    sk.expand(data, &mut key)
        .map_err(|_| "Error during key expansion")
        .expect("Key expansion failed");

    // Création de la clé Aria256Gcm
    let key: &Aria256Key = &Key::<Aria256Gcm>::clone_from_slice(&key);
    let cipher = Aria256Gcm::new(key);

    // Déchiffrement du message
    let plaintext_result = cipher.decrypt(&im.nonce, im.ect.as_ref());
    match plaintext_result {
        Ok(plaintext) => {
            let plaintext_str = String::from_utf8_lossy(&plaintext);
            println!("Decrypted message: {}", plaintext_str);
            // Utiliser le message déchiffré dans votre application...
        }
        Err(e) => {
            eprintln!("Error during decryption: {}", e);
            // Autres actions à prendre en cas d'erreur de déchiffrement...
        }
    }
}
