use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{AeadCore, Aes256Gcm, Key};
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use hkdf::Hkdf;
use pqc_kyber::{decapsulate, encapsulate, keypair, PublicKey as pqcPublicKey};
use rand::rngs::OsRng;
use sha2::Sha256;

// pqxdh spec: https://signal.org/docs/specifications/pqxdh/

const AES_KEY_BYTES: usize = 32;

fn main() {
    let bob_key_bundle = PreKeyBundle::new();
    let initial_message = InitialMessage::alice_handle_pre_key(&bob_key_bundle.0);
    bob_handle_initial_message(&initial_message, &bob_key_bundle.1)
}


#[derive(Debug)]
struct PreKeyBundle {
    ik: PublicKey,
    spk: ed25519_compact::x25519::PublicKey,
    opk: ed25519_compact::x25519::PublicKey,
    spk_sig: Signature,
    opk_sig: Signature,
    pqkem: pqcPublicKey,
    pqkem_sig: Signature,
}

#[derive(Debug)]
struct PrivateKeyBundle {
    ik: SecretKey,
    spk: SecretKey,
    opk: SecretKey,
    pqkem: Keypair,
}

#[derive(Debug)]
struct InitialMessage {
    ik: PublicKey,
    ed: ed25519_compact::x25519::PublicKey,
    ct: [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES],
    ect: Vec<u8>,
    nonce: Nonce<Aes256Gcm>,
}

fn secure_rng() -> OsRng {
    OsRng
}

// Refactor encryption function for reusability
fn encrypt_message(key: &Key<Aes256Gcm>, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut secure_rng());

    cipher
        .encrypt(&nonce, associated_data, plaintext)
        .map_err(|_| "Error during AES encryption")
}

// Refactor decryption function for reusability
fn decrypt_message(key: &Key<Aes256Gcm>, initial_message: &InitialMessage) -> Result<String, &'static str> {
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(&initial_message.nonce, &initial_message.ect)
        .map_err(|_| "Error during AES decryption")
        .and_then(|plaintext| String::from_utf8(plaintext).map_err(|_| "Error converting plaintext to string"))

impl PreKeyBundle {
    fn new() -> (PreKeyBundle, PrivateKeyBundle) {
        // Create bob's identity, signed prekey, and onetime, prekey as ed25519 KeyPairs
        let bob_ik = KeyPair::generate();
        let bob_spk_ed25519 = KeyPair::generate();
        let bob_opk_ed25519 = KeyPair::generate();
        // Convert bob's signed prekey and onetime prekey into x25519 PublicKeys
        let bob_spk =
            ed25519_compact::x25519::PublicKey::from_ed25519(&bob_spk_ed25519.pk).unwrap();
        let bob_opk =
            ed25519_compact::x25519::PublicKey::from_ed25519(&bob_opk_ed25519.pk).unwrap();
        // Sign the signed prekey and onetime prekey with bob's identity key
        let spk_sig = bob_ik.sk.sign(bob_spk.as_ref(), Some(Noise::default()));
        let opk_sig = bob_ik.sk.sign(bob_opk.as_ref(), Some(Noise::default()));
        // create an random source
        let mut rng = rand::thread_rng();
        // use the random source to generate a Kyber Keypair
        let bob_pqkem = keypair(&mut rng).unwrap();
        // sign the Kyber public key
        let pqkem_sig = bob_ik
            .sk
            .sign(bob_pqkem.public.as_ref(), Some(Noise::default()));
        // give the PreKeyBundle that will be sent to the "server"
        // also give the Private Key Bundle so bob can finish the pqxdh when the "server" contacts him with the initial message
        (
            PreKeyBundle {
                ik: bob_ik.pk,
                spk: bob_spk,
                opk: bob_opk,
                spk_sig,
                opk_sig,
                pqkem: bob_pqkem.public,
                pqkem_sig,
            },
            PrivateKeyBundle {
                ik: bob_ik.sk,
                spk: bob_spk_ed25519.sk,
                opk: bob_opk_ed25519.sk,
                pqkem: bob_pqkem,
            },
        )
    }
}

#[derive(Debug)]
struct InitialMessage {
    // Public ed25519 identity key
    ik: PublicKey,
    // Public x25519 ephemeral key
    ed: ed25519_compact::x25519::PublicKey,
    // kyber cipher text
    ct: [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES],
    // aes encrypted cipher text
    ect: Vec<u8>,
    // aes nonce
    nonce: Nonce<Aes256Gcm>,
}

impl InitialMessage {
    pub fn alice_handle_pre_key(pkb: &PreKeyBundle) -> Result<InitialMessage, &'static str> {
        // verify keys
        if let Err(e) = pkb.ik.verify(pkb.spk.as_ref(), &pkb.spk_sig) {
            panic!("Error: {}", e)
        }
        if let Err(e) = pkb.ik.verify(pkb.opk.as_ref(), &pkb.opk_sig) {
            panic!("Error: {}", e)
        }
        if let Err(e) = pkb.ik.verify(pkb.pqkem.as_ref(), &pkb.pqkem_sig) {
            panic!("Error: {}", e)
        }
        // source of entropy
        let mut rng = rand::thread_rng();
        // ciphertext and shared secret bytes
        let (ct, ss): (
            [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES],
            [u8; pqc_kyber::KYBER_SSBYTES],
        ) = encapsulate(&pkb.pqkem, &mut rng).unwrap();
        // turns bob's ed25519 public key into x25519 public key
        let bob_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&pkb.ik).unwrap();
        // creates alice's ed25519 key pair
        let alice_ed_ik = KeyPair::generate();
        // makes a secret x25519 key from alice's ed25519 secret key
        let alice_ik = ed25519_compact::x25519::SecretKey::from_ed25519(&alice_ed_ik.sk).unwrap();
        // makes x25519 keypair representing alice's ephemeral keys
        let alice_ek = ed25519_compact::x25519::KeyPair::generate();
        // doing the diffie hellman 1 (dh1) as defined in pqxdh spec
        let dh1 = pkb.spk.dh(&alice_ik).unwrap();
        // doing the diffie hellman 2 (dh2) as defined in pqxdh spec
        let dh2 = bob_ik_x25519.dh(&alice_ek.sk).unwrap();
        // doing the diffie hellman 3 (dh3) as defined in pqxdh spec
        let dh3 = pkb.spk.dh(&alice_ek.sk).unwrap();
        // doing the diffie hellman 4 (dh4) as defined in pqxdh spec
        let dh4 = pkb.opk.dh(&alice_ek.sk).unwrap();
        // creates the sum of the dh operations and the shared secret
        let sum = [
            dh1.as_slice(),
            dh2.as_slice(),
            dh3.as_slice(),
            dh4.as_slice(),
            ss.as_slice(),
        ]
        .concat();
        // makes a source of entropy derived from the sum
        let sk = Hkdf::<Sha256>::new(None, sum.as_slice());
        let data = "alice".as_bytes();

        // AES starts
        let mut key: [u8; AES_KEY_BYTES] = [0; AES_KEY_BYTES];
        // utilise cette source d'entropie pour créer la clé AES
        sk.expand(data, &mut key).map_err(|_| "Erreur lors de l'expansion de la clé")?;
        let key: &[u8; AES_KEY_BYTES] = &key;
        let key: &Key<Aes256Gcm> = key.into();
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        // concatène les clés d'identité d'Alice et Bob comme données associées dans AES
        let associated_data = [pkb.ik.as_ref(), &pkb.spk.as_ref(), &pkb.opk.as_ref()].concat();
        // chiffre le texte "totally secret first message" avec la clé AES que Bob peut reproduire
        let ciphertext = cipher
            .encrypt(&nonce, &associated_data, b"totally secret first message".as_ref())
            .map_err(|_| "Erreur lors du chiffrement avec AES")?;

        Ok(InitialMessage {
            ik: alice_ed_ik.pk,
            ed: alice_ek.pk,
            ct,
            ect: ciphertext,
            nonce,
        })
    }
}

fn bob_handle_initial_message(im: &InitialMessage, skb: &PrivateKeyBundle) {
    // bob turning his keys into x25519 keys to do the dh operations alice did
    let alice_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&im.ik).unwrap();
    let bob_ik_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.ik).unwrap();
    let bob_opk_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.opk).unwrap();
    let bob_spk_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.spk).unwrap();
    // getting the shared secret from decapsulating the cipher text
    let ss: [u8; pqc_kyber::KYBER_SSBYTES] = decapsulate(&im.ct, &skb.pqkem.secret).unwrap();
    // bob doing the dh operations alice did as defined in the pqxdh spec
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
// making the same source of entropy alice made
let sk = Hkdf::<Sha256>::new(None, sum.as_slice());
let mut key: [u8; AES_KEY_BYTES] = [0; AES_KEY_BYTES];
let data = "alice".as_ref();
sk.expand(data, &mut key).map_err(|_| "Erreur lors de l'expansion de la clé")?;

let key: &Key<Aes256Gcm> = (&mut key).into();
let cipher = Aes256Gcm::new(key);

// decrypting the initial message cipher text from alice
let plaintext_result = cipher.decrypt(&im.nonce, im.ect.as_ref());
match plaintext_result {
    Ok(plaintext) => {
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        println!("{}", plaintext_str);
    }
    Err(e) => {
        eprintln!("Erreur lors du déchiffrement : {}", e);
        // Autres actions à entreprendre en cas d'erreur...
    }
}
