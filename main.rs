use hkdf::Hkdf;
use sha2::Sha512;
use aria_gcm::aead::{Aead, Nonce};
use aria_gcm::{AeadCore, Aria256Gcm, Key};
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use pqc_kyber::{decapsulate, encapsulate, keypair, PublicKey as pqcPublicKey};
use rand::rngs::OsRng;

const ARIA_KEY_BYTES: usize = 32;
type Aria256Key = Key<Aria256Gcm>;
type AriaNonce = Nonce<Aria256Gcm>;

mod crypto;
use crypto::{InitialMessage, PreKeyBundle, PrivateKeyBundle, secure_rng};

fn main() {
    let bob_key_bundle = PreKeyBundle::new();
    let initial_message = InitialMessage::alice_handle_pre_key(&bob_key_bundle.0);
    crypto::bob_handle_initial_message(&initial_message, &bob_key_bundle.1);
}
