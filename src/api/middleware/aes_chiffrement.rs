use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use std::env;
use base64::{engine::general_purpose, Engine as _};

/// Chiffre une chaîne (le hash Argon2) en AES-256-GCM
pub fn chiffrer_aes(donnees: &str) -> String {
    let key_hex = env::var("PWD_ENCRYPTION_KEY").expect("PWD_ENCRYPTION_KEY manquante");
    let key_bytes = hex::decode(key_hex).expect("Format hex de la clé AES invalide");
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // IV (Nonce) : Doit être unique. Pour simplifier ici, on utilise un fixe de 12 octets.
    // NOTE : En production, on génère un nonce aléatoire et on le préfixe au message.
    let nonce = Nonce::from_slice(b"unique_nonce"); 

    let ciphertext = cipher
        .encrypt(nonce, donnees.as_bytes())
        .expect("Échec du chiffrement AES");

    // Retourne le résultat en Base64 pour stockage en BDD TEXT
    general_purpose::STANDARD.encode(ciphertext)
}

/// Déchiffre une chaîne Base64 pour retrouver le hash Argon2 original
pub fn dechiffrer_aes(blob_base64: &str) -> String {
    let key_hex = env::var("PWD_ENCRYPTION_KEY").expect("PWD_ENCRYPTION_KEY manquante");
    let key_bytes = hex::decode(key_hex).expect("Format hex de la clé AES invalide");
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let ciphertext = general_purpose::STANDARD
        .decode(blob_base64)
        .expect("Échec du décodage Base64");

    let nonce = Nonce::from_slice(b"unique_nonce"); 

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("Échec du déchiffrement : clé incorrecte ou donnée altérée");

    String::from_utf8(plaintext_bytes).expect("Données déchiffrées corrompues (UTF-8)")
}