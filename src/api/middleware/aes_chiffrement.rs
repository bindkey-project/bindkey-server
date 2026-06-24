use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::{Engine as _, engine::general_purpose};
use std::env;

/// Chiffre une chaîne en AES-256-GCM.
/// Format stocké : base64(nonce || ciphertext || tag)
pub fn chiffrer_aes(donnees: &str) -> String {
    let key_hex = env::var("PWD_ENCRYPTION_KEY").expect("PWD_ENCRYPTION_KEY manquante");
    let key_bytes = hex::decode(key_hex).expect("Format hex de la clé AES invalide");

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut ciphertext = cipher
        .encrypt(&nonce, donnees.as_bytes())
        .expect("Échec du chiffrement AES");

    let mut final_blob = nonce.to_vec();
    final_blob.append(&mut ciphertext);

    general_purpose::STANDARD.encode(final_blob)
}

/// Déchiffre une chaîne AES-256-GCM encodée en base64.
pub fn dechiffrer_aes(blob_base64: &str) -> String {
    let key_hex = env::var("PWD_ENCRYPTION_KEY").expect("PWD_ENCRYPTION_KEY manquante");
    let key_bytes = hex::decode(key_hex).expect("Format hex de la clé AES invalide");

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let full_data = general_purpose::STANDARD
        .decode(blob_base64)
        .expect("Échec du décodage Base64");

    if full_data.len() < 12 {
        panic!("Données corrompues : trop courtes");
    }

    let (nonce_slice, ciphertext) = full_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice);

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .expect("Échec du déchiffrement AES");

    String::from_utf8(plaintext_bytes).expect("UTF-8 invalide")
}

/// Alias explicites pour les champs sensibles.
pub fn chiffrer_champ_sensible(data: &str) -> String {
    chiffrer_aes(data)
}

pub fn dechiffrer_champ_sensible(data: &str) -> String {
    dechiffrer_aes(data)
}
