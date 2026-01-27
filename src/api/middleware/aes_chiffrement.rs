use aes_gcm::{
    Aes256Gcm,
    Key,
    Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng}, // On importe OsRng ICI
};
// Supprime l'import "use rand::rngs::OsRng;" s'il y est encore
use base64::{Engine as _, engine::general_purpose};
use std::env;
/// Chiffre une chaîne (le hash Argon2) en AES-256-GCM
pub fn chiffrer_aes(donnees: &str) -> String {
    let key_hex = env::var("PWD_ENCRYPTION_KEY").expect("PWD_ENCRYPTION_KEY manquante");
    let key_bytes = hex::decode(key_hex).expect("Format hex de la clé AES invalide");
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Maintenant OsRng est compatible !
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut ciphertext = cipher
        .encrypt(&nonce, donnees.as_bytes())
        .expect("Échec du chiffrement AES");

    // Concaténation Nonce + Ciphertext
    let mut final_blob = nonce.to_vec();
    final_blob.append(&mut ciphertext);

    general_purpose::STANDARD.encode(final_blob)
}

/// Déchiffre une chaîne Base64 pour retrouver le hash Argon2 original
pub fn dechiffrer_aes(blob_base64: &str) -> String {
    let key_hex = env::var("PWD_ENCRYPTION_KEY").expect("PWD_ENCRYPTION_KEY manquante");
    let key_bytes = hex::decode(key_hex).expect("Format hex de la clé AES invalide");
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let full_data = general_purpose::STANDARD
        .decode(blob_base64)
        .expect("Échec du décodage Base64");

    // On sépare le nonce (12 premiers octets) du reste (le message)
    if full_data.len() < 12 {
        panic!("Données corrompues : trop courtes");
    }
    let (nonce_slice, ciphertext) = full_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice);

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .expect("Échec du déchiffrement : clé incorrecte ou donnée altérée");

    String::from_utf8(plaintext_bytes).expect("UTF-8 invalide")
}
