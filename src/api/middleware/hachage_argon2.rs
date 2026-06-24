use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

/// Transforme un mot de passe brut en hash Argon2id (format PHC)
pub fn hasher_mot_de_passe(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Erreur critique : échec du hachage Argon2")
        .to_string()
}

/// Vérifie si un mot de passe brut correspond à un hash Argon2id
pub fn verifier_hachage(password_tentative: &str, hash_stocke: &str) -> bool {
    let parsed_hash =
        PasswordHash::new(hash_stocke).expect("Erreur : le format du hash en BDD est invalide");

    Argon2::default()
        .verify_password(password_tentative.as_bytes(), &parsed_hash)
        .is_ok()
}
