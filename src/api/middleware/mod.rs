pub mod auth_middleware;
// Déclaration des modules (fichiers dans le même dossier)
pub mod aes_chiffrement;
pub mod hachage_argon2;
pub mod ca;

// Re-exportation pour simplifier les appels ailleurs
// Au lieu de middleware::hachage_argon2::hasher_mot_de_passe
// On pourra faire middleware::hasher_mot_de_passe
pub use aes_chiffrement::{chiffrer_aes, dechiffrer_aes};
pub use hachage_argon2::{hasher_mot_de_passe, verifier_hachage};
pub use ca::{generate_root_ca};
