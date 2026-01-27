use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};

// ✅ IMPORTANT : OsRng doit venir de password_hash (rand_core 0.6)
use argon2::password_hash::rand_core::OsRng;

fn main() {
    let password = std::env::args()
        .nth(1)
        .expect("Usage: cargo run --bin hash_password <password>");

    let salt = SaltString::generate(&mut OsRng);

    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    println!("{hash}");
}
