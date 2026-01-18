use std::env;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use rand_core::OsRng;

fn main() -> anyhow::Result<()> {
    let password = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: cargo run --bin hash_password -- <password>");
        std::process::exit(2);
    });

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash failed: {e}"))?
        .to_string();

    println!("{hash}");
    Ok(())
}
