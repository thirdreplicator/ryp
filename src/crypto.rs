use std::num::NonZeroU32;
use ring::{pbkdf2};
use ring::rand::{self, SecureRandom};
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, aead::Aead}; // For encrypting and decrypting.

use data_encoding::BASE64_NOPAD;

use crate::error::MyError;

pub const CREDENTIAL_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

pub fn gen_key(salt: [u8;32], password: String) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(100_000).unwrap(),
        &salt,
        password.as_bytes(),
        &mut key,
    );
    key
}

pub fn gen_salt() -> Result<[u8; CREDENTIAL_LEN], MyError> {
    let mut salt = [0u8; CREDENTIAL_LEN];
    let rng = rand::SystemRandom::new();
    rng.fill(&mut salt)?;
    Ok(salt)
}

pub fn gen_nonce() -> Result<[u8; NONCE_LEN], MyError> {
    let mut nonce = [0u8; 24];
    let rng = rand::SystemRandom::new();
    rng.fill(&mut nonce)?;
    Ok(nonce)
}

pub fn decode_salt(b64_salt: String) -> [u8; CREDENTIAL_LEN] {
    let decoded_salt = BASE64_NOPAD.decode(b64_salt.as_bytes()).unwrap();
    let mut salt = [0u8; CREDENTIAL_LEN];
    salt.copy_from_slice(&decoded_salt[..CREDENTIAL_LEN]);
    salt
}
pub fn encrypt_to_base64(
    content: String,
    key: [u8; 32],
    nonce: [u8; 24],
) -> String {
    let cipher = XChaCha20Poly1305::new((&key).into());
    let encrypted_file = cipher
        .encrypt(&nonce.into(), content.as_ref())
        .unwrap();
    let cipher_string = BASE64_NOPAD.encode(&encrypted_file);
    cipher_string
}

pub fn decrypt_from_base64(
    ciphertext_string: String,
    key: [u8; 32],
    nonce: [u8; 24],
) -> Result<String, MyError> {
    let decoded_ciphertext = BASE64_NOPAD.decode(ciphertext_string.as_bytes()).unwrap();
    let cipher = XChaCha20Poly1305::new(&key.into());
    let decrypted_file = cipher
        .decrypt(&nonce.into(), decoded_ciphertext.as_ref())
        .unwrap();
    let text = std::str::from_utf8(&decrypted_file)?.to_string();
    Ok(text)
}

// Check if password is valid.
pub fn verify_password(hash_string: &String, password: &String) {
    let matches = argon2::verify_encoded(&hash_string, password.as_bytes()).unwrap();
    if !matches {
        eprintln!("Wrong password!");
        std::process::exit(1);
    }    
}