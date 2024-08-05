use chacha20poly1305::XNonce;
use sha2::{ Sha256, digest::Digest };
use password_hash::PasswordHasher;
use argon2::{ Algorithm, Argon2, Params, Version };
use aes_gcm::aead::Aead;

use anyhow::anyhow;
use super::{credentials::Credentials, encrypt::{Argon2Params, IDENTIFIER, xchacha20_poly_1305}};




/// Decrypts the data using the provided credentials
/// 
/// ### Arguments
/// 
/// - `data` - The data to decrypt
/// - `credentials` - The credentials to use for decryption
pub fn decrypt_data(data: Vec<u8>, credentials: Credentials) -> Result<Vec<u8>, anyhow::Error> {
    let decrypted_data = decrypt(credentials, data)?;
    Ok(decrypted_data)
}


pub fn decrypt(credentials: Credentials, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    credentials.is_valid()?;

    // find the argon2 params in the encrypted data
    let identifier_position = find_identifier_position(&data, IDENTIFIER).ok_or(
        anyhow!("Failed to find the identifier in the encrypted data")
    )?;

    // get the argon2 params from the encrypted data
    let (encrypted_data, identifier_data) = data.split_at(identifier_position);
    let params = &identifier_data[IDENTIFIER.len()..];


    // Parse the encryption params
    let argon2_params = Argon2Params::from_u8(params)?;


    let params = Params::new(
        argon2_params.m_cost,
        argon2_params.t_cost,
        argon2_params.p_cost,
        Some(argon2_params.hash_length)
    ).map_err(|e| anyhow!("Failed to create Argon2 params {:?}", e))?;

    // create the argon2 instance used
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params.clone());

    // generate the salt needed for the password hashing
    let salt = credentials.generate_saltstring()?;

    // hash the password
    let password_hash = argon2
        .hash_password(credentials.password().as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password {:?}", e))?;

    // get the hash output
    let key = password_hash.hash.ok_or(anyhow!("Failed to get the hash output"))?;

    // create the cipher using the hashed password as the key
    let cipher = xchacha20_poly_1305(key);

    let hash = Sha256::digest(credentials.username().as_bytes());
    let nonce = XNonce::from_slice(&hash.as_slice()[..24]);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| anyhow!("Failed to decrypt data {:?}", e))?;

    Ok(decrypted_data)
}

/// Finds the position of the [IDENTIFIER] in the encrypted data
fn find_identifier_position(data: &[u8], identifier: &[u8]) -> Option<usize> {
    data.windows(identifier.len()).rposition(|window| window == identifier)
}