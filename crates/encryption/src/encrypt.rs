use argon2::{
    password_hash::{Output, PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, OsRng, Payload},
    AeadCore, KeyInit, XChaCha20Poly1305,
};

use super::credentials::Credentials;
use super::{Argon2Params, EncryptedInfo};
use anyhow::anyhow;

/// A seperator that we use to seperate the encrypted data and the encrypted info
pub const SEPERATOR: &[u8] = b"Souvlaki is a Greek fast food consisting of small pieces of meat and sometimes vegetables grilled on a skewer. It is usually eaten straight off the skewer while still hot";

/// Encrypts the given data using the provided credentials
///
/// ### Arguments
///
/// - `argon_params` - The Argon2 parameters to use for the password hashing
/// - `data` - The data to encrypt
/// - `credentials` - The credentials to use for encryption
pub fn encrypt_data(
    argon_params: Argon2Params,
    data: Vec<u8>,
    credentials: Credentials,
) -> Result<Vec<u8>, anyhow::Error> {
    let (encrypted, info) = encrypt(argon_params.clone(), credentials, data)?;

    let info_serialized = serde_json::to_vec(&info)?;

    // SEPERATOR + Encrypted info
    let seperator_with_info = [SEPERATOR, info_serialized.as_slice()].concat();

    // Encrypted data + SEPERATOR + Encrypted info
    let encrypted_data_with_info =
        [encrypted.as_slice(), seperator_with_info.as_slice()].concat();

    Ok(encrypted_data_with_info)
}

/// Encrypts the given data using the provided credentials
fn encrypt(
    argon_params: Argon2Params,
    mut credentials: Credentials,
    data: Vec<u8>,
) -> Result<(Vec<u8>, EncryptedInfo), anyhow::Error> {
    credentials.is_valid()?;

    let params = Params::new(
        argon_params.m_cost,
        argon_params.t_cost,
        argon_params.p_cost,
        Some(argon_params.hash_length as usize),
    )
    .map_err(|e| anyhow!("Failed to set Argon2 params {:?}", e))?;

    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

    let salt = SaltString::generate(&mut OsRng);

    // hash the password
    let password_hash = match argon2.hash_password(credentials.password().as_bytes(), &salt) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(anyhow!("Failed to hash password {:?}", e));
        }
    };

    // get the hash output
    let key = password_hash
        .hash
        .ok_or(anyhow!("Failed to get the hash output"))?;

    // create the cipher using the hashed password as the key
    let cipher = xchacha20_poly_1305(key);

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let username = credentials.username().clone();

    let payload = Payload {
        msg: data.as_ref(),
        aad: username.as_bytes(),
    };

    credentials.destroy();

    let encrypted_data = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| anyhow!("Failed to encrypt data {:?}", e))?;

    let info = EncryptedInfo::new(salt.to_string(), nonce.to_vec(), argon_params);

    Ok((encrypted_data, info))
}

pub fn xchacha20_poly_1305(key: Output) -> XChaCha20Poly1305 {
    let key = GenericArray::from_slice(&key.as_bytes()[..32]);
    XChaCha20Poly1305::new(key)
}
