use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chacha20poly1305::aead::{generic_array::GenericArray, Aead, Payload};

use super::{
    credentials::Credentials,
    encrypt::{xchacha20_poly_1305, SEPERATOR},
    EncryptedInfo,
};

use anyhow::anyhow;

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

fn decrypt(mut credentials: Credentials, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    credentials.is_valid()?;

    // Find the position of SEPERATOR
    let identifier_position = data.windows(SEPERATOR.len())
        .position(|window| window == SEPERATOR)
        .ok_or(anyhow!("SEPERATOR not found in data"))?;

    // Split the data
    let (encrypted_data, identifier_data) = data.split_at(identifier_position);
    let info_serialized = &identifier_data[SEPERATOR.len()..];


    // Deserialize EncryptedInfo
    let info: EncryptedInfo = serde_json::from_slice(info_serialized)?;


    let params = Params::new(
        info.argon2_params.m_cost,
        info.argon2_params.t_cost,
        info.argon2_params.p_cost,
        Some(info.argon2_params.hash_length as usize),
    )
    .map_err(|e| anyhow!("Failed to create Argon2 params {:?}", e))?;

    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params.clone());

    let salt_string = SaltString::from_b64(&info.password_salt)
        .map_err(|e| anyhow!("Failed to parse salt {:?}", e))?;

    let password_hash = argon2
        .hash_password(credentials.password().as_bytes(), &salt_string)
        .map_err(|e| anyhow!("Failed to hash password {:?}", e))?;

    let key = password_hash
        .hash
        .ok_or(anyhow!("Failed to get the hash output"))?;

    // create the cipher using the hashed password as the key
    let cipher = xchacha20_poly_1305(key);

    let username = credentials.username().clone();

    let payload = Payload {
        msg: encrypted_data.as_ref(),
        aad: username.as_bytes(),
    };

    credentials.destroy();

    let nonce = GenericArray::from_slice(&info.cipher_nonce);

    let decrypted_data = cipher
        .decrypt(nonce, payload)
        .map_err(|e| anyhow!("Failed to decrypt data {:?}", e))?;

    Ok(decrypted_data)
}