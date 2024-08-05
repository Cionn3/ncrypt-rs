use chacha20poly1305::{ XChaCha20Poly1305, XNonce };
use sha2::{ Sha256, digest::Digest };
use password_hash::{ Output, PasswordHasher};
use argon2::{ Algorithm, Argon2, Params, Version };
use aes_gcm::{ KeyInit, aead::{ Aead, generic_array::GenericArray } };

use anyhow::anyhow;
use super::credentials::Credentials;

/// The identifier used to find the Argon2 params that was used to encrypt the data
pub const IDENTIFIER: &[u8] = b"params";


/// The parameters used to encrypt the data
#[derive(Clone, Debug)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub hash_length: usize,
}

impl Argon2Params {

    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32, hash_length: usize) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
            hash_length,
        }
    }

    pub fn from_argon2(argon2: Argon2) -> Result<Self, anyhow::Error> {
        let hash_lenght = argon2.params().output_len();

        if hash_lenght.is_none() {
            return Err(anyhow!("Failed to get output length"));
        }
        
        Ok(Self {
            m_cost: argon2.params().m_cost(),
            t_cost: argon2.params().t_cost(),
            p_cost: argon2.params().p_cost(),
            hash_length: hash_lenght.unwrap(),
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.m_cost.to_be_bytes());
        data.extend_from_slice(&self.t_cost.to_be_bytes());
        data.extend_from_slice(&self.p_cost.to_be_bytes());

        // Ensure hash_length is always 8 bytes
        data.extend_from_slice(&(self.hash_length as u64).to_be_bytes());
        data
    }

    /// Recover the params
    pub fn from_u8(data: &[u8]) -> Result<Self, anyhow::Error> {
        if data.len() != 20 {
            return Err(anyhow!("Invalid data length for EncryptionParams"));
        }
        let m_cost = u32::from_be_bytes(data[0..4].try_into().map_err(|_| anyhow!("Failed to convert m_cost from bytes"))?);
        let t_cost = u32::from_be_bytes(data[4..8].try_into().map_err(|_| anyhow!("Failed to convert t_cost from bytes"))?);
        let p_cost = u32::from_be_bytes(data[8..12].try_into().map_err(|_| anyhow!("Failed to convert p_cost from bytes"))?);
        let hash_length = u64::from_be_bytes(data[12..20].try_into().map_err(|_| anyhow!("Failed to convert hash_length from bytes"))?) as usize;

        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
            hash_length,
        })
    }
}

// A Default instance that should not take too long to hash even on low-end machines
impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 4096,
            t_cost: 200,
            p_cost: 8,
            hash_length: 64,
        }
    }
}


/// Encrypts the given data using the provided credentials
/// 
/// ### Arguments
/// 
/// - `argon_params` - The Argon2 parameters to use for the password hashing
/// - `data` - The data to encrypt
/// - `credentials` - The credentials to use for encryption
pub fn encrypt_data(argon_params: Argon2Params, data: Vec<u8>, credentials: Credentials) -> Result<Vec<u8>, anyhow::Error> {
    let encrypted = encrypt(argon_params.clone(), credentials, data)?;

    let params_with_identifier = [IDENTIFIER, argon_params.to_vec().as_slice()].concat();

    let encrypted_data_with_params = [
        encrypted.as_slice(),
        params_with_identifier.as_slice(),
    ].concat();

    Ok(encrypted_data_with_params)
}


/// Encrypts the given data using the provided credentials
fn encrypt(argon_params: Argon2Params, credentials: Credentials, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    credentials.is_valid()?;

    // generate a salt needed for the password hashing
    let salt = credentials.generate_saltstring()?;

    // set the argon2 parameters
    let params = Params::new(
        argon_params.m_cost,
        argon_params.t_cost,
        argon_params.p_cost,
        Some(argon_params.hash_length),
    ).map_err(|e| anyhow!("Failed to set Argon2 params {:?}", e))?;

    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

    // hash the password
    let password_hash = match argon2.hash_password(credentials.password().as_bytes(), &salt) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(anyhow!("Failed to hash password {:?}", e));
        }
    };

    // get the hash output
    let key = password_hash.hash.ok_or(anyhow!("Failed to get the hash output"))?;

    // create the cipher using the hashed password as the key
    let cipher = xchacha20_poly_1305(key);

    // use the SHA-256 hash of the username as the nonce
    // ! usually this is a random value but assuming 
    // ! we are using a strong username and not save it anywhere as plain text
    // ! this should be safe
    let hash = Sha256::digest(credentials.username().as_bytes());
    let nonce = XNonce::from_slice(&hash.as_slice()[..24]);

    let encrypted_data = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|e| anyhow!("Failed to encrypt data {:?}", e))?;

    Ok(encrypted_data)
}


pub fn xchacha20_poly_1305(key: Output) -> XChaCha20Poly1305 {
    let key = GenericArray::from_slice(&key.as_bytes()[..32]);
    XChaCha20Poly1305::new(key)
}