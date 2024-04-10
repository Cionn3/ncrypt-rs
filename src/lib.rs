use password_hash::{PasswordHasher, SaltString };
use argon2::{ Algorithm, Argon2, Params, Version };

use aes_gcm::{ Aes256Gcm, KeyInit, aead::{ Aead, generic_array::GenericArray } };
use sha2::{ Sha256, digest::Digest };

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::Context;


const IDENTIFIER: &[u8] = b"nCrypt_Params";

/// Successfully encrypted file
pub const SUCCESS_ENCRYPT: &str = "File encrypted successfully";

/// Successfully decrypted file
pub const SUCCESS_DECRYPT: &str = "File decrypted successfully";

/// Maximum Memory Cost
pub const MAX_M_COST: u32 = 1_000_000;

/// Maximum Iterations
pub const MAX_T_COST: u32 = 1_000_000;

/// Maximum Parallelism
pub const MAX_P_COST: u32 = 64;

/// Maximum Hash Length
pub const MAX_HASH_LENGTH: usize = 64;

pub struct File {
    pub path: String,
    pub name: String,
    pub extension: String,
}

impl Default for File {
    fn default() -> Self {
        Self {
            path: Default::default(),
            name: Default::default(),
            extension: Default::default(),
        }
    }
}

/// `data` The encrypted file data
///
/// `argon2` The Argon2 instance used to encrypt the file
///
/// `name` The original name of the file
pub struct EncryptedFile<'a> {
    data: Vec<u8>,
    argon2: Argon2<'a>,
    name: String,
}

impl Default for EncryptedFile<'_> {
    fn default() -> Self {
        Self {
            data: Default::default(),
            argon2: Default::default(),
            name: Default::default(),
        }
    }
}

/// The credentials used to encrypt a file
#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub confrim_password: String,
}

impl Default for Credentials {
    fn default() -> Self {
        Self {
            username: Default::default(),
            password: Default::default(),
            confrim_password: Default::default(),
        }
    }
}

impl File {
    pub fn new(path: String) -> Result<File, anyhow::Error> {
        let path_obj = Path::new(&path);

        let name = path_obj.file_name().ok_or(anyhow::anyhow!("Failed to get file name"))?;
        let name = String::from(name.to_str().ok_or(anyhow::anyhow!("Failed to convert file name to string"))?);
        
        let extension = path_obj.extension().ok_or(anyhow::anyhow!("Failed to get file extension"))?;
        let extension = String::from(extension.to_str().ok_or(anyhow::anyhow!("Failed to convert file extension to string"))?);

        Ok(File {
            path,
            name,
            extension,
        })
    }

    pub fn name_encrypted(&self) -> String {
        format!("{}_encrypted.nc", self.name)
    }

    /// Removes the "_encrypted.nc" extension
    pub fn name_decrypted(&self) -> String {
        let name = self.name.replace("_encrypted.nc", "");
        format!("{}", name)
    }

    pub fn decrypted_path(&self) -> Result<String, anyhow::Error> {
        let mut path = current_dir()?;
        path.push(self.name_decrypted());
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert path to string"))
            .map(|s| s.to_string())
    }
    
    pub fn encrypted_path(&self) -> Result<String, anyhow::Error> {
        let mut path = current_dir()?;
        path.push(self.name_encrypted());
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert path to string"))
            .map(|s| s.to_string())
    }


    pub fn is_encrypted(&self, data: &[u8]) -> bool {
        if let Some(_id) = find_identifier_position(data, IDENTIFIER) {
            return true;
        } else {
            return false;
        }
    }

    
}

impl Credentials {
    pub fn generate_saltstring(&self) -> SaltString {
        let salt_array = Sha256::digest(self.username.as_bytes());
        let salt = salt_array.to_vec();
        let salt = String::from(
            salt
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        SaltString::from_b64(&salt).unwrap()
    }

    pub fn confrim_password(&self) -> bool {
        self.password == self.confrim_password
    }

    pub fn is_valid(&self) -> bool {
        self.username.len() > 0 && self.password.len() > 0 && self.confrim_password.len() > 0
    }
}

pub fn encrypt(argon: Argon2, credentials: Credentials, file: File) -> Result<(), anyhow::Error> {

    if !credentials.confrim_password() {
        return Err(anyhow::anyhow!("Passwords do not match"));
    }

    if !credentials.is_valid() {
        return Err(anyhow::anyhow!("Invalid credentials, Username and Password must be provided"));
    }

    let file_data = fs::read(&file.path)?;

    if file.is_encrypted(&file_data.as_ref()) {
        return Err(anyhow::anyhow!("File is already encrypted"));
    }

    let salt = credentials.generate_saltstring();

    let password_hash = match argon.hash_password(credentials.password.as_bytes(), &salt) {
        Ok(hash) => hash,
        Err(e) => return Err(anyhow::anyhow!("Failed to hash password {:?}", e)),
    };

    let key = password_hash.hash.ok_or(anyhow::anyhow!("Failed to get the hash output"))?;
    let file_key = GenericArray::from_slice(&key.as_bytes()[..32]);
    let cipher = Aes256Gcm::new(file_key);

    let nonce = Sha256::digest(credentials.username.as_bytes());
    let nonce = GenericArray::from_slice(&nonce.as_slice()[..12]);

    let encrypted_file = match cipher.encrypt(&nonce, file_data.as_ref()) {
        Ok(data) => data,
        Err(e) => return Err(anyhow::anyhow!("Failed to encrypt file {:?}", e)),
    };

    let ncrypt_params =
        serde_json::json!({
        "m_cost": argon.params().m_cost(),
        "t_cost": argon.params().t_cost(),
        "p_cost": argon.params().p_cost(),
        "hash_length": argon.params().output_len(),
        "file_name": file.name,
    });

    let ncrypt_params = ncrypt_params.to_string().as_bytes().to_vec();

    let params_with_identifier = [IDENTIFIER, ncrypt_params.as_slice()].concat();

    let encrypted_file_with_metadata = [
        encrypted_file.as_slice(),
        params_with_identifier.as_slice(),
    ].concat();

    fs::write(&file.name_encrypted(), &encrypted_file_with_metadata)?;

    Ok(())
}

pub fn decrypt(file: File, credentials: Credentials) -> Result<(), anyhow::Error> {

    if !credentials.confrim_password() {
        return Err(anyhow::anyhow!("Passwords do not match"));
    }

    if !credentials.is_valid() {
        return Err(anyhow::anyhow!("Invalid credentials, Username and Password must be provided"));
    }

    let encrypted_file = get_file_data(&file.path)?;
    let salt = credentials.generate_saltstring();

    let password_hash = match encrypted_file.argon2
        .hash_password(credentials.password.as_bytes(), &salt) {
        Ok(hash) => hash,
        Err(e) => return Err(anyhow::anyhow!("Failed to hash password {:?}", e)),
    };
        

    let key = password_hash.hash.ok_or(anyhow::anyhow!("Failed to get the hash output"))?;
    let file_key = GenericArray::from_slice(&key.as_bytes()[..32]);
    let cipher = Aes256Gcm::new(file_key);

    let nonce = Sha256::digest(credentials.username.as_bytes());
    let nonce = GenericArray::from_slice(&nonce.as_slice()[..12]);

    let decrypted_file = match cipher.decrypt(&nonce, encrypted_file.data.as_ref()) {
        Ok(data) => data,
        Err(e) => return Err(anyhow::anyhow!("Failed to decrypt file {:?}", e)),
    };

    fs::write(&encrypted_file.name, decrypted_file)?;
    Ok(())
}

/// Gets the data of an encrypted file and its nCrypt parameters
fn get_file_data(path: &str) -> Result<EncryptedFile, anyhow::Error> {
    let file = fs::read(path)?;
    let identifier_position = find_identifier_position(&file, IDENTIFIER).ok_or(
        anyhow::anyhow!("Failed to find identifier, Is the file encrypted?")
    )?;
    let (encrypted_file, identifier_data) = file.split_at(identifier_position);
    let file_params = &identifier_data[IDENTIFIER.len()..];

    // Parse the Argon2 params
    let params: serde_json::Value = serde_json::from_slice(file_params)?;
    let m_cost = params["m_cost"].as_u64().ok_or(
        anyhow::anyhow!("Failed to parse m_cost")
    )?;
    let t_cost = params["t_cost"].as_u64().ok_or(
        anyhow::anyhow!("Failed to parse t_cost")
    )?;
    let p_cost = params["p_cost"].as_u64().ok_or(
        anyhow::anyhow!("Failed to parse p_cost")
    )?;
    let hash_length = params["hash_length"].as_u64().ok_or(
        anyhow::anyhow!("Failed to parse hash_length")
    )?;
    let file_name = params["file_name"].as_str().ok_or(
        anyhow::anyhow!("Failed to parse file_name")
    )?;

    let params = Params::new(
        m_cost.try_into()?,
        t_cost.try_into()?,
        p_cost.try_into()?,
        Some(hash_length.try_into()?)
    ).map_err(|e| anyhow::anyhow!("Failed to create Argon2 params {:?}", e))?;
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params.clone());

    Ok(EncryptedFile {
        data: encrypted_file.to_vec(),
        argon2,
        name: file_name.to_string(),
    })
}

fn find_identifier_position(data: &[u8], identifier: &[u8]) -> Option<usize> {
    data.windows(identifier.len()).rposition(|window| window == identifier)
}

    /// Get the current directory the executable is running from
    pub fn current_dir() -> anyhow::Result<PathBuf> {
        Ok(std::env::current_exe()
            .context("Failed to get the current executable path")?
            .parent()
            .context("Failed to get the executable's directory")?
            .to_path_buf())
    }