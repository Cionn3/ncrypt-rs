use password_hash::{ Output, PasswordHasher, SaltString };
use argon2::{ Algorithm, Argon2, Params, Version };

use aes_gcm::{ Aes256Gcm, KeyInit, aead::{ Aead, generic_array::GenericArray } };
use chacha20poly1305::{ XChaCha20Poly1305, XNonce };

use sha2::{ Sha256, digest::Digest };

use std::fs;
use std::path::{ Path, PathBuf };
use anyhow::{ Context, anyhow };

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

/// Holds the encryption settings
pub struct EncryptionInstance<'a> {
    pub algorithm: EncryptionAlgorithm,
    pub argon2: Argon2<'a>,
    pub credentials: Credentials,
}

impl Default for EncryptionInstance<'_> {
    fn default() -> Self {
        Self {
            algorithm: Default::default(),
            argon2: Default::default(),
            credentials: Default::default(),
        }
    }
}

impl<'a> EncryptionInstance<'a> {
    pub fn new(
        algorithm: EncryptionAlgorithm,
        argon2: Argon2<'a>,
        credentials: Credentials
    ) -> Self {
        Self {
            algorithm,
            argon2,
            credentials,
        }
    }

    pub fn algorithm(&self) -> String {
        match self.algorithm {
            EncryptionAlgorithm::XChaCha20Poly1305 => "XChaCha20Poly1305".to_string(),
            EncryptionAlgorithm::Aes256Gcm => "Aes256Gcm".to_string(),
        }
    }
}

/// The encryption algorithm to use
#[derive(Clone, Default, PartialEq)]
pub enum EncryptionAlgorithm {
    XChaCha20Poly1305,
    #[default]
    Aes256Gcm,
}

/// The chosen file to encrypt or decrypt
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

impl File {
    pub fn new(path: String) -> Result<File, anyhow::Error> {
        let path_obj = Path::new(&path);

        let name = path_obj.file_name().ok_or(anyhow!("Failed to get file name"))?;
        let name = String::from(
            name.to_str().ok_or(anyhow!("Failed to convert file name to string"))?
        );

        let extension = path_obj.extension().ok_or(anyhow!("Failed to get file extension"))?;
        let extension = String::from(
            extension.to_str().ok_or(anyhow!("Failed to convert file extension to string"))?
        );

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

/// A file that has been encrypted
///
/// `data` The encrypted file data
///
/// `argon2` The Argon2 instance used to encrypt the file
///
/// `algorithm` The encryption algorithm used to encrypt the file
///
/// `name` The original name of the file
pub struct EncryptedFile<'a> {
    data: Vec<u8>,
    argon2: Argon2<'a>,
    algorithm: EncryptionAlgorithm,
    name: String,
}

impl Default for EncryptedFile<'_> {
    fn default() -> Self {
        Self {
            data: Default::default(),
            argon2: Default::default(),
            algorithm: Default::default(),
            name: Default::default(),
        }
    }
}

impl<'a> EncryptedFile<'a> {
    pub fn new(data: Vec<u8>, argon2: Argon2<'a>, name: String, algo: &str) -> Self {
        let algorithm = match algo {
            "XChaCha20Poly1305" => EncryptionAlgorithm::XChaCha20Poly1305,
            "Aes256Gcm" => EncryptionAlgorithm::Aes256Gcm,
            _ => EncryptionAlgorithm::Aes256Gcm,
        };
        Self {
            data,
            argon2,
            algorithm,
            name,
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

    pub fn is_valid(&self) -> Result<(), anyhow::Error> {
        if self.username.is_empty() || self.password.is_empty() || self.confrim_password.is_empty() {
            return Err(anyhow!("Username and Password must be provided"));
        } else if self.password != self.confrim_password {
            return Err(anyhow!("Passwords do not match"));
        } else {
            Ok(())
        }
    }
}

pub fn encrypt(encryption: EncryptionInstance, file: File) -> Result<(), anyhow::Error> {
    encryption.credentials.is_valid()?;

    let file_data = fs::read(&file.path)?;

    if file.is_encrypted(&file_data.as_ref()) {
        return Err(anyhow!("File is already encrypted"));
    }

    let salt = encryption.credentials.generate_saltstring();
    let password_hash = match
        encryption.argon2.hash_password(encryption.credentials.password.as_bytes(), &salt)
    {
        Ok(hash) => hash,
        Err(e) => {
            return Err(anyhow!("Failed to hash password {:?}", e));
        }
    };

    let key = password_hash.hash.ok_or(anyhow!("Failed to get the hash output"))?;

    let encrypted_data = match encryption.algorithm {
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            let cipher = xchacha20_poly_1305(key);
            let hash = Sha256::digest(encryption.credentials.username.as_bytes());
            let nonce = XNonce::from_slice(&hash.as_slice()[..24]);
            cipher
                .encrypt(nonce, file_data.as_ref())
                .map_err(|e| anyhow!("Failed to encrypt file {:?}", e))?
        }
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = aes_gcm(key);
            let hash = Sha256::digest(encryption.credentials.username.as_bytes());
            let nonce = GenericArray::from_slice(&hash.as_slice()[..12]);
            cipher
                .encrypt(&nonce, file_data.as_ref())
                .map_err(|e| anyhow!("Failed to encrypt file {:?}", e))?
        }
    };

    let ncrypt_params =
        serde_json::json!({
        "m_cost": encryption.argon2.params().m_cost(),
        "t_cost": encryption.argon2.params().t_cost(),
        "p_cost": encryption.argon2.params().p_cost(),
        "hash_length": encryption.argon2.params().output_len(),
        "file_name": file.name,
        "encryption": encryption.algorithm(),
    })
            .to_string()
            .as_bytes()
            .to_vec();

    let params_with_identifier = [IDENTIFIER, ncrypt_params.as_slice()].concat();

    let encrypted_file_with_metadata = [
        encrypted_data.as_slice(),
        params_with_identifier.as_slice(),
    ].concat();

    fs::write(&file.name_encrypted(), &encrypted_file_with_metadata)?;

    Ok(())
}

pub fn decrypt(file: File, credentials: Credentials) -> Result<(), anyhow::Error> {
    credentials.is_valid()?;

    let encrypted_file = get_file_data(&file.path)?;
    let salt = credentials.generate_saltstring();

    let password_hash = match
        encrypted_file.argon2.hash_password(credentials.password.as_bytes(), &salt)
    {
        Ok(hash) => hash,
        Err(e) => {
            return Err(anyhow!("Failed to hash password {:?}", e));
        }
    };

    let key = password_hash.hash.ok_or(anyhow!("Failed to get the hash output"))?;

    let decrypted_data = match encrypted_file.algorithm {
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            let cipher = xchacha20_poly_1305(key);
            let hash = Sha256::digest(credentials.username.as_bytes());
            let nonce = XNonce::from_slice(&hash.as_slice()[..24]);
            cipher
                .decrypt(nonce, encrypted_file.data.as_ref())
                .map_err(|e| anyhow!("Failed to decrypt file {:?}", e))?
        }
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = aes_gcm(key);
            let hash = Sha256::digest(credentials.username.as_bytes());
            let nonce = GenericArray::from_slice(&hash.as_slice()[..12]);
            cipher
                .decrypt(&nonce, encrypted_file.data.as_slice())
                .map_err(|e| anyhow!("Failed to decrypt file {:?}", e))?
        }
    };

    fs::write(&encrypted_file.name, decrypted_data)?;
    Ok(())
}

/// Gets the data of an encrypted file and its nCrypt parameters
fn get_file_data(path: &str) -> Result<EncryptedFile, anyhow::Error> {
    let file = fs::read(path)?;
    let identifier_position = find_identifier_position(&file, IDENTIFIER).ok_or(
        anyhow::anyhow!("Failed to find identifier, Is the file encrypted?")
    )?;
    let (encrypted_data, identifier_data) = file.split_at(identifier_position);
    let file_params = &identifier_data[IDENTIFIER.len()..];

    // Parse the encryption params
    let params: serde_json::Value = serde_json::from_slice(file_params)?;
    let m_cost = params["m_cost"].as_u64().ok_or(anyhow!("Failed to parse m_cost"))?;
    let t_cost = params["t_cost"].as_u64().ok_or(anyhow!("Failed to parse t_cost"))?;
    let p_cost = params["p_cost"].as_u64().ok_or(anyhow!("Failed to parse p_cost"))?;
    let hash_length = params["hash_length"].as_u64().ok_or(anyhow!("Failed to parse hash_length"))?;
    let file_name = params["file_name"].as_str().ok_or(anyhow!("Failed to parse file_name"))?;
    let algo_used = params["encryption"].as_str().ok_or(anyhow!("Failed to parse encryption"))?;

    let params = Params::new(
        m_cost.try_into()?,
        t_cost.try_into()?,
        p_cost.try_into()?,
        Some(hash_length.try_into()?)
    ).map_err(|e| anyhow!("Failed to create Argon2 params {:?}", e))?;

    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params.clone());
    let encrypted_file = EncryptedFile::new(
        encrypted_data.to_vec(),
        argon2,
        file_name.to_string(),
        algo_used
    );

    Ok(encrypted_file)
}

fn find_identifier_position(data: &[u8], identifier: &[u8]) -> Option<usize> {
    data.windows(identifier.len()).rposition(|window| window == identifier)
}

/// Get the current directory the executable is running from
pub fn current_dir() -> anyhow::Result<PathBuf> {
    Ok(
        std::env
            ::current_exe()
            .context("Failed to get the current executable path")?
            .parent()
            .context("Failed to get the executable's directory")?
            .to_path_buf()
    )
}

pub fn aes_gcm(key: Output) -> Aes256Gcm {
    let key = GenericArray::from_slice(&key.as_bytes()[..32]);
    Aes256Gcm::new(key)
}

pub fn xchacha20_poly_1305(key: Output) -> XChaCha20Poly1305 {
    let key = GenericArray::from_slice(&key.as_bytes()[..32]);
    XChaCha20Poly1305::new(key)
}