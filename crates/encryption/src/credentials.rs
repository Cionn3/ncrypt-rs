use sha2::{ Sha256, digest::Digest };
use password_hash::SaltString;
use zeroize::Zeroize;

use anyhow::anyhow;


/// The credentials needed to encrypt and decrypt an encrypted file
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Credentials {
    username: String,
    password: String,
    confirm_password: String,
}


impl Credentials {

    pub fn new(username: String, password: String, confirm_password: String) -> Self {
        Self {
            username,
            password,
            confirm_password,
        }
    }

    /// Destroy the credentials by zeroizing the username and password
    pub fn destroy(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.confirm_password.zeroize();
    }

    pub fn username(&self) -> &String {
        &self.username
    }

    pub fn password(&self) -> &String {
        &self.password
    }

    pub fn confirm_password(&self) -> &String {
        &self.confirm_password
    }

    /// Get a mutable reference to the username
    pub fn user_mut(&mut self) -> &mut String {
        &mut self.username
    }

    /// Get a mutable reference to the password
    pub fn passwd_mut(&mut self) -> &mut String {
        &mut self.password
    }

    /// Get a mutable reference to the confirm password
    pub fn confirm_passwd_mut(&mut self) -> &mut String {
        &mut self.confirm_password
    }


    /// Generate a Salt from the username
    pub fn generate_saltstring(&self) -> Result<SaltString, anyhow::Error> {
        let salt_array = Sha256::digest(self.username.as_bytes());
        let salt = salt_array.to_vec();
        let salt = salt.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let salt = SaltString::from_b64(&salt).map_err(|e| anyhow!("Failed to generate salt string {:?}", e))?;
        Ok(salt)
    }

    pub fn is_valid(&self) -> Result<(), anyhow::Error> {
        if self.username.is_empty() || self.password.is_empty() || self.confirm_password.is_empty() {
            return Err(anyhow!("Username and Password must be provided"));
        }

        if self.password != self.confirm_password {
            return Err(anyhow!("Passwords do not match"));
        }

        Ok(())
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_credentials() {
        let mut credentials = Credentials::new("test".to_string(), "password".to_string(), "password".to_string());
        assert!(credentials.is_valid().is_ok());

        let salt = credentials.generate_saltstring().unwrap();
        assert_eq!(salt.to_string().len(), 64);

        credentials.destroy();
        assert!(credentials.is_valid().is_err());
    }
}