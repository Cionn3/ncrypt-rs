pub mod credentials;
pub mod encrypt;
pub mod decrypt;
pub mod prelude;




#[cfg(test)]
mod tests {

    use super::prelude::*;

    #[test]
    fn can_encrypt() {

        let some_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let credentials = Credentials::new("username".to_string(), "password".to_string(), "password".to_string());
        let argon_params = Argon2Params::default();

        let encrypted_data = encrypt_data(argon_params, some_data.clone(), credentials.clone()).expect("Failed to encrypt data");

        // write the encrypted data to a file
        std::fs::write("test.ncrypt", &encrypted_data).expect("Failed to write encrypted data to file");

        // read the encrypted data from the file
        let encrypted_data = std::fs::read("test.ncrypt").expect("Failed to read encrypted data from file");

        // decrypt the data
        let decrypted_data = decrypt_data(encrypted_data, credentials).expect("Failed to decrypt data");

        assert_eq!(some_data, decrypted_data);

        // remove the test file
        std::fs::remove_file("test.ncrypt").expect("Failed to remove test file");
        
    }
}
