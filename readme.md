# nCrypt-rs

### A simple GUI App to safely encrypt any file


![Screenshot](app.png)


## How it works

Data is encrypted with [XChaCha20Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)

The encryption key is derived from the password hash we generate using the [Argon2id](https://github.com/RustCrypto/password-hashes/blob/master/argon2) hashing alogrithm.

Both salt needed for the `Argon2id` hash and the nonce for the encryption key are derived from the [sha256](https://github.com/RustCrypto/hashes/blob/master/sha2) hash of the username input.

To make sure to be able to decrypt the file using the same credentials the Argon2id parameters are saved at the end of the file as plaintext.

For example if we take a txt file:
```
Some Text
```

It will look like this:
```
&³1:ß¥\ËºÁs%;8#4à5
xqparams      È          @
```

## Build From Source
```
cargo build --release
```