//! Protocol equivalents of kdf.c and cipher.c. The wire format deliberately
//! remains compatible with LastPass; local storage uses authenticated AES-GCM.
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub type Key = Zeroizing<[u8; 32]>;
pub fn derive_key(username: &str, password: &str, iterations: u32) -> Result<Key> {
    ensure!(
        (2..=10_000_000).contains(&iterations),
        "Unsupported iteration count (must be 2..=10000000)"
    );
    let mut key = Zeroizing::new([0; 32]);
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        username.to_lowercase().as_bytes(),
        iterations,
        &mut *key,
    );
    Ok(key)
}
pub fn login_hash(key: &[u8; 32], password: &str) -> Zeroizing<String> {
    let mut result = Zeroizing::new([0; 32]);
    pbkdf2_hmac::<Sha256>(key, password.as_bytes(), 1, &mut *result);
    Zeroizing::new(hex::encode(*result))
}
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
pub fn decrypt_raw(bytes: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.is_empty() {
        return Ok(Zeroizing::new(Vec::new()));
    }
    let plain = if bytes.len() >= 33 && bytes.len() % 16 == 1 && bytes[0] == b'!' {
        cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &bytes[1..17])
            .map_err(|_| anyhow::anyhow!("Invalid AES key or IV"))?
            .decrypt_padded_vec_mut::<Pkcs7>(&bytes[17..])
    } else {
        ensure!(bytes.len() % 16 == 0, "Invalid AES ciphertext length");
        ecb::Decryptor::<aes::Aes256>::new_from_slice(key)
            .map_err(|_| anyhow::anyhow!("Invalid AES key"))?
            .decrypt_padded_vec_mut::<Pkcs7>(bytes)
    }
    .map_err(|_| anyhow::anyhow!("AES decryption failed (wrong key or damaged vault)"))?;
    Ok(Zeroizing::new(plain))
}
pub fn encrypt_raw(bytes: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let iv = random_bytes::<16>();
    let mut result = Vec::with_capacity(bytes.len() + 33);
    result.push(b'!');
    result.extend_from_slice(&iv);
    result.extend(
        cbc::Encryptor::<aes::Aes256>::new(key.into(), (&iv).into())
            .encrypt_padded_vec_mut::<Pkcs7>(bytes),
    );
    result
}
pub fn wire_base64(bytes: &[u8]) -> String {
    if bytes.len() >= 33 && bytes.len() % 16 == 1 && bytes[0] == b'!' {
        format!(
            "!{}|{}",
            STANDARD.encode(&bytes[1..17]),
            STANDARD.encode(&bytes[17..])
        )
    } else {
        STANDARD.encode(bytes)
    }
}
pub fn wire_unbase64(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(v) = value.strip_prefix('!') {
        let (iv, data) = v
            .split_once('|')
            .context("Invalid LastPass CBC base64 format")?;
        let iv = STANDARD.decode(iv).context("Invalid IV base64")?;
        ensure!(iv.len() == 16, "Invalid IV length");
        let mut result = vec![b'!'];
        result.extend(iv);
        result.extend(STANDARD.decode(data).context("Invalid ciphertext base64")?);
        Ok(result)
    } else {
        STANDARD.decode(value).context("Invalid ciphertext base64")
    }
}
pub fn encrypt_base64(value: &str, key: &[u8; 32]) -> String {
    wire_base64(&encrypt_raw(value.as_bytes(), key))
}
pub fn decrypt_base64(value: &str, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_raw(&wire_unbase64(value)?, key)
}
pub fn text(bytes: &[u8]) -> String {
    // The C implementation exposes NUL-terminated strings.
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
pub fn decrypt_private_key(value: &str, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    if value.is_empty() {
        return Ok(Zeroizing::new(Vec::new()));
    }
    let plain = if value.starts_with('!') {
        decrypt_base64(value, key)?
    } else {
        let ciphertext = hex::decode(value).context("Invalid private key hex")?;
        let mut v = vec![b'!'];
        v.extend_from_slice(&key[..16]);
        v.extend(ciphertext);
        decrypt_raw(&v, key)?
    };
    let value = std::str::from_utf8(&plain).context("Invalid private key envelope")?;
    let value = value
        .strip_prefix("LastPassPrivateKey<")
        .and_then(|v| v.strip_suffix(">LastPassPrivateKey"))
        .context("Missing private key envelope")?;
    Ok(Zeroizing::new(
        hex::decode(value).context("Invalid private key DER hex")?,
    ))
}
pub fn encrypt_private_key(der: &[u8], key: &[u8; 32]) -> String {
    if der.is_empty() {
        return String::new();
    }
    let value = Zeroizing::new(format!(
        "LastPassPrivateKey<{}>LastPassPrivateKey",
        hex::encode(der)
    ));
    encrypt_base64(&value, key)
}
pub fn rsa_decrypt(ciphertext: &[u8], der: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let private = RsaPrivateKey::from_pkcs8_der(der).context("Invalid sharing private key")?;
    Ok(Zeroizing::new(
        private
            .decrypt(Oaep::new::<Sha1>(), ciphertext)
            .context("Sharing key RSA decryption failed")?,
    ))
}
pub fn rsa_encrypt(plain: &[u8], public_der: &[u8]) -> Result<Vec<u8>> {
    let public =
        RsaPublicKey::from_public_key_der(public_der).context("Invalid sharing public key")?;
    public
        .encrypt(&mut OsRng, Oaep::new::<Sha1>(), plain)
        .context("Sharing key RSA encryption failed")
}
pub fn seal(bytes: &[u8], key: &[u8; 32], label: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes::<12>();
    let cipher = Aes256Gcm::new(key.into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: bytes,
                aad: label,
            },
        )
        .map_err(|_| anyhow::anyhow!("Local encryption failed"))?;
    let mut output = b"LPRS1".to_vec();
    output.extend_from_slice(&nonce);
    output.extend(ciphertext);
    Ok(output)
}
pub fn unseal(bytes: &[u8], key: &[u8; 32], label: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() < 33 || &bytes[..5] != b"LPRS1" {
        bail!("Invalid encrypted local file");
    }
    let plain = Aes256Gcm::new(key.into())
        .decrypt(
            Nonce::from_slice(&bytes[5..17]),
            Payload {
                msg: &bytes[17..],
                aad: label,
            },
        )
        .map_err(|_| {
            anyhow::anyhow!("Cannot unlock local state (wrong password or damaged file)")
        })?;
    Ok(Zeroizing::new(plain))
}
