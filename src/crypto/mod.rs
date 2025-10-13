// src/crypto/mod.rs
use ring::{aead, rand};
use ring::aead::UnboundKey;
use ring::rand::SecureRandom;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, EphemeralSecret};

#[derive(Debug)]
pub enum CryptoError {
    RingError(ring::error::Unspecified),
    NtorError(String),
}

impl From<ring::error::Unspecified> for CryptoError {
    fn from(err: ring::error::Unspecified) -> Self {
        CryptoError::RingError(err)
    }
}

fn generate_aead_key(rng: &ring::rand::SystemRandom) -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    rng.fill(&mut key)?;
    Ok(key)
}

fn generate_nonce(nonce: u64) -> [u8; 12] {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
    nonce_bytes
}

/// Onion encryption state for a circuit
#[derive(Debug, Clone)]
pub struct OnionCrypto {
    forward_key: aead::LessSafeKey,
    backward_key: aead::LessSafeKey,
    forward_nonce: u64,
    backward_nonce: u64,
}

impl OnionCrypto {
    pub fn new() -> Result<Self, CryptoError> {
        let rng = rand::SystemRandom::new();

        // Generate initial keys
        let forward_key = generate_aead_key(&rng)?;
        let backward_key = generate_aead_key(&rng)?;

        Ok(Self {
            forward_key: aead::LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &forward_key)?),
            backward_key: aead::LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &backward_key)?),
            forward_nonce: 0,
            backward_nonce: 0,
        })
    }

    pub fn from_ntor_keys(keys: NtorKeys) -> Result<Self, CryptoError> {
        Ok(Self {
            forward_key: aead::LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &keys.forward_key)?),
            backward_key: aead::LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &keys.backward_key)?),
            forward_nonce: 0,
            backward_nonce: 0,
        })
    }

    /// Encrypt data for forward direction
    pub fn encrypt_forward(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = generate_nonce(self.forward_nonce);
        self.forward_nonce += 1;

        let mut in_out = plaintext.to_vec();
        let tag = self.forward_key.seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out
        )?;

        in_out.extend_from_slice(tag.as_ref());
        Ok(in_out)
    }

    /// Decrypt data from forward direction
    pub fn decrypt_forward(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = generate_nonce(self.forward_nonce);
        self.forward_nonce += 1;

        let mut in_out = ciphertext.to_vec();
        self.forward_key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out
        )?;

        Ok(in_out)
    }
}


pub struct NtorKeys {
    pub forward_key: [u8; 32],
    pub backward_key: [u8; 32],
}

pub fn ntor_handshake(
    client_private_key: EphemeralSecret,
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
    relay_identity_key: &[u8],
    relay_onion_key: &[u8],
) -> Result<(NtorKeys, Vec<u8>), CryptoError> {
    // ECDH calculation
    let ecdh_secret = client_private_key.diffie_hellman(server_public_key);

    let mut secret_input = Vec::new();
    secret_input.extend_from_slice(ecdh_secret.as_bytes());
    secret_input.extend_from_slice(relay_identity_key);
    secret_input.extend_from_slice(relay_onion_key);
    secret_input.extend_from_slice(client_public_key.as_bytes());
    secret_input.extend_from_slice(server_public_key.as_bytes());
    secret_input.extend_from_slice(b"ntor-curve25519-sha256-1");

    let prk = Hkdf::<Sha256>::new(Some(b"ntor-curve25519-sha256-1"), &secret_input);

    let mut okm = [0u8; 96];
    prk.expand(b"ntor-kdf-expand", &mut okm).map_err(|_| CryptoError::NtorError("HKDF expand failed".to_string()))?;

    let forward_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let backward_key: [u8; 32] = okm[32..64].try_into().unwrap();
    let auth: Vec<u8> = okm[64..96].to_vec();

    Ok((NtorKeys { forward_key, backward_key }, auth))
}
