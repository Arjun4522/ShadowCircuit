// src/crypto/mod.rs
use ring::{aead, rand};
use ring::aead::UnboundKey;
use ring::rand::SecureRandom;

#[derive(Debug)]
pub enum CryptoError {
    RingError(ring::error::Unspecified),
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