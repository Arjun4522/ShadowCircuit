
use x25519_dalek::{PublicKey, EphemeralSecret};
use rand_core::OsRng;
use sha2::Sha256;
use hkdf::Hkdf;

pub struct NtorSecret {
    pub secret: EphemeralSecret,
}

#[derive(Clone, PartialEq, Debug)]
pub struct NtorPublic {
    pub public: PublicKey,
}

pub struct NtorKeys {
    pub forward_key: [u8; 32],
    pub backward_key: [u8; 32],
}

impl NtorSecret {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        Self { secret }
    }

    pub fn public_key(&self) -> NtorPublic {
        NtorPublic {
            public: PublicKey::from(&self.secret),
        }
    }
}

impl NtorPublic {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(bytes);
        Some(NtorPublic {
            public: PublicKey::from(public_key),
        })
    }
}

pub fn ntor_handshake(
    client_private_key: EphemeralSecret,
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
    relay_identity_key: &[u8],
    relay_onion_key: &[u8],
) -> (NtorKeys, Vec<u8>) {
    let shared_secret = client_private_key.diffie_hellman(server_public_key);
    ntor_key_derivation(
        shared_secret.as_bytes(),
        relay_identity_key,
        relay_onion_key,
        client_public_key.as_bytes(),
        server_public_key.as_bytes(),
    )
}

pub fn ntor_key_derivation(
    shared_secret: &[u8],
    relay_identity_key: &[u8],
    relay_onion_key: &[u8],
    client_public_key: &[u8],
    server_public_key: &[u8],
) -> (NtorKeys, Vec<u8>) {
    const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
    const M_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";
    const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";

    let mut secret_input = Vec::with_capacity(32 + 32 + 20 + 32 + 32 + 32 + PROTOID.len());
    secret_input.extend_from_slice(shared_secret);
    secret_input.extend_from_slice(shared_secret); // Simplified
    secret_input.extend_from_slice(relay_identity_key);
    secret_input.extend_from_slice(relay_onion_key);
    secret_input.extend_from_slice(client_public_key);
    secret_input.extend_from_slice(server_public_key);
    secret_input.extend_from_slice(PROTOID);

    let hkdf = Hkdf::<Sha256>::new(Some(T_KEY), &secret_input);

    let mut key_material = [0u8; 96];
    hkdf.expand(M_EXPAND, &mut key_material).unwrap();

    let auth: Vec<u8> = key_material[0..32].to_vec();
    let forward_key: [u8; 32] = key_material[32..64].try_into().unwrap();
    let backward_key: [u8; 32] = key_material[64..96].try_into().unwrap();

    (NtorKeys { forward_key, backward_key }, auth)
}

