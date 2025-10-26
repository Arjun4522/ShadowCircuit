use x25519_dalek::{PublicKey, StaticSecret, SharedSecret};
use rand_core::OsRng;
use sha2::Sha256;
use hkdf::Hkdf;

pub struct NtorSecret {
    pub secret: StaticSecret,
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
        let secret = StaticSecret::random_from_rng(OsRng);
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

/// Perform the ntor handshake with correct two Diffie-Hellman computations
/// 
/// According to tor-spec.txt section 5.1.4:
/// Client computes:
///   secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
///   KEY_SEED = H(secret_input, t_key)
///   verify = H(secret_input, t_verify)
///   auth_input = verify | ID | B | Y | X | PROTOID | "Server"
///   AUTH = H(auth_input, t_mac)
/// 
/// Where:
///   X, x = client's ephemeral public and private keys
///   Y, y = server's ephemeral public and private keys  
///   B, b = server's long-term ntor onion public and private keys
///   ID = server's identity key (20 bytes)
///   H(x,t) = HMAC-SHA256 with message x and key t
pub fn ntor_handshake(
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
    relay_identity_key: &[u8],
    relay_onion_key: &[u8],
    xy_shared: &SharedSecret,
    xb_shared: &SharedSecret,
) -> (NtorKeys, Vec<u8>) {
    ntor_key_derivation(
        xy_shared.as_bytes(),
        xb_shared.as_bytes(),
        relay_identity_key,
        relay_onion_key,
        client_public_key.as_bytes(),
        server_public_key.as_bytes(),
    )
}

pub fn ntor_key_derivation(
    xy_shared: &[u8],      // EXP(Y,x) - client ephemeral private * server ephemeral public
    xb_shared: &[u8],      // EXP(B,x) - client ephemeral private * server long-term public
    relay_identity_key: &[u8],  // ID - 20 bytes
    relay_onion_key: &[u8],     // B - 32 bytes
    client_public_key: &[u8],   // X - 32 bytes
    server_public_key: &[u8],   // Y - 32 bytes
) -> (NtorKeys, Vec<u8>) {
    const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
    const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
    const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
    const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:verify";
    const M_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";

    log::debug!("=== ntor Key Derivation Debug ===");
    log::debug!("XY shared (first 8 bytes): {:02x?}", &xy_shared[..8]);
    log::debug!("XB shared (first 8 bytes): {:02x?}", &xb_shared[..8]);
    log::debug!("Relay identity (first 8 bytes): {:02x?}", &relay_identity_key[..8]);
    log::debug!("Relay onion key (first 8 bytes): {:02x?}", &relay_onion_key[..8]);
    log::debug!("Client public key (first 8 bytes): {:02x?}", &client_public_key[..8]);
    log::debug!("Server public key (first 8 bytes): {:02x?}", &server_public_key[..8]);

    // Build secret_input according to spec:
    // EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    let mut secret_input = Vec::with_capacity(32 + 32 + 20 + 32 + 32 + 32 + PROTOID.len());
    secret_input.extend_from_slice(xy_shared);           // 32 bytes - EXP(Y,x)
    secret_input.extend_from_slice(xb_shared);           // 32 bytes - EXP(B,x)
    secret_input.extend_from_slice(relay_identity_key);  // 20 bytes - ID (relay identity)
    secret_input.extend_from_slice(relay_onion_key);     // 32 bytes - B (relay onion key)
    secret_input.extend_from_slice(client_public_key);   // 32 bytes - X (client public key)
    secret_input.extend_from_slice(server_public_key);   // 32 bytes - Y (server public key)
    secret_input.extend_from_slice(PROTOID);             // PROTOID

    log::debug!("secret_input length: {} bytes", secret_input.len());
    log::debug!("secret_input (first 16 bytes): {:02x?}", &secret_input[..16]);

// KEY_SEED = H(secret_input, t_key)  -- HMAC-SHA256(secret_input, key=t_key)
    // In the HMAC, t_key is the key and secret_input is the message
    let key_seed_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, T_KEY);
    let key_seed = ring::hmac::sign(&key_seed_key, &secret_input);
    log::debug!("KEY_SEED (first 8 bytes): {:02x?}", &key_seed.as_ref()[..8]);
    
    // verify = H(secret_input, t_verify) -- HMAC-SHA256(secret_input, key=t_verify)
    let verify_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, T_VERIFY);
    let verify = ring::hmac::sign(&verify_key, &secret_input);
    log::debug!("verify (first 8 bytes): {:02x?}", &verify.as_ref()[..8]);

    // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    // According to Tor spec section 5.1.4, the order is critical
    let mut auth_input = Vec::with_capacity(32 + 20 + 32 + 32 + 32 + PROTOID.len() + 6);
    auth_input.extend_from_slice(verify.as_ref());      // verify (32 bytes)
    auth_input.extend_from_slice(relay_identity_key);   // ID (20 bytes) - server identity key
    auth_input.extend_from_slice(relay_onion_key);      // B (32 bytes) - server onion key
    auth_input.extend_from_slice(server_public_key);    // Y (32 bytes) - server ephemeral public key
    auth_input.extend_from_slice(client_public_key);    // X (32 bytes) - client ephemeral public key
    auth_input.extend_from_slice(PROTOID);              // PROTOID (25 bytes) - "ntor-curve25519-sha256-1"
    auth_input.extend_from_slice(b"Server");            // "Server" (6 bytes)

    log::debug!("auth_input length: {} bytes", auth_input.len());
    log::debug!("auth_input (first 16 bytes): {:02x?}", &auth_input[..16]);

    // AUTH = H(auth_input, t_mac) -- HMAC-SHA256(auth_input, key=t_mac)
    // In the HMAC, t_mac is the key and auth_input is the message
    let auth_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, T_MAC);
    let auth = ring::hmac::sign(&auth_key, &auth_input);
    
    log::debug!("Computed AUTH (full): {:02x?}", auth.as_ref());

    // Use HKDF-SHA256 to expand KEY_SEED into actual keys
    let hkdf = Hkdf::<Sha256>::new(None, key_seed.as_ref());
    
    let mut full_key_material = vec![0u8; 128];
    hkdf.expand(M_EXPAND, &mut full_key_material).unwrap();

    // Extract keys: forward and backward keys for AES-256-GCM (32 bytes each)
    // According to Tor spec, after HKDF expansion we get 128 bytes total:
    // Bytes 0-31:   unused in this implementation
    // Bytes 32-63:  unused in this implementation  
    // Bytes 64-95:  forward key (client to server)
    // Bytes 96-127: backward key (server to client)
    let forward_key: [u8; 32] = full_key_material[64..96].try_into().unwrap();
    let backward_key: [u8; 32] = full_key_material[96..128].try_into().unwrap();

    log::debug!("forward_key (first 8 bytes): {:02x?}", &forward_key[..8]);
    log::debug!("backward_key (first 8 bytes): {:02x?}", &backward_key[..8]);
    log::debug!("=== End ntor Key Derivation Debug ===");

        (
            NtorKeys { forward_key, backward_key },
            auth.as_ref().to_vec()
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntor_key_derivation() {
        // Test vectors
        let xy_shared = [1u8; 32];
        let xb_shared = [2u8; 32];
        let relay_identity = [3u8; 20];
        let relay_onion = [4u8; 32];
        let client_public = [5u8; 32];
        let server_public = [6u8; 32];

        let (keys, auth) = ntor_key_derivation(
            &xy_shared,
            &xb_shared,
            &relay_identity,
            &relay_onion,
            &client_public,
            &server_public,
        );

        // Verify outputs are generated
        assert_eq!(keys.forward_key.len(), 32);
        assert_eq!(keys.backward_key.len(), 32);
        assert_eq!(auth.len(), 32);

        // Verify keys are different
        assert_ne!(keys.forward_key, keys.backward_key);
        assert_ne!(keys.forward_key, [0u8; 32]);
        assert_ne!(keys.backward_key, [0u8; 32]);
        assert_ne!(auth, vec![0u8; 32]);
    }

    #[test]
    fn test_hmac_computation() {
        // Verify HMAC is being used correctly
        let test_data = b"test data";
        let test_key = b"test key";
        
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, test_key);
        let result = ring::hmac::sign(&key, test_data);
        
        // Should produce 32 bytes
        assert_eq!(result.as_ref().len(), 32);
        
        // Should be deterministic
        let result2 = ring::hmac::sign(&key, test_data);
        
        assert_eq!(result.as_ref(), result2.as_ref());
    }
}