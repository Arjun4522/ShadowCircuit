use x25519_dalek::PublicKey;
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use x25519_dalek::EphemeralSecret;

type HmacSha256 = Hmac<Sha256>;

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

/// h_tweak: Compute HMAC-SHA256 with tweak as the key
/// This matches Tor's h_tweak function which uses the tweak as the HMAC key
fn h_tweak(tweak: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(tweak)
        .expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

/// Performs the ntor handshake - CLIENT SIDE
/// 
/// This implements the client side of the ntor handshake as specified in tor-spec.txt section 5.1.4
/// and matches the implementation in src/core/crypto/onion_ntor.c
/// 
/// Inputs:
/// - client_private_key (x): Client's ephemeral private key as bytes [u8; 32]
/// - client_public_key (X): Client's ephemeral public key
/// - server_public_key (Y): Server's ephemeral public key (from CREATED2)
/// - relay_identity_key (ID): Server's identity key (20 bytes)
/// - relay_onion_key (B): Server's ntor onion key (32 bytes)
/// 
/// Returns:
/// - (NtorKeys, auth): Derived keys and authentication value
/// 
/// The client computes:
///   XY = EXP(Y, x) - shared secret with server's ephemeral key
///   XB = EXP(B, x) - shared secret with server's static onion key
pub fn ntor_handshake(
    client_private_key: &[u8; 32],
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
    relay_identity_key: &[u8],
    relay_onion_key: &[u8],
) -> (NtorKeys, Vec<u8>) {
    // Parse relay_onion_key (B) as PublicKey
    let mut b_bytes = [0u8; 32];
    b_bytes.copy_from_slice(relay_onion_key);
    let relay_onion_pubkey = PublicKey::from(b_bytes);
    
    // Compute BOTH shared secrets using the same private key
    // XY = x * Y (client private * server ephemeral public)
    let xy_shared = x25519_dalek::x25519(*client_private_key, server_public_key.to_bytes());
    
    // XB = x * B (client private * server static onion public)  
    let xb_shared = x25519_dalek::x25519(*client_private_key, relay_onion_pubkey.to_bytes());
    
    log::debug!("XY DH (first 8 bytes): {:02x?}", &xy_shared[..8]);
    log::debug!("XB DH (first 8 bytes): {:02x?}", &xb_shared[..8]);
    log::info!("Computed both DH operations: EXP(Y,x) and EXP(B,x)");
    log::info!("Starting ntor key derivation...");
    
    ntor_key_derivation(
        &xy_shared,
        &xb_shared,
        relay_identity_key,
        relay_onion_key,
        client_public_key.as_bytes(),
        server_public_key.as_bytes(),
    )
}

/// Performs ntor key derivation
/// 
/// This implements the key derivation function EXACTLY as in Tor's onion_ntor.c
/// 
/// According to Tor's implementation:
/// 1. secret_input = XY | XB | ID | B | X | Y | PROTOID
/// 2. verify = HMAC-SHA256(T_VERIFY, secret_input)
/// 3. auth_input = verify | ID | B | Y | X | PROTOID | "Server"
/// 4. AUTH = HMAC-SHA256(T_MAC, auth_input)
/// 5. Key material = HKDF-SHA256-Expand(HKDF-SHA256-Extract(T_KEY, secret_input), M_EXPAND, length)
pub fn ntor_key_derivation(
    xy_shared: &[u8],       // EXP(Y, x) - 32 bytes
    xb_shared: &[u8],       // EXP(B, x) - 32 bytes  
    relay_identity: &[u8],  // ID - 20 bytes
    relay_onion_key: &[u8], // B - 32 bytes  
    client_public: &[u8],   // X - 32 bytes
    server_public: &[u8],   // Y - 32 bytes
) -> (NtorKeys, Vec<u8>) {
    const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
    const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
    const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
    const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:verify";
    const M_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";
    const SERVER_STR: &[u8] = b"Server";

    log::debug!("=== ntor Key Derivation Debug ===");
    log::debug!("XY shared (first 8 bytes): {:02x?}", &xy_shared[..8]);
    log::debug!("XB shared (first 8 bytes): {:02x?}", &xb_shared[..8]);
    log::debug!("Relay identity (first 8 bytes): {:02x?}", &relay_identity[..8]);
    log::debug!("Relay onion key (first 8 bytes): {:02x?}", &relay_onion_key[..8]);
    log::debug!("Client public key (first 8 bytes): {:02x?}", &client_public[..8]);
    log::debug!("Server public key (first 8 bytes): {:02x?}", &server_public[..8]);

    // Build secret_input per Tor spec:
    // secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    let mut secret_input = Vec::new();
    secret_input.extend_from_slice(xy_shared);      // 32 bytes
    secret_input.extend_from_slice(xb_shared);      // 32 bytes
    secret_input.extend_from_slice(relay_identity); // 20 bytes
    secret_input.extend_from_slice(relay_onion_key);// 32 bytes
    secret_input.extend_from_slice(client_public);  // 32 bytes
    secret_input.extend_from_slice(server_public);  // 32 bytes
    secret_input.extend_from_slice(PROTOID);        // 24 bytes
    // Total: 204 bytes ✓

    log::debug!("secret_input length: {} bytes", secret_input.len());
    log::debug!("secret_input (first 16 bytes): {:02x?}", &secret_input[..16]);

    // Step 1: Compute verify = HMAC-SHA256(T_VERIFY, secret_input)
    // This is h_tweak in Tor's code
    let verify = h_tweak(T_VERIFY, &secret_input);
    log::debug!("verify (first 8 bytes): {:02x?}", &verify[..8]);

    // Step 2: Build auth_input
    // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    let mut auth_input = Vec::new();
    auth_input.extend_from_slice(&verify);           // 32 bytes
    auth_input.extend_from_slice(relay_identity);    // 20 bytes
    auth_input.extend_from_slice(relay_onion_key);   // 32 bytes
    auth_input.extend_from_slice(server_public);     // 32 bytes (Y)
    auth_input.extend_from_slice(client_public);     // 32 bytes (X)
    auth_input.extend_from_slice(PROTOID);           // 24 bytes
    auth_input.extend_from_slice(SERVER_STR);        // 6 bytes
    // Total: 178 bytes ✓

    log::debug!("auth_input length: {} bytes", auth_input.len());
    log::debug!("auth_input (first 16 bytes): {:02x?}", &auth_input[..16]);

    // Step 3: Compute AUTH = HMAC-SHA256(T_MAC, auth_input)
    let auth = h_tweak(T_MAC, &auth_input);
    log::debug!("Computed AUTH (full): {:02x?}", auth);

    // Step 4: Derive key material using HKDF-SHA256
    // This matches crypto_expand_key_material_rfc5869_sha256 in Tor
    // HKDF-Extract(salt=T_KEY, IKM=secret_input) -> PRK
    // HKDF-Expand(PRK, info=M_EXPAND, length) -> output key material
    let hkdf = Hkdf::<Sha256>::new(Some(T_KEY), &secret_input);
    
    let mut key_material = [0u8; 72];
    hkdf.expand(M_EXPAND, &mut key_material)
        .expect("HKDF expand failed");

    let forward_key: [u8; 32] = key_material[0..32].try_into().unwrap();
    let backward_key: [u8; 32] = key_material[32..64].try_into().unwrap();
    // bytes 64..72 can be used for additional key material if needed

    log::debug!("forward_key (first 8 bytes): {:02x?}", &forward_key[..8]);
    log::debug!("backward_key (first 8 bytes): {:02x?}", &backward_key[..8]);
    log::debug!("=== End ntor Key Derivation Debug ===");

    (
        NtorKeys {
            forward_key,
            backward_key,
        },
        auth.to_vec(),
    )
}