use x25519_dalek::{PublicKey, ReusableSecret};
use rand_core::OsRng;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;

type HmacSha256 = Hmac<Sha256>;

pub struct NtorSecret {
    pub secret: ReusableSecret,
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
        let secret = ReusableSecret::random_from_rng(OsRng);
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
/// This matches Tor's h_tweak function
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
/// This matches the official Tor implementation in onion_ntor.c
/// See: onion_skin_ntor_client_handshake()
/// 
/// Key insight: The client uses the SAME private key x for TWO DH operations:
/// - XY = x * Y (with server's ephemeral public key)
/// - XB = x * B (with server's static onion key)
/// 
/// This is why we use StaticSecret instead of EphemeralSecret!
pub fn ntor_handshake(
    client_private_key: &ReusableSecret,
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
    relay_identity_key: &[u8],
    relay_onion_key: &[u8],
) -> (NtorKeys, Vec<u8>) {
    // Parse relay_onion_key (B) as PublicKey
    let mut b_bytes = [0u8; 32];
    b_bytes.copy_from_slice(relay_onion_key);
    let relay_onion_pubkey = PublicKey::from(b_bytes);
    
    // CRITICAL: Compute BOTH shared secrets using the SAME private key
    // This matches the official Tor implementation exactly:
    //   curve25519_handshake(si, &handshake_state->seckey_x, &s.pubkey_Y);
    //   curve25519_handshake(si, &handshake_state->seckey_x, &handshake_state->pubkey_B);
    
    // XY = x * Y (client private * server ephemeral public)
    let xy_shared = client_private_key.diffie_hellman(server_public_key);
    
    // XB = x * B (client private * server static onion public)  
    let xb_shared = client_private_key.diffie_hellman(&relay_onion_pubkey);
    
    log::debug!("XY DH (first 8 bytes): {:02x?}", &xy_shared.as_bytes()[..8]);
    log::debug!("XB DH (first 8 bytes): {:02x?}", &xb_shared.as_bytes()[..8]);
    log::info!("Computed both DH operations: EXP(Y,x) and EXP(B,x)");
    
    ntor_key_derivation(
        xy_shared.as_bytes(),
        xb_shared.as_bytes(),
        relay_identity_key,
        relay_onion_key,
        client_public_key.as_bytes(),
        server_public_key.as_bytes(),
    )
}

/// Performs ntor key derivation
/// 
/// This matches the official Tor implementation exactly:
/// 1. Build secret_input = XY | XB | ID | B | X | Y | PROTOID (204 bytes)
/// 2. Compute verify = h_tweak(T_VERIFY, secret_input)
/// 3. Build auth_input = verify | ID | B | Y | X | PROTOID | "Server" (178 bytes)
/// 4. Compute AUTH = h_tweak(T_MAC, auth_input)
/// 5. Derive keys using HKDF-SHA256
fn ntor_key_derivation(
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

    log::debug!("=== ntor Key Derivation (matches Tor onion_ntor.c) ===");
    log::debug!("XY shared (first 8 bytes): {:02x?}", &xy_shared[..8]);
    log::debug!("XB shared (first 8 bytes): {:02x?}", &xb_shared[..8]);

    // Build secret_input per official Tor spec (SECRET_INPUT_LEN = 204):
    // secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    let mut secret_input = Vec::new();
    secret_input.extend_from_slice(xy_shared);      // 32 bytes - XY
    secret_input.extend_from_slice(xb_shared);      // 32 bytes - XB
    secret_input.extend_from_slice(relay_identity); // 20 bytes - ID
    secret_input.extend_from_slice(relay_onion_key);// 32 bytes - B
    secret_input.extend_from_slice(client_public);  // 32 bytes - X
    secret_input.extend_from_slice(server_public);  // 32 bytes - Y
    secret_input.extend_from_slice(PROTOID);        // 24 bytes - PROTOID
    // Total: 204 bytes ✓

    log::debug!("secret_input length: {} bytes (expected 204)", secret_input.len());
    assert_eq!(secret_input.len(), 204, "secret_input must be 204 bytes");

    // Step 1: Compute verify = HMAC-SHA256(T_VERIFY, secret_input)
    // Matches: h_tweak(s.verify, s.secret_input, sizeof(s.secret_input), T->t_verify);
    let verify = h_tweak(T_VERIFY, &secret_input);
    log::debug!("verify (first 8 bytes): {:02x?}", &verify[..8]);

    // Step 2: Build auth_input per official Tor spec (AUTH_INPUT_LEN = 178):
    // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    let mut auth_input = Vec::new();
    auth_input.extend_from_slice(&verify);           // 32 bytes - verify
    auth_input.extend_from_slice(relay_identity);    // 20 bytes - ID
    auth_input.extend_from_slice(relay_onion_key);   // 32 bytes - B
    auth_input.extend_from_slice(server_public);     // 32 bytes - Y
    auth_input.extend_from_slice(client_public);     // 32 bytes - X
    auth_input.extend_from_slice(PROTOID);           // 24 bytes - PROTOID
    auth_input.extend_from_slice(SERVER_STR);        // 6 bytes - "Server"
    // Total: 178 bytes ✓

    log::debug!("auth_input length: {} bytes (expected 178)", auth_input.len());
    assert_eq!(auth_input.len(), 178, "auth_input must be 178 bytes");

    // Step 3: Compute AUTH = HMAC-SHA256(T_MAC, auth_input)
    // Matches: h_tweak(s.auth, s.auth_input, sizeof(s.auth_input), T->t_mac);
    let auth = h_tweak(T_MAC, &auth_input);
    log::debug!("Computed AUTH (full): {:02x?}", auth);

    // Step 4: Derive key material using HKDF-SHA256
    // Matches: crypto_expand_key_material_rfc5869_sha256(...)
    // HKDF-Extract(salt=T_KEY, IKM=secret_input) -> PRK
    // HKDF-Expand(PRK, info=M_EXPAND, length) -> output key material
    let hkdf = Hkdf::<Sha256>::new(Some(T_KEY), &secret_input);
    
    let mut key_material = [0u8; 72];
    hkdf.expand(M_EXPAND, &mut key_material)
        .expect("HKDF expand failed");

    let forward_key: [u8; 32] = key_material[0..32].try_into().unwrap();
    let backward_key: [u8; 32] = key_material[32..64].try_into().unwrap();
    // bytes 64..72 available for additional key material if needed

    log::debug!("forward_key (first 8 bytes): {:02x?}", &forward_key[..8]);
    log::debug!("backward_key (first 8 bytes): {:02x?}", &backward_key[..8]);
    log::debug!("=== End ntor Key Derivation ===");

    (
        NtorKeys {
            forward_key,
            backward_key,
        },
        auth.to_vec(),
    )
}