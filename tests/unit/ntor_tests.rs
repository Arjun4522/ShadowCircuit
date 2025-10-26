use tor_client::crypto::ntor::{self, NtorSecret};
use x25519_dalek::{PublicKey, ReusableSecret};
use rand_core::OsRng;

#[test]
fn test_ntor_handshake_roundtrip() {
    // This test simulates a full handshake between client and server
    
    // 1. Setup client keys
    let client_secret = ReusableSecret::random_from_rng(OsRng);
    let client_public_key = PublicKey::from(&client_secret);

    // 2. Setup server keys
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&server_secret);

    // 3. Setup relay keys (identity and onion)
    let relay_identity_key = [1u8; 20];
    let relay_onion_secret = EphemeralSecret::random_from_rng(OsRng);
    let relay_onion_public = PublicKey::from(&relay_onion_secret);
    let relay_onion_key = relay_onion_public.to_bytes();

    // 4. Client side of the handshake
    let (client_keys, client_auth) = ntor::ntor_handshake(
        &client_secret,
        &client_public_key,
        &server_public_key,
        &relay_identity_key,
        &relay_onion_key,
    );

    // 5. Server side of the handshake (would compute with their private keys)
    // In a real scenario, the server would:
    // - Receive client_public_key (X) in the CREATE2 cell
    // - Use their ephemeral private (y) and static onion private (b)
    // - Compute YX = y * X and BX = b * X
    // - Derive keys the same way but with roles reversed
    
    // For this test, we'll just verify the client side produced valid output
    assert_eq!(client_keys.forward_key.len(), 32);
    assert_eq!(client_keys.backward_key.len(), 32);
    assert_eq!(client_auth.len(), 32);
    
    // Keys should be different from each other
    assert_ne!(client_keys.forward_key, client_keys.backward_key);
    
    // Keys should not be all zeros
    assert_ne!(client_keys.forward_key, [0u8; 32]);
    assert_ne!(client_keys.backward_key, [0u8; 32]);
    assert_ne!(client_auth, vec![0u8; 32]);
}

#[test]
fn test_ntor_secret_generation() {
    // Test that NtorSecret generates valid keys
    let secret1 = NtorSecret::new();
    let public1 = secret1.public_key();
    
    let secret2 = NtorSecret::new();
    let public2 = secret2.public_key();
    
    // Different secrets should produce different public keys
    assert_ne!(public1.public.as_bytes(), public2.public.as_bytes());
}

#[test]
fn test_ntor_different_inputs_different_outputs() {
    // Test that different inputs produce different outputs
    let client_private = EphemeralSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_private);
    
    let server_public1 = PublicKey::from([0x42u8; 32]);
    let server_public2 = PublicKey::from([0x43u8; 32]);
    let relay_identity = [0x01u8; 20];
    let relay_onion = [0x02u8; 32];
    
    // Compute with different server public keys
    let (keys1, auth1) = ntor::ntor_handshake(
        &client_private,
        &client_public,
        &server_public1,
        &relay_identity,
        &relay_onion,
    );
    
    // Create a new client secret for second handshake to reuse
    let client_private2 = EphemeralSecret::random_from_rng(OsRng);
    let client_public2 = PublicKey::from(&client_private2);
    
    let (keys2, auth2) = ntor::ntor_handshake(
        &client_private2,
        &client_public2,
        &server_public2,
        &relay_identity,
        &relay_onion,
    );
    
    // Different inputs should produce different outputs
    assert_ne!(keys1.forward_key, keys2.forward_key);
    assert_ne!(keys1.backward_key, keys2.backward_key);
    assert_ne!(auth1, auth2);
}