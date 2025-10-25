use tor_client::crypto::ntor::{self, NtorSecret};
use x25519_dalek::PublicKey;

#[test]
fn test_ntor_handshake_roundtrip() {
    // 1. Setup client and server keys
    let client_secret = NtorSecret::new();
    let client_public_key = PublicKey::from(&client_secret.secret);

    let server_secret = NtorSecret::new();
    let server_public_key = PublicKey::from(&server_secret.secret);

    let relay_identity_key = [1u8; 20];
    let relay_onion_key = [2u8; 32];

    // 2. Client side of the handshake
    let (client_keys, client_auth) = ntor::ntor_handshake(
        client_secret.secret,
        &client_public_key,
        &server_public_key,
        &relay_identity_key,
        &relay_onion_key,
    );

    // 3. Server side of the handshake
    let (server_keys, server_auth) = ntor::ntor_handshake(
        server_secret.secret,
        &server_public_key,
        &client_public_key,
        &relay_identity_key,
        &relay_onion_key,
    );

    // 4. Verification
    assert_eq!(client_auth, server_auth);
    assert_eq!(client_keys.forward_key, server_keys.backward_key);
    assert_eq!(client_keys.backward_key, server_keys.forward_key);
}
