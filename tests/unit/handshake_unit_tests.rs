use tor_client::crypto::ntor_handshake;
use tor_client::network::cells::{Create2Cell, Created2Cell};
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;

#[test]
fn test_ntor_handshake() {
    let client_private_key = EphemeralSecret::random_from_rng(OsRng);
    let client_public_key = PublicKey::from(&client_private_key);

    let server_private_key = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&server_private_key);

    let relay_identity_key = [1u8; 32];
    let relay_onion_key = [2u8; 32];

    let result = ntor_handshake(
        client_private_key,
        &client_public_key,
        &server_public_key,
        &relay_identity_key,
        &relay_onion_key,
    );

    assert!(result.is_ok());

    let (keys, auth) = result.unwrap();

    assert_ne!(keys.forward_key, [0u8; 32]);
    assert_ne!(keys.backward_key, [0u8; 32]);
    assert_eq!(auth.len(), 32);
    assert_ne!(auth, vec![0u8; 32]);
}

#[test]
fn test_create2_cell_to_bytes() {
    let client_private_key = EphemeralSecret::random_from_rng(OsRng);
    let client_public_key = PublicKey::from(&client_private_key);

    let create2_cell = Create2Cell::new(&client_public_key);
    let bytes = create2_cell.to_bytes();

    assert_eq!(bytes.len(), 2 + 2 + 32);

    let handshake_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    assert_eq!(handshake_type, 2);

    let hlen = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
    assert_eq!(hlen, 32);

    let hdata = &bytes[4..];
    assert_eq!(hdata, client_public_key.as_bytes());
}

#[test]
fn test_created2_cell_from_bytes() {
    let server_private_key = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&server_private_key);
    let auth = [3u8; 32];

    let mut payload = Vec::new();
    payload.extend_from_slice(server_public_key.as_bytes());
    payload.extend_from_slice(&auth);

    let result = Created2Cell::from_bytes(&payload);
    assert!(result.is_ok());

    let created2_cell = result.unwrap();
    assert_eq!(created2_cell.server_public_key.as_bytes(), server_public_key.as_bytes());
    assert_eq!(created2_cell.auth, auth.to_vec());
}
