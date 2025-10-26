use tor_client::crypto::ntor::ntor_handshake;
use tor_client::network::cells::{Create2Cell, Created2Cell};
use x25519_dalek::{ReusableSecret, PublicKey};
use rand_core::OsRng;

#[test]
fn test_ntor_handshake() {
    let client_private_key = ReusableSecret::random_from_rng(OsRng);
    let client_public_key = PublicKey::from(&client_private_key);

    let server_private_key = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&server_private_key);

    let relay_identity_key = [1u8; 20];  // 20 bytes for identity
    let relay_onion_key = [2u8; 32];     // 32 bytes for onion key

    let (keys, auth) = ntor_handshake(
        &client_private_key,  // Pass EphemeralSecret reference
        &client_public_key,
        &server_public_key,
        &relay_identity_key,
        &relay_onion_key,
    );

    assert_ne!(keys.forward_key, [0u8; 32]);
    assert_ne!(keys.backward_key, [0u8; 32]);
    assert_eq!(auth.len(), 32);
    assert_ne!(auth, vec![0u8; 32]);
}

#[test]
fn test_create2_cell_to_bytes() {
    let client_private_key = ReusableSecret::random_from_rng(OsRng);
    let client_public_key = PublicKey::from(&client_private_key);
    
    let relay_identity = [1u8; 20];
    let relay_onion_key = [2u8; 32];

    let create2_cell = Create2Cell::new(
        &client_public_key,
        &relay_identity,
        &relay_onion_key
    ).expect("Failed to create CREATE2 cell");
    
    let bytes = create2_cell.to_bytes();

    // Should be: 2 (type) + 2 (len) + 84 (data) = 88 bytes
    assert_eq!(bytes.len(), 88);

    let handshake_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    assert_eq!(handshake_type, 2);

    let hlen = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
    assert_eq!(hlen, 84);

    let hdata = &bytes[4..];
    assert_eq!(hdata.len(), 84);
    
    // ntor format: NODEID (20) | KEYID (32) | CLIENT_PK (32)
    assert_eq!(&hdata[0..20], &relay_identity);
    assert_eq!(&hdata[20..52], &relay_onion_key);
    assert_eq!(&hdata[52..84], client_public_key.as_bytes());
}

#[test]
fn test_created2_cell_from_bytes() {
    let server_private_key = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&server_private_key);
    let auth = [3u8; 32];

    let mut hdata = Vec::new();
    hdata.extend_from_slice(server_public_key.as_bytes());
    hdata.extend_from_slice(&auth);

    let mut payload = Vec::new();
    payload.extend_from_slice(&(hdata.len() as u16).to_be_bytes());
    payload.extend_from_slice(&hdata);

    let result = Created2Cell::from_bytes(&payload);
    assert!(result.is_ok());

    let created2_cell = result.unwrap();
    assert_eq!(created2_cell.server_public_key.as_bytes(), server_public_key.as_bytes());
    assert_eq!(created2_cell.auth, auth.to_vec());
}

#[test]
fn test_create2_cell_validation() {
    let client_private_key = ReusableSecret::random_from_rng(OsRng);
    let client_public_key = PublicKey::from(&client_private_key);
    
    // Test with wrong identity length
    let wrong_identity = [1u8; 19]; // Should be 20
    let relay_onion_key = [2u8; 32];
    
    let result = Create2Cell::new(
        &client_public_key,
        &wrong_identity,
        &relay_onion_key
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("identity must be 20 bytes"));
    
    // Test with wrong onion key length
    let relay_identity = [1u8; 20];
    let wrong_onion_key = [2u8; 31]; // Should be 32
    
    let result = Create2Cell::new(
        &client_public_key,
        &relay_identity,
        &wrong_onion_key
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("onion key must be 32 bytes"));
}

#[test]
fn test_ntor_handshake_deterministic() {
    // Test that handshake produces reasonable outputs
    let client_private_key = ReusableSecret::random_from_rng(OsRng);
    let client_public_key = PublicKey::from(&client_private_key);

    let server_private_key = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&server_private_key);

    let relay_identity_key = [1u8; 20];
    let relay_onion_key = [2u8; 32];

    let (keys1, auth1) = ntor_handshake(
        &client_private_key,
        &client_public_key,
        &server_public_key,
        &relay_identity_key,
        &relay_onion_key,
    );
    
    // Verify outputs are reasonable
    assert_eq!(keys1.forward_key.len(), 32);
    assert_eq!(keys1.backward_key.len(), 32);
    assert_eq!(auth1.len(), 32);
    
    // Verify forward and backward keys are different
    assert_ne!(keys1.forward_key, keys1.backward_key);
}

#[test]
fn test_ntor_key_material_differs() {
    // Test that different inputs produce different outputs
    let client1_private = EphemeralSecret::random_from_rng(OsRng);
    let client1_public = PublicKey::from(&client1_private);

    let client2_private = EphemeralSecret::random_from_rng(OsRng);
    let client2_public = PublicKey::from(&client2_private);

    let server_private = EphemeralSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_private);

    let relay_identity = [1u8; 20];
    let relay_onion = [2u8; 32];

    let (keys1, auth1) = ntor_handshake(
        &client1_private,
        &client1_public,
        &server_public,
        &relay_identity,
        &relay_onion,
    );

    let (keys2, auth2) = ntor_handshake(
        &client2_private,
        &client2_public,
        &server_public,
        &relay_identity,
        &relay_onion,
    );

    // Different client keys should produce different outputs
    assert_ne!(keys1.forward_key, keys2.forward_key);
    assert_ne!(keys1.backward_key, keys2.backward_key);
    assert_ne!(auth1, auth2);
}