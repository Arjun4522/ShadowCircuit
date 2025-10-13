// tests/integration/handshake_test.rs
use tor_client::{CircuitManager, DirectoryClient, TorConfig};
use std::sync::Arc;

#[tokio::test]
async fn test_single_hop_handshake() {
    let _ = env_logger::builder().is_test(true).try_init();
    let config = TorConfig {
        directory_authorities: vec!["tor-collector".to_string()],
        ..Default::default()
    };
    let directory_client = Arc::new(DirectoryClient::new(config.directory_authorities));
    let circuit_manager = Arc::new(CircuitManager::new());

    let result = circuit_manager.create_circuit(1, &directory_client).await;
    if let Err(e) = &result {
        println!("Error creating circuit: {:?}", e);
    }
    assert!(result.is_ok());

    let circuit_id = result.unwrap();
    let state = circuit_manager.get_circuit_state(circuit_id).await;

    assert_eq!(state, Some(tor_client::circuit::CircuitState::Ready));
}
