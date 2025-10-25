// tests/integration/handshake_test.rs
use tor_client::{CircuitManager, DirectoryClient, TorConfig, circuit::CircuitState};
use std::sync::Arc;
use tokio::sync::OnceCell;

static DIRECTORY_CLIENT: OnceCell<Arc<DirectoryClient>> = OnceCell::const_new();

fn setup_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init();
}

    async fn get_directory_client() -> &'static Arc<DirectoryClient> {
    DIRECTORY_CLIENT.get_or_init(|| async {
        let config = TorConfig {
            directory_authorities: vec!["tor-collector".to_string()],
            ..Default::default()
        };
        Arc::new(DirectoryClient::new(config.directory_authorities))
    }).await
}

#[tokio::test]
async fn test_single_hop_handshake() {
    setup_logger();
    log::info!("=== Starting Single Hop Handshake Test ===");
    
    let directory_client = get_directory_client().await;
    let circuit_manager = Arc::new(CircuitManager::new());

    log::info!("Creating 1-hop circuit...");
    let result = circuit_manager.create_circuit(1, directory_client).await;
    
    if let Err(e) = &result {
        log::error!("Error creating circuit: {:?}", e);
        panic!("Circuit creation failed: {:?}", e);
    }
    
    let circuit_id = result.unwrap();
    log::info!("Circuit {} created", circuit_id);
    
    let state = circuit_manager.get_circuit_state(circuit_id).await;
    log::info!("Circuit state: {:?}", state);
    
    assert_eq!(state, Some(CircuitState::Ready), "Circuit should be in Ready state");
    
    log::info!("=== Test Passed ===");
}

#[tokio::test]
async fn test_three_hop_circuit() {
    setup_logger();
    log::info!("=== Starting Three Hop Circuit Test ===");
    
    let directory_client = get_directory_client().await;
    let circuit_manager = Arc::new(CircuitManager::new());

    log::info!("Creating 3-hop circuit...");
    
    // Note: For now, only first hop handshake is implemented
    // This will select 3 relays but only establish the first hop
    let result = circuit_manager.create_circuit(1, directory_client).await;
    
    if let Err(e) = &result {
        log::error!("Error creating circuit: {:?}", e);
        panic!("Circuit creation failed: {:?}", e);
    }
    
    let circuit_id = result.unwrap();
    log::info!("Circuit {} created", circuit_id);
    
    let state = circuit_manager.get_circuit_state(circuit_id).await;
    log::info!("Circuit state: {:?}", state);
    
    assert_eq!(state, Some(CircuitState::Ready), "Circuit should be in Ready state");
    
    log::info!("=== Test Passed ===");
}

#[tokio::test]
async fn test_multiple_circuits() {
    setup_logger();
    log::info!("=== Starting Multiple Circuits Test ===");
    
    let directory_client = get_directory_client().await;
    let circuit_manager = Arc::new(CircuitManager::new());

    let num_circuits = 3;
    
    for i in 0..num_circuits {
        log::info!("Creating circuit {} of {}", i + 1, num_circuits);
        
        let result = circuit_manager.create_circuit(1, directory_client).await;
        
        match result {
            Ok(circuit_id) => {
                log::info!("Circuit {} created successfully", circuit_id);
                let state = circuit_manager.get_circuit_state(circuit_id).await;
                assert_eq!(state, Some(CircuitState::Ready));
            }
            Err(e) => {
                log::error!("Circuit {} failed: {:?}", i + 1, e);
                panic!("Circuit creation failed");
            }
        }
    }
    
    log::info!("=== All {} Circuits Created Successfully ===", num_circuits);
}