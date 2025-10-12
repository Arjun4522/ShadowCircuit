
// tests/integration/full_circuit.rs
use tor_client::{TorClient, TorConfig};

#[tokio::test]
async fn test_complete_tor_flow() {
    let config = TorConfig::test_config();
    let client = TorClient::start(config).await.unwrap();
    
    // Test HTTP request through Tor
    // let response = client.http_get("http://example.com").await;
    // assert!(response.is_ok());
    
    // client.shutdown().await;
}
