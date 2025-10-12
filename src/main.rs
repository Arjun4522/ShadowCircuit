
// src/main.rs
use tor_client::{TorClient, TorConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Configure Tor client
    let config = TorConfig {
        data_directory: dirs::home_dir()
            .unwrap()
            .join(".tor-client")
            .to_string_lossy()
            .to_string(),
        socks_port: 9050,
        control_port: 9051,
        directory_authorities: vec![
            "authority1.example.com:80".to_string(),
            "authority2.example.com:80".to_string(),
        ],
        ..Default::default()
    };
    
    // Start Tor client
    let tor_client = TorClient::start(config).await?;
    
    // Start SOCKS5 proxy
    tokio::spawn(async move {
        if let Err(e) = tor_client.socks5_proxy.run().await {
            log::error!("SOCKS5 proxy error: {:?}", e);
        }
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    // tor_client.shutdown().await;
    
    Ok(())
}
