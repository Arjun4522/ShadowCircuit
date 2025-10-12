
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
            // These are some of the real Tor directory authorities.
            // A full list can be found in the Tor source code.
            "86.59.21.38:80".to_string(), // tor26
            "45.66.33.45:80".to_string(), // dizum
            "131.188.40.189:80".to_string(), // gabelmoo
            "199.58.81.140:80".to_string(), // longclaw
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
