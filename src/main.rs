// src/main.rs
use tor_client::{TorClient, TorConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger with default level INFO
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    
    log::info!("Starting Tor client...");
    
    // Configure Tor client with REAL directory authorities
    let config = TorConfig {
        data_directory: "/tmp/tor-client".to_string(), // Use /tmp in container
        socks_port: 9050,
        control_port: 9051,
        directory_authorities: vec![
            // Real Tor directory authorities (using IPs for reliability)
            "86.59.21.38:80".to_string(),        // tor26
            "45.66.33.45:80".to_string(),        // dizum  
            "131.188.40.189:80".to_string(),     // gabelmoo
            "199.58.81.140:80".to_string(),      // longclaw
            "193.23.244.244:80".to_string(),     // dannenberg
        ],
        ..Default::default()
    };
    
    log::info!("Configuration loaded, starting Tor client...");
    
    // Start Tor client
    let tor_client = TorClient::start(config).await?;
    
    log::info!("Tor client started, launching SOCKS5 proxy on port 9050");
    
    // Start SOCKS5 proxy
    tokio::spawn(async move {
        if let Err(e) = tor_client.socks5_proxy.run().await {
            log::error!("SOCKS5 proxy error: {:?}", e);
        }
    });

    log::info!("Ready! You can now use SOCKS5 proxy at localhost:9050");
    log::info!("Try: curl --socks5-hostname localhost:9050 http://example.com");
    
    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    log::info!("Shutting down...");
    
    Ok(())
}