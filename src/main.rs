// src/main.rs
use tor_client::{TorClient, TorConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    log::info!("🚀 Starting Tor client...");
    
    let config = TorConfig {
        data_directory: dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".tor-client")
            .to_string_lossy()
            .to_string(),
        socks_port: 9050,
        control_port: 9051,
        directory_authorities: vec!["tor-collector".to_string()], // Not used, for compatibility
        entry_guards: vec![],
    };
    
    log::info!("📡 Using Tor Collector: https://collector.torproject.org");
    
    let tor_client = TorClient::start(config).await?;
    
    log::info!("✓ Tor client started");
    log::info!("🔌 SOCKS5 proxy listening on 127.0.0.1:9050");
    
    tokio::spawn(async move {
        if let Err(e) = tor_client.socks5_proxy.run().await {
            log::error!("❌ SOCKS5 proxy error: {:?}", e);
        }
    });

    log::info!("Press Ctrl+C to shutdown");
    tokio::signal::ctrl_c().await?;
    log::info!("👋 Shutting down...");
    
    Ok(())
}