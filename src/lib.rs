// src/lib.rs

use std::sync::Arc;

pub use circuit::{CircuitId, CircuitManager, CircuitError};
pub use directory::{DirectoryClient, DirectoryError};
// pub use proxy::ProxyServer;

#[derive(Debug, Clone)]
pub struct TorConfig {
    pub data_directory: String,
    pub socks_port: u16,
    pub control_port: u16,
    pub directory_authorities: Vec<String>,
    pub entry_guards: Vec<String>,
    // pub exit_policy: ExitPolicy,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            data_directory: "".to_string(),
            socks_port: 9050,
            control_port: 9051,
            directory_authorities: vec![],
            entry_guards: vec![],
        }
    }
}

impl TorConfig {
    pub fn test_config() -> Self {
        Self {
            data_directory: "".to_string(),
            socks_port: 9050,
            control_port: 9051,
            directory_authorities: vec![],
            entry_guards: vec![],
        }
    }
}


use crate::proxy::socks5::Socks5Proxy;

pub struct TorClient {
    circuit_manager: Arc<CircuitManager>,
    directory_client: Arc<DirectoryClient>,
    pub socks5_proxy: Socks5Proxy,
}

impl TorClient {
    pub async fn start(config: TorConfig) -> Result<Self, TorError> {
        let circuit_manager = Arc::new(CircuitManager::new());
        
        // Create directory client with real authorities or mock for testing
        let directory_client = if config.directory_authorities.is_empty() {
            log::warn!("No directory authorities configured, using mock directory");
            Arc::new(DirectoryClient::new_mock())
        } else {
            log::info!("Using real directory authorities");
            Arc::new(DirectoryClient::new(config.directory_authorities))
        };
        
        let socks5_proxy = Socks5Proxy::new(
            format!("0.0.0.0:{}", config.socks_port),
            circuit_manager.clone(),
            directory_client.clone(),
        );

        Ok(Self {
            circuit_manager,
            directory_client,
            socks5_proxy,
        })
    }

    pub async fn create_circuit(&self, num_hops: usize) -> Result<CircuitId, TorError> {
        self.circuit_manager
            .create_circuit(num_hops, &self.directory_client)
            .await
            .map_err(TorError::Circuit)
    }

    pub async fn http_get(&self, url: &str) -> Result<String, TorError> {
        // Create a circuit first
        let _circuit_id = self.create_circuit(3).await?;
        
        // TODO: Route HTTP request through the circuit
        // For now, this is a placeholder
        log::warn!("HTTP GET not fully implemented, URL: {}", url);
        Err(TorError::NotImplemented("HTTP GET through Tor circuit".to_string()))
    }

    pub async fn shutdown(self) {
        log::info!("Shutting down TorClient");
        // TODO: Cleanup circuits, close connections
    }
}

#[derive(Debug)]
pub enum TorError {
    Circuit(CircuitError),
    Directory(DirectoryError),
    Proxy(crate::proxy::socks5::ProxyError),
    NotImplemented(String),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorError::Circuit(e) => write!(f, "Circuit error: {:?}", e),
            TorError::Directory(e) => write!(f, "Directory error: {}", e),
            TorError::Proxy(e) => write!(f, "Proxy error: {:?}", e),
            TorError::NotImplemented(s) => write!(f, "Not implemented: {}", s),
        }
    }
}

impl std::error::Error for TorError {}

impl From<CircuitError> for TorError {
    fn from(err: CircuitError) -> Self {
        TorError::Circuit(err)
    }
}

impl From<DirectoryError> for TorError {
    fn from(err: DirectoryError) -> Self {
        TorError::Directory(err)
    }
}

pub mod circuit;
pub mod crypto;
pub mod directory;
pub mod proxy;
pub mod security;
pub mod metrics;
pub mod network;