
// src/lib.rs

use std::sync::Arc;

pub use circuit::{CircuitId, CircuitManager};
pub use directory::DirectoryClient;
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
        let directory_client = Arc::new(DirectoryClient::new(config.directory_authorities));
        let socks5_proxy = Socks5Proxy::new(
            format!("127.0.0.1:{}", config.socks_port),
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
        // self.circuit_manager.create_circuit(num_hops, &self.directory_client).await.map_err(|e| TorError::Circuit(e))
        todo!()
    }

    pub async fn http_get(&self, url: &str) -> Result<String, TorError> {
        todo!()
    }

    pub async fn shutdown(self) {
        todo!()
    }
}

#[derive(Debug)]
pub enum TorError {
    // Circuit(CircuitError),
    // Directory(DirectoryError),
    // Proxy(ProxyError),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TorError")
    }
}

impl std::error::Error for TorError {}

pub mod circuit;
pub mod crypto;
pub mod directory;
pub mod proxy;
pub mod security;
pub mod metrics;
