// src/circuit/mod.rs
use crate::crypto::{OnionCrypto, ntor_handshake};
use crate::directory::DirectoryClient;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use crate::network::cells::{Cell, Create2Cell, Created2Cell, VersionsCell, CELL_COMMAND_CREATE2, CELL_COMMAND_CREATED2, CELL_COMMAND_VERSIONS};
use rand_core::OsRng;
use tokio_rustls::{TlsConnector, rustls};
use std::sync::Arc;

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[derive(Debug)]
pub enum CircuitError {
    Crypto(String),
    Directory(crate::directory::DirectoryError),
    Io(String),
    NoSuitableRelays,
    HandshakeFailed(String),
}

impl From<crate::crypto::CryptoError> for CircuitError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        CircuitError::Crypto(format!("{:?}", err))
    }
}

impl From<crate::directory::DirectoryError> for CircuitError {
    fn from(err: crate::directory::DirectoryError) -> Self {
        CircuitError::Directory(err)
    }
}

pub type CircuitId = u32;

#[derive(Debug, Clone)]
pub struct RelayHop {
    pub relay_id: String,
    pub ip: std::net::SocketAddr,
    pub identity_key: Vec<u8>,
    pub onion_key: Vec<u8>,
    pub crypto_state: OnionCrypto,
}

#[derive(Debug)]
pub struct Circuit {
    pub id: CircuitId,
    pub hops: Vec<RelayHop>,
    pub state: CircuitState,
    pub created_at: std::time::Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Building,
    Ready,
    Closed,
    Error(String),
}

#[derive(Debug)]
pub struct CircuitManager {
    circuits: RwLock<HashMap<CircuitId, Circuit>>,
    next_circuit_id: RwLock<CircuitId>,
}

impl CircuitManager {
    pub fn new() -> Self {
        Self {
            circuits: RwLock::new(HashMap::new()),
            next_circuit_id: RwLock::new(1),
        }
    }

    pub async fn get_circuit_state(&self, circuit_id: CircuitId) -> Option<CircuitState> {
        self.circuits.read().await.get(&circuit_id).map(|c| c.state.clone())
    }
    
    /// Create a new circuit with specified number of hops
    pub async fn create_circuit(
        &self,
        num_hops: usize,
        directory: &DirectoryClient
    ) -> Result<CircuitId, CircuitError> {
        let circuit_id = {
            let mut next_id = self.next_circuit_id.write().await;
            let id = *next_id;
            *next_id += 1;
            id
        };
        
        log::info!("Creating circuit {} with {} hops", circuit_id, num_hops);
        
        let mut hops = Vec::with_capacity(num_hops);
        
        // Select relays for each hop
        for hop_num in 0..num_hops {
            log::debug!("Selecting relay for hop {}", hop_num);
            let relay = directory.select_relay(hop_num).await?;
            let crypto = OnionCrypto::new()?;
            
            log::info!(
                "Selected relay for hop {}: {} (Address: {}, Bandwidth: {}, Flags: {:?})",
                hop_num,
                relay.nickname,
                relay.address,
                relay.bandwidth,
                relay.flags
            );
            
            hops.push(RelayHop {
                relay_id: relay.id,
                ip: relay.address,
                identity_key: relay.identity_key,
                onion_key: relay.onion_key,
                crypto_state: crypto,
            });
        }
        
        let circuit = Circuit {
            id: circuit_id,
            hops,
            state: CircuitState::Building,
            created_at: std::time::Instant::now(),
        };
        
        // Store circuit
        self.circuits.write().await.insert(circuit_id, circuit);
        
        // Perform circuit handshake with each hop
        self.perform_handshakes(circuit_id).await?;
        
        // Mark circuit as ready
        if let Some(circuit) = self.circuits.write().await.get_mut(&circuit_id) {
            circuit.state = CircuitState::Ready;
            log::info!("Circuit {} is ready", circuit_id);
        }
        
        Ok(circuit_id)
    }
    
    async fn perform_handshakes(&self, circuit_id: CircuitId) -> Result<(), CircuitError> {
        log::info!("Performing handshakes for circuit {}", circuit_id);

        let mut circuits = self.circuits.write().await;
        let circuit = circuits.get_mut(&circuit_id).unwrap();

        // For now, we only handle the first hop
        let hop = &mut circuit.hops[0];

        // 1. Generate ephemeral keypair for the client
        let client_private_key = EphemeralSecret::random_from_rng(OsRng);
        let client_public_key = PublicKey::from(&client_private_key);

        // 2. Create a CREATE2 cell
        let create2_cell_payload = Create2Cell::new(&client_public_key);
        let cell = Cell {
            circ_id: circuit.id,
            command: CELL_COMMAND_CREATE2,
            payload: create2_cell_payload.to_bytes(),
        };

        // 3. Connect to the relay
        let addr: SocketAddr = hop.ip.parse().map_err(|e| CircuitError::Io(format!("Invalid address: {}", e)))?;
        let tcp_stream = TcpStream::connect(addr).await.map_err(|e| CircuitError::Io(e.to_string()))?;
        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::ServerName::IpAddress(addr.ip().into());
        let mut stream = connector.connect(server_name, tcp_stream).await.map_err(|e| CircuitError::Io(format!("TLS error: {}", e)))?;
        log::info!("Connected to relay {} via TLS", hop.relay_id);

        // 3.1. Send VERSIONS cell
        let versions_cell_payload = VersionsCell::new(vec![3, 4, 5]).to_bytes();
        let versions_cell = Cell {
            circ_id: 0,
            command: CELL_COMMAND_VERSIONS,
            payload: versions_cell_payload,
        };
        let mut versions_cell_bytes = Vec::with_capacity(514);
        versions_cell_bytes.extend_from_slice(&versions_cell.circ_id.to_be_bytes());
        versions_cell_bytes.push(versions_cell.command);
        versions_cell_bytes.extend_from_slice(&versions_cell.payload);
        versions_cell_bytes.resize(514, 0);
        stream.write_all(&versions_cell_bytes).await.map_err(|e| CircuitError::Io(format!("Failed to send VERSIONS: {}", e)))?;
        log::info!("Sent VERSIONS cell");

        // 3.2. Read VERSIONS response
        let mut response = vec![0; 514];
        let n = stream.read(&mut response).await.map_err(|e| CircuitError::Io(format!("Failed to read VERSIONS response: {}", e)))?;
        if n != 514 {
            return Err(CircuitError::HandshakeFailed("Invalid response size for VERSIONS".to_string()));
        }
        let response_circ_id = u32::from_be_bytes(response[0..4].try_into().unwrap());
        let response_command = response[4];
        if response_circ_id != 0 || response_command != CELL_COMMAND_VERSIONS {
            return Err(CircuitError::HandshakeFailed("Invalid VERSIONS response".to_string()));
        }
        let server_versions = VersionsCell::from_bytes(&response[5..514]).map_err(|e| CircuitError::HandshakeFailed(format!("Failed to parse server VERSIONS: {}", e)))?;
        log::info!("Received VERSIONS from server: {:?}", server_versions.versions);
        // Negotiate version (use 4 if supported)
        let negotiated_version = if server_versions.versions.contains(&4) { 4 } else { 3 };
        log::info!("Negotiated link version: {}", negotiated_version);

        // 4. Serialize the cell and send it
        let mut cell_bytes = Vec::with_capacity(514);
        cell_bytes.extend_from_slice(&cell.circ_id.to_be_bytes());
        cell_bytes.push(cell.command);
        cell_bytes.extend_from_slice(&cell.payload);
        cell_bytes.resize(514, 0);

        stream.write_all(&cell_bytes).await.map_err(|e| CircuitError::Io(e.to_string()))?;
        log::info!("Sent CREATE2 cell to relay {}", hop.relay_id);

        // 5. Receive the response
        let mut response = vec![0; 514];
        let n = stream.read(&mut response).await.map_err(|e| CircuitError::Io(e.to_string()))?;
        log::info!("Received {} bytes from relay {}", n, hop.relay_id);

        // 6. Parse the response
        let response_cell = &response[..n];
        let response_circ_id = u32::from_be_bytes(response_cell[0..4].try_into().unwrap());
        let response_command = response_cell[4];
        let response_payload = &response_cell[5..];

        if response_circ_id != circuit.id || response_command != CELL_COMMAND_CREATED2 {
            return Err(CircuitError::HandshakeFailed("Invalid response from relay".to_string()));
        }

        let created2_cell = Created2Cell::from_bytes(response_payload).map_err(|e| CircuitError::HandshakeFailed(e.to_string()))?;

        // 7. Perform key derivation
        let (keys, auth) = ntor_handshake(
            client_private_key,
            &client_public_key,
            &created2_cell.server_public_key,
            &hop.identity_key,
            &hop.onion_key,
        )?;

        // 8. Verify the auth value
        if auth != created2_cell.auth {
            return Err(CircuitError::HandshakeFailed("Invalid auth value from relay".to_string()));
        }

        // 9. Update the crypto state for the hop
        hop.crypto_state = OnionCrypto::from_ntor_keys(keys)?;

        log::info!("Handshake with relay {} successful", hop.relay_id);

        Ok(())
    }
}