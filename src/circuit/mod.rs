// src/circuit/mod.rs
use crate::crypto::{OnionCrypto, ntor_handshake};
use crate::directory::DirectoryClient;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use crate::network::cells::{Cell, Create2Cell, Created2Cell, VersionsCell, 
    CELL_COMMAND_CREATE2, CELL_COMMAND_CREATED2, CELL_COMMAND_VERSIONS, CELL_LEN};
use rand_core::OsRng;
use tokio_rustls::{TlsConnector, rustls};
use std::sync::Arc;
use std::time::Duration;

// Always use dangerous configuration since we're connecting to Tor relays
// which don't have traditional CA-signed certificates
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
    Timeout(String),
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
        // Generate a valid circuit ID (odd numbers for client-initiated circuits in v4+)
        let circuit_id = {
            let mut next_id = self.next_circuit_id.write().await;
            let id = *next_id;
            *next_id += 2; // Increment by 2 to keep odd
            if id % 2 == 0 {
                id + 1
            } else {
                id
            }
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
        match self.perform_handshakes(circuit_id).await {
            Ok(_) => {
                // Mark circuit as ready
                if let Some(circuit) = self.circuits.write().await.get_mut(&circuit_id) {
                    circuit.state = CircuitState::Ready;
                    log::info!("Circuit {} is ready", circuit_id);
                }
                Ok(circuit_id)
            }
            Err(e) => {
                // Mark circuit as error
                if let Some(circuit) = self.circuits.write().await.get_mut(&circuit_id) {
                    circuit.state = CircuitState::Error(format!("{:?}", e));
                }
                Err(e)
            }
        }
    }
    
    async fn perform_handshakes(&self, circuit_id: CircuitId) -> Result<(), CircuitError> {
        log::info!("Performing handshakes for circuit {}", circuit_id);

        let mut circuits = self.circuits.write().await;
        let circuit = circuits.get_mut(&circuit_id)
            .ok_or(CircuitError::HandshakeFailed("Circuit not found".to_string()))?;

        // For now, we only handle the first hop
        if circuit.hops.is_empty() {
            return Err(CircuitError::HandshakeFailed("No hops in circuit".to_string()));
        }
        
        let hop = &mut circuit.hops[0];

        // 1. Generate ephemeral keypair for the client
        let client_private_key = EphemeralSecret::random_from_rng(OsRng);
        let client_public_key = PublicKey::from(&client_private_key);

        // 2. Connect to the relay via TLS with timeout
        let addr: SocketAddr = hop.ip;
        log::info!("Connecting to relay at {}", addr);
        
        let tcp_stream = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(addr)
        ).await
            .map_err(|_| CircuitError::Timeout(format!("TCP connect to {} timed out", addr)))?
            .map_err(|e| CircuitError::Io(format!("TCP connect failed: {}", e)))?;
        
        // Use custom certificate verifier for Tor relays
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::ServerName::IpAddress(addr.ip().into());
        
        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(server_name, tcp_stream)
        ).await
            .map_err(|_| CircuitError::Timeout("TLS handshake timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("TLS connect failed: {}", e)))?;
        
        log::info!("Connected to relay {} via TLS", hop.relay_id);

        // 3. Send VERSIONS cell (variable-length, circuit ID = 0)
        // IMPORTANT: VERSIONS cell uses special format (2-byte circ_id)
        let versions_cell = Cell {
            circ_id: 0,
            command: CELL_COMMAND_VERSIONS,
            payload: VersionsCell::new(vec![3, 4, 5]).to_bytes(),
        };
        
        let versions_bytes = versions_cell.versions_to_bytes();
        
        log::debug!("VERSIONS cell bytes: {:?}", versions_bytes);
        
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.write_all(&versions_bytes)
        ).await
            .map_err(|_| CircuitError::Timeout("Sending VERSIONS timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to send VERSIONS: {}", e)))?;
        
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.flush()
        ).await
            .map_err(|_| CircuitError::Timeout("Flushing VERSIONS timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to flush VERSIONS: {}", e)))?;
        
        log::info!("Sent VERSIONS cell");

        // 4. Read VERSIONS response with timeout
        let mut response = vec![0u8; 512];
        let n = tokio::time::timeout(
            Duration::from_secs(10),
            stream.read(&mut response)
        ).await
            .map_err(|_| CircuitError::Timeout("Reading VERSIONS response timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to read VERSIONS response: {}", e)))?;
        
        if n == 0 {
            return Err(CircuitError::HandshakeFailed("Connection closed after VERSIONS".to_string()));
        }
        
        log::info!("Received VERSIONS response ({} bytes)", n);
        
        if n < 7 {
            return Err(CircuitError::HandshakeFailed(format!("VERSIONS response too short: {} bytes", n)));
        }
        
        let response_cell = Cell::from_bytes(&response[..n], 4)
            .map_err(|e| CircuitError::HandshakeFailed(format!("Failed to parse VERSIONS response: {}", e)))?;
        
        if response_cell.command != CELL_COMMAND_VERSIONS {
            return Err(CircuitError::HandshakeFailed(
                format!("Expected VERSIONS response, got command {}", response_cell.command)
            ));
        }
        
        let server_versions = VersionsCell::from_bytes(&response_cell.payload)
            .map_err(|e| CircuitError::HandshakeFailed(format!("Failed to parse server VERSIONS: {}", e)))?;
        
        log::info!("Received VERSIONS from server: {:?}", server_versions.versions);
        
        // Negotiate version (use highest common version)
        let negotiated_version = if server_versions.versions.contains(&5) {
            5
        } else if server_versions.versions.contains(&4) {
            4
        } else if server_versions.versions.contains(&3) {
            3
        } else {
            return Err(CircuitError::HandshakeFailed("No compatible link protocol version".to_string()));
        };
        
        log::info!("Negotiated link protocol version: {}", negotiated_version);

        // 5. Create CREATE2 cell with proper NTor handshake data
        let create2_payload = Create2Cell::new(
            &client_public_key,
            &hop.identity_key,
            &hop.onion_key
        ).map_err(|e| CircuitError::HandshakeFailed(format!("Failed to create CREATE2 cell: {}", e)))?;
        
        let create2_cell = Cell {
            circ_id: circuit.id,
            command: CELL_COMMAND_CREATE2,
            payload: create2_payload.to_bytes(),
        };

        // 6. Send CREATE2 cell with timeout
        let cell_bytes = create2_cell.to_bytes(negotiated_version);
        
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.write_all(&cell_bytes)
        ).await
            .map_err(|_| CircuitError::Timeout("Sending CREATE2 timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to send CREATE2: {}", e)))?;
        
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.flush()
        ).await
            .map_err(|_| CircuitError::Timeout("Flushing CREATE2 timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to flush CREATE2: {}", e)))?;
        
        log::info!("Sent CREATE2 cell to relay {} (circuit ID: {})", hop.relay_id, circuit.id);

        // 7. Receive CREATED2 response with timeout
        let mut response = vec![0u8; CELL_LEN];
        let n = tokio::time::timeout(
            Duration::from_secs(15),
            stream.read(&mut response)
        ).await
            .map_err(|_| CircuitError::Timeout("Reading CREATED2 response timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to read CREATED2 response: {}", e)))?;
        
        if n == 0 {
            return Err(CircuitError::HandshakeFailed("Connection closed after CREATE2".to_string()));
        }
        
        log::info!("Received CREATED2 response ({} bytes)", n);

        // 8. Parse CREATED2 response
        let response_cell = Cell::from_bytes(&response[..n], negotiated_version)
            .map_err(|e| CircuitError::HandshakeFailed(format!("Failed to parse CREATED2 cell: {}", e)))?;

        if response_cell.circ_id != circuit.id {
            return Err(CircuitError::HandshakeFailed(
                format!("Circuit ID mismatch: expected {}, got {}", circuit.id, response_cell.circ_id)
            ));
        }
        
        if response_cell.command != CELL_COMMAND_CREATED2 {
            return Err(CircuitError::HandshakeFailed(
                format!("Expected CREATED2 response, got command {}", response_cell.command)
            ));
        }

        let created2_cell = Created2Cell::from_bytes(&response_cell.payload)
            .map_err(|e| CircuitError::HandshakeFailed(format!("Failed to parse CREATED2 payload: {}", e)))?;

        // 9. Perform NTor key derivation
        let (keys, auth) = ntor_handshake(
            client_private_key,
            &client_public_key,
            &created2_cell.server_public_key,
            &hop.identity_key,
            &hop.onion_key,
        )?;

        // 10. Verify the auth value
        if auth != created2_cell.auth {
            return Err(CircuitError::HandshakeFailed("Authentication verification failed".to_string()));
        }

        // 11. Update the crypto state for the hop
        hop.crypto_state = OnionCrypto::from_ntor_keys(keys)?;

        log::info!("✓ Handshake with relay {} successful!", hop.relay_id);

        Ok(())
    }
}