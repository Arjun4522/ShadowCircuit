// src/circuit/mod.rs - COMPLETE HANDSHAKE WITH CERTS/NETINFO HANDLING
use crate::crypto::{OnionCrypto, ntor_handshake};
use crate::directory::DirectoryClient;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use crate::network::cells::{Cell, Create2Cell, Created2Cell, VersionsCell, 
    CELL_COMMAND_CREATE2, CELL_COMMAND_CREATED2, CELL_COMMAND_VERSIONS, 
    CELL_COMMAND_NETINFO, CELL_LEN};
use rand_core::OsRng;
use tokio_rustls::{TlsConnector, rustls};
use std::sync::Arc;
use std::time::Duration;

// Additional cell commands
const CELL_COMMAND_CERTS: u8 = 14;
const CELL_COMMAND_AUTH_CHALLENGE: u8 = 15;
const CELL_COMMAND_AUTHENTICATE: u8 = 16;
const CELL_COMMAND_VPADDING: u8 = 13;

// Custom certificate verifier for Tor relays
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
    
    pub async fn create_circuit(
        &self,
        num_hops: usize,
        directory: &DirectoryClient
    ) -> Result<CircuitId, CircuitError> {
        let circuit_id = {
            let mut next_id = self.next_circuit_id.write().await;
            let id = *next_id;
            *next_id += 2;
            if id % 2 == 0 { id + 1 } else { id }
        };
        
        log::info!("Creating circuit {} with {} hops", circuit_id, num_hops);
        
        let mut hops = Vec::with_capacity(num_hops);
        
        for hop_num in 0..num_hops {
            let relay = directory.select_relay(hop_num).await?;
            let crypto = OnionCrypto::new()?;
            
            log::info!(
                "Selected relay for hop {}: {} (Address: {}, Bandwidth: {}, Flags: {:?})",
                hop_num, relay.nickname, relay.address, relay.bandwidth, relay.flags
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
        
        self.circuits.write().await.insert(circuit_id, circuit);
        
        match self.perform_handshakes(circuit_id).await {
            Ok(_) => {
                if let Some(circuit) = self.circuits.write().await.get_mut(&circuit_id) {
                    circuit.state = CircuitState::Ready;
                    log::info!("Circuit {} is ready", circuit_id);
                }
                Ok(circuit_id)
            }
            Err(e) => {
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

        if circuit.hops.is_empty() {
            return Err(CircuitError::HandshakeFailed("No hops in circuit".to_string()));
        }
        
        let hop = &mut circuit.hops[0];
        let client_private_key = EphemeralSecret::random_from_rng(OsRng);
        let client_public_key = PublicKey::from(&client_private_key);

        // Connect to relay
        let addr: SocketAddr = hop.ip;
        log::info!("Connecting to relay at {}", addr);
        
        let tcp_stream = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(addr)
        ).await
            .map_err(|_| CircuitError::Timeout(format!("TCP connect to {} timed out", addr)))?
            .map_err(|e| CircuitError::Io(format!("TCP connect failed: {}", e)))?;
        
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

        // Send VERSIONS
        let versions_cell = Cell {
            circ_id: 0,
            command: CELL_COMMAND_VERSIONS,
            payload: VersionsCell::new(vec![3, 4, 5]).to_bytes(),
        };
        
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.write_all(&versions_cell.versions_to_bytes())
        ).await
            .map_err(|_| CircuitError::Timeout("Sending VERSIONS timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to send VERSIONS: {}", e)))?;
        
        stream.flush().await.map_err(|e| CircuitError::Io(format!("Flush failed: {}", e)))?;
        log::info!("Sent VERSIONS cell");

        // Read VERSIONS response (VERSIONS uses 2-byte circ_id pre-negotiation)
        let header_size = 5; // 2 (circ_id) + 1 (cmd) + 2 (len)
        let mut header = vec![0u8; header_size];
        tokio::time::timeout(
            Duration::from_secs(10),
            stream.read_exact(&mut header)
        ).await
            .map_err(|_| CircuitError::Timeout("Reading VERSIONS header timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to read VERSIONS header: {}", e)))?;

        let circ_id = u16::from_be_bytes(header[0..2].try_into().unwrap()) as u32;
        let command = header[2];
        let payload_len = u16::from_be_bytes(header[3..5].try_into().unwrap()) as usize;

        if command != CELL_COMMAND_VERSIONS {
            return Err(CircuitError::HandshakeFailed(
                format!("Expected VERSIONS response (cmd 7), got command {}", command)
            ));
        }

        let mut payload = vec![0u8; payload_len];
        tokio::time::timeout(
            Duration::from_secs(10),
            stream.read_exact(&mut payload)
        ).await
            .map_err(|_| CircuitError::Timeout("Reading VERSIONS payload timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to read VERSIONS payload: {}", e)))?;

        let server_versions = VersionsCell::from_bytes(&payload)
            .map_err(|e| CircuitError::HandshakeFailed(format!("Failed to parse server VERSIONS: {}", e)))?;

        log::info!("Received VERSIONS from server: {:?}", server_versions.versions);
        
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

        // ===== NEW: Handle CERTS, AUTH_CHALLENGE, NETINFO cells =====
        // After VERSIONS, the relay sends these cells before we can send CREATE2
        
        // Read and process intermediate cells (CERTS, AUTH_CHALLENGE, NETINFO)
        let mut max_cells = 10; // Prevent infinite loop

        while max_cells > 0 {
            max_cells -= 1;
            // Read cell header first (5 or 7 bytes depending on version)
            let header_size = if negotiated_version >= 4 { 5 } else { 3 };
            let mut header = vec![0u8; header_size];
            
            tokio::time::timeout(
                Duration::from_secs(10),
                stream.read_exact(&mut header)
            ).await
                .map_err(|_| CircuitError::Timeout("Reading cell header timed out".to_string()))?
                .map_err(|e| CircuitError::Io(format!("Failed to read cell header: {}", e)))?;
            
            // Parse header to get circuit ID and command
            let (circ_id, command) = if negotiated_version >= 4 {
                let circ_id = u32::from_be_bytes(header[0..4].try_into().unwrap());
                let command = header[4];
                (circ_id, command)
            } else {
        let _circ_id = u16::from_be_bytes(header[0..2].try_into().unwrap()) as u32;
                let command = header[2];
                (circ_id, command)
            };
            
            log::debug!("Received cell with command: {}", command);
            
            // Variable-length cells (>= 128) have a 2-byte length field
            let payload = if command >= 128 {
                // Read 2-byte payload length
                let mut len_bytes = [0u8; 2];
                tokio::time::timeout(
                    Duration::from_secs(10),
                    stream.read_exact(&mut len_bytes)
                ).await
                    .map_err(|_| CircuitError::Timeout("Reading payload length timed out".to_string()))?
                    .map_err(|e| CircuitError::Io(format!("Failed to read payload length: {}", e)))?;
                
                let payload_len = u16::from_be_bytes(len_bytes) as usize;
                log::debug!("Variable-length cell, payload length: {}", payload_len);
                
                // Read the full payload
                let mut payload = vec![0u8; payload_len];
                tokio::time::timeout(
                    Duration::from_secs(10),
                    stream.read_exact(&mut payload)
                ).await
                    .map_err(|_| CircuitError::Timeout("Reading payload timed out".to_string()))?
                    .map_err(|e| CircuitError::Io(format!("Failed to read payload: {}", e)))?;
                
                payload
            } else {
                // Fixed-length cell: 509 bytes payload (514 - 5 header)
                let payload_len = CELL_LEN - header_size;
                let mut payload = vec![0u8; payload_len];
                tokio::time::timeout(
                    Duration::from_secs(10),
                    stream.read_exact(&mut payload)
                ).await
                    .map_err(|_| CircuitError::Timeout("Reading payload timed out".to_string()))?
                    .map_err(|e| CircuitError::Io(format!("Failed to read payload: {}", e)))?;
                
                payload
            };
            
            let cell = Cell {
                circ_id,
                command,
                payload,
            };
            
            log::debug!("Successfully read cell with command {} ({} bytes payload)", command, cell.payload.len());
            
            match cell.command {
                CELL_COMMAND_CERTS => {
                    log::debug!("Received CERTS cell ({} bytes payload)", cell.payload.len());
                    // We can ignore CERTS for now (certificate chain validation)
                }
                CELL_COMMAND_AUTH_CHALLENGE => {
                    log::debug!("Received AUTH_CHALLENGE cell ({} bytes payload)", cell.payload.len());
                    // We can ignore AUTH_CHALLENGE (we're not authenticating)
                }
                CELL_COMMAND_NETINFO => {
                    log::info!("Received NETINFO cell ({} bytes payload)", cell.payload.len());
                    // Reply with our own NETINFO cell using the same circ_id as received
                    let netinfo_response = self.create_netinfo_cell(cell.circ_id, &addr)?;
                    let netinfo_bytes = netinfo_response.to_bytes(negotiated_version);

                    tokio::time::timeout(
                        Duration::from_secs(5),
                        stream.write_all(&netinfo_bytes)
                    ).await
                        .map_err(|_| CircuitError::Timeout("Sending NETINFO timed out".to_string()))?
                        .map_err(|e| CircuitError::Io(format!("Failed to send NETINFO: {}", e)))?;

                    stream.flush().await.map_err(|e| CircuitError::Io(format!("Flush failed: {}", e)))?;
                    log::info!("Sent NETINFO response");

                    // After NETINFO exchange, we can send CREATE2
                    break;
                }
                CELL_COMMAND_VPADDING => {
                    log::debug!("Received VPADDING cell (padding, ignoring)");
                    // Just padding, ignore
                }
                _ => {
                    log::warn!("Received unexpected cell with command {} while waiting for NETINFO", cell.command);
                    // Don't break - some relays send other cells, we just ignore them
                }
            }
        }
        
        // Now send CREATE2
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

        let cell_bytes = create2_cell.to_bytes(negotiated_version);
        
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.write_all(&cell_bytes)
        ).await
            .map_err(|_| CircuitError::Timeout("Sending CREATE2 timed out".to_string()))?
            .map_err(|e| CircuitError::Io(format!("Failed to send CREATE2: {}", e)))?;
        
        stream.flush().await.map_err(|e| CircuitError::Io(format!("Flush failed: {}", e)))?;
        log::info!("Sent CREATE2 cell to relay {} (circuit ID: {})", hop.relay_id, circuit.id);

        // Receive CREATED2 response
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
        
        log::info!("Received response ({} bytes)", n);

        let response_cell = Cell::from_bytes(&response[..n], negotiated_version)
            .map_err(|e| CircuitError::HandshakeFailed(format!("Failed to parse response cell: {}", e)))?;

        if response_cell.command != CELL_COMMAND_CREATED2 {
            return Err(CircuitError::HandshakeFailed(
                format!("Expected CREATED2 response (cmd 11), got command {}", response_cell.command)
            ));
        }

        if response_cell.circ_id != circuit.id {
            return Err(CircuitError::HandshakeFailed(
                format!("Circuit ID mismatch: expected {}, got {}", circuit.id, response_cell.circ_id)
            ));
        }

        let created2_cell = Created2Cell::from_bytes(&response_cell.payload)
            .map_err(|e| CircuitError::HandshakeFailed(format!("Failed to parse CREATED2 payload: {}", e)))?;

        // Perform ntor key derivation
        let (keys, auth) = ntor_handshake(
            client_private_key,
            &client_public_key,
            &created2_cell.server_public_key,
            &hop.identity_key,
            &hop.onion_key,
        )?;

        // Verify auth
        if auth != created2_cell.auth {
            log::error!("Auth verification failed!");
            log::debug!("Expected auth: {:02x?}", &auth[..8]);
            log::debug!("Received auth: {:02x?}", &created2_cell.auth[..8]);
            return Err(CircuitError::HandshakeFailed("Authentication verification failed".to_string()));
        }

        log::info!("✓ Auth verification successful");

        // Update crypto state
        hop.crypto_state = OnionCrypto::from_ntor_keys(keys)?;

        log::info!("✓ Handshake with relay {} completed successfully!", hop.relay_id);
        log::info!("✓ Circuit {} first hop established", circuit.id);

        Ok(())
    }
    
    /// Create a NETINFO cell to send to the relay
    fn create_netinfo_cell(&self, circ_id: u32, relay_addr: &SocketAddr) -> Result<Cell, CircuitError> {
        let mut payload = Vec::new();
        
        // Timestamp (4 bytes) - current Unix timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        payload.extend_from_slice(&timestamp.to_be_bytes());
        
        // Other's address (relay's address as we see it)
        // Type: 1 byte (0x04 = IPv4, 0x06 = IPv6)
        // Length: 1 byte
        // Address: 4 or 16 bytes
        match relay_addr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                payload.push(0x04); // IPv4
                payload.push(4);    // Length
                payload.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                payload.push(0x06); // IPv6
                payload.push(16);   // Length
                payload.extend_from_slice(&ipv6.octets());
            }
        }
        
        // Number of our addresses (1 byte) - we say 0 for simplicity
        payload.push(0);
        
        Ok(Cell {
            circ_id,
            command: CELL_COMMAND_NETINFO,
            payload,
        })
    }
}