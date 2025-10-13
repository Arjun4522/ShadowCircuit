// src/proxy/socks5.rs
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::sync::Arc;
use crate::circuit::CircuitManager;

#[derive(Debug)]
pub enum ProxyError {
    InvalidVersion(u8),
    Io(std::io::Error),
    Circuit(crate::circuit::CircuitError),
    Unsupported(String),
}

impl From<std::io::Error> for ProxyError {
    fn from(err: std::io::Error) -> Self {
        ProxyError::Io(err)
    }
}

impl From<crate::circuit::CircuitError> for ProxyError {
    fn from(err: crate::circuit::CircuitError) -> Self {
        ProxyError::Circuit(err)
    }
}

#[derive(Debug)]
pub struct Socks5Proxy {
    bind_address: String,
    circuit_manager: Arc<CircuitManager>,
    directory_client: Arc<crate::directory::DirectoryClient>,
}

impl Socks5Proxy {
    pub fn new(
        bind_address: String,
        circuit_manager: Arc<CircuitManager>,
        directory_client: Arc<crate::directory::DirectoryClient>,
    ) -> Self {
        Self {
            bind_address,
            circuit_manager,
            directory_client,
        }
    }

    pub async fn run(&self) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(&self.bind_address).await?;
        log::info!("SOCKS5 proxy listening on {}", self.bind_address);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    log::info!("New connection from {}", addr);
                    let circuit_manager = self.circuit_manager.clone();
                    let directory_client = self.directory_client.clone();
                    
                    tokio::spawn(async move {
                        log::debug!("Spawned handler for {}", addr);
                        match Self::handle_client(stream, circuit_manager, directory_client).await {
                            Ok(_) => log::info!("Client {} handled successfully", addr),
                            Err(e) => log::error!("Client {} handling error: {:?}", addr, e),
                        }
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_client(
        mut stream: TcpStream,
        circuit_manager: Arc<CircuitManager>,
        directory_client: Arc<crate::directory::DirectoryClient>,
    ) -> Result<(), ProxyError> {
        log::debug!("Starting client handler");
        
        // SOCKS5 handshake
        log::debug!("Performing handshake");
        Self::perform_handshake(&mut stream).await?;
        log::debug!("Handshake complete");

        // Parse SOCKS5 request
        log::debug!("Parsing request");
        let request = Self::parse_request(&mut stream).await?;
        
        log::info!("SOCKS5 request: {}:{}", request.host, request.port);

        // Create a circuit
        log::debug!("Creating circuit");
        match circuit_manager.create_circuit(3, &directory_client).await {
            Ok(circuit_id) => {
                log::info!("Created circuit {}", circuit_id);
                // Send success response
                log::debug!("Sending success response");
                Self::send_response(&mut stream, 0x00).await?;
                log::debug!("Response sent");
                
                // TODO: Actually relay traffic through circuit
                // For now, simulate a basic HTTP response for testing
                log::info!("Attempting to connect to {}:{}", request.host, request.port);
                
                // Try to connect directly (just for testing purposes)
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    TcpStream::connect(format!("{}:{}", request.host, request.port))
                ).await {
                    Ok(Ok(target)) => {
                        log::info!("Connected to target, relaying traffic");
                        
                        // Simple bidirectional relay (not through Tor circuit yet)
                        let (mut client_read, mut client_write) = stream.into_split();
                        let (mut target_read, mut target_write) = target.into_split();
                        
                        // Spawn task for client -> target
                        let client_to_target = tokio::spawn(async move {
                            let mut buf = [0u8; 8192];
                            let mut total_bytes = 0;
                            loop {
                                match client_read.read(&mut buf).await {
                                    Ok(0) => {
                                        log::debug!("Client closed connection (sent {} bytes)", total_bytes);
                                        break;
                                    }
                                    Ok(n) => {
                                        total_bytes += n;
                                        if let Err(e) = target_write.write_all(&buf[..n]).await {
                                            log::error!("Error writing to target: {}", e);
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("Error reading from client: {}", e);
                                        break;
                                    }
                                }
                            }
                        });
                        
                        // Spawn task for target -> client
                        let target_to_client = tokio::spawn(async move {
                            let mut buf = [0u8; 8192];
                            let mut total_bytes = 0;
                            loop {
                                match target_read.read(&mut buf).await {
                                    Ok(0) => {
                                        log::debug!("Target closed connection (received {} bytes)", total_bytes);
                                        break;
                                    }
                                    Ok(n) => {
                                        total_bytes += n;
                                        if let Err(e) = client_write.write_all(&buf[..n]).await {
                                            log::error!("Error writing to client: {}", e);
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("Error reading from target: {}", e);
                                        break;
                                    }
                                }
                            }
                        });
                        
                        // Wait for both tasks to complete
                        let _ = tokio::join!(client_to_target, target_to_client);
                        log::info!("Connection relay finished");
                    }
                    Ok(Err(e)) => {
                        log::error!("Failed to connect to target: {}", e);
                        // Connection already established, can't send failure response
                    }
                    Err(_) => {
                        log::error!("Timeout connecting to target");
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to create circuit: {:?}", e);
                // Send failure response
                Self::send_response(&mut stream, 0x01).await?;
            }
        }

        Ok(())
    }
    
    async fn perform_handshake(stream: &mut TcpStream) -> Result<(), ProxyError> {
        log::debug!("Reading SOCKS5 version and method count");
        
        // Read version and methods
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        
        let version = buf[0];
        let nmethods = buf[1] as usize;
        
        log::debug!("SOCKS5 version: {}, nmethods: {}", version, nmethods);
        
        if version != 0x05 {
            log::error!("Invalid SOCKS version: {}", version);
            return Err(ProxyError::InvalidVersion(version));
        }
        
        // Read methods
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;
        
        log::debug!("SOCKS5 handshake: version={}, methods={:?}", version, methods);
        
        // Accept no authentication (0x00)
        log::debug!("Sending handshake response");
        stream.write_all(&[0x05, 0x00]).await?;
        stream.flush().await?;
        log::debug!("Handshake response sent");
        
        Ok(())
    }

    async fn parse_request(stream: &mut TcpStream) -> Result<Socks5Request, ProxyError> {
        log::debug!("Reading SOCKS5 request header");
        
        // Read request header
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        
        let version = buf[0];
        let cmd = buf[1];
        let _reserved = buf[2];
        let atyp = buf[3];
        
        log::debug!("Request: version={}, cmd={}, atyp={}", version, cmd, atyp);
        
        if version != 0x05 {
            return Err(ProxyError::InvalidVersion(version));
        }
        
        if cmd != 0x01 { // Only support CONNECT
            return Err(ProxyError::Unsupported(format!("Command {} not supported", cmd)));
        }
        
        // Read address
        let host = match atyp {
            0x01 => {
                // IPv4
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
            }
            0x03 => {
                // Domain name
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await?;
                String::from_utf8_lossy(&domain).to_string()
            }
            0x04 => {
                // IPv6
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                    addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15])
            }
            _ => return Err(ProxyError::Unsupported(format!("Address type {} not supported", atyp))),
        };
        
        // Read port
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);
        
        log::debug!("Parsed request: {}:{}", host, port);
        
        Ok(Socks5Request { host, port })
    }

    async fn send_response(stream: &mut TcpStream, status: u8) -> Result<(), ProxyError> {
        log::debug!("Sending SOCKS5 response with status {}", status);
        
        // Send SOCKS5 response
        // VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
        let response = [
            0x05,  // Version
            status, // Status (0x00 = success)
            0x00,  // Reserved
            0x01,  // Address type (IPv4)
            0, 0, 0, 0,  // Bind address (0.0.0.0)
            0, 0,  // Bind port (0)
        ];
        stream.write_all(&response).await?;
        stream.flush().await?;
        log::debug!("SOCKS5 response sent");
        
        Ok(())
    }
}

#[derive(Debug)]
pub struct Socks5Request {
    pub host: String,
    pub port: u16,
}