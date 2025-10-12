// src/directory/mod.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusSignature {
    pub algorithm: String,
    pub identity: String,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub enum DirectoryError {
    NoSuitableRelays,
    RequestFailed,
    InvalidConsensus,
    ParseError(String),
    NetworkError(String),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::NoSuitableRelays => write!(f, "No suitable relays found"),
            DirectoryError::RequestFailed => write!(f, "Request to directory authority failed"),
            DirectoryError::InvalidConsensus => write!(f, "Invalid consensus received"),
            DirectoryError::ParseError(e) => write!(f, "Parse error: {}", e),
            DirectoryError::NetworkError(e) => write!(f, "Network error: {}", e),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDescriptor {
    pub id: String,
    pub nickname: String,
    pub address: std::net::SocketAddr,
    pub identity_key: Vec<u8>,
    pub onion_key: Vec<u8>,
    pub bandwidth: u32,
    pub flags: Vec<RelayFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RelayFlag {
    Exit,
    Guard,
    Fast,
    Stable,
    Running,
    Valid,
    HSDir,
    V2Dir,
    Authority,
}

impl RelayFlag {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "Exit" => Some(RelayFlag::Exit),
            "Guard" => Some(RelayFlag::Guard),
            "Fast" => Some(RelayFlag::Fast),
            "Stable" => Some(RelayFlag::Stable),
            "Running" => Some(RelayFlag::Running),
            "Valid" => Some(RelayFlag::Valid),
            "HSDir" => Some(RelayFlag::HSDir),
            "V2Dir" => Some(RelayFlag::V2Dir),
            "Authority" => Some(RelayFlag::Authority),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConsensus {
    pub valid_after: SystemTime,
    pub valid_until: SystemTime,
    pub relays: HashMap<String, RelayDescriptor>,
    pub signatures: Vec<ConsensusSignature>,
}

#[derive(Debug)]
pub struct DirectoryClient {
    authorities: Vec<String>,
    consensus: RwLock<Option<NetworkConsensus>>,
    last_update: RwLock<SystemTime>,
}

impl DirectoryClient {
    pub fn new(authorities: Vec<String>) -> Self {
        Self {
            authorities,
            consensus: RwLock::new(None),
            last_update: RwLock::new(SystemTime::UNIX_EPOCH),
        }
    }

    async fn is_consensus_fresh(&self) -> bool {
        let last_update = *self.last_update.read().await;
        let age = SystemTime::now()
            .duration_since(last_update)
            .unwrap_or(Duration::from_secs(u64::MAX));
        
        // Consider fresh if less than 1 hour old
        age < Duration::from_secs(3600)
    }

    async fn fetch_from_authority(&self, authority: &str) -> Result<NetworkConsensus, DirectoryError> {
        log::info!("Fetching consensus from: {}", authority);
        
        // If it's a full URL, use it directly
        let url = if authority.starts_with("http://") || authority.starts_with("https://") {
            authority.to_string()
        } else {
            // Otherwise assume it's a directory authority IP
            format!("http://{}/tor/status-vote/current/consensus", authority)
        };
        
        log::debug!("Fetching from URL: {}", url);
        
        // Fetch the consensus document
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| DirectoryError::NetworkError(e.to_string()))?;
        
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| DirectoryError::NetworkError(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(DirectoryError::NetworkError(format!(
                "HTTP error: {}",
                response.status()
            )));
        }
        
        let text = response
            .text()
            .await
            .map_err(|e| DirectoryError::NetworkError(e.to_string()))?;
        
        log::info!("Downloaded consensus document, {} bytes", text.len());
        
        // Parse the consensus
        self.parse_consensus(&text).await
    }

    async fn parse_consensus(&self, text: &str) -> Result<NetworkConsensus, DirectoryError> {
        log::info!("Parsing consensus document");
        
        let mut relays = HashMap::new();
        let mut valid_after = SystemTime::UNIX_EPOCH;
        let mut valid_until = SystemTime::UNIX_EPOCH;
        
        let mut current_relay: Option<RelayDescriptor> = None;
        let mut in_router_section = false;
        
        for line in text.lines() {
            let line = line.trim();
            
            // Parse header fields
            if line.starts_with("valid-after ") {
                // Format: valid-after 2024-01-15 12:00:00
                // For simplicity, we'll just mark it as now
                valid_after = SystemTime::now();
            } else if line.starts_with("valid-until ") {
                valid_until = SystemTime::now() + Duration::from_secs(3600);
            }
            // Parse router status entries (r lines)
            else if line.starts_with("r ") {
                // Save previous relay if exists
                if let Some(relay) = current_relay.take() {
                    relays.insert(relay.id.clone(), relay);
                }
                in_router_section = true;
                
                // Parse: r nickname identity published IP ORPort DirPort
                // Example: r moria1 npFBIw4qLbDVe+891Z/0kZZpRq4 2024-01-15 12:00:00 128.31.0.34 9101 9131
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 7 {
                    let nickname = parts[1].to_string();
                    let identity = parts[2].to_string(); // Base64 encoded
                    let ip = parts[5];
                    let or_port: u16 = parts[6].parse().unwrap_or(9001);
                    
                    // Try to parse the address
                    if let Ok(addr) = format!("{}:{}", ip, or_port).parse() {
                        current_relay = Some(RelayDescriptor {
                            id: identity.clone(),
                            nickname,
                            address: addr,
                            identity_key: identity.as_bytes().to_vec(), // Store raw for now
                            onion_key: vec![0; 32], // Will be filled from 's' line if present
                            bandwidth: 1000000, // Default, will be updated
                            flags: vec![],
                        });
                    }
                }
            }
            // Parse flags (s lines)
            else if line.starts_with("s ") && in_router_section {
                if let Some(ref mut relay) = current_relay {
                    // Parse: s Exit Fast Guard Running Stable Valid
                    let flags: Vec<RelayFlag> = line[2..]
                        .split_whitespace()
                        .filter_map(RelayFlag::from_str)
                        .collect();
                    relay.flags = flags;
                }
            }
            // Parse bandwidth (w lines)
            else if line.starts_with("w ") && in_router_section {
                if let Some(ref mut relay) = current_relay {
                    // Parse: w Bandwidth=1000
                    for part in line[2..].split_whitespace() {
                        if let Some(bw_str) = part.strip_prefix("Bandwidth=") {
                            if let Ok(bw) = bw_str.parse::<u32>() {
                                relay.bandwidth = bw;
                            }
                        }
                    }
                }
            }
        }
        
        // Save last relay
        if let Some(relay) = current_relay {
            relays.insert(relay.id.clone(), relay);
        }
        
        log::info!("Parsed {} relays from consensus", relays.len());
        
        if relays.is_empty() {
            return Err(DirectoryError::ParseError("No relays found in consensus".to_string()));
        }
        
        Ok(NetworkConsensus {
            valid_after,
            valid_until,
            relays,
            signatures: vec![],
        })
    }

    async fn validate_consensus(&self, candidates: Vec<NetworkConsensus>) -> Result<NetworkConsensus, DirectoryError> {
        // For now, just use the first valid consensus
        // In real Tor, this would verify signatures from multiple authorities
        for consensus in candidates {
            if !consensus.relays.is_empty() {
                return Ok(consensus);
            }
        }
        Err(DirectoryError::InvalidConsensus)
    }

    fn is_relay_suitable(&self, relay: &RelayDescriptor, hop_number: usize) -> bool {
        // Relay must be Running and Valid
        if !relay.flags.contains(&RelayFlag::Running) || !relay.flags.contains(&RelayFlag::Valid) {
            return false;
        }
        
        // Position-specific requirements
        match hop_number {
            0 => {
                // Entry/Guard node - should have Guard flag
                relay.flags.contains(&RelayFlag::Guard) && relay.flags.contains(&RelayFlag::Fast)
            }
            1 => {
                // Middle node - should be Fast
                relay.flags.contains(&RelayFlag::Fast)
            }
            2 => {
                // Exit node - should have Exit flag
                relay.flags.contains(&RelayFlag::Exit) && relay.flags.contains(&RelayFlag::Fast)
            }
            _ => relay.flags.contains(&RelayFlag::Fast),
        }
    }

    fn select_weighted_relay(&self, relays: Vec<&RelayDescriptor>) -> Result<RelayDescriptor, DirectoryError> {
        if relays.is_empty() {
            return Err(DirectoryError::NoSuitableRelays);
        }
        
        // Simple weighted selection based on bandwidth
        let total_bandwidth: u64 = relays.iter().map(|r| r.bandwidth as u64).sum();
        
        if total_bandwidth == 0 {
            // Fallback to random selection
            let mut rng = rand::thread_rng();
            let idx = rng.gen_range(0..relays.len());
            return Ok(relays[idx].clone());
        }
        
        let mut rng = rand::thread_rng();
        let mut selection = rng.gen_range(0..total_bandwidth);
        
        for relay in &relays {
            if selection < relay.bandwidth as u64 {
                return Ok((*relay).clone());
            }
            selection -= relay.bandwidth as u64;
        }
        
        // Fallback to first relay
        Ok(relays[0].clone())
    }
    
    /// Fetch and validate network consensus
    pub async fn fetch_consensus(&self) -> Result<NetworkConsensus, DirectoryError> {
        // Check if we have a recent consensus
        if self.is_consensus_fresh().await {
            if let Some(consensus) = self.consensus.read().await.as_ref() {
                log::debug!("Using cached consensus");
                return Ok(consensus.clone());
            }
        }
        
        log::info!("Consensus is stale or missing, fetching new one");
        
        // Fetch from directory authorities
        let mut consensus_candidates = Vec::new();
        
        for authority in &self.authorities {
            match self.fetch_from_authority(authority).await {
                Ok(consensus) => {
                    log::info!("Successfully fetched consensus from {}", authority);
                    consensus_candidates.push(consensus);
                    break; // Use first successful fetch
                }
                Err(e) => {
                    log::warn!("Failed to fetch from {}: {}", authority, e);
                }
            }
        }
        
        if consensus_candidates.is_empty() {
            return Err(DirectoryError::RequestFailed);
        }
        
        // Validate and select consensus
        let consensus = self.validate_consensus(consensus_candidates).await?;
        
        log::info!("Using consensus with {} relays", consensus.relays.len());
        
        // Update cache
        *self.consensus.write().await = Some(consensus.clone());
        *self.last_update.write().await = SystemTime::now();
        
        Ok(consensus)
    }
    
    /// Select appropriate relay for a specific hop position
    pub async fn select_relay(&self, hop_number: usize) -> Result<RelayDescriptor, DirectoryError> {
        let consensus = self.fetch_consensus().await?;
        
        log::debug!("Selecting relay for hop {} from {} total relays", 
                   hop_number, consensus.relays.len());
        
        let suitable_relays: Vec<&RelayDescriptor> = consensus.relays
            .values()
            .filter(|relay| self.is_relay_suitable(relay, hop_number))
            .collect();
        
        log::info!("Found {} suitable relays for hop {}", suitable_relays.len(), hop_number);
        
        if suitable_relays.is_empty() {
            // Fallback: relax requirements and just use Running relays
            log::warn!("No suitable relays with strict requirements, relaxing constraints");
            let fallback_relays: Vec<&RelayDescriptor> = consensus.relays
                .values()
                .filter(|relay| {
                    relay.flags.contains(&RelayFlag::Running) && 
                    relay.flags.contains(&RelayFlag::Valid)
                })
                .collect();
            
            if fallback_relays.is_empty() {
                return Err(DirectoryError::NoSuitableRelays);
            }
            
            return self.select_weighted_relay(fallback_relays);
        }
        
        // Weighted random selection based on bandwidth
        self.select_weighted_relay(suitable_relays)
    }
}