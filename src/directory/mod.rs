// src/directory/mod.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use rand::Rng;
use chrono::{Utc, Timelike, Datelike};
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusSignature {
    pub algorithm: String,
    pub identity: String,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub enum DirectoryError {
    NoSuitableRelays,
    RequestFailed(String),
    InvalidConsensus(String),
    ParseError(String),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::NoSuitableRelays => write!(f, "No suitable relays found"),
            DirectoryError::RequestFailed(e) => write!(f, "Request failed: {}", e),
            DirectoryError::InvalidConsensus(e) => write!(f, "Invalid consensus: {}", e),
            DirectoryError::ParseError(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for DirectoryError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDescriptor {
    pub id: String,
    pub nickname: String,
    pub address: SocketAddr,
    pub identity_key: Vec<u8>,
    pub onion_key: Vec<u8>,
    pub bandwidth: u32,
    pub flags: Vec<RelayFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RelayFlag {
    Exit,
    Guard,
    Middle,
    Fast,
    Stable,
    Running,
    Valid,
    HSDir,
    V2Dir,
    Authority,
    BadExit,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConsensus {
    pub valid_after: SystemTime,
    pub valid_until: SystemTime,
    pub relays: HashMap<String, RelayDescriptor>,
    pub signatures: Vec<ConsensusSignature>,
}

const TOR_COLLECTOR_BASE: &str = "https://collector.torproject.org/recent/relay-descriptors/consensuses";

#[derive(Debug)]
pub struct DirectoryClient {
    consensus: RwLock<Option<NetworkConsensus>>,
    last_update: RwLock<SystemTime>,
    use_real_consensus: bool,
}

impl DirectoryClient {
    pub fn new(_authorities: Vec<String>) -> Self {
        log::info!("DirectoryClient initialized with Tor Collector API");
        Self {
            consensus: RwLock::new(None),
            last_update: RwLock::new(SystemTime::UNIX_EPOCH),
            use_real_consensus: true,
        }
    }

    pub fn new_mock() -> Self {
        log::info!("DirectoryClient initialized with mock data");
        Self {
            consensus: RwLock::new(None),
            last_update: RwLock::new(SystemTime::UNIX_EPOCH),
            use_real_consensus: false,
        }
    }

    async fn is_consensus_fresh(&self) -> bool {
        let last_update = *self.last_update.read().await;
        let age = SystemTime::now()
            .duration_since(last_update)
            .unwrap_or(Duration::from_secs(u64::MAX));
        age < Duration::from_secs(3600)
    }

    async fn fetch_latest_consensus(&self) -> Result<NetworkConsensus, DirectoryError> {
        log::info!("Fetching latest consensus from Tor Collector");
        
        let now = Utc::now();
        
        // Try current hour and previous (up to 48 for ~2-day coverage)
        for hour_offset in 0..48u32 {
            let timestamp = now - chrono::Duration::hours(hour_offset as i64);
            let url = format!(
                "{}/{:04}-{:02}-{:02}-{:02}-00-00-consensus",
                TOR_COLLECTOR_BASE,
                timestamp.year(),
                timestamp.month(),
                timestamp.day(),
                timestamp.hour()
            );
            
            log::info!("Trying: {}", url);
            
            match self.download_and_parse(&url).await {
                Ok(consensus) => {
                    log::info!("✓ Successfully fetched consensus (offset: {} hours)", hour_offset);
                    return Ok(consensus);
                }
                Err(e) => {
                    log::warn!("✗ Failed offset {}: {}", hour_offset, e);
                }
            }
        }
        
        Err(DirectoryError::RequestFailed("Could not fetch from any recent hour".to_string()))
    }

    async fn download_and_parse(&self, url: &str) -> Result<NetworkConsensus, DirectoryError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))  // Increased for large file
            .build()
            .map_err(|e| DirectoryError::RequestFailed(e.to_string()))?;
        
        let response = client.get(url).send().await
            .map_err(|e| DirectoryError::RequestFailed(format!("HTTP: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(DirectoryError::RequestFailed(format!("Status: {}", response.status())));
        }
        
        let text = response.text().await
            .map_err(|e| DirectoryError::RequestFailed(format!("Read: {}", e)))?;
        
        log::info!("Downloaded {} bytes", text.len());

        // Debug: Count raw r lines
        let r_count = text.lines().filter(|l| l.trim().starts_with("r ")).count();
        log::info!("Raw r line count in download: {}", r_count);
        
        self.parse_consensus(&text).await
    }

    async fn create_mock_consensus(&self) -> Result<NetworkConsensus, DirectoryError> {
        log::info!("Creating mock consensus");
        let mut relays = HashMap::new();
        
        // Mock 10 relays with varied flags
        let mock_relays = vec![
            ("Guard1", "192.168.1.1:9001", vec![RelayFlag::Guard, RelayFlag::Fast, RelayFlag::Running, RelayFlag::Valid], 1000000),
            ("Middle1", "192.168.1.2:9001", vec![RelayFlag::Fast, RelayFlag::Stable, RelayFlag::Running, RelayFlag::Valid], 2000000),
            ("Exit1", "192.168.1.3:9001", vec![RelayFlag::Exit, RelayFlag::Fast, RelayFlag::Running, RelayFlag::Valid], 3000000),
            ("Guard2", "192.168.1.4:9001", vec![RelayFlag::Guard, RelayFlag::Fast, RelayFlag::Running, RelayFlag::Valid], 1500000),
            ("Middle2", "192.168.1.5:9001", vec![RelayFlag::Fast, RelayFlag::Stable, RelayFlag::Running, RelayFlag::Valid], 2500000),
            ("Exit2", "192.168.1.6:9001", vec![RelayFlag::Exit, RelayFlag::Fast, RelayFlag::Running, RelayFlag::Valid], 3500000),
            ("Guard3", "192.168.1.7:9001", vec![RelayFlag::Guard, RelayFlag::Fast, RelayFlag::Running, RelayFlag::Valid], 1200000),
            ("Middle3", "192.168.1.8:9001", vec![RelayFlag::Fast, RelayFlag::Stable, RelayFlag::Running, RelayFlag::Valid], 2200000),
            ("Exit3", "192.168.1.9:9001", vec![RelayFlag::Exit, RelayFlag::Fast, RelayFlag::Running, RelayFlag::Valid], 3200000),
            ("Fallback", "192.168.1.10:9001", vec![RelayFlag::Fast, RelayFlag::Running, RelayFlag::Valid], 1000000),
        ];

        for (nick, addr_str, flags, bw) in mock_relays {
            let addr: SocketAddr = addr_str.parse().unwrap();
            let id = format!("mock-{}", nick);
            relays.insert(id.clone(), RelayDescriptor {
                id,
                nickname: nick.to_string(),
                address: addr,
                identity_key: vec![0u8; 20],  // Dummy
                onion_key: vec![0u8; 32],  // Dummy
                bandwidth: bw,
                flags,
            });
        }

        log::info!("Created mock consensus with {} relays", relays.len());

        Ok(NetworkConsensus {
            valid_after: SystemTime::now(),
            valid_until: SystemTime::now() + Duration::from_secs(3600),
            relays,
            signatures: vec![],
        })
    }

    async fn parse_consensus(&self, text: &str) -> Result<NetworkConsensus, DirectoryError> {
        let mut relays = HashMap::new();
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0usize;

        while i < lines.len() {
            let line = lines[i].trim();
            if line.starts_with("r ") {
                match self.parse_relay(&lines, &mut i) {
                    Ok(relay) => {
                        relays.insert(relay.id.clone(), relay);
                    }
                    Err(e) => {
                        log::warn!("Failed to parse relay at line {}: {}", i, e);
                    }
                }
                // Skip to next potential r (handles s/w/p/v lines in block)
                i += 1;
                while i < lines.len() && !lines[i].trim().starts_with("r ") {
                    i += 1;
                }
                continue;
            }
            i += 1;
        }

        log::info!("Parsed {} relays", relays.len());

        if relays.is_empty() {
            return Err(DirectoryError::InvalidConsensus("No relays found".to_string()));
        }

        Ok(NetworkConsensus {
            valid_after: SystemTime::now(),
            valid_until: SystemTime::now() + Duration::from_secs(3600),
            relays,
            signatures: vec![],
        })
    }

    fn parse_relay(&self, lines: &[&str], i: &mut usize) -> Result<RelayDescriptor, DirectoryError> {
        let parts: Vec<&str> = lines[*i].trim().split_whitespace().collect();
        if parts.len() != 9 || parts[0] != "r" {
            return Err(DirectoryError::ParseError(format!(
                "Invalid r line (expected 9 parts due to space in timestamp, got {}): {}",
                parts.len(), lines[*i]
            )));
        }

        let nickname = parts[1].to_string();
        let identity_full = parts[2];  // Unpadded base64
        let _digest = parts[3];  // Base64 digest, unused
        let _published_date = parts[4];  // "YYYY-MM-DD", unused
        let _published_time = parts[5];  // "HH:MM:SS", unused
        let ip = parts[6];  // IPv4
        let or_port: u16 = parts[7].parse()
            .map_err(|_| DirectoryError::ParseError("Invalid OR port".to_string()))?;
        let _dir_port: u16 = parts[8].parse()
            .map_err(|_| DirectoryError::ParseError("Invalid Dir port".to_string()))?;

        let address = format!("{}:{}", ip, or_port).parse()
            .map_err(|e| DirectoryError::ParseError(format!("Invalid address: {}", e)))?;

        // Decode identity: Unpadded base64 → replace chars, add padding, decode to 20 bytes
        let mut identity_padded = identity_full.replace('-', "+").replace('_', "/");
        while identity_padded.len() % 4 != 0 {
            identity_padded.push('=');
        }
        let identity_key = general_purpose::STANDARD
            .decode(&identity_padded)
            .map_err(|e| DirectoryError::ParseError(format!("Invalid identity base64: {}", e)))?;
        if identity_key.len() != 20 {
            return Err(DirectoryError::ParseError(format!(
                "Identity key wrong length: {} bytes (expected 20)", identity_key.len()
            )));
        }

        let onion_key = identity_key.clone();  // Placeholder; fetch NTor key from microdesc later

        // Parse flags: Next line usually "s "
        let mut flags = vec![RelayFlag::Running, RelayFlag::Valid];
        let mut j = *i + 1;
        if j < lines.len() {
            let next_line = lines[j].trim();
            if next_line.starts_with("s ") {
                flags = self.parse_flags(next_line);
                j += 1;
            }
        }

        // Parse bandwidth: First "w Bandwidth=..." in next 5 lines
        let mut bandwidth = 1000000u32;
        for offset in 0..5 {
            let check_j = j + offset;
            if check_j < lines.len() {
                let w_line = lines[check_j].trim();
                if let Some(bw) = self.parse_bandwidth(w_line) {
                    bandwidth = bw;
                    break;
                }
            }
        }

        *i = j - 1;  // For outer loop advance

        Ok(RelayDescriptor {
            id: identity_full.to_string(),
            nickname,
            address,
            identity_key,
            onion_key,
            bandwidth,
            flags,
        })
    }

    fn parse_flags(&self, line: &str) -> Vec<RelayFlag> {
        line.split_whitespace().skip(1).map(|flag| match flag {
            "Exit" => RelayFlag::Exit,
            "Guard" => RelayFlag::Guard,
            "Middle" => RelayFlag::Middle,
            "Fast" => RelayFlag::Fast,
            "Stable" => RelayFlag::Stable,
            "Running" => RelayFlag::Running,
            "Valid" => RelayFlag::Valid,
            "HSDir" => RelayFlag::HSDir,
            "V2Dir" => RelayFlag::V2Dir,
            "Authority" => RelayFlag::Authority,
            "BadExit" => RelayFlag::BadExit,
            "MiddleOnly" | "StaleDesc" | "Sybil" | "NoEdConsensus" => RelayFlag::Unknown(flag.to_string()),
            other => RelayFlag::Unknown(other.to_string()),
        }).collect()
    }

    fn parse_bandwidth(&self, line: &str) -> Option<u32> {
        line.split_whitespace().skip(1).find_map(|part| {
            part.strip_prefix("Bandwidth=").and_then(|bw_str| bw_str.parse().ok())
        })
    }

    fn is_relay_suitable(&self, relay: &RelayDescriptor, hop: usize) -> bool {
        if !relay.flags.contains(&RelayFlag::Running) || !relay.flags.contains(&RelayFlag::Valid) {
            return false;
        }
        if relay.flags.contains(&RelayFlag::BadExit) {
            return false;
        }
        match hop {
            0 => relay.flags.contains(&RelayFlag::Guard) && relay.flags.contains(&RelayFlag::Fast),
            1 => {
                // If relay has explicit Middle flag, use it
                if relay.flags.contains(&RelayFlag::Middle) {
                    return relay.flags.contains(&RelayFlag::Fast);
                }
                // Otherwise, middle relay = Fast + Stable, not Guard, not Exit
                relay.flags.contains(&RelayFlag::Fast) 
                    && relay.flags.contains(&RelayFlag::Stable)
                    && !relay.flags.contains(&RelayFlag::Guard)
                    && !relay.flags.contains(&RelayFlag::Exit)
            },
            2 => relay.flags.contains(&RelayFlag::Exit) && relay.flags.contains(&RelayFlag::Fast),
            _ => relay.flags.contains(&RelayFlag::Fast),
        }
    }

    fn select_weighted(&self, relays: Vec<&RelayDescriptor>) -> Result<RelayDescriptor, DirectoryError> {
        if relays.is_empty() {
            return Err(DirectoryError::NoSuitableRelays);
        }
        
        let total: u64 = relays.iter().map(|r| r.bandwidth as u64).sum();
        if total == 0 {
            let mut rng = rand::thread_rng();
            return Ok(relays[rng.gen_range(0..relays.len())].clone());
        }
        
        let mut rng = rand::thread_rng();
        let mut sel = rng.gen_range(0..total);
        
        for relay in &relays {
            if sel < relay.bandwidth as u64 {
                return Ok((*relay).clone());
            }
            sel -= relay.bandwidth as u64;
        }
        
        Ok(relays[0].clone())
    }
    
    pub async fn fetch_consensus(&self) -> Result<NetworkConsensus, DirectoryError> {
        if self.is_consensus_fresh().await {
            if let Some(c) = self.consensus.read().await.as_ref() {
                log::debug!("Using cached consensus");
                return Ok(c.clone());
            }
        }
        
        let consensus = if self.use_real_consensus {
            self.fetch_latest_consensus().await?
        } else {
            self.create_mock_consensus().await?
        };
        
        *self.consensus.write().await = Some(consensus.clone());
        *self.last_update.write().await = SystemTime::now();
        
        Ok(consensus)
    }
    
    pub async fn select_relay(&self, hop: usize) -> Result<RelayDescriptor, DirectoryError> {
        let consensus = self.fetch_consensus().await?;
        
        let suitable: Vec<&RelayDescriptor> = consensus.relays.values()
            .filter(|r| self.is_relay_suitable(r, hop))
            .collect();
        
        log::debug!("Found {} suitable relays for hop {}", suitable.len(), hop);
        
        if suitable.is_empty() {
            let fallback: Vec<&RelayDescriptor> = consensus.relays.values()
                .filter(|r| r.flags.contains(&RelayFlag::Running) && !r.flags.contains(&RelayFlag::BadExit))
                .collect();
            
            if fallback.is_empty() {
                return Err(DirectoryError::NoSuitableRelays);
            }
            
            log::warn!("Using fallback for hop {}", hop);
            return self.select_weighted(fallback);
        }
        
        self.select_weighted(suitable)
    }
}