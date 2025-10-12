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
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::NoSuitableRelays => write!(f, "No suitable relays found"),
            DirectoryError::RequestFailed => write!(f, "Request to directory authority failed"),
            DirectoryError::InvalidConsensus => write!(f, "Invalid consensus received"),
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

    async fn fetch_from_authority(&self, _authority: &str) -> Result<NetworkConsensus, DirectoryError> {
        // Mock implementation - return dummy consensus
        log::info!("Creating mock consensus for testing");
        
        let mut relays = HashMap::new();
        
        // Create 10 mock relays
        for i in 0..10 {
            let relay = RelayDescriptor {
                id: format!("relay_{}", i),
                nickname: format!("MockRelay{}", i),
                address: format!("127.0.0.{}:9001", i + 1).parse().unwrap(),
                identity_key: vec![i as u8; 32],
                onion_key: vec![i as u8; 32],
                bandwidth: 1000000 + i * 100000,
                flags: vec![RelayFlag::Fast, RelayFlag::Stable],
            };
            relays.insert(relay.id.clone(), relay);
        }
        
        Ok(NetworkConsensus {
            valid_after: SystemTime::now(),
            valid_until: SystemTime::now() + Duration::from_secs(3600),
            relays,
            signatures: vec![],
        })
    }

    async fn validate_consensus(&self, candidates: Vec<NetworkConsensus>) -> Result<NetworkConsensus, DirectoryError> {
        // For testing, just return the first candidate
        candidates.into_iter().next().ok_or(DirectoryError::InvalidConsensus)
    }

    fn is_relay_suitable(&self, relay: &RelayDescriptor, hop_number: usize) -> bool {
        // Simple suitability check
        match hop_number {
            0 => relay.flags.contains(&RelayFlag::Guard) || relay.flags.contains(&RelayFlag::Fast),
            1 => relay.flags.contains(&RelayFlag::Fast),
            2 => relay.flags.contains(&RelayFlag::Exit) || relay.flags.contains(&RelayFlag::Fast),
            _ => relay.flags.contains(&RelayFlag::Fast),
        }
    }

    fn select_weighted_relay(&self, relays: Vec<&RelayDescriptor>) -> Result<RelayDescriptor, DirectoryError> {
        if relays.is_empty() {
            return Err(DirectoryError::NoSuitableRelays);
        }
        
        // Simple weighted selection based on bandwidth
        let total_bandwidth: u64 = relays.iter().map(|r| r.bandwidth as u64).sum();
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
                return Ok(consensus.clone());
            }
        }
        
        // Fetch from directory authorities
        let mut consensus_candidates = Vec::new();
        
        for authority in &self.authorities {
            match self.fetch_from_authority(authority).await {
                Ok(consensus) => consensus_candidates.push(consensus),
                Err(e) => log::warn!("Failed to fetch from {}: {}", authority, e),
            }
        }
        
        // If no authorities worked, create mock consensus
        if consensus_candidates.is_empty() {
            log::warn!("No authorities available, using mock consensus");
            consensus_candidates.push(self.fetch_from_authority("mock").await?);
        }
        
        // Validate and select consensus
        let consensus = self.validate_consensus(consensus_candidates).await?;
        
        // Update cache
        *self.consensus.write().await = Some(consensus.clone());
        *self.last_update.write().await = SystemTime::now();
        
        Ok(consensus)
    }
    
    /// Select appropriate relay for a specific hop position
    pub async fn select_relay(&self, hop_number: usize) -> Result<RelayDescriptor, DirectoryError> {
        let consensus = self.fetch_consensus().await?;
        
        let suitable_relays: Vec<&RelayDescriptor> = consensus.relays
            .values()
            .filter(|relay| self.is_relay_suitable(relay, hop_number))
            .collect();
        
        if suitable_relays.is_empty() {
            return Err(DirectoryError::NoSuitableRelays);
        }
        
        // Weighted random selection based on bandwidth
        self.select_weighted_relay(suitable_relays)
    }
}