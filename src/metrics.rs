
// src/metrics.rs
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Metrics {
    pub circuits_created: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub active_circuits: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            circuits_created: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            active_circuits: AtomicU64::new(0),
        }
    }
    
    pub fn report(&self) -> String {
        format!(
            "circuits_created: {}, bytes_sent: {}, bytes_received: {}, active_circuits: {}",
            self.circuits_created.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.active_circuits.load(Ordering::Relaxed),
        )
    }
}
