
// tests/unit/crypto_tests.rs
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_onion_encryption_roundtrip() {
        let mut crypto = OnionCrypto::new().unwrap();
        let plaintext = b"test message";
        
        let encrypted = crypto.encrypt_forward(plaintext).unwrap();
        let decrypted = crypto.decrypt_forward(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[tokio::test]
    async fn test_circuit_creation() {
        let manager = CircuitManager::new();
        let directory = MockDirectory::new();
        
        let circuit_id = manager.create_circuit(3, &directory).await.unwrap();
        assert!(circuit_id > 0);
    }
}
