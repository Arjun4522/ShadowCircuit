
// src/security.rs

// Always use constant-time comparisons
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b) {
        result |= x ^ y;
    }
    
    result == 0
}

// Secure memory zeroization
use zeroize::Zeroize;

struct SecretData {
    key: [u8; 32],
}

impl Zeroize for SecretData {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for SecretData {
    fn drop(&mut self) {
        self.zeroize();
    }
}
