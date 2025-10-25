// src/network/cells.rs

use x25519_dalek::PublicKey;

pub const CELL_COMMAND_PADDING: u8 = 0;
pub const CELL_COMMAND_CREATE: u8 = 1;
pub const CELL_COMMAND_CREATED: u8 = 2;
pub const CELL_COMMAND_RELAY: u8 = 3;
pub const CELL_COMMAND_DESTROY: u8 = 4;
pub const CELL_COMMAND_CREATE_FAST: u8 = 5;
pub const CELL_COMMAND_CREATED_FAST: u8 = 6;
pub const CELL_COMMAND_VERSIONS: u8 = 7;
pub const CELL_COMMAND_NETINFO: u8 = 8;
pub const CELL_COMMAND_RELAY_EARLY: u8 = 9;
pub const CELL_COMMAND_CREATE2: u8 = 10;
pub const CELL_COMMAND_CREATED2: u8 = 11;

pub const CELL_LEN: usize = 514;

#[derive(Debug, Clone)]
pub struct Cell {
    pub circ_id: u32,
    pub command: u8,
    pub payload: Vec<u8>,
}

impl Cell {
    /// Serialize cell to bytes
    pub fn to_bytes(&self, link_version: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Circuit ID (4 bytes for link protocol 4+, 2 bytes for older)
        if link_version >= 4 {
            bytes.extend_from_slice(&self.circ_id.to_be_bytes());
        } else {
            bytes.extend_from_slice(&(self.circ_id as u16).to_be_bytes());
        }
        
        // Command
        bytes.push(self.command);
        
        // Payload
        bytes.extend_from_slice(&self.payload);
        
        // Variable-length cells (VERSIONS=7, VPADDING=128, CERTS=129, etc.)
        if self.command == CELL_COMMAND_VERSIONS || self.command >= 128 {
            // Variable-length: no padding needed, length is in payload
            bytes
        } else {
            // Fixed-length: pad to CELL_LEN
            bytes.resize(CELL_LEN, 0);
            bytes
        }
    }
    
    /// Serialize VERSIONS cell (special case - sent before version negotiation)
    pub fn versions_to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // VERSIONS cells ALWAYS use 2-byte circuit ID (pre-negotiation)
        bytes.extend_from_slice(&(self.circ_id as u16).to_be_bytes());
        
        // Command
        bytes.push(self.command);
        
        // Payload length (2 bytes) - for variable-length cells
        bytes.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        
        // Payload
        bytes.extend_from_slice(&self.payload);
        
        bytes
    }
    
    pub fn from_bytes(bytes: &[u8], link_version: u16) -> Result<Self, String> {
        let header_len = if link_version >= 4 { 4 } else { 2 };
        if bytes.len() < header_len + 1 {
            return Err("Cell header too short".to_string());
        }
        
        let (circ_id, offset) = if link_version >= 4 {
            (u32::from_be_bytes(bytes[0..4].try_into().unwrap()), 4)
        } else {
            (u16::from_be_bytes(bytes[0..2].try_into().unwrap()) as u32, 2)
        };
        
        let command = bytes[offset];
        
        if command == CELL_COMMAND_VERSIONS || command >= 128 {
            if bytes.len() < offset + 3 {
                return Err("Variable-length cell header too short".to_string());
            }
            let payload_len = u16::from_be_bytes(bytes[offset + 1..offset + 3].try_into().unwrap()) as usize;
            let expected_len = offset + 3 + payload_len;
            if bytes.len() < expected_len {
                return Err(format!("Variable-length cell payload too short: expected {}, got {}", payload_len, bytes.len() - (offset + 3)));
            }
            let payload = bytes[offset + 3..expected_len].to_vec();
            Ok(Cell {
                circ_id,
                command,
                payload,
            })
        } else {
            let expected_len = offset + 1 + 509;
            if bytes.len() < expected_len {
                return Err(format!("Fixed-length cell too short: expected {}, got {}", expected_len, bytes.len()));
            }
            let payload = bytes[offset + 1..expected_len].to_vec();
            Ok(Cell {
                circ_id,
                command,
                payload,
            })
        }
    }
    
    pub fn is_variable_length(&self) -> bool {
        self.command == CELL_COMMAND_VERSIONS || self.command >= 128
    }
    
    /// Parse VERSIONS cell (special case)
    pub fn versions_from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 5 {
            return Err(format!("VERSIONS cell too short: {} bytes", bytes.len()));
        }
        
        // VERSIONS always uses 2-byte circuit ID
        let circ_id = u16::from_be_bytes(bytes[0..2].try_into().unwrap()) as u32;
        let command = bytes[2];
        
        if command != CELL_COMMAND_VERSIONS {
            return Err(format!("Not a VERSIONS cell: command {}", command));
        }
        
        // Payload length
        let payload_len = u16::from_be_bytes(bytes[3..5].try_into().unwrap()) as usize;
        
        if bytes.len() < 5 + payload_len {
            return Err(format!("VERSIONS payload too short: expected {}, got {}", payload_len, bytes.len() - 5));
        }
        
        let payload = bytes[5..5 + payload_len].to_vec();
        
        Ok(Cell {
            circ_id,
            command,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Create2Cell {
    pub handshake_type: u16,
    pub handshake_data: Vec<u8>,
}

impl Create2Cell {
    /// Create a new CREATE2 cell with proper NTor handshake data
    pub fn new(
        client_public_key: &PublicKey,
        relay_identity: &[u8],
        relay_onion_key: &[u8]
    ) -> Result<Self, String> {
        if relay_identity.len() != 20 {
            return Err(format!("Relay identity must be 20 bytes, got {}", relay_identity.len()));
        }
        if relay_onion_key.len() != 32 {
            return Err(format!("Relay onion key must be 32 bytes, got {}", relay_onion_key.len()));
        }
        
        let mut handshake_data = Vec::with_capacity(32);
        handshake_data.extend_from_slice(client_public_key.as_bytes());
        
        Ok(Self {
            handshake_type: 2, // ntor
            handshake_data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.handshake_data.len());
        bytes.extend_from_slice(&self.handshake_type.to_be_bytes());
        bytes.extend_from_slice(&(self.handshake_data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.handshake_data);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct Created2Cell {
    pub server_public_key: PublicKey,
    pub auth: Vec<u8>,
}

impl Created2Cell {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, String> {
        if payload.len() < 2 {
            return Err("Payload too short for CREATED2 hlen".to_string());
        }
        
        let hlen = u16::from_be_bytes(payload[0..2].try_into().unwrap()) as usize;
        
        if hlen != 64 {
            log::warn!("Unexpected HLEN in CREATED2 cell: expected 64, got {}", hlen);
        }

        let expected_payload_len = 2 + hlen;
        if payload.len() < expected_payload_len {
            return Err(format!("Payload too short for CREATED2 data: expected at least {}, got {}", expected_payload_len, payload.len()));
        }

        let hdata = &payload[2..expected_payload_len];
        
        if hdata.len() < 64 {
            return Err(format!("Handshake data too short: expected 64, got {}", hdata.len()));
        }

        let server_pk_bytes: [u8; 32] = hdata[0..32].try_into()
            .map_err(|_| "Failed to parse server public key from CREATED2")?;
        let server_public_key = PublicKey::from(server_pk_bytes);
        
        let auth = hdata[32..64].to_vec();

        Ok(Self {
            server_public_key,
            auth,
        })
    }
} // <-- This closing brace was missing!

#[derive(Debug, Clone)]
pub struct VersionsCell {
    pub versions: Vec<u16>,
}

impl VersionsCell {
    pub fn new(versions: Vec<u16>) -> Self {
        Self { versions }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &v in &self.versions {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut versions = Vec::new();
        for chunk in bytes.chunks(2) {
            if chunk.len() != 2 {
                break;
            }
            let v = u16::from_be_bytes(chunk.try_into().unwrap());
            if v == 0 {
                break;
            }
            versions.push(v);
        }
        Ok(Self { versions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::EphemeralSecret;
    use rand_core::OsRng;

    #[test]
    fn test_versions_cell_format() {
        let versions_cell = Cell {
            circ_id: 0,
            command: CELL_COMMAND_VERSIONS,
            payload: VersionsCell::new(vec![3, 4, 5]).to_bytes(),
        };
        
        let bytes = versions_cell.versions_to_bytes();
        
        // Should be: 2 (circ_id) + 1 (cmd) + 2 (len) + 6 (3 versions * 2 bytes) = 11 bytes
        assert_eq!(bytes.len(), 11);
        
        // Circuit ID should be 0
        assert_eq!(u16::from_be_bytes(bytes[0..2].try_into().unwrap()), 0);
        
        // Command should be 7
        assert_eq!(bytes[2], CELL_COMMAND_VERSIONS);
        
        // Payload length should be 6
        assert_eq!(u16::from_be_bytes(bytes[3..5].try_into().unwrap()), 6);
        
        // Versions should be 3, 4, 5
        assert_eq!(u16::from_be_bytes(bytes[5..7].try_into().unwrap()), 3);
        assert_eq!(u16::from_be_bytes(bytes[7..9].try_into().unwrap()), 4);
        assert_eq!(u16::from_be_bytes(bytes[9..11].try_into().unwrap()), 5);
    }

    #[test]
    fn test_create2_cell_to_bytes() {
        let client_private_key = EphemeralSecret::random_from_rng(OsRng);
        let client_public_key = PublicKey::from(&client_private_key);
        
        let relay_identity = [1u8; 20];
        let relay_onion_key = [2u8; 32];

        let create2_cell = Create2Cell::new(&client_public_key, &relay_identity, &relay_onion_key).unwrap();
        let bytes = create2_cell.to_bytes();

        // Should be: 2 (type) + 2 (len) + 84 (data) = 88 bytes
        assert_eq!(bytes.len(), 88);

        let handshake_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        assert_eq!(handshake_type, 2);

        let hlen = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        assert_eq!(hlen, 84);

        let hdata = &bytes[4..];
        assert_eq!(hdata.len(), 84);
        assert_eq!(&hdata[0..32], client_public_key.as_bytes());
        assert_eq!(&hdata[32..52], &relay_identity);
        assert_eq!(&hdata[52..84], &relay_onion_key);
    }

    #[test]
    fn test_created2_cell_from_bytes() {
        let server_private_key = EphemeralSecret::random_from_rng(OsRng);
        let server_public_key = PublicKey::from(&server_private_key);
        let auth = [3u8; 32];

        let mut hdata = Vec::new();
        hdata.extend_from_slice(server_public_key.as_bytes());
        hdata.extend_from_slice(&auth);

        let mut payload = Vec::new();
        payload.extend_from_slice(&(hdata.len() as u16).to_be_bytes());
        payload.extend_from_slice(&hdata);

        let result = Created2Cell::from_bytes(&payload);
        assert!(result.is_ok());

        let created2_cell = result.unwrap();
        assert_eq!(created2_cell.server_public_key.as_bytes(), server_public_key.as_bytes());
        assert_eq!(created2_cell.auth, auth.to_vec());
    }
}