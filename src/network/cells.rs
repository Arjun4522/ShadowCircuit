// src/network/cells.rs

use x25519_dalek::PublicKey;

pub const CELL_COMMAND_CREATE2: u8 = 10;
pub const CELL_COMMAND_CREATED2: u8 = 11;
pub const CELL_COMMAND_RELAY: u8 = 3;

#[derive(Debug, Clone)]
pub struct Cell {
    pub circ_id: u32,
    pub command: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Create2Cell {
    pub handshake_type: u16,
    pub handshake_data: Vec<u8>,
}

impl Create2Cell {
    pub fn new(client_public_key: &PublicKey) -> Self {
        let handshake_data = client_public_key.as_bytes().to_vec();

        Self {
            handshake_type: 2, // ntor
            handshake_data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + 2 + self.handshake_data.len());
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
    pub fn from_bytes(payload: &[u8]) -> Result<Self, &'static str> {
        if payload.len() < 2 {
            return Err("Payload too short for CREATED2 cell");
        }
        let hlen = u16::from_be_bytes(payload[0..2].try_into().unwrap());
        if hlen != 64 {
            return Err("Invalid HLEN for CREATED2 cell");
        }
        if payload.len() < 2 + 64 {
            return Err("Payload too short for CREATED2 cell");
        }

        let hdata = &payload[2..];
        let server_pk_bytes: [u8; 32] = hdata[0..32].try_into().unwrap();
        let server_public_key = PublicKey::from(server_pk_bytes);
        let auth = hdata[32..64].to_vec();

        Ok(Self {
            server_public_key,
            auth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::EphemeralSecret;
    use rand_core::OsRng;

    #[test]
    fn test_create2_cell_to_bytes() {
        let client_private_key = EphemeralSecret::random_from_rng(OsRng);
        let client_public_key = PublicKey::from(&client_private_key);

        let create2_cell = Create2Cell::new(&client_public_key);
        let bytes = create2_cell.to_bytes();

        assert_eq!(bytes.len(), 2 + 2 + 32);

        let handshake_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        assert_eq!(handshake_type, 2);

        let hlen = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        assert_eq!(hlen, 32);

        let hdata = &bytes[4..];
        assert_eq!(hdata, client_public_key.as_bytes());
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
