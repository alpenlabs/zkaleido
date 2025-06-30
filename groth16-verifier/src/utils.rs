use crate::error::Error;

// Helper functions for hex conversion
pub(super) fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub(super) fn hex_to_bytes(hex_str: &str) -> Result<[u8; 32], Error> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|_| Error::InvalidData)?;
    if bytes.len() != 32 {
        return Err(Error::InvalidXLength);
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}
