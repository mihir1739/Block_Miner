use sha2::{Digest, Sha256};
use ripemd160::Ripemd160;
use std::time::{SystemTime, UNIX_EPOCH};
/// Prints a hex string from byte array
///
/// # Arguments
///
/// * `bytes`: byte array of the string
///
/// # Returns
///
/// nothing.
pub fn print_hex_string(bytes: &[u8]) {
    let hex_string = bytes
        .iter()
        .map(|&b| format!("{:02x}", b))
        .collect::<String>();
    println!("{}", hex_string);
}


/// Computes Hash160 of a bytes array
///
/// # Arguments
///
/// * `data`: byte array
///
/// # Returns
///
/// Thw hash160 of the byte array`data` [u8; 20].
/// 
pub fn compute_hash160(data: &[u8]) -> [u8; 20] {
    let mut sha256 = Sha256::new();
    sha256.update(data);
    let sha256_result = sha256.finalize();

    // Compute the RIPEMD-160 hash of the SHA-256 hash
    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(&sha256_result);
    let ripemd160_result = ripemd160.finalize();

    // Return the hash160 result as a fixed-size array
    let mut hash160 = [0; 20];
    hash160.copy_from_slice(&ripemd160_result[..]);
    hash160
}

/// Computes Hash256 of a bytes array
///
/// # Arguments
///
/// * `data`: byte array
///
/// # Returns
///
/// Thw hash256 of the byte array`data` [u8; 20].
/// 
pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(&first_hash);
    hasher2.finalize().to_vec()
  }

/// Computes Unix Time Stamp at the given time 
///
/// # Arguments
///
/// No arguements
///
/// # Returns
///
/// unix timestamp as `u32`.
/// 


pub  fn get_current_unix_timestamp_u32() -> u32 {
    let now = SystemTime::now();
    let timestamp: u32 = now.duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as u32;
    timestamp
}

pub fn sha256_double_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(&first_hash);
    hasher.finalize().to_vec()
}

pub fn ripemd160_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}