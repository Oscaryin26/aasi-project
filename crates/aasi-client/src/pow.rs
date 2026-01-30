use argon2::{
    password_hash::{
        SaltString
    },
    Argon2, Algorithm, Version, Params, PasswordHasher
};
use sha2::{Sha256, Digest};
use aasi_proto::aasi::v1::ArgonParams;

pub fn generate_work(did: &str, difficulty: u32, timestamp: u64, params: &ArgonParams) -> Result<(u64, Vec<u8>), String> {
    // 1. Construct input "password" = did + timestamp
    let input = format!("{}:{}", did, timestamp);

    // 2. Construct Salt
    // Use SHA256(did) as salt source.
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    let salt_binding = hasher.finalize();
    // Argon2 expects a SaltString (base64) or similar valid salt.
    // We encode the first 16 bytes of the hash as B64 salt.
    let salt_b64 = SaltString::encode_b64(&salt_binding[0..16])
        .map_err(|e| e.to_string())?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            Some(32), // Output length
        ).map_err(|e| e.to_string())?
    );

    // 3. Loop for Nonce
    
    // Simplistic solver loop
    let mut nonce: u64 = 0;
    loop {
        // Input: "did:timestamp:nonce"
        let current_input = format!("{}:{}", input, nonce);
        
        let hash = argon2.hash_password(current_input.as_bytes(), &salt_b64)
            .map_err(|e| e.to_string())?;
        
        // hash.hash is Output (Option<Output>)
        let hash_bytes = hash.hash.ok_or("No hash output")?.as_bytes().to_vec();

        if check_difficulty(&hash_bytes, difficulty) {
            return Ok((nonce, hash_bytes));
        }

        nonce += 1;
        // In a real implementation, we might want to allow aborting or have a max nonce.
        // For MVP, if difficulty is reasonable, it should return quickly. 
        // If difficulty is too high, it might hang.
        // We assume test difficulty is low.
    }
}

pub fn check_difficulty(hash: &[u8], difficulty: u32) -> bool {
    // difficulty = number of leading zero bits.
    let mut zeros = 0;
    for &byte in hash {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    
    zeros >= difficulty
}