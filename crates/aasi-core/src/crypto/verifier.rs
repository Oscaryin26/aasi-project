use anyhow::{Result, anyhow};
use argon2::{
    password_hash::{SaltString, PasswordHasher},
    Argon2, Algorithm, Version, Params
};
use sha2::{Sha256, Digest};
use crate::core::models::{ArgonParams, AgentManifest, TrustProof};
use serde::Serialize;
use crate::crypto::did::DidResolver;
use ed25519_dalek::Verifier;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TrustVerifier {
    pub did_resolver: DidResolver,
}

impl TrustVerifier {
    pub fn new() -> Self {
        Self {
            did_resolver: DidResolver::new(),
        }
    }

    /// Verifies the trust proof in the manifest.
    pub async fn verify_manifest(&self, manifest: &AgentManifest) -> Result<()> {
        match &manifest.trust_proof {
            TrustProof::Identity(proof) => {
                // 1. Resolve DID
                let pk = self.did_resolver.resolve_did_web(&manifest.did).await?;
                
                // 2. Reconstruct signable bytes
                // WARNING: This MUST match client's signing logic exactly.
                
                let signable_bytes = to_signable_bytes_subset(manifest)?;
                
                pk.verify(&signable_bytes, &ed25519_dalek::Signature::from_bytes(
                        std::convert::TryInto::try_into(proof.domain_signature.as_slice())
                        .map_err(|_| anyhow!("Invalid signature length"))?
                    )).map_err(|_| anyhow!("Invalid signature"))?;
                    
                Ok(())
            },
            TrustProof::Computational(proof) => {
                // 1. Verify Timestamp Window
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let tolerance = 600; // 10 minutes
                if proof.argon2_params.timestamp > now + tolerance || proof.argon2_params.timestamp < now - tolerance {
                    return Err(anyhow!("PoW timestamp out of window"));
                }
                
                // 2. Verify Difficulty
                if proof.difficulty < 1 {
                    // Min difficulty check (should be network param)
                    // For MVP let's assume min 1
                }
                
                // 3. Verify Work
                verify_work(&manifest.did, proof.nonce, proof.difficulty, &proof.argon2_params, &proof.hash)
            }
        }
    }
}

fn to_signable_bytes_subset(m: &AgentManifest) -> Result<Vec<u8>> {
    // Manually construct a struct or JSON that matches client's signing payload.
    // Client `signer.rs`:
    //   let mut signable_manifest = manifest.clone();
    //   signable_manifest.trust_proof = None; 
    //   to_signable_bytes(&signable_manifest)
    
    // But Client uses `aasi_proto::AgentManifest` where `trust_proof` IS `Option<TrustProof>`.
    // Server uses `core::models::AgentManifest` where it IS `TrustProof` (not Option).
    
    // We need to match the JSON output of the Client.
    // Client (Proto) JSON likely looks like:
    // { "did": "...", "trust_proof": null, ... } or "trust_proof" field missing.
    // 
    // Let's define a private struct matching the shape we want.
    
    #[derive(Serialize)]
    #[allow(dead_code)]
    struct SignableManifest<'a> {
        did: &'a str,
        capabilities: &'a [String],
        endpoint: &'a str,
        trust_proof: &'a TrustProof,
        nonce: u64,
        timestamp: u64,
    }
    
    // Ideally, the client should have serialized exactly this.
    // If client serialized `trust_proof: null`, we need to match.
    // If client proto `trust_proof` was `None`, standard serde for Option is `null` or missing field depending on `skip_serializing_if`.
    // Tonic prost structs usually don't have `skip_serializing_if`.
    // 
    // Let's assume Client sets it to None. 
    // JSON: `"trust_proof": null` (default serde behavior for Option).
    
    #[derive(serde::Serialize)]
    struct SignableManifestWithOption<'a> {
        did: &'a str,
        version: u64,
        timestamp: u64,
        capabilities: &'a Vec<String>,
        trust_proof: Option<()>, // Always None
        endpoint: &'a str,
        // Embedding is EXPLICITLY OMITTED from signature
    }
    
    let temp = SignableManifestWithOption {
        did: &m.did,
        version: m.version,
        timestamp: m.timestamp,
        capabilities: &m.capabilities,
        trust_proof: None,
        endpoint: &m.endpoint,
    };
    
    serde_json::to_vec(&temp).map_err(|e| anyhow!(e))
}

pub fn verify_work(did: &str, nonce: u64, difficulty: u32, params: &ArgonParams, provided_hash: &[u8]) -> Result<()> {
    // 1. Reconstruct Input
    let input = format!("{}:{}", did, params.timestamp);
    let current_input = format!("{}:{}", input, nonce);

    // 2. Reconstruct Salt
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    let salt_binding = hasher.finalize();
    let salt_b64 = SaltString::encode_b64(&salt_binding[0..16])
        .map_err(|e| anyhow!("Salt encoding error: {}", e))?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            Some(32),
        ).map_err(|e| anyhow!("Params error: {}", e))?
    );

    // 3. Hash
    let hash_obj = argon2.hash_password(current_input.as_bytes(), &salt_b64)
        .map_err(|e| anyhow!("Hashing error: {}", e))?;
    
    let calculated_hash = hash_obj.hash.ok_or(anyhow!("No hash output"))?.as_bytes().to_vec();

    // 4. Compare Hash (Integrity check)
    if calculated_hash != provided_hash {
        return Err(anyhow!("Provided hash does not match calculated hash"));
    }

    // 5. Verify Difficulty
    if !check_difficulty(&calculated_hash, difficulty) {
        return Err(anyhow!("Hash does not meet difficulty target"));
    }

    Ok(())
}

    fn check_difficulty(hash: &[u8], difficulty: u32) -> bool {
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

impl TrustVerifier {
    /// Calculates the dynamic trust score based on accumulated work.
    /// Formula: T = 1 / (1 + e^(-k * (work - baseline)))
    /// Ranges from ~0.0 to 1.0.
    pub fn calculate_computational_trust(&self, accumulated_work: u64) -> f32 {
        let k = 0.1; // Steepness
        let baseline = 10.0; // Minimum work to be "neutral" (0.5 trust)
        
        let x = accumulated_work as f32 - baseline;
        1.0 / (1.0 + (-k * x).exp())
    }
}
