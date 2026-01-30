use ed25519_dalek::{Signer, SigningKey, Signature};
use aasi_proto::aasi::v1::{AgentManifest, FeedbackRequest};
use serde::Serialize;
use sha2::{Sha256, Digest};

// Helper to canonicalize for signing
fn to_signable_bytes<T: Serialize>(data: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(data).map_err(|e| e.to_string())
}

pub fn sign_manifest(signing_key: &SigningKey, manifest: &AgentManifest) -> Result<Vec<u8>, String> {
    // We sign the manifest fields EXCEPT the trust_proof itself (which contains the signature).
    // So we need a subset or we assume manifest.trust_proof is empty/default when signing.
    // Or, more robustly, sign a specific payload structure.
    // For MVP, let's sign the `compute_hash` equivalent from aasi-core, i.e., serialized manifest with trust_proof=None/Empty.
    
    // We must match the Server's `SignableManifestWithOption` structure EXACTLY.
    // Server expects: { did, version, timestamp, capabilities, trust_proof: null, endpoint }
    // Embedding is excluded.
    
    #[derive(Serialize)]
    struct SignableManifest<'a> {
        did: &'a str,
        version: u64,
        timestamp: u64,
        capabilities: &'a Vec<String>,
        trust_proof: Option<()>,
        endpoint: &'a str,
    }

    let signable = SignableManifest {
        did: &manifest.did,
        version: manifest.version,
        timestamp: manifest.timestamp,
        capabilities: &manifest.capabilities,
        trust_proof: None,
        endpoint: &manifest.endpoint,
    };

    let bytes = to_signable_bytes(&signable)?;
    let signature: Signature = signing_key.sign(&bytes);
    Ok(signature.to_vec())
}

pub fn sign_feedback(signing_key: &SigningKey, feedback: &mut FeedbackRequest) -> Result<(), String> {
    // reporter_did + target_did + success + timestamp + nonce
    let mut hasher = Sha256::new();
    hasher.update(feedback.reporter_did.as_bytes());
    hasher.update(feedback.target_did.as_bytes());
    hasher.update(if feedback.success { b"1" } else { b"0" });
    hasher.update(&feedback.timestamp.to_be_bytes());
    hasher.update(&feedback.nonce.to_be_bytes());
    
    let digest = hasher.finalize();
    let signature: Signature = signing_key.sign(&digest);
    
    feedback.signature = signature.to_vec();
    Ok(())
}
