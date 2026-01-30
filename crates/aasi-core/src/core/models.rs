use serde::{Serialize, Deserialize};
use aasi_proto::aasi::v1 as proto;
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AgentManifest {
    pub did: String,
    pub version: u64,
    pub timestamp: u64,
    pub capabilities: Vec<String>,
    pub trust_proof: TrustProof,
    pub endpoint: String,
    pub embedding: Vec<f32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", content = "proof")]
pub enum TrustProof {
    Identity(IdentityProof),
    Computational(ComputationalProof),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityProof {
    pub domain_signature: Vec<u8>,
    pub verifiable_credentials: Vec<Credential>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ComputationalProof {
    pub argon2_params: ArgonParams,
    pub nonce: u64,
    pub hash: Vec<u8>,
    pub difficulty: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ArgonParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Credential {
    pub provider: String,
    pub id: String, // Username or ID
    pub proof: String,
}

impl AgentManifest {
    /// Computes the canonical SHA256 hash of the manifest for Merkle Tree inclusion.
    /// This includes the embedding, freezing the semantic vector.
    pub fn compute_hash(&self) -> Result<[u8; 32]> {
        let serialized = serde_json::to_vec(self)?;
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().into())
    }
}

// --- Conversions ---

impl TryFrom<proto::AgentManifest> for AgentManifest {
    type Error = anyhow::Error;

    fn try_from(p: proto::AgentManifest) -> Result<Self> {
        let trust_proof_proto = p.trust_proof.ok_or_else(|| anyhow!("Missing trust_proof"))?;
        
        let trust_proof = match trust_proof_proto.proof.ok_or_else(|| anyhow!("Missing proof oneof"))? {
            proto::trust_proof::Proof::Identity(i) => TrustProof::Identity(IdentityProof {
                domain_signature: i.domain_signature,
                verifiable_credentials: i.verifiable_credentials.into_iter().map(|c| Credential {
                    provider: c.provider,
                    id: c.id,
                    proof: c.proof,
                }).collect(),
            }),
            proto::trust_proof::Proof::Computational(c) => TrustProof::Computational(ComputationalProof {
                argon2_params: c.argon2_params.map(|ap| ArgonParams {
                    m_cost: ap.m_cost,
                    t_cost: ap.t_cost,
                    p_cost: ap.p_cost,
                    timestamp: ap.timestamp,
                }).ok_or_else(|| anyhow!("Missing ArgonParams"))?,
                nonce: c.nonce,
                hash: c.hash,
                difficulty: c.difficulty,
            }),
        };

        Ok(AgentManifest {
            did: p.did,
            version: p.version,
            timestamp: p.timestamp,
            capabilities: p.capabilities,
            trust_proof,
            endpoint: p.endpoint,
            embedding: p.embedding,
        })
    }
}

impl From<AgentManifest> for proto::AgentManifest {
    fn from(d: AgentManifest) -> Self {
        let (proof_enum, _) = match d.trust_proof {
            TrustProof::Identity(i) => (
                Some(proto::trust_proof::Proof::Identity(proto::IdentityProof {
                    domain_signature: i.domain_signature,
                    verifiable_credentials: i.verifiable_credentials.into_iter().map(|c| proto::Credential {
                        provider: c.provider,
                        id: c.id,
                        proof: c.proof,
                    }).collect(),
                })),
                ()
            ),
            TrustProof::Computational(c) => (
                Some(proto::trust_proof::Proof::Computational(proto::ComputationalProof {
                    argon2_params: Some(proto::ArgonParams {
                        m_cost: c.argon2_params.m_cost,
                        t_cost: c.argon2_params.t_cost,
                        p_cost: c.argon2_params.p_cost,
                        timestamp: c.argon2_params.timestamp,
                    }),
                    nonce: c.nonce,
                    hash: c.hash,
                    difficulty: c.difficulty,
                })),
                ()
            ),
        };

        proto::AgentManifest {
            did: d.did,
            version: d.version,
            timestamp: d.timestamp,
            capabilities: d.capabilities,
            trust_proof: Some(proto::TrustProof { proof: proof_enum }),
            endpoint: d.endpoint,
            embedding: d.embedding,
        }
    }
}
