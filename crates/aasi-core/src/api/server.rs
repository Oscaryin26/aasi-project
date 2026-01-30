use tonic::{Request, Response, Status};
use std::sync::Arc;
use anyhow::Result;
use crate::core::models::{AgentManifest};
use crate::core::embedder::EmbeddingEngine;
use crate::core::stats::StatsStore;
use crate::core::ranker::AgentRanker;
use crate::core::graph::GraphStore;
use crate::storage::transparency_log::TransparencyLog;
use crate::storage::vector_store::VectorStore;
use crate::crypto::verifier::TrustVerifier;
use aasi_proto::aasi::v1 as proto;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::social::SocialVerifier;

#[derive(Debug, Default)]
struct RankRecomputeState {
    last_recompute: Option<Instant>,
    in_progress: bool,
}

pub struct DiscoveryServiceImpl {
    transparency_log: Arc<TransparencyLog>,
    vector_store: Arc<VectorStore>,
    stats_store: Arc<StatsStore>,
    graph_store: Arc<GraphStore>,
    embedder: Arc<EmbeddingEngine>,
    trust_verifier: Arc<TrustVerifier>,
    social_verifier: Arc<SocialVerifier>,
    ranker: AgentRanker,
    rank_recompute_interval: Duration,
    rank_recompute_state: Arc<std::sync::Mutex<RankRecomputeState>>,
    search_oversampling: u64,
}

impl DiscoveryServiceImpl {
    pub fn new(
        transparency_log: Arc<TransparencyLog>,
        vector_store: Arc<VectorStore>,
        stats_store: Arc<StatsStore>,
        graph_store: Arc<GraphStore>,
        embedder: Arc<EmbeddingEngine>,
        trust_verifier: Arc<TrustVerifier>,
    ) -> Self {
        let alpha = std::env::var("AASI_RANK_ALPHA").ok().and_then(|s| s.parse().ok()).unwrap_or(0.5);
        let beta = std::env::var("AASI_RANK_BETA").ok().and_then(|s| s.parse().ok()).unwrap_or(0.3);
        let gamma = std::env::var("AASI_RANK_GAMMA").ok().and_then(|s| s.parse().ok()).unwrap_or(0.2);
        
        let ranker = AgentRanker::new(
            stats_store.clone(), 
            graph_store.clone(), 
            vector_store.clone(),
            alpha,
            beta,
            gamma
        );

        let social_verifier = Arc::new(SocialVerifier::new());
        let rank_recompute_interval = std::env::var("AASI_RANK_RECOMPUTE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(10));
            
        let search_oversampling = std::env::var("AASI_SEARCH_OVERSAMPLING")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);

        Self {
            transparency_log,
            vector_store,
            stats_store,
            graph_store,
            embedder,
            trust_verifier,
            social_verifier,
            ranker,
            rank_recompute_interval,
            rank_recompute_state: Arc::new(std::sync::Mutex::new(RankRecomputeState::default())),
            search_oversampling,
        }
    }

    async fn maybe_recompute_rank(&self) -> Result<(), Status> {
        if self.rank_recompute_interval == Duration::from_secs(0) {
            self.ranker
                .compute_global_rank()
                .map_err(|e| Status::internal(format!("Ranking computation failed: {}", e)))?;
            return Ok(());
        }

        let should_run = {
            let mut state = self.rank_recompute_state.lock().unwrap();
            let now = Instant::now();
            let elapsed_ok = match state.last_recompute {
                Some(t) => now.duration_since(t) >= self.rank_recompute_interval,
                None => true,
            };

            if state.in_progress || !elapsed_ok {
                false
            } else {
                state.in_progress = true;
                true
            }
        };

        if !should_run {
            return Ok(());
        }

        let ranker = self.ranker.clone();
        let result = tokio::task::spawn_blocking(move || ranker.compute_global_rank())
            .await
            .map_err(|e| Status::internal(format!("Ranking task join failed: {}", e)))?;

        {
            let mut state = self.rank_recompute_state.lock().unwrap();
            state.in_progress = false;
            state.last_recompute = Some(Instant::now());
        }

        result.map_err(|e| Status::internal(format!("Ranking computation failed: {}", e)))?;
        Ok(())
    }
}

#[tonic::async_trait]
impl proto::discovery_service_server::DiscoveryService for DiscoveryServiceImpl {
    
    async fn register_agent(&self, request: Request<proto::RegisterRequest>) -> Result<Response<proto::RegisterResponse>, Status> {
        let req = request.into_inner();
        let manifest_proto = req.manifest.ok_or(Status::invalid_argument("Missing manifest"))?;
        
        // 1. Convert to internal model
        let mut manifest: AgentManifest = manifest_proto.try_into()
            .map_err(|e| Status::invalid_argument(format!("Invalid manifest format: {}", e)))?;

        // 2. Verify Trust Proof (PoW or Signature)
        self.trust_verifier.verify_manifest(&manifest).await
            .map_err(|e| Status::unauthenticated(format!("Trust verification failed: {}", e)))?;

        // 2.1 Verify Social Proofs (Identity Depth)
        if let crate::core::models::TrustProof::Identity(id_proof) = &manifest.trust_proof {
            for cred in &id_proof.verifiable_credentials {
                let valid = self.social_verifier.verify_credential(cred, &manifest.did).await
                    .map_err(|e| Status::unauthenticated(format!("Social verification error: {}", e)))?;
                
                if !valid {
                    return Err(Status::unauthenticated(format!("Social proof failed for {}", cred.provider)));
                }
            }
        }

        // 2.5 Record Accumulated Work (Stateful Trust)
        if let crate::core::models::TrustProof::Computational(c) = &manifest.trust_proof {
            self.stats_store.record_pow(&manifest.did, c.difficulty, c.argon2_params.timestamp)
                .map_err(|e| Status::internal(format!("Failed to record PoW stats: {}", e)))?;
        }

        // 3. Generate Embedding (Server-side)
        // Concatenate capabilities for semantic representation
        let embedding_vec = self.embedder.generate_embedding(manifest.capabilities.clone())
            .map_err(|e| Status::internal(format!("Embedding generation failed: {}", e)))?;

        // 4. Inject Embedding into Manifest & Compute Integrity Hash
        // CRITICAL FIX: The embedding must be part of the manifest BEFORE hashing.
        // This anchors the semantic vector in the Merkle Log.
        manifest.embedding = embedding_vec.clone();
        
        let manifest_hash = manifest.compute_hash()
            .map_err(|e| Status::internal(format!("Hash computation failed: {}", e)))?;

        // 5. Append to Transparency Log
        let root = self.transparency_log.append(manifest_hash)
            .map_err(|e| Status::internal(format!("Log append failed: {}", e)))?;

        // 6. Index in Vector Store
        // We pass the manifest (which now contains the embedding) and the embedding vector
        self.vector_store.index_manifest(&manifest, embedding_vec).await
            .map_err(|e| Status::internal(format!("Vector indexing failed: {}", e)))?;

        Ok(Response::new(proto::RegisterResponse {
            success: true,
            registration_id: manifest.did,
            merkle_root_hex: hex::encode(root),
            // log_index: index as u64, // Removed as not in proto or returned
            message: "Agent registered successfully".to_string(),
        }))
    }

    async fn search_agents(&self, request: Request<proto::SearchRequest>) -> Result<Response<proto::SearchResponse>, Status> {
        let req = request.into_inner();
        
        // 1. Generate Query Embedding
        let query_vector = self.embedder.generate_query_embedding(&req.query_text)
            .map_err(|e| Status::internal(format!("Query embedding failed: {}", e)))?;

        // 2. Build Filters
        // Currently just empty filter or basic
        // If min_trust_score provided, we assume we stored it in payload. 
        // For MVP, maybe skip complex filtering or rely on post-filtering.
        // Let's do simple Qdrant filtering if possible.
        // Since we didn't strictly store trust_score in payload in Phase 3, let's skip trust filter inside Qdrant for now.
        let filter = None;

        // 3. Search Qdrant (Stage 1: Retrieval with Oversampling)
        // We fetch X times the requested limit to allow the Re-ranking stage (Stage 2)
        // to promote high-Trust/high-Performance agents that might be semantically ranked 
        // outside the initial top-K (e.g. 11th-100th).
        let candidate_limit = req.limit.saturating_mul(self.search_oversampling);
        
        let scored_points = self.vector_store.search(query_vector, candidate_limit, filter).await
            .map_err(|e| Status::internal(format!("Search failed: {}", e)))?;

        // 4. Re-rank & Assemble Response (Stage 2: Re-ranking)
        let mut results = Vec::new();
        for point in scored_points {
            let payload = point.payload;
            
            // Extract fields from payload
            let did_val = payload.get("did").map(|v| v.to_string().trim_matches('"').to_string()).unwrap_or_default();
            let endpoint_val = payload.get("endpoint").map(|v| v.to_string().trim_matches('"').to_string()).unwrap_or_default();
            let caps_val = payload.get("capabilities").map(|v| v.to_string().trim_matches('"').to_string()).unwrap_or_default();
            
            // Calculate AgentRank
            // S = point.score (Cosine Similarity)
            // T = Sigmoid(AccumulatedWork) for Computational, 1.0 for Identity
            
            let s = point.score;
            let stats = self.stats_store.get_stats(&did_val).unwrap_or_default();
            
            // Extract trust_mode from payload to determine Trust Score (T)
            let trust_mode = payload.get("trust_mode")
                .map(|v| v.to_string().trim_matches('"').to_string())
                .unwrap_or_default();

            let t = match trust_mode.as_str() {
                "identity" => 1.0,
                "computational" => {
                    if stats.accumulated_work > 0 {
                        self.trust_verifier.calculate_computational_trust(stats.accumulated_work)
                    } else {
                        0.0 // New Computational Agent starts with 0 trust
                    }
                },
                _ => 0.0, // Unknown or Legacy agents treated as untrusted
            };
            
            // Final Score = (Alpha * S) + (Beta * T) + (Gamma * P)
            // Weights are defined in ranker implementation (0.5, 0.3, 0.2)
            let rank_score = self.ranker.calculate_rank(&did_val, s, t)
                .map_err(|e| Status::internal(format!("Ranking failed: {}", e)))?;
            
            if rank_score < 0.0 { continue; } 

            results.push(proto::ScoredAgent {
                manifest: Some(proto::AgentManifest {
                    did: did_val.clone(),
                    endpoint: endpoint_val,
                    capabilities: vec![caps_val], 
                    ..Default::default()
                }),
                score: rank_score,
                rank_similarity: s,
                rank_trust: t,
                // Fix 8.3: Return Normalized Score for Visibility
                rank_performance: self.ranker.get_normalized_performance(&did_val).unwrap_or(0.0),
            });
        }
        
        // Sort by final rank desc
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        // Stage 3: Truncation to original requested limit
        let final_results: Vec<_> = results.into_iter().take(req.limit as usize).collect();

        Ok(Response::new(proto::SearchResponse {
            results: final_results,
        }))
    }

    async fn verify_inclusion(&self, request: Request<proto::VerifyRequest>) -> Result<Response<proto::VerifyResponse>, Status> {
        let req = request.into_inner();
        
        let index = match req.target {
            Some(proto::verify_request::Target::Index(i)) => i as usize,
            // Resolving DID to Index would require a DID->Index map. 
            // We only have Index->Hash in MerkleLog.
            // MVP: Support Index only.
            _ => return Err(Status::unimplemented("Only Index verification supported for MVP")),
        };

        let proof = self.transparency_log.prove(index)
            .map_err(|e| Status::not_found(format!("Proof generation failed: {}", e)))?;
            
        let root = self.transparency_log.root().unwrap_or([0u8; 32]);

        Ok(Response::new(proto::VerifyResponse {
            included: true, // If proof generated, it is included
            proof_hashes: proof.proof_hashes().iter().map(|h| h.to_vec()).collect(),
            merkle_root_hex: hex::encode(root),
        }))
    }

    async fn submit_feedback(&self, request: Request<proto::FeedbackRequest>) -> Result<Response<proto::FeedbackResponse>, Status> {
        let req = request.into_inner();
        
        // 1. Verify Timestamp Window (Replay Attack prevention part 1)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if req.timestamp > now + 300 || req.timestamp < now - 300 {
             return Err(Status::invalid_argument("Timestamp out of window"));
        }
        
        // 2. Verify Signature
        // We need Reporter's Public Key.
        // Resolve reporter_did.
        let pk = self.trust_verifier.did_resolver.resolve_did_web(&req.reporter_did).await
             .map_err(|e| Status::unauthenticated(format!("Could not resolve reporter DID: {}", e)))?;
             
        // Reconstruct signature payload
        // reporter_did + target_did + success + timestamp + nonce
        // (Logic matching client signer.rs)
        use sha2::{Sha256, Digest};
        use ed25519_dalek::Verifier;
        
        let mut hasher = Sha256::new();
        hasher.update(req.reporter_did.as_bytes());
        hasher.update(req.target_did.as_bytes());
        hasher.update(if req.success { b"1" } else { b"0" });
        hasher.update(&req.timestamp.to_be_bytes());
        hasher.update(&req.nonce.to_be_bytes());
        let digest = hasher.finalize();
        
        let sig_bytes = req.signature.clone(); // make verify happy
        pk.verify(&digest, &ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| Status::invalid_argument("Bad sig len"))?))
            .map_err(|_| Status::permission_denied("Invalid feedback signature"))?;

        // 3. Update Interaction Graph
        self.graph_store.record_interaction(&req.reporter_did, &req.target_did, req.success)
            .map_err(|e| Status::internal(format!("Graph update failed: {}", e)))?;
            
        // 4. Trigger Re-ranking (throttled)
        // Default: recompute at most once every 10s (see `AASI_RANK_RECOMPUTE_INTERVAL_SECS`).
        self.maybe_recompute_rank().await?;

        Ok(Response::new(proto::FeedbackResponse {
            success: true,
            message: "Feedback accepted".to_string(),
        }))
    }

    async fn get_network_params(&self, _request: Request<proto::ParamsRequest>) -> Result<Response<proto::ParamsResponse>, Status> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Ok(Response::new(proto::ParamsResponse {
            difficulty: 1, // Fixed for MVP
            server_timestamp: now,
            current_argon_params: Some(proto::ArgonParams {
                m_cost: 19456, // Default argon2
                t_cost: 2,
                p_cost: 1,
                timestamp: now, // Server time for PoW window
            }),
        }))
    }

    async fn debug_recompute_rank(&self, _request: Request<proto::DebugRecomputeRankRequest>) -> Result<Response<proto::DebugRecomputeRankResponse>, Status> {
        // Bypass throttling and force recompute
        // We use spawn_blocking to avoid blocking the async runtime
        let ranker = self.ranker.clone();
        let result = tokio::task::spawn_blocking(move || ranker.compute_global_rank())
            .await
            .map_err(|e| Status::internal(format!("Ranking task join failed: {}", e)))?;

        match result {
            Ok(_) => Ok(Response::new(proto::DebugRecomputeRankResponse {
                success: true,
                message: "Global rank recomputed successfully".to_string(),
            })),
            Err(e) => Err(Status::internal(format!("Ranking computation failed: {}", e))),
        }
    }
}
