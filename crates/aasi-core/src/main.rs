use tonic::transport::Server;
use aasi_core::api::server::DiscoveryServiceImpl;
use aasi_core::storage::{transparency_log::TransparencyLog, vector_store::VectorStore};
use aasi_core::core::{stats::StatsStore, embedder::EmbeddingEngine, graph::GraphStore};
use aasi_core::crypto::verifier::TrustVerifier;
use aasi_proto::aasi::v1::discovery_service_server::DiscoveryServiceServer;
use std::sync::Arc;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    println!("Starting AASI Discovery Node on {}", addr);

    // Initialize Components
    let transparency_log = Arc::new(TransparencyLog::new("data/merkle_log")?);
    let vector_store = Arc::new(VectorStore::new("http://localhost:6334", "agents_v1").await?); // Ensure Qdrant runs
    let stats_store = Arc::new(StatsStore::new("data/stats_db")?);
    let graph_store = Arc::new(GraphStore::new("data/graph_db")?);
    let embedder = Arc::new(EmbeddingEngine::new()?);
    let trust_verifier = Arc::new(TrustVerifier::new());

    let service = DiscoveryServiceImpl::new(
        transparency_log,
        vector_store,
        stats_store,
        graph_store,
        embedder,
        trust_verifier,
    );

    Server::builder()
        .add_service(DiscoveryServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}