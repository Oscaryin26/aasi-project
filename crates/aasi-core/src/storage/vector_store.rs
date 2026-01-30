use anyhow::Result;
use qdrant_client::Qdrant;
use qdrant_client::qdrant::{
    vectors_config::Config, VectorParams, VectorsConfig, PointStruct, Filter, ScoredPoint, SearchPoints, CreateCollection, UpsertPoints,
    Distance,
};
use qdrant_client::client::Payload;
use crate::core::models::AgentManifest;

pub struct VectorStore {
    client: Qdrant,
    collection_name: String,
}

impl VectorStore {
    pub async fn new(url: &str, collection_name: &str) -> Result<Self> {
        let client = Qdrant::from_url(url).build()?;
        
        // Check if collection exists, create if not
        if !client.collection_exists(collection_name).await? {
            client.create_collection(CreateCollection {
                collection_name: collection_name.to_string(),
                vectors_config: Some(VectorsConfig {
                    config: Some(Config::Params(VectorParams {
                        size: 384, // Must match embedder
                        distance: Distance::Cosine.into(),
                        ..Default::default()
                    })),
                }),
                ..Default::default()
            })
            .await?;
        }

        Ok(Self {
            client,
            collection_name: collection_name.to_string(),
        })
    }

    pub async fn index_manifest(&self, manifest: &AgentManifest, embedding: Vec<f32>) -> Result<()> {
        let trust_mode = match manifest.trust_proof {
            crate::core::models::TrustProof::Computational(_) => "computational",
            crate::core::models::TrustProof::Identity(_) => "identity",
        };

        let payload = serde_json::json!({
            "did": manifest.did,
            "capabilities": manifest.capabilities.join("\n"),
            "endpoint": manifest.endpoint,
            "trust_mode": trust_mode,
        });
        
        let payload_map: Payload = payload.try_into()?;

        let points = vec![PointStruct::new(
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, manifest.did.as_bytes()).to_string(),
            embedding,
            payload_map,
        )];

        self.client.upsert_points(UpsertPoints {
            collection_name: self.collection_name.clone(),
            points: points,
            ..Default::default()
        }).await?;
        Ok(())
    }

    pub async fn search(&self, query_vector: Vec<f32>, limit: u64, filter: Option<Filter>) -> Result<Vec<ScoredPoint>> {
        let search_result = self.client.search_points(SearchPoints {
            collection_name: self.collection_name.clone(),
            vector: query_vector,
            filter,
            limit,
            with_payload: Some(true.into()),
            ..Default::default()
        }).await?;

        Ok(search_result.result)
    }

    pub async fn set_payload(&self, did: &str, key: &str, value: serde_json::Value) -> Result<()> {
        let point_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, did.as_bytes()).to_string();
        
        let payload_map: serde_json::Map<String, serde_json::Value> = 
            [(key.to_string(), value)].into_iter().collect();

        // Fix 7.1 & 7.2: Correct PointId and Payload types
        use qdrant_client::qdrant::{SetPayloadPointsBuilder, PointId, point_id::PointIdOptions};
        use qdrant_client::client::Payload;
        
        // 1. Construct PointId (UUID)
        let point_selector = PointId { 
            point_id_options: Some(PointIdOptions::Uuid(point_id)) 
        };
        
        // 2. Convert serde Map to Qdrant Payload
        let qdrant_payload: Payload = payload_map.try_into()?;

        let request = SetPayloadPointsBuilder::new(self.collection_name.clone(), qdrant_payload)
            .points_selector(vec![point_selector])
            .build();

        self.client.set_payload(request).await?;
        Ok(())
    }

    pub async fn set_payload_batch(&self, updates: Vec<(String, String, serde_json::Value)>) -> Result<()> {
        use qdrant_client::qdrant::{SetPayloadPointsBuilder, PointId, point_id::PointIdOptions};
        use qdrant_client::client::Payload;
        use futures::future::join_all;

        let mut futures = Vec::new();

        for (did, key, value) in updates {
            let point_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, did.as_bytes()).to_string();
            let payload_map: serde_json::Map<String, serde_json::Value> = 
                [(key, value)].into_iter().collect();
            
            let qdrant_payload: Payload = payload_map.try_into()?; // Note: handling error inside future might be tricky, unwrapping for now or handle better
            
            let point_selector = PointId { 
                point_id_options: Some(PointIdOptions::Uuid(point_id)) 
            };

            let request = SetPayloadPointsBuilder::new(self.collection_name.clone(), qdrant_payload)
                .points_selector(vec![point_selector])
                .build();
            
            // Clone client for async move
            let client = self.client.clone();
            futures.push(async move {
                client.set_payload(request).await
            });
        }

        // Run all updates concurrently
        join_all(futures).await;
        
        Ok(())
    }
}
