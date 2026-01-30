use anyhow::{Result, anyhow};
use fastembed::{TextEmbedding, InitOptions, EmbeddingModel};

pub struct EmbeddingEngine {
    model: TextEmbedding,
}

impl EmbeddingEngine {
    pub fn new() -> Result<Self> {
        let model = TextEmbedding::try_new(
            InitOptions::new(EmbeddingModel::AllMiniLML6V2)
                .with_show_download_progress(true)
        )?;
        Ok(Self { model })
    }

    pub fn generate_embedding(&self, inputs: Vec<String>) -> Result<Vec<f32>> {
        // Concatenate inputs to single string for context
        let text = inputs.join("\n");
        let embeddings = self.model.embed(vec![text], None)?;
        embeddings.into_iter().next().ok_or(anyhow!("Failed to generate embedding"))
    }
    
    pub fn generate_query_embedding(&self, text: &str) -> Result<Vec<f32>> {
        self.generate_embedding(vec![text.to_string()])
    }
}
