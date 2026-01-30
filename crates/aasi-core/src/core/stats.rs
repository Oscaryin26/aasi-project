use anyhow::Result;
use sled::Db;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AgentStats {
    pub total_interactions: u64,
    pub successful_interactions: u64,
    
    // Sybil Resistance State
    pub accumulated_work: u64,
    pub last_pow_timestamp: u64,
    
    // Rank Vectors (Updated by background ranker)
    pub usage_score: f32,      
    pub competence_score: f32, 
}

pub struct StatsStore {
    db: Db,
}

impl StatsStore {
    pub fn new(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn get_stats(&self, did: &str) -> Result<AgentStats> {
        match self.db.get(did)? {
            Some(ivec) => {
                let stats: AgentStats = bincode::deserialize(&ivec)?;
                Ok(stats)
            }
            None => Ok(AgentStats::default()),
        }
    }

    pub fn count(&self) -> Result<usize> {
        Ok(self.db.len())
    }

    pub fn update_rank_scores(&self, did: &str, usage: f32, competence: f32) -> Result<()> {
        let mut stats = self.get_stats(did)?;
        stats.usage_score = usage;
        stats.competence_score = competence;
        let bytes = bincode::serialize(&stats)?;
        self.db.insert(did, bytes)?;
        Ok(())
    }
    
    pub fn record_pow(&self, did: &str, difficulty: u32, timestamp: u64) -> Result<()> {
        let mut stats = self.get_stats(did)?;
        stats.accumulated_work += difficulty as u64;
        stats.last_pow_timestamp = timestamp;
        let bytes = bincode::serialize(&stats)?;
        self.db.insert(did, bytes)?;
        Ok(())
    }
    
    // Interaction updates are now handled by GraphStore primarily, 
    // but we can keep aggregate counters here for quick lookups if needed.
    // Ideally, GraphStore is source of truth for matrix math.
}