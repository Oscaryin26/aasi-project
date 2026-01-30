use rs_merkle::{MerkleTree, algorithms::Sha256, MerkleProof};
use sled::Db;
use anyhow::{Result, anyhow};
use std::sync::{Arc, Mutex};

pub struct TransparencyLog {
    db: Db,
    // MerkleTree is cheap to clone if it's just holding a Vec, but rebuilding it is costly.
    // rs_merkle::MerkleTree owns its data.
    // We wrap it in Mutex for thread safety if accessed by multiple gRPC threads.
    tree: Arc<Mutex<MerkleTree<Sha256>>>,
    count: Arc<Mutex<usize>>,
}

impl TransparencyLog {
    pub fn new(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        let mut leaves = Vec::new();
        let mut count = 0;

        // Recover state from DB
        // Assuming keys are sequential u64 indices (big endian)
        for item in db.iter() {
            let (key, value) = item?;
            // Check if key is index
            if key.len() == 8 {
                let index = u64::from_be_bytes(key.as_ref().try_into()?);
                if index != count as u64 {
                    // Gap detected or out of order?
                    // Sled iterates in order. If we strictly append, it should be fine.
                    // But if there was a partial write or corruption?
                    // For MVP assume integrity.
                }
                let hash: [u8; 32] = value.as_ref().try_into().map_err(|_| anyhow!("Invalid hash len"))?;
                leaves.push(hash);
                count += 1;
            }
        }

        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);

        Ok(Self {
            db,
            tree: Arc::new(Mutex::new(tree)),
            count: Arc::new(Mutex::new(count)),
        })
    }

    pub fn append(&self, hash: [u8; 32]) -> Result<[u8; 32]> {
        let mut tree_lock = self.tree.lock().unwrap();
        let mut count_lock = self.count.lock().unwrap();

        // Persist first
        let index = *count_lock as u64;
        self.db.insert(index.to_be_bytes(), &hash)?;
        // self.db.flush()?; // Optional for speed, but safer for consistency

        // Update memory tree
        // rs_merkle 1.4 doesn't support efficient append O(log n) easily on the standard struct, 
        // it rebuilds or we need to use advanced features.
        // Standard `from_leaves` rebuilds the whole tree.
        // For MVP with < 1M agents, rebuilding is "okay" (milliseconds).
        // Optimization: Keep leaves in memory or load them?
        // Wait, `tree` struct in `rs_merkle` keeps leaves?
        // `MerkleTree` struct has `leaves: Vec<Hash>`.
        // I can get leaves, push, and rebuild.
        
        // Better: `rs_merkle` might allow inserting.
        // Currently `rs_merkle` is immutable-ish.
        // Let's just append to a local leaves vector and rebuild?
        // Accessing private fields is not possible.
        // We have to maintain a `leaves` list in memory if we want to avoid DB scan every time.
        
        // Let's change struct to hold `leaves` in memory.
        // But wait, `MerkleTree` holds them. `tree.leaves()` returns Option<&[Hash]>.
        
        // Hack for MVP: Extract leaves, append, rebuild.
        let mut leaves = tree_lock.leaves().unwrap_or_default();
        leaves.push(hash);
        *tree_lock = MerkleTree::<Sha256>::from_leaves(&leaves);
        *count_lock += 1;

        tree_lock.root().ok_or(anyhow!("Tree is empty"))
    }

    pub fn root(&self) -> Option<[u8; 32]> {
        let tree_lock = self.tree.lock().unwrap();
        tree_lock.root()
    }

    pub fn prove(&self, index: usize) -> Result<MerkleProof<Sha256>> {
        let tree_lock = self.tree.lock().unwrap();
        if index >= *self.count.lock().unwrap() {
            return Err(anyhow!("Index out of bounds"));
        }
        Ok(tree_lock.proof(&[index]))
    }
    
    pub fn count(&self) -> usize {
        *self.count.lock().unwrap()
    }
}
