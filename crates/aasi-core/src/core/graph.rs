use anyhow::Result;
use sled::Db;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InteractionEdge {
    pub calls: u32,
    pub successes: u32,
    pub last_interaction: u64,
}

pub struct GraphStore {
    db: Db,
}

impl GraphStore {
    const KEY_PREFIX: &'static [u8] = b"edge\0";

    pub fn new(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    fn key(caller: &str, target: &str) -> Vec<u8> {
        // IMPORTANT: DIDs contain `:` characters (e.g., `did:web:...`), so we must not
        // use `:` as a delimiter in persisted keys. We store a binary key:
        //   b"edge\0" + caller + b"\0" + target
        // where `\0` is not a valid character in DIDs.
        let mut out = Vec::with_capacity(Self::KEY_PREFIX.len() + caller.len() + 1 + target.len());
        out.extend_from_slice(Self::KEY_PREFIX);
        out.extend_from_slice(caller.as_bytes());
        out.push(0);
        out.extend_from_slice(target.as_bytes());
        out
    }

    fn parse_key(key: &[u8]) -> Option<(String, String)> {
        if !key.starts_with(Self::KEY_PREFIX) {
            return None;
        }
        let rest = &key[Self::KEY_PREFIX.len()..];
        let sep = rest.iter().position(|&b| b == 0)?;
        let (caller_bytes, tail) = rest.split_at(sep);
        let target_bytes = tail.get(1..)?; // skip delimiter

        let caller = String::from_utf8(caller_bytes.to_vec()).ok()?;
        let target = String::from_utf8(target_bytes.to_vec()).ok()?;
        Some((caller, target))
    }

    pub fn record_interaction(&self, caller: &str, target: &str, success: bool) -> Result<()> {
        let key = Self::key(caller, target);
        
        let mut edge = match self.db.get(&key)? {
            Some(bytes) => bincode::deserialize(&bytes)?,
            None => InteractionEdge {
                calls: 0,
                successes: 0,
                last_interaction: 0,
            },
        };

        edge.calls += 1;
        if success {
            edge.successes += 1;
        }
        edge.last_interaction = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        self.db.insert(key, bincode::serialize(&edge)?)?;
        Ok(())
    }

    /// Loads the full graph for matrix computation.
    /// Returns: (List of DIDs, Adjacency Map: Caller -> [(Target, Edge)])
    pub fn load_graph(&self) -> Result<(Vec<String>, HashMap<usize, Vec<(usize, InteractionEdge)>>)> {
        let mut nodes = HashSet::new();
        let mut raw_edges = Vec::new();

        // Scan all edges
        for item in self.db.iter() {
            let (key, value) = item?;
            let Some((caller, target)) = Self::parse_key(key.as_ref()) else {
                continue; // Skip non-edge keys
            };
            
            nodes.insert(caller.clone());
            nodes.insert(target.clone());
            
            let edge: InteractionEdge = bincode::deserialize(&value)?;
            raw_edges.push((caller, target, edge));
        }

        // Map DIDs to Indices
        let mut sorted_nodes: Vec<String> = nodes.into_iter().collect();
        sorted_nodes.sort(); // Deterministic order
        
        let node_map: HashMap<String, usize> = sorted_nodes.iter()
            .enumerate()
            .map(|(i, did)| (did.clone(), i))
            .collect();

        // Build Adjacency List (Index based)
        let mut adj = HashMap::new();
        for (caller, target, edge) in raw_edges {
            let u = node_map[&caller];
            let v = node_map[&target];
            adj.entry(u).or_insert_with(Vec::new).push((v, edge));
        }

        Ok((sorted_nodes, adj))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_keys_support_dids_with_colons() -> Result<()> {
        let tmp = std::env::temp_dir().join(format!(
            "aasi_graph_store_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let path = tmp.to_string_lossy().to_string();
        let store = GraphStore::new(&path)?;

        let caller = "did:web:127.0.0.1%3A8000:honest:0001";
        let target = "did:web:127.0.0.1%3A8000:sybil:0001";
        store.record_interaction(caller, target, true)?;

        let (nodes, adj) = store.load_graph()?;
        assert!(nodes.contains(&caller.to_string()));
        assert!(nodes.contains(&target.to_string()));
        assert!(!adj.is_empty());

        drop(store);
        let _ = std::fs::remove_dir_all(&tmp);
        Ok(())
    }
}
