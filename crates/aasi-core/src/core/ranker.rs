use anyhow::Result;
use ndarray::{Array1, Array2};
use crate::core::graph::GraphStore;
use crate::core::stats::StatsStore;
use crate::storage::vector_store::VectorStore;
use std::sync::Arc;

#[derive(Clone)]
pub struct AgentRanker {
    stats_store: Arc<StatsStore>,
    graph_store: Arc<GraphStore>,
    vector_store: Option<Arc<VectorStore>>,
    // Weights
    alpha: f32,
    beta: f32,
    gamma: f32,
}

impl AgentRanker {
    pub fn new(
        stats_store: Arc<StatsStore>, 
        graph_store: Arc<GraphStore>, 
        vector_store: Arc<VectorStore>,
        alpha: f32,
        beta: f32,
        gamma: f32
    ) -> Self {
        Self { 
            stats_store, 
            graph_store, 
            vector_store: Some(vector_store),
            alpha,
            beta,
            gamma,
        }
    }

    /// Run the iterative coupled fixed-point algorithm
    pub fn compute_global_rank(&self) -> Result<()> {
        let (nodes, adj) = self.graph_store.load_graph()?;
        let n = nodes.len();
        if n == 0 { return Ok(()); }

        // Initialize vectors u and c
        let mut u = Array1::<f32>::from_elem(n, 1.0 / n as f32);
        let mut c = Array1::<f32>::from_elem(n, 1.0 / n as f32);

        // Parameters
        let d_u = 0.15; // Damping factor for Usage (1-alpha in PageRank)
        let d_c = 0.15; // Damping factor for Competence
        let epsilon = 1e-4;
        let max_iter = 50;

        // Build Static Usage Matrix M_u
        // M_u[i][j] = Probability i calls j
        let mut m_u = Array2::<f32>::zeros((n, n));
        for (i, edges) in &adj {
            let total_calls: u32 = edges.iter().map(|(_, e)| e.calls).sum();
            if total_calls > 0 {
                for (j, edge) in edges {
                    m_u[[*i, *j]] = edge.calls as f32 / total_calls as f32;
                }
            } else {
                // Dangling node handling: distribute evenly or self-loop
                // Standard PageRank: distribute 1/N to all
                for j in 0..n {
                    m_u[[*i, j]] = 1.0 / n as f32;
                }
            }
        }

        // Iteration
        for _iter in 0..max_iter {
            let u_prev = u.clone();
            let c_prev = c.clone();

            // 1. Update Usage: u = (1-d) M_u^T * u + d * e
            // Note: M_u is row-stochastic. PageRank uses column-stochastic if M[j][i] is j->i.
            // Here M_u[i][j] is i->j. So we want "popularity of j" = sum(u_i * M_u[i][j]).
            // This corresponds to u * M_u in row-vector notation, or M_u^T * u in column-vector notation.
            // ndarray dot is row * col.
            // u_new = (1-d) * (u dot M_u) + d/N
            let mut u_new = u.dot(&m_u) * (1.0 - d_u);
            u_new = u_new + (d_u / n as f32);

            // 2. Build Dynamic Competence Matrix M_c(u)
            // M_c[i][j] = Q_ij * u_i
            // Q_ij = Success/Calls
            // Normalized so columns sum to 1? Or just raw trust transfer?
            // EigenTrust normalizes rows: Trust_i distributes their trust to j.
            // We want "Competence of j" = sum(u_i * Q_ij * c_i?? No)
            // Paper formula: c = (1-dc) M_c(u) c + dc e
            // Interpretation: Competence flows from trusted nodes.
            // Let's assume M_c[i][j] is row-normalized weighting of i's opinion on j.
            // Weight w_ij = u_i * Q_ij.
            // M_c_weighted[i][j] = w_ij / sum_k(w_ik).
            // Then c_new = c * M_c_weighted.
            
            let mut m_c = Array2::<f32>::zeros((n, n));
            for (i, edges) in &adj {
                let u_i = u[*i];
                let mut row_sum = 0.0;
                
                // Calculate raw weights
                for (j, edge) in edges {
                    let q_ij = if edge.calls > 0 { edge.successes as f32 / edge.calls as f32 } else { 0.0 };
                    let weight = q_ij * u_i; 
                    m_c[[*i, *j]] = weight;
                    row_sum += weight;
                }
                
                // Normalize row
                if row_sum > 0.0 {
                    for (j, _) in edges {
                        m_c[[*i, *j]] /= row_sum;
                    }
                } else {
                     // No valid opinions or zero usage score? Distribute evenly
                     for j in 0..n {
                        m_c[[*i, j]] = 1.0 / n as f32;
                    }
                }
            }
            
            // Update Competence: c = (1-d) * (c dot M_c) + d/N
            let mut c_new = c.dot(&m_c) * (1.0 - d_c);
            c_new = c_new + (d_c / n as f32);

            u = u_new;
            c = c_new;

            // Check convergence
            let diff_u = (&u - &u_prev).mapv(|x| x.abs()).sum();
            let diff_c = (&c - &c_prev).mapv(|x| x.abs()).sum();
            
            if diff_u < epsilon && diff_c < epsilon {
                break;
            }
        }

        // Persist & Sync to Vector Store
        // We use a runtime handle or blocking call since this is likely running in a blocking thread (spawn_blocking in server.rs)
        let rt = tokio::runtime::Handle::current(); 
        
        // Prepare batch updates
        let mut updates = Vec::new();

        for (i, score) in u.iter().enumerate() {
            let did = &nodes[i];
            let comp_score = c[i];
            self.stats_store.update_rank_scores(did, *score, comp_score)?;
            
            updates.push((did.clone(), "rank_performance".to_string(), serde_json::json!(comp_score)));
        }

        // Fix 8.1: Batch Sync to Qdrant
        if let Some(vs) = &self.vector_store {
            // We must use `block_on` because set_payload_batch is async.
            let _ = rt.block_on(async {
                let _ = vs.set_payload_batch(updates).await;
            });
        }

        Ok(())
    }

    /// Calculates the final rank R = α*S + β*T + γ*P
    pub fn calculate_rank(
        &self, 
        did: &str, 
        similarity_score: f32, // S
        trust_score: f32       // T
    ) -> Result<f32> {
        let norm_p = self.get_normalized_performance(did)?;

        Ok(self.alpha * similarity_score + self.beta * trust_score + self.gamma * norm_p)
    }
    
    pub fn get_performance_score(&self, did: &str) -> Result<f32> {
        Ok(self.stats_store.get_stats(did)?.competence_score)
    }

    pub fn get_normalized_performance(&self, did: &str) -> Result<f32> {
        let stats = self.stats_store.get_stats(did)?;
        let raw_performance_score = stats.competence_score;
        let n = self.stats_store.count()?.max(1) as f32;
        Ok((raw_performance_score * n).min(5.0))
    }
}
