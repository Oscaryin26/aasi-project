use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Instant};

use aasi_proto::aasi::v1::{
    discovery_service_client::DiscoveryServiceClient,
    trust_proof::Proof,
    AgentManifest,
    ComputationalProof,
    DebugRecomputeRankRequest,
    FeedbackRequest,
    IdentityProof,
    ParamsRequest,
    RegisterRequest,
    SearchRequest,
    TrustProof,
};

use aasi_client::pow::generate_work;
use aasi_client::signer::{sign_feedback, sign_manifest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey};
use plotters::prelude::*;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "aasi-experiment")]
#[command(about = "AASI experiment harness (dataset + benchmarks)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "http://[::1]:50051")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    #[command(subcommand)]
    Dataset(DatasetCommand),
    BenchSearch(BenchSearchArgs),
    RunAll(RunAllArgs),
}

#[derive(Subcommand)]
enum DatasetCommand {
    Scifact(DatasetScifactArgs),
    Synthetic(DatasetSyntheticArgs),
}

#[derive(Parser)]
struct DatasetScifactArgs {
    #[arg(long)]
    out: PathBuf,

    #[arg(long, default_value_t = 42)]
    seed: u64,

    #[arg(long, default_value_t = 1000)]
    n: u64,
}

#[derive(Parser)]
struct DatasetSyntheticArgs {
    #[arg(long)]
    out: PathBuf,

    #[arg(long, default_value_t = 42)]
    seed: u64,

    #[arg(long, default_value_t = 1000)]
    n: u64,
}

#[derive(Parser)]
struct BenchSearchArgs {
    #[arg(long)]
    dataset: PathBuf,

    #[arg(long, default_value = "1,16,64")]
    concurrency: String,

    #[arg(long, default_value_t = 200)]
    warmup: u64,

    #[arg(long, default_value = "30s")]
    duration: String,

    #[arg(long, default_value_t = 20)]
    limit: u64,
}

#[derive(Parser)]
struct RunAllArgs {
    #[arg(long, default_value = "datasets/scifact_1k")]
    dataset: PathBuf,

    #[arg(long, default_value_t = 42)]
    seed: u64,

    #[arg(long, default_value_t = 40)]
    rounds: u64,

    #[arg(long, default_value_t = 10)]
    topk: u64,

    #[arg(long, default_value = "180000s")]
    time_budget: String,

    #[arg(long, default_value_t = 0.1)]
    epsilon_noise: f64,

    #[arg(long, default_value_t = 200)]
    sybil_interactions_per_round: u64,

    #[arg(long, default_value = "results")]
    results_dir: PathBuf,

    #[arg(long)]
    run_id: Option<String>,

    #[arg(long)]
    reset: bool,

    #[arg(long)]
    start_server: bool,

    #[arg(long, default_value = "cargo run -p aasi-core")]
    server_cmd: String,

    #[arg(long, default_value = "127.0.0.1")]
    did_bind: String,

    #[arg(long, default_value_t = 8000)]
    did_port: u16,

    #[arg(long, default_value_t = 11)]
    rank_recompute_wait_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Dataset(DatasetCommand::Scifact(args)) => dataset_scifact(args).await,
        Commands::Dataset(DatasetCommand::Synthetic(args)) => dataset_synthetic(args).await,
        Commands::BenchSearch(args) => bench_search(&cli.server, args).await,
        Commands::RunAll(args) => run_all(&cli.server, args).await,
    }
}

async fn dataset_scifact(args: DatasetScifactArgs) -> Result<()> {
    let repo_root = repo_root_from_manifest()?;
    let script_path = repo_root.join("tools").join("download_dataset.py");
    if !script_path.exists() {
        return Err(anyhow!("dataset script not found: {}", script_path.display()));
    }

    let status = Command::new("python3")
        .current_dir(&repo_root)
        .arg(&script_path)
        .args([
            "--out",
            args.out.to_string_lossy().as_ref(),
            "--seed",
            &args.seed.to_string(),
            "--n",
            &args.n.to_string(),
        ])
        .status()
        .with_context(|| "failed to run python3 tools/download_dataset.py")?;

    if !status.success() {
        return Err(anyhow!("dataset generation failed (exit code: {:?})", status.code()));
    }
    Ok(())
}

async fn dataset_synthetic(_args: DatasetSyntheticArgs) -> Result<()> {
    dataset_synthetic_impl(_args)
}

async fn bench_search(server: &str, args: BenchSearchArgs) -> Result<()> {
    let repo_root = repo_root_from_manifest()?;
    let dataset_dir = resolve_repo_relative(&repo_root, &args.dataset);
    let concurrency_levels = parse_concurrency_list(&args.concurrency)?;
    let queries = load_queries(&dataset_dir.join("queries.jsonl"))?;
    if queries.is_empty() {
        return Err(anyhow!("no queries found in dataset: {}", dataset_dir.display()));
    }
    let duration = parse_duration(&args.duration)?;

    let endpoint = tonic::transport::Endpoint::from_shared(server.to_string())
        .with_context(|| format!("invalid server URL: {server}"))?
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint
        .connect()
        .await
        .with_context(|| format!("failed to connect to AASI server: {server}"))?;
    let mut client = DiscoveryServiceClient::new(channel.clone());

    // Sanity check: server reachable and returns params.
    let _ = client
        .get_network_params(ParamsRequest {})
        .await
        .context("GetNetworkParams failed")?;

    for c in concurrency_levels {
        println!(
            "\n=== bench-search: concurrency={}, warmup={}, duration={} ===",
            c,
            args.warmup,
            args.duration
        );
        let metrics =
            run_bench_search_round(channel.clone(), &queries, c, args.warmup, duration, args.limit).await?;
        println!("{}", serde_json::to_string_pretty(&metrics)?);
    }

    Ok(())
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct DatasetMeta {
    dataset: String,
    seed: u64,
    n_agents: u64,
    n_elite: u64,
    n_honest: u64,
    n_sybil: u64,
    n_queries_final: u64,
    did_domain: String,
    endpoint: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct DatasetAgent {
    did: String,
    role: String,
    register_mode: String,
    endpoint: String,
    capabilities: Vec<String>,
    #[allow(dead_code)]
    scifact_doc_id: Option<String>,
}

#[derive(serde::Serialize)]
struct BenchSearchMetrics {
    concurrency: u64,
    warmup: u64,
    duration_ms: u128,
    requests: u64,
    errors: u64,
    qps: f64,
    latency_ms_p50: f64,
    latency_ms_p95: f64,
    latency_ms_p99: f64,
}

async fn run_bench_search_round(
    channel: tonic::transport::Channel,
    queries: &[Query],
    concurrency: u64,
    warmup: u64,
    duration: Duration,
    limit: u64,
) -> Result<BenchSearchMetrics> {
    // Warmup.
    let mut warm_client = DiscoveryServiceClient::new(channel.clone());
    for i in 0..warmup {
        let q = &queries[(i as usize) % queries.len()];
        let _ = warm_client
            .search_agents(SearchRequest {
                query_text: q.text.clone(),
                min_trust_score: 0.0,
                required_credentials: vec![],
                limit,
            })
            .await;
    }

    // Measure.
    let start = Instant::now();
    let deadline = start + duration;

    let mut handles = Vec::new();
    for worker_idx in 0..concurrency {
        let channel = channel.clone();
        let queries = queries.to_vec();
        let deadline = deadline;
        let limit = limit;
        handles.push(tokio::spawn(async move {
            let mut client = DiscoveryServiceClient::new(channel);
            let mut latencies_ms: Vec<f64> = Vec::new();
            let mut requests: u64 = 0;
            let mut errors: u64 = 0;
            let mut i: u64 = 0;

            while Instant::now() < deadline {
                let q = &queries[((worker_idx + i) as usize) % queries.len()];
                i += 1;

                let t0 = Instant::now();
                let resp = client
                    .search_agents(SearchRequest {
                        query_text: q.text.clone(),
                        min_trust_score: 0.0,
                        required_credentials: vec![],
                        limit,
                    })
                    .await;
                let dt = t0.elapsed();

                requests += 1;
                if resp.is_err() {
                    errors += 1;
                    continue;
                }
                latencies_ms.push(dt.as_secs_f64() * 1000.0);
            }

            (latencies_ms, requests, errors)
        }));
    }

    let mut latencies_ms: Vec<f64> = Vec::new();
    let mut requests: u64 = 0;
    let mut errors: u64 = 0;
    for h in handles {
        let (mut lats, reqs, errs) = h.await?;
        latencies_ms.append(&mut lats);
        requests += reqs;
        errors += errs;
    }

    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let duration_ms = start.elapsed().as_millis();
    let qps = if duration_ms == 0 {
        0.0
    } else {
        (requests as f64) / (duration_ms as f64 / 1000.0)
    };

    Ok(BenchSearchMetrics {
        concurrency,
        warmup,
        duration_ms,
        requests,
        errors,
        qps,
        latency_ms_p50: quantile(&latencies_ms, 0.50),
        latency_ms_p95: quantile(&latencies_ms, 0.95),
        latency_ms_p99: quantile(&latencies_ms, 0.99),
    })
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    if q <= 0.0 {
        return sorted[0];
    }
    if q >= 1.0 {
        return sorted[sorted.len() - 1];
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Query {
    query_id: String,
    text: String,
}

fn load_queries(path: &Path) -> Result<Vec<Query>> {
    let f = std::fs::File::open(path).with_context(|| format!("failed to open: {}", path.display()))?;
    let reader = std::io::BufReader::new(f);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}

fn parse_concurrency_list(s: &str) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(part.parse::<u64>().with_context(|| format!("invalid concurrency: {part}"))?);
    }
    if out.is_empty() {
        return Err(anyhow!("concurrency list is empty"));
    }
    Ok(out)
}

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("duration is empty"));
    }

    let (num_str, unit) = s
        .chars()
        .position(|c| !c.is_ascii_digit())
        .map(|i| (&s[..i], &s[i..]))
        .unwrap_or((s, "s"));

    let value: u64 = num_str
        .parse()
        .with_context(|| format!("invalid duration value: {num_str}"))?;

    match unit {
        "ms" => Ok(Duration::from_millis(value)),
        "s" => Ok(Duration::from_secs(value)),
        "m" => Ok(Duration::from_secs(value.saturating_mul(60))),
        _ => Err(anyhow!("unsupported duration unit: {unit} (use ms/s/m)")),
    }
}

fn repo_root_from_manifest() -> Result<PathBuf> {
    // aasi/aasi-experiment -> repo root is two levels up.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .join("..")
        .join("..")
        .canonicalize()
        .context("failed to resolve repo root")?)
}

fn load_dataset_meta(path: &Path) -> Result<DatasetMeta> {
    let s = std::fs::read_to_string(path).with_context(|| format!("failed to read: {}", path.display()))?;
    Ok(serde_json::from_str(&s)?)
}

fn load_agents_jsonl(path: &Path) -> Result<Vec<DatasetAgent>> {
    let f = std::fs::File::open(path).with_context(|| format!("failed to open: {}", path.display()))?;
    let reader = std::io::BufReader::new(f);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}

fn load_qrels(path: &Path) -> Result<BTreeMap<String, BTreeMap<String, i32>>> {
    let s = std::fs::read_to_string(path).with_context(|| format!("failed to read: {}", path.display()))?;
    Ok(serde_json::from_str(&s)?)
}

fn did_relative_doc_path(did: &str) -> Result<PathBuf> {
    if !did.starts_with("did:web:") {
        return Err(anyhow!("unsupported DID (only did:web): {did}"));
    }
    let rest = &did["did:web:".len()..];
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.is_empty() {
        return Err(anyhow!("invalid did:web format: {did}"));
    }
    let path = parts[1..].join("/");
    if path.is_empty() {
        Ok(PathBuf::from(".well-known").join("did.json"))
    } else {
        Ok(PathBuf::from(path).join("did.json"))
    }
}

fn did_domain_for(bind: &str, port: u16) -> String {
    // did:web encodes ":" as "%3A" for host:port.
    // For this experiment we primarily use 127.0.0.1.
    format!("{bind}%3A{port}")
}

fn derive_signing_key(seed: u64, did: &str) -> Result<SigningKey> {
    let mut hasher = Sha256::new();
    hasher.update(b"aasi-experiment-ed25519-seed-v1");
    hasher.update(&seed.to_be_bytes());
    hasher.update(did.as_bytes());
    let digest = hasher.finalize();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&digest[..32]);
    SigningKey::try_from(key_bytes.as_slice()).map_err(|_| anyhow!("failed to derive ed25519 key for {did}"))
}

fn write_did_doc(root: &Path, did: &str, signing_key: &SigningKey) -> Result<()> {
    let verifying_key = signing_key.verifying_key();
    let x = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
    let owner = format!("{did}#owner");

    let doc = serde_json::json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "verificationMethod": [{
            "id": owner,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
            }
        }],
        "authentication": [owner],
        "assertionMethod": [owner],
    });

    let rel = did_relative_doc_path(did)?;
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&doc)?)?;
    Ok(())
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn spawn_did_server(root: &Path, bind: &str, port: u16) -> Result<ChildGuard> {
    let mut child = Command::new("python3")
        .current_dir(root)
        .args([
            "-m",
            "http.server",
            &port.to_string(),
            "--bind",
            bind,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| "failed to start python3 http.server for DID docs")?;

    // Give the server a brief moment; if it exits immediately, surface a clearer error.
    std::thread::sleep(Duration::from_millis(200));
    if let Some(status) = child.try_wait()? {
        return Err(anyhow!(
            "DID server exited early (status={status}); is {bind}:{port} already in use?"
        ));
    }

    Ok(ChildGuard { child })
}

fn csv_escape(s: &str) -> String {
    if s.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn derive_u64(seed: u64, parts: &[&str]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"aasi-experiment-prng-v1");
    hasher.update(&seed.to_be_bytes());
    for p in parts {
        hasher.update(p.as_bytes());
        hasher.update(&[0u8]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(out)
}

fn u64_to_unit_f64(x: u64) -> f64 {
    // Deterministic in [0,1).
    (x as f64) / (u64::MAX as f64)
}

#[derive(Debug, Clone, serde::Serialize)]
struct RoundMetrics {
    round: u64,
    n_queries: u64,
    sybil_at_10: BTreeMap<String, f64>,
    ndcg_at_10: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RunMetrics {
    run_id: String,
    rounds: Vec<RoundMetrics>,
}

fn dcg_at_k(relevances: &[i32], k: usize) -> f64 {
    let mut dcg = 0.0;
    for (i, &rel) in relevances.iter().take(k).enumerate() {
        let gain = (2f64).powi(rel.max(0)) - 1.0;
        let denom = (i as f64 + 2.0).log2();
        dcg += gain / denom;
    }
    dcg
}

fn ndcg_at_k(ranked_dids: &[String], qrels: &BTreeMap<String, i32>, k: usize) -> f64 {
    let mut rels: Vec<i32> = Vec::new();
    for did in ranked_dids.iter().take(k) {
        rels.push(*qrels.get(did).unwrap_or(&0));
    }

    let mut ideal: Vec<i32> = qrels.values().copied().collect();
    ideal.sort_by(|a, b| b.cmp(a));

    let dcg = dcg_at_k(&rels, k);
    let idcg = dcg_at_k(&ideal, k);
    if idcg == 0.0 {
        0.0
    } else {
        dcg / idcg
    }
}

fn score_baseline_s_t(similarity: f32, trust: f32) -> f32 {
    // Match server weights, but omit performance (gamma=0).
    // Server full score: 0.5*S + 0.3*T + 0.2*P
    0.5 * similarity + 0.3 * trust
}

async fn run_all(server: &str, args: RunAllArgs) -> Result<()> {
    let time_budget = parse_duration(&args.time_budget)?;
    let run_deadline = Instant::now() + time_budget;

    let repo_root = repo_root_from_manifest()?;
    let dataset_dir = resolve_repo_relative(&repo_root, &args.dataset);
    let results_dir = resolve_repo_relative(&repo_root, &args.results_dir);
    let run_id = args.run_id.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string()
    });

    let results_root = results_dir.join(&run_id);
    let plots_dir = results_root.join("plots");
    std::fs::create_dir_all(&plots_dir)?;

    let meta = load_dataset_meta(&dataset_dir.join("dataset_meta.json"))
        .with_context(|| format!("dataset_meta.json missing under {}", dataset_dir.display()))?;

    let expected_domain = did_domain_for(&args.did_bind, args.did_port);
    if meta.did_domain != expected_domain {
        return Err(anyhow!(
            "dataset did_domain mismatch: dataset has {}, but run-all expects {} (did_bind={}, did_port={})\nHint: regenerate the dataset with tools/download_dataset.py --did-domain {}",
            meta.did_domain,
            expected_domain,
            args.did_bind,
            args.did_port,
            expected_domain
        ));
    }

    if args.reset && !args.start_server {
        return Err(anyhow!("--reset requires --start-server (so the harness can reset state safely)"));
    }

    if args.reset {
        // Best-effort: ensure infra is up so the reset can drop Qdrant collections and Anvil can be restarted.
        let _ = Command::new("docker")
            .current_dir(&repo_root)
            .args(["compose", "-f", "infra/docker-compose.yml", "up", "-d"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let reset_script = repo_root.join("scripts").join("reset_state.sh");
        let status = Command::new(&reset_script)
            .current_dir(&repo_root)
            .arg("--yes")
            .status()
            .with_context(|| format!("failed to run reset script: {}", reset_script.display()))?;
        if !status.success() {
            return Err(anyhow!("reset_state.sh failed (exit code: {:?})", status.code()));
        }

        // Best-effort: restart Anvil to clear chain state for baseline runs (even if baseline isn't executed here yet).
        let _ = Command::new("docker")
            .current_dir(&repo_root)
            .args(["compose", "-f", "infra/docker-compose.yml", "restart", "anvil"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    let mut server_guard: Option<ChildGuard> = None;
    let server_log_path = results_root.join("server.log");
    if args.start_server {
        let log_file = std::fs::File::create(&server_log_path)
            .with_context(|| format!("failed to create server log: {}", server_log_path.display()))?;
        let log_file_err = log_file.try_clone()?;
        let mut child = Command::new("sh")
            .arg("-lc")
            .arg(&args.server_cmd)
            .current_dir(&repo_root)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .with_context(|| format!("failed to start server_cmd: {}", args.server_cmd))?;

        // Give the process a moment; `cargo run` may still be compiling.
        std::thread::sleep(Duration::from_millis(200));
        if let Some(status) = child.try_wait()? {
            return Err(anyhow!(
                "AASI server exited early (status={status}); see {}",
                server_log_path.display()
            ));
        }
        server_guard = Some(ChildGuard { child });
    }

    // DID documents: generate per-run docs and serve them locally.
    let did_root = results_root.join("did");
    std::fs::create_dir_all(&did_root)?;

    let agents = load_agents_jsonl(&dataset_dir.join("agents.jsonl"))?;
    let queries = load_queries(&dataset_dir.join("queries.jsonl"))?;
    let qrels = load_qrels(&dataset_dir.join("qrels.json"))?;

    if agents.is_empty() {
        return Err(anyhow!("dataset has no agents: {}", args.dataset.display()));
    }
    if queries.is_empty() {
        return Err(anyhow!("dataset has no queries: {}", args.dataset.display()));
    }
    if qrels.is_empty() {
        return Err(anyhow!("dataset has no qrels: {}", args.dataset.display()));
    }

    let mut role_by_did: HashMap<String, String> = HashMap::new();
    for a in &agents {
        role_by_did.insert(a.did.clone(), a.role.clone());
    }

    // Keys + DID docs (all agents must be resolvable because SubmitFeedback verifies signatures by did:web).
    let mut signing_keys: HashMap<String, SigningKey> = HashMap::new();
    for a in &agents {
        let k = derive_signing_key(args.seed, &a.did)?;
        write_did_doc(&did_root, &a.did, &k)?;
        signing_keys.insert(a.did.clone(), k);
    }

    // Runner DID for artifacts signature.
    let runner_did = format!("did:web:{}:runner", meta.did_domain);
    let runner_key = derive_signing_key(args.seed, &runner_did)?;
    write_did_doc(&did_root, &runner_did, &runner_key)?;

    let _did_server = spawn_did_server(&did_root, &args.did_bind, args.did_port)?;

    let endpoint = tonic::transport::Endpoint::from_shared(server.to_string())
        .with_context(|| format!("invalid server URL: {server}"))?
        .connect_timeout(Duration::from_secs(2));

    let max_wait = if args.start_server {
        // `cargo run -p aasi-core` may need time for the first build and the first embedding model download.
        Duration::from_secs(600)
    } else {
        Duration::from_secs(30)
    };

    if args.start_server {
        println!(
            "Waiting for AASI server readiness on {} (up to {}s). Server log: {}",
            server,
            max_wait.as_secs(),
            server_log_path.display()
        );
    }

    let connect_deadline = {
        let max = Instant::now() + max_wait;
        if max < run_deadline { max } else { run_deadline }
    };

    let mut backoff = Duration::from_millis(250);
    let mut last_err: Option<anyhow::Error> = None;
    let channel = loop {
        if let Some(guard) = server_guard.as_mut() {
            if let Some(status) = guard.child.try_wait()? {
                return Err(anyhow!(
                    "AASI server exited while waiting for readiness (status={status}); see {}",
                    server_log_path.display()
                ));
            }
        }

        match endpoint.clone().connect().await {
            Ok(ch) => {
                let mut probe = DiscoveryServiceClient::new(ch.clone());
                match probe.get_network_params(ParamsRequest {}).await {
                    Ok(_) => break ch,
                    Err(e) => {
                        last_err.replace(anyhow!(e));
                    }
                }
            }
            Err(e) => {
                last_err.replace(anyhow!(e));
            }
        }

        if Instant::now() >= connect_deadline {
            let extra = if args.start_server {
                format!("\nServer log: {}", server_log_path.display())
            } else {
                String::new()
            };
            return Err(anyhow!(
                "failed to connect to AASI server: {server}\nLast error: {}{}",
                last_err
                    .as_ref()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                extra
            ));
        }

        sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    };

    let mut client = DiscoveryServiceClient::new(channel.clone());

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut run_config = serde_json::json!({
        "run_id": run_id,
        "started_at_unix": now,
        "server": server,
        "dataset_dir": dataset_dir.to_string_lossy(),
        "dataset_meta": meta,
        "seed": args.seed,
        "rounds": args.rounds,
        "topk": args.topk,
        "epsilon_noise": args.epsilon_noise,
        "sybil_interactions_per_round": args.sybil_interactions_per_round,
        "rank_recompute_wait_secs": args.rank_recompute_wait_secs,
        "did": {
            "bind": args.did_bind,
            "port": args.did_port,
            "root": did_root.to_string_lossy(),
        },
        "baselines": {
            "full": "server-returned order by score = 0.5*S + 0.3*T + 0.2*P",
            "baseline_s": "re-sort returned candidates by rank_similarity desc",
            "baseline_s_t": "re-sort returned candidates by (0.5*S + 0.3*T) desc (omit performance)",
        },
        "success_model": {
            "epsilon_noise": args.epsilon_noise,
            "p_elite_relevant": 0.95,
            "p_honest_relevant": 0.90,
            "p_non_relevant": 0.10,
            "p_sybil_target": 0.05,
            "sybil_sybil_success": true,
        },
        "artifacts_signer_did": runner_did,
    });

    // --- Phase A: Bootstrap (register agents) ---
    println!("Registering {} agents...", agents.len());
    let register_t0 = Instant::now();

    // Refresh PoW params at most once per minute to avoid timestamp window failures.
    let mut cached_pow: Option<(u32, aasi_proto::aasi::v1::ArgonParams, Instant)> = None;

    let mut ordered_agents = agents.clone();
    ordered_agents.sort_by_key(|a| match a.role.as_str() {
        "sybil" => 0,
        "honest" => 1,
        "elite" => 2,
        _ => 3,
    });

    let mut register_ok: u64 = 0;
    let mut register_err: u64 = 0;
    for (idx, a) in ordered_agents.iter().enumerate() {
        if Instant::now() > run_deadline {
            break;
        }

        let (difficulty, argon_params_proto) = if a.register_mode == "computational" {
            let need_refresh = match &cached_pow {
                Some((_, _, fetched_at)) => fetched_at.elapsed() >= Duration::from_secs(60),
                None => true,
            };
            if need_refresh {
                let resp = client
                    .get_network_params(ParamsRequest {})
                    .await?
                    .into_inner();
                let params = resp
                    .current_argon_params
                    .ok_or_else(|| anyhow!("missing argon params from GetNetworkParams"))?;
                cached_pow = Some((resp.difficulty, params.clone(), Instant::now()));
            }
            let (d, p, _) = cached_pow.clone().unwrap();
            (d, p)
        } else {
            (0u32, aasi_proto::aasi::v1::ArgonParams::default())
        };

        let server_time = client
            .get_network_params(ParamsRequest {})
            .await?
            .into_inner()
            .server_timestamp;

        let mut manifest = AgentManifest {
            did: a.did.clone(),
            version: 1,
            timestamp: server_time,
            capabilities: a.capabilities.clone(),
            trust_proof: None,
            endpoint: a.endpoint.clone(),
            embedding: vec![],
        };

        let trust_proof = if a.register_mode == "identity" {
            let key = signing_keys
                .get(&a.did)
                .ok_or_else(|| anyhow!("missing signing key for {}", a.did))?;
            let sig = sign_manifest(key, &manifest).map_err(|e| anyhow!(e))?;
            TrustProof {
                proof: Some(Proof::Identity(IdentityProof {
                    domain_signature: sig,
                    verifiable_credentials: vec![],
                })),
            }
        } else {
            let mut argon_params = argon_params_proto.clone();
            argon_params.timestamp = server_time;
            let (nonce, hash) =
                generate_work(&a.did, difficulty, server_time, &argon_params).map_err(|e| anyhow!(e))?;
            TrustProof {
                proof: Some(Proof::Computational(ComputationalProof {
                    argon2_params: Some(argon_params),
                    nonce,
                    hash,
                    difficulty,
                })),
            }
        };

        manifest.trust_proof = Some(trust_proof);

        let resp = client
            .register_agent(RegisterRequest {
                manifest: Some(manifest),
            })
            .await;
        match resp {
            Ok(r) if r.get_ref().success => register_ok += 1,
            Ok(r) => {
                register_err += 1;
                eprintln!(
                    "register failed ({}): {}",
                    a.did,
                    r.get_ref().message
                );
            }
            Err(e) => {
                register_err += 1;
                eprintln!("register error ({}): {}", a.did, e);
            }
        }

        if (idx + 1) % 100 == 0 {
            println!(
                "  progress: {}/{} (ok={}, err={})",
                idx + 1,
                ordered_agents.len(),
                register_ok,
                register_err
            );
        }
    }

    let register_ms = register_t0.elapsed().as_millis();
    run_config["bootstrap"] = serde_json::json!({
        "registered_ok": register_ok,
        "registered_err": register_err,
        "duration_ms": register_ms,
    });

    // Fix 8.4: Initial Recompute
    // Ensure all agents have a valid initial rank (even if uniform) before Round 1.
    println!("Triggering initial rank recompute...");
    let _ = client.debug_recompute_rank(DebugRecomputeRankRequest {}).await
        .context("Initial DebugRecomputeRank failed")?;

    // --- Phase B: Trace-driven simulation (RQ2) ---
    let honest_dids: Vec<String> = agents
        .iter()
        .filter(|a| a.role == "honest")
        .map(|a| a.did.clone())
        .collect();
    let elite_dids: HashSet<String> = agents
        .iter()
        .filter(|a| a.role == "elite")
        .map(|a| a.did.clone())
        .collect();
    let sybil_dids: Vec<String> = agents
        .iter()
        .filter(|a| a.role == "sybil")
        .map(|a| a.did.clone())
        .collect();
    let all_dids: Vec<String> = agents.iter().map(|a| a.did.clone()).collect();

    let mut relevant_by_qid: HashMap<String, Vec<String>> = HashMap::new();
    for (qid, relmap) in &qrels {
        relevant_by_qid.insert(qid.clone(), relmap.keys().cloned().collect());
    }

    let mut non_relevant_by_qid: HashMap<String, Vec<String>> = HashMap::new();
    for q in &queries {
        let rel_set: HashSet<String> = qrels
            .get(&q.query_id)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        non_relevant_by_qid.insert(
            q.query_id.clone(),
            all_dids
                .iter()
                .filter(|did| !rel_set.contains(*did))
                .cloned()
                .collect(),
        );
    }

    let mut trace_interactions =
        std::io::BufWriter::new(std::fs::File::create(results_root.join("trace_interactions.csv"))?);
    writeln!(
        trace_interactions,
        "round,caller_did,caller_role,query_id,target_did,target_role,is_relevant,success"
    )?;

    let mut trace_search =
        std::io::BufWriter::new(std::fs::File::create(results_root.join("trace_search.csv"))?);
    writeln!(
        trace_search,
        "round,method,query_id,rank,did,role,is_sybil,relevance,score,rank_similarity,rank_trust,rank_performance"
    )?;

    let mut rounds_metrics: Vec<RoundMetrics> = Vec::new();

    for round in 1..=args.rounds {
        if Instant::now() > run_deadline {
            break;
        }

        println!("Round {round}/{}: search snapshot...", args.rounds);
        let mut sybil_at_10: BTreeMap<String, f64> = BTreeMap::new();
        let mut ndcg_at_10: BTreeMap<String, f64> = BTreeMap::new();
        let methods = ["full", "baseline_s", "baseline_s_t"];
        for m in methods {
            sybil_at_10.insert(m.to_string(), 0.0);
            ndcg_at_10.insert(m.to_string(), 0.0);
        }

        for q in &queries {
            let resp = client
                .search_agents(SearchRequest {
                    query_text: q.text.clone(),
                    min_trust_score: 0.0,
                    required_credentials: vec![],
                    limit: args.topk,
                })
                .await?
                .into_inner();

            let full = resp.results;

            let mut baseline_s = full.clone();
            baseline_s.sort_by(|a, b| {
                b.rank_similarity
                    .partial_cmp(&a.rank_similarity)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        let ad = a
                            .manifest
                            .as_ref()
                            .map(|m| m.did.as_str())
                            .unwrap_or("");
                        let bd = b
                            .manifest
                            .as_ref()
                            .map(|m| m.did.as_str())
                            .unwrap_or("");
                        ad.cmp(bd)
                    })
            });

            let mut baseline_s_t = full.clone();
            baseline_s_t.sort_by(|a, b| {
                let ascore = score_baseline_s_t(a.rank_similarity, a.rank_trust);
                let bscore = score_baseline_s_t(b.rank_similarity, b.rank_trust);
                bscore
                    .partial_cmp(&ascore)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        let ad = a
                            .manifest
                            .as_ref()
                            .map(|m| m.did.as_str())
                            .unwrap_or("");
                        let bd = b
                            .manifest
                            .as_ref()
                            .map(|m| m.did.as_str())
                            .unwrap_or("");
                        ad.cmp(bd)
                    })
            });

            let per_method = [("full", &full), ("baseline_s", &baseline_s), ("baseline_s_t", &baseline_s_t)];

            for (method, list) in per_method {
                let ranked: Vec<String> = list
                    .iter()
                    .filter_map(|a| a.manifest.as_ref().map(|m| m.did.clone()))
                    .collect();

                let qrel_map = qrels
                    .get(&q.query_id)
                    .ok_or_else(|| anyhow!("missing qrels for query_id={}", q.query_id))?;
                let ndcg = ndcg_at_k(&ranked, qrel_map, 10);
                *ndcg_at_10.get_mut(method).unwrap() += ndcg;

                let mut sybil_hits = 0u64;
                for did in ranked.iter().take(10) {
                    if role_by_did.get(did).map(|r| r.as_str()) == Some("sybil") {
                        sybil_hits += 1;
                    }
                }
                *sybil_at_10.get_mut(method).unwrap() += (sybil_hits as f64) / 10.0;

                for (rank_idx, agent) in list.iter().enumerate() {
                    let did = agent
                        .manifest
                        .as_ref()
                        .map(|m| m.did.clone())
                        .unwrap_or_default();
                    let role = role_by_did.get(&did).cloned().unwrap_or_else(|| "unknown".to_string());
                    let is_sybil = role == "sybil";
                    let rel = qrel_map.get(&did).copied().unwrap_or(0);
                    writeln!(
                        trace_search,
                        "{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6}",
                        round,
                        method,
                        csv_escape(&q.query_id),
                        rank_idx + 1,
                        csv_escape(&did),
                        role,
                        if is_sybil { 1 } else { 0 },
                        rel,
                        agent.score,
                        agent.rank_similarity,
                        agent.rank_trust,
                        agent.rank_performance
                    )?;
                }
            }
        }

        let n_q = queries.len() as f64;
        for v in sybil_at_10.values_mut() {
            *v /= n_q;
        }
        for v in ndcg_at_10.values_mut() {
            *v /= n_q;
        }

        rounds_metrics.push(RoundMetrics {
            round,
            n_queries: queries.len() as u64,
            sybil_at_10: sybil_at_10.clone(),
            ndcg_at_10: ndcg_at_10.clone(),
        });

        println!("Round {round}: submit feedback...");
        
        // Honest interactions: Search -> Click -> Feedback (Trace-Driven)
        // Fix 9.2: Concurrent Feedback Submission & Search-Driven Selection
        use futures::stream::{self, StreamExt};
        
        // 1. Perform Searches for all queries concurrently
        let mut search_futs = Vec::new();
        for (qi, q) in queries.iter().enumerate() {
            let mut c = client.clone();
            let q_text = q.text.clone();
            let limit = args.topk;
            search_futs.push(async move {
                let resp = c.search_agents(SearchRequest {
                    query_text: q_text,
                    min_trust_score: 0.0,
                    required_credentials: vec![],
                    limit,
                }).await;
                (qi, resp)
            });
        }
        
        let search_results = stream::iter(search_futs)
            .buffer_unordered(50) // Concurrency limit
            .collect::<Vec<_>>()
            .await;
            
        let mut honest_feedbacks = Vec::new();
        
        // 2. Process Search Results & Simulate Clicks
        for (qi, resp_result) in search_results {
            let q = &queries[qi];
            let caller = &honest_dids[qi % honest_dids.len()]; // Round-robin honest agents
            
            // Resolve search result
            let candidates = match resp_result {
                Ok(r) => r.into_inner().results,
                Err(e) => {
                    eprintln!("Search failed for qid={}: {}", q.query_id, e);
                    continue;
                }
            };
            
            if candidates.is_empty() {
                continue;
            }
            
            // User Click Model:
            // Users are more likely to click higher ranked results.
            // We simulate this by picking from the returned Top-K with a rank-biased probability.
            // Weight = 1 / (rank + 1)
            // If the picked agent is Sybil (but high similarity), they click -> Negative Feedback.
            // If the picked agent is Honest/Relevant -> Click -> Positive Feedback.
            
            let mut weights = Vec::new();
            let mut total_weight = 0.0;
            for (i, _) in candidates.iter().enumerate() {
                let w = 1.0 / (i as f64 + 1.0);
                weights.push(w);
                total_weight += w;
            }
            
            let mut pick_roll = u64_to_unit_f64(derive_u64(
                args.seed,
                &["click_roll", &round.to_string(), caller, &q.query_id],
            ));
            
            // Scale roll to total weight
            pick_roll *= total_weight;
            
            let mut target_idx = 0;
            let mut cum_weight = 0.0;
            for (i, w) in weights.iter().enumerate() {
                cum_weight += w;
                if pick_roll <= cum_weight {
                    target_idx = i;
                    break;
                }
            }
            // Fallback
            if target_idx >= candidates.len() {
                target_idx = candidates.len() - 1;
            }
            
            let target_agent = &candidates[target_idx];
            let target_did = target_agent.manifest.as_ref().map(|m| m.did.clone()).unwrap_or_default();
            
            if target_did.is_empty() || target_did == *caller {
                continue;
            }

            // 3. Evaluate Validity (Ground Truth)
            let is_relevant = qrels
                .get(&q.query_id)
                .map(|m| m.contains_key(&target_did))
                .unwrap_or(false);
            
            let target_role = role_by_did.get(&target_did).map(|s| s.as_str()).unwrap_or("unknown");

            // Success Probability
            // If Relevant: High success (depends on Elite vs Honest)
            // If Sybil: Low success (0.05)
            // If Irrelevant (Noise): Low success (0.10)
            
            let p_success = if target_role == "sybil" {
                0.05
            } else if is_relevant {
                if elite_dids.contains(&target_did) {
                    0.95
                } else {
                    0.90
                }
            } else {
                0.10
            };

            let success_roll = u64_to_unit_f64(derive_u64(
                args.seed,
                &["success", &round.to_string(), caller, &q.query_id, &target_did],
            ));
            let success = success_roll < p_success;

            // Trace Log
            writeln!(
                trace_interactions,
                "{},{},{},{},{},{},{},{}",
                round,
                csv_escape(caller),
                "honest",
                csv_escape(&q.query_id),
                csv_escape(&target_did),
                target_role,
                if is_relevant { 1 } else { 0 },
                if success { 1 } else { 0 }
            )?;

            // 4. Generate Feedback Request
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let nonce = derive_u64(
                args.seed,
                &["fb_nonce", &round.to_string(), caller, &q.query_id, &target_did],
            );
            
            let mut fb = FeedbackRequest {
                reporter_did: caller.clone(),
                target_did: target_did.clone(),
                success,
                timestamp: now,
                nonce,
                signature: vec![],
            };

            if let Some(key) = signing_keys.get(caller) {
                 if let Ok(_) = sign_feedback(key, &mut fb) {
                     honest_feedbacks.push(fb);
                 }
            }
        }
        
        // Execute Honest Feedbacks Concurrently
        // Using a buffer of 50 concurrent requests
        let client_clone = client.clone();
        stream::iter(honest_feedbacks)
            .map(|fb| {
                let mut c = client_clone.clone();
                async move {
                    c.submit_feedback(fb).await
                }
            })
            .buffer_unordered(50)
            .collect::<Vec<_>>()
            .await;

        // Sybil interactions: create Sybil↔Sybil "success" edges.
        let mut sybil_feedbacks = Vec::new();
        for i in 0..args.sybil_interactions_per_round {
            if Instant::now() > run_deadline {
                break;
            }
            let caller_idx = (round as usize + i as usize) % sybil_dids.len();
            let caller = &sybil_dids[caller_idx];
            let mut target_idx = derive_u64(
                args.seed,
                &[
                    "sybil_target",
                    &round.to_string(),
                    &i.to_string(),
                    caller,
                ],
            ) as usize
                % sybil_dids.len();
            if target_idx == caller_idx {
                target_idx = (target_idx + 1) % sybil_dids.len();
            }
            let target = &sybil_dids[target_idx];

            writeln!(
                trace_interactions,
                "{},{},{},{},{},{},{},{}",
                round,
                csv_escape(caller),
                "sybil",
                "",
                csv_escape(target),
                "sybil",
                0,
                1
            )?;

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let nonce = derive_u64(
                args.seed,
                &[
                    "sybil_fb_nonce",
                    &round.to_string(),
                    &i.to_string(),
                    caller,
                    target,
                ],
            );
            let mut fb = FeedbackRequest {
                reporter_did: caller.clone(),
                target_did: target.clone(),
                success: true,
                timestamp: now,
                nonce,
                signature: vec![],
            };
            let key = signing_keys
                .get(caller)
                .ok_or_else(|| anyhow!("missing signing key for sybil {}", caller))?;
            sign_feedback(key, &mut fb).map_err(|e| anyhow!(e))?;
            sybil_feedbacks.push(fb);
        }
        
        // Execute Sybil Feedbacks Concurrently
        let client_clone_sybil = client.clone();
        stream::iter(sybil_feedbacks)
            .map(|fb| {
                let mut c = client_clone_sybil.clone();
                async move {
                    c.submit_feedback(fb).await
                }
            })
            .buffer_unordered(50)
            .collect::<Vec<_>>()
            .await;

        trace_interactions.flush()?;
        trace_search.flush()?;

        // Fix 3.1: Switch to Explicit Recompute
        // Instead of waiting, we force recompute to ensure experiment consistency.
        if args.rank_recompute_wait_secs > 0 {
            // Deprecated wait, using debug rpc if available, but for now we replace it.
            // We keep the arg for backward compat but ignore it if we use the RPC.
            // Actually, let's just use the RPC call.
            println!("  Triggering explicit rank recompute...");
            let _ = client.debug_recompute_rank(DebugRecomputeRankRequest {}).await
                .context("DebugRecomputeRank failed")?;
        }
    }

    let metrics = RunMetrics {
        run_id: run_id.clone(),
        rounds: rounds_metrics.clone(),
    };
    std::fs::write(
        results_root.join("metrics.json"),
        serde_json::to_vec_pretty(&metrics)?,
    )?;

    write_plots(&plots_dir, &rounds_metrics)?;

    // Summary markdown (minimal, paper-friendly)
    let mut summary = String::new();
    summary.push_str("# AASI Experiment Summary (SciFact)\n\n");
    summary.push_str(&format!("- run_id: `{}`\n", run_id));
    summary.push_str(&format!("- agents: `{}` (elite={}, honest={}, sybil={})\n", meta.n_agents, meta.n_elite, meta.n_honest, meta.n_sybil));
    summary.push_str(&format!("- queries: `{}`\n", queries.len()));
    summary.push_str(&format!("- rounds: `{}`\n", rounds_metrics.len()));
    summary.push_str("\n## Key Metrics (last round)\n\n");
    if let Some(last) = rounds_metrics.last() {
        let mut methods: Vec<String> = last.sybil_at_10.keys().cloned().collect();
        methods.sort();

        summary.push_str("| Metric |");
        for m in &methods {
            summary.push_str(&format!(" {m} |"));
        }
        summary.push_str("\n|---|");
        for _ in &methods {
            summary.push_str("---:|");
        }
        summary.push('\n');

        summary.push_str("| Sybil@10 |");
        for m in &methods {
            let v = last.sybil_at_10.get(m).copied().unwrap_or(0.0);
            summary.push_str(&format!(" {:.3} |", v));
        }
        summary.push('\n');

        summary.push_str("| nDCG@10 |");
        for m in &methods {
            let v = last.ndcg_at_10.get(m).copied().unwrap_or(0.0);
            summary.push_str(&format!(" {:.3} |", v));
        }
        summary.push('\n');

        for (k, v) in &last.sybil_at_10 {
            summary.push_str(&format!("- Sybil@10 `{}`: `{:.3}`\n", k, v));
        }
        for (k, v) in &last.ndcg_at_10 {
            summary.push_str(&format!("- nDCG@10 `{}`: `{:.3}`\n", k, v));
        }
    }
    std::fs::write(results_root.join("summary.md"), summary)?;

    std::fs::write(
        results_root.join("run_config.json"),
        serde_json::to_vec_pretty(&run_config)?,
    )?;

    // Artifacts: SHA256 manifest -> Merkle root -> signature.
    generate_artifacts(&results_root, &runner_did, &runner_key)?;

    // Ensure child processes are cleaned up before return (Drop handles).
    drop(server_guard);

    println!("Done. Results written to: {}", results_root.display());
    Ok(())
}

fn resolve_repo_relative(repo_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    }
}

fn write_plots(plots_dir: &Path, rounds: &[RoundMetrics]) -> Result<()> {
    if rounds.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(plots_dir)?;

    let methods: Vec<String> = rounds[0].sybil_at_10.keys().cloned().collect();
    let max_round = rounds.last().map(|r| r.round).unwrap_or(1);

    plot_metric(
        &plots_dir.join("sybil_at_10.png"),
        "Sybil@10 Over Time",
        "Sybil@10",
        rounds,
        &methods,
        max_round,
        |r, m| r.sybil_at_10.get(m).copied().unwrap_or(0.0),
    )?;

    plot_metric(
        &plots_dir.join("ndcg_at_10.png"),
        "nDCG@10 Over Time",
        "nDCG@10",
        rounds,
        &methods,
        max_round,
        |r, m| r.ndcg_at_10.get(m).copied().unwrap_or(0.0),
    )?;

    Ok(())
}

fn plot_metric<F>(
    out_path: &Path,
    title: &str,
    y_label: &str,
    rounds: &[RoundMetrics],
    methods: &[String],
    max_round: u64,
    value: F,
) -> Result<()>
where
    F: Fn(&RoundMetrics, &str) -> f64,
{
    let root = BitMapBackend::new(out_path, (980, 520)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 28))
        .margin(10)
        .x_label_area_size(40)
        .y_label_area_size(60)
        .build_cartesian_2d(1u64..(max_round + 1), 0f64..1f64)?;

    chart
        .configure_mesh()
        .x_desc("Round")
        .y_desc(y_label)
        .draw()?;

    for (idx, method) in methods.iter().enumerate() {
        let style = Palette99::pick(idx).stroke_width(2);
        let series = rounds
            .iter()
            .map(|r| (r.round, value(r, method.as_str())));
        chart
            .draw_series(LineSeries::new(series, style.clone()))?
            .label(method.clone())
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 18, y)], style.clone())
            });
    }

    chart
        .configure_series_labels()
        .background_style(&WHITE.mix(0.8))
        .border_style(&BLACK)
        .draw()?;

    root.present()?;
    Ok(())
}

fn generate_artifacts(results_root: &Path, signer_did: &str, signer_key: &SigningKey) -> Result<()> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in walk_dir_files(results_root)? {
        let rel = entry.strip_prefix(results_root).unwrap_or(&entry);
        let name = rel.to_string_lossy();
        if name == "artifacts.sha256.json"
            || name == "artifacts.merkle_root_hex"
            || name == "artifacts.signature"
        {
            continue;
        }
        files.push(entry);
    }
    files.sort();

    let mut sha256_map: BTreeMap<String, String> = BTreeMap::new();
    for path in &files {
        let rel = path.strip_prefix(results_root).unwrap_or(path);
        let bytes = std::fs::read(path)?;
        let digest = Sha256::digest(&bytes);
        sha256_map.insert(rel.to_string_lossy().to_string(), hex::encode(digest));
    }

    let sha_path = results_root.join("artifacts.sha256.json");
    std::fs::write(&sha_path, serde_json::to_vec_pretty(&sha256_map)?)?;

    // Merkle root over (path, sha256) pairs.
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for (path, hash_hex) in &sha256_map {
        let mut h = Sha256::new();
        h.update(path.as_bytes());
        h.update(&[0u8]);
        h.update(hash_hex.as_bytes());
        let digest = h.finalize();
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&digest[..32]);
        leaves.push(leaf);
    }

    let root = merkle_root_sha256(&leaves);
    let root_hex = hex::encode(root);
    std::fs::write(results_root.join("artifacts.merkle_root_hex"), format!("{root_hex}\n"))?;

    let signature: Signature = signer_key.sign(root.as_slice());
    let sig_hex = hex::encode(signature.to_bytes());
    let sig_obj = serde_json::json!({
        "signer_did": signer_did,
        "algorithm": "ed25519",
        "merkle_root_hex": root_hex,
        "signature_hex": sig_hex,
    });
    std::fs::write(
        results_root.join("artifacts.signature"),
        serde_json::to_vec_pretty(&sig_obj)?,
    )?;

    Ok(())
}

fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::new();
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            let mut h = Sha256::new();
            h.update(&left);
            h.update(&right);
            let digest = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest[..32]);
            next.push(out);
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn walk_dir_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    Ok(out)
}

fn dataset_synthetic_impl(args: DatasetSyntheticArgs) -> Result<()> {
    let repo_root = repo_root_from_manifest()?;
    let out_dir = resolve_repo_relative(&repo_root, &args.out);
    std::fs::create_dir_all(&out_dir)?;
    let did_domain = "127.0.0.1%3A8000";
    let endpoint = "http://127.0.0.1:8080";

    let mut rng = rand::rngs::StdRng::seed_from_u64(args.seed);
    let topics = vec![
        "machine learning",
        "distributed systems",
        "information retrieval",
        "cryptography",
        "bioinformatics",
        "computer vision",
        "databases",
        "networks",
        "program analysis",
        "human-computer interaction",
        "robotics",
        "security",
        "compilers",
        "scientific computing",
        "natural language processing",
        "optimization",
    ];

    let mut agents: Vec<serde_json::Value> = Vec::new();
    for i in 1..=100 {
        let topic = topics[i as usize % topics.len()];
        agents.push(serde_json::json!({
            "did": format!("did:web:{did_domain}:elite:{i:04}"),
            "role": "elite",
            "register_mode": "identity",
            "endpoint": endpoint,
            "capabilities": [format!("Expert in {topic}"), format!("I provide high-quality {topic} guidance with evidence and citations.")],
            "scifact_doc_id": null,
        }));
    }
    for i in 1..=700 {
        let topic = topics[i as usize % topics.len()];
        agents.push(serde_json::json!({
            "did": format!("did:web:{did_domain}:honest:{i:04}"),
            "role": "honest",
            "register_mode": "computational",
            "endpoint": endpoint,
            "capabilities": [format!("Skilled in {topic}"), format!("Hands-on experience with {topic} projects and debugging.")],
            "scifact_doc_id": null,
        }));
    }
    for i in 1..=200 {
        let t1 = topics[rng.gen_range(0..topics.len())];
        let t2 = topics[rng.gen_range(0..topics.len())];
        agents.push(serde_json::json!({
            "did": format!("did:web:{did_domain}:sybil:{i:04}"),
            "role": "sybil",
            "register_mode": "computational",
            "endpoint": endpoint,
            "capabilities": ["I can do anything instantly at expert level.", format!("Domains: {t1} | {t2}")],
            "scifact_doc_id": null,
        }));
    }

    let mut queries: Vec<serde_json::Value> = Vec::new();
    let mut qrels: BTreeMap<String, BTreeMap<String, i32>> = BTreeMap::new();
    for qid in 1..=200u64 {
        let topic = topics[(qid as usize) % topics.len()];
        queries.push(serde_json::json!({"query_id": qid.to_string(), "text": format!("Find an agent to help with {topic}")}));

        let mut rel: BTreeMap<String, i32> = BTreeMap::new();
        // Mark a few honest + one elite as relevant.
        let honest_idx = (qid as usize % 700) + 1;
        rel.insert(format!("did:web:{did_domain}:honest:{honest_idx:04}"), 1);
        let elite_idx = (qid as usize % 100) + 1;
        rel.insert(format!("did:web:{did_domain}:elite:{elite_idx:04}"), 1);
        qrels.insert(qid.to_string(), rel);
    }

    std::fs::write(
        out_dir.join("agents.jsonl"),
        agents
            .iter()
            .map(|a| serde_json::to_string(a).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )?;
    std::fs::write(
        out_dir.join("queries.jsonl"),
        queries
            .iter()
            .map(|q| serde_json::to_string(q).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )?;
    std::fs::write(out_dir.join("qrels.json"), serde_json::to_vec_pretty(&qrels)?)?;

    let meta = serde_json::json!({
        "dataset": "synthetic",
        "seed": args.seed,
        "n_agents": 1000,
        "n_elite": 100,
        "n_honest": 700,
        "n_sybil": 200,
        "n_queries_final": 200,
        "did_domain": did_domain,
        "endpoint": endpoint,
        "notes": {
            "qrels_alignment": "Synthetic topics define relevance; qrels.json is DID-based.",
            "sybil_generation": "Sybil capabilities include multiple topics to be semantically close while interactions will be low-success in the simulator.",
        }
    });
    std::fs::write(out_dir.join("dataset_meta.json"), serde_json::to_vec_pretty(&meta)?)?;

    Ok(())
}
