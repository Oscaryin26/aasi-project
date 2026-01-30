use aasi_proto::aasi::v1::{
    discovery_service_client::DiscoveryServiceClient,
    AgentManifest, TrustProof, ComputationalProof, IdentityProof,
    RegisterRequest, SearchRequest, VerifyRequest, FeedbackRequest,
    trust_proof::Proof, ParamsRequest
};
use aasi_client::pow::generate_work;
use aasi_client::signer::{sign_manifest, sign_feedback};
use clap::Parser;
use anyhow::{Result, anyhow};
use ed25519_dalek::SigningKey;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;

mod commands;
use commands::{Cli, Commands, RegisterArgs, SearchArgs, VerifyArgs, FeedbackArgs};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    let mut client = DiscoveryServiceClient::connect(cli.server).await?;

    match cli.command {
        Commands::Register(args) => handle_register(&mut client, args).await?,
        Commands::Search(args) => handle_search(&mut client, args).await?,
        Commands::Verify(args) => handle_verify(&mut client, args).await?,
        Commands::Feedback(args) => handle_feedback(&mut client, args).await?,
    }

    Ok(())
}

async fn handle_register(
    client: &mut DiscoveryServiceClient<tonic::transport::Channel>,
    args: RegisterArgs
) -> Result<()> {
    println!("Registering agent {}...", args.did);

    // 1. Get Network Params (Difficulty)
    let params_resp = client.get_network_params(ParamsRequest {}).await?.into_inner();
    let difficulty = params_resp.difficulty;
    let server_time = params_resp.server_timestamp;
    let argon_params_proto = params_resp.current_argon_params.ok_or(anyhow!("Missing Argon params"))?;

    // 2. Prepare Manifest Base
    let mut manifest = AgentManifest {
        did: args.did.clone(),
        version: 1,
        timestamp: server_time,
        capabilities: vec![args.capability],
        trust_proof: None, // Filled later
        endpoint: args.endpoint,
        embedding: vec![], // Empty for client init
    };

    // 3. Generate Trust Proof
    let proof = if args.mode == "identity" {
        let key_path = args.key_file.ok_or(anyhow!("--key-file required for identity mode"))?;
        // Read key (assume raw bytes or hex)
        let key_bytes = fs::read(&key_path).or_else(|_| {
             // Try reading as hex string
             let content = fs::read_to_string(&key_path).map_err(|e| hex::FromHexError::from(hex::FromHexError::OddLength))?; // Dummy err, we just want to try hex decode next
             hex::decode(content.trim())
        })?;
        
        let signing_key = SigningKey::try_from(key_bytes.as_slice())
            .map_err(|_| anyhow!("Invalid private key"))?;
            
        let sig = sign_manifest(&signing_key, &manifest).map_err(|e| anyhow!(e))?;
        
        TrustProof {
            proof: Some(Proof::Identity(IdentityProof {
                domain_signature: sig,
                verifiable_credentials: vec![], // Optional
            })),
        }
    } else {
        println!("Solving PoW (Difficulty: {})...", difficulty);
        let (nonce, hash) = generate_work(&args.did, difficulty, server_time, &argon_params_proto)
            .map_err(|e| anyhow!(e))?;
        println!("PoW Solved! Nonce: {}", nonce);
        
        TrustProof {
            proof: Some(Proof::Computational(ComputationalProof {
                argon2_params: Some(argon_params_proto),
                nonce,
                hash,
                difficulty,
            })),
        }
    };

    manifest.trust_proof = Some(proof);

    // 4. Send Request
    let response = client.register_agent(RegisterRequest {
        manifest: Some(manifest),
    }).await?.into_inner();

    if response.success {
        println!("✅ Registration Successful!");
        println!("ID: {}", response.registration_id);
        println!("Merkle Root: {}", response.merkle_root_hex);
    } else {
        println!("❌ Registration Failed: {}", response.message);
    }

    Ok(())
}

async fn handle_search(
    client: &mut DiscoveryServiceClient<tonic::transport::Channel>,
    args: SearchArgs
) -> Result<()> {
    println!("Searching for: '{}'", args.query);
    
    let response = client.search_agents(SearchRequest {
        query_text: args.query,
        min_trust_score: 0.0,
        required_credentials: vec![],
        limit: args.limit,
    }).await?.into_inner();

    if response.results.is_empty() {
        println!("No agents found.");
        return Ok(());
    }

    println!("{:<40} | {:<10} | {:<10} | {:<10}", "DID", "Score", "Trust", "Perf");
    println!("{:-<80}", "");
    for agent in response.results {
        if let Some(m) = agent.manifest {
            println!("{:<40} | {:<10.4} | {:<10.2} | {:<10.2}", 
                m.did, agent.score, agent.rank_trust, agent.rank_performance);
            println!("  Capabilities: {:?}", m.capabilities);
            println!("  Endpoint: {}", m.endpoint);
            println!();
        }
    }

    Ok(())
}

async fn handle_verify(
    client: &mut DiscoveryServiceClient<tonic::transport::Channel>,
    args: VerifyArgs
) -> Result<()> {
    let response = client.verify_inclusion(VerifyRequest {
        target: Some(aasi_proto::aasi::v1::verify_request::Target::Index(args.index)),
    }).await?.into_inner();

    if response.included {
        println!("✅ Agent Included in Merkle Log");
        println!("Root: {}", response.merkle_root_hex);
        println!("Proof Path Length: {}", response.proof_hashes.len());
    } else {
        println!("❌ Verification Failed (Not included)");
    }
    Ok(())
}

async fn handle_feedback(
    client: &mut DiscoveryServiceClient<tonic::transport::Channel>,
    args: FeedbackArgs
) -> Result<()> {
    // Load key
    let key_bytes = fs::read(&args.key_file).or_else(|_| {
         let content = fs::read_to_string(&args.key_file).map_err(|_| hex::FromHexError::OddLength)?; // Dummy err
         hex::decode(content.trim())
    })?;
    let signing_key = SigningKey::try_from(key_bytes.as_slice()).map_err(|_| anyhow!("Invalid Key"))?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let nonce: u64 = rand::random();

    let mut feedback = FeedbackRequest {
        reporter_did: args.reporter_did,
        target_did: args.target_did,
        success: args.success,
        timestamp: now,
        nonce,
        signature: vec![],
    };

    sign_feedback(&signing_key, &mut feedback).map_err(|e| anyhow!(e))?;

    let response = client.submit_feedback(feedback).await?.into_inner();
    println!("Feedback status: {}", response.message);

    Ok(())
}