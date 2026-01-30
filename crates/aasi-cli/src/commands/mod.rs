use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(name = "aasi-cli")]
#[command(about = "AASI Command Line Interface", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Server address
    #[arg(short, long, default_value = "http://[::1]:50051")]
    pub server: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Register a new agent
    Register(RegisterArgs),
    /// Search for agents
    Search(SearchArgs),
    /// Verify an agent's inclusion in the transparency log
    Verify(VerifyArgs),
    /// Submit feedback for an interaction
    Feedback(FeedbackArgs),
}

#[derive(Args)]
pub struct RegisterArgs {
    /// Decentralized Identifier (e.g., did:web:example.com)
    #[arg(long)]
    pub did: String,

    /// Capability description
    #[arg(long)]
    pub capability: String,

    /// Service endpoint
    #[arg(long)]
    pub endpoint: String,

    /// Mode: 'identity' or 'computational'
    #[arg(long, default_value = "computational")]
    pub mode: String,

    /// Path to private key file (for identity mode)
    #[arg(long)]
    pub key_file: Option<String>,
}

#[derive(Args)]
pub struct SearchArgs {
    /// Natural language query
    #[arg(long)]
    pub query: String,

    /// Limit results
    #[arg(long, default_value_t = 5)]
    pub limit: u64,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Index in the Merkle Log
    #[arg(long)]
    pub index: u64,
}

#[derive(Args)]
pub struct FeedbackArgs {
    /// Reporter DID
    #[arg(long)]
    pub reporter_did: String,

    /// Target DID (Agent being rated)
    #[arg(long)]
    pub target_did: String,

    /// Success? (true/false)
    #[arg(long)]
    pub success: bool,

    /// Path to reporter's private key file
    #[arg(long)]
    pub key_file: String,
}
