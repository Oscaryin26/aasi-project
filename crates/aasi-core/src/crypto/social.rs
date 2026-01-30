use anyhow::{Result, anyhow};
use reqwest::header::USER_AGENT;
use crate::core::models::Credential;

pub struct SocialVerifier;

impl SocialVerifier {
    pub fn new() -> Self {
        Self
    }

    pub async fn verify_credential(&self, cred: &Credential, did: &str) -> Result<bool> {
        match cred.provider.as_str() {
            "github" => self.verify_github(&cred.id, &cred.proof, did).await,
            // "twitter" => self.verify_twitter(...),
            _ => Err(anyhow!("Unsupported provider: {}", cred.provider)),
        }
    }

    async fn verify_github(&self, username: &str, gist_url: &str, did: &str) -> Result<bool> {
        // 1. Validate URL host
        if !gist_url.starts_with("https://gist.github.com/") {
            return Err(anyhow!("Invalid Gist URL"));
        }

        // 2. Fetch Gist Content
        // Raw URL usually: https://gist.githubusercontent.com/<user>/<id>/raw
        // If user provides the UI URL, we might need to transform it or just scrape.
        // For MVP, assume user provides raw URL or handle simple transformation?
        // Let's expect Raw URL for simplicity or handle UI url.
        // GitHub API is better but requires token for higher rates. Public raw fetch is easier.
        
        let client = reqwest::Client::new();
        let resp = client.get(gist_url)
            .header(USER_AGENT, "AASI-Verifier/1.0")
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to fetch Gist: {}", resp.status()));
        }

        let content = resp.text().await?;

        // 3. Verify Content
        // Check if the Gist content contains the DID signature or just the DID itself as a simple claim?
        // Spec says: "Check if body contains did".
        if content.contains(did) {
            // Optional: Check if the Gist owner matches `username`.
            // With Raw URL, URL structure contains username.
            // https://gist.githubusercontent.com/USERNAME/ID/raw...
            if gist_url.contains(username) {
                return Ok(true);
            } else {
                return Err(anyhow!("Gist URL does not match claimed username"));
            }
        }

        Ok(false)
    }
}
