use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::Deserialize;
use ed25519_dalek::VerifyingKey;
use std::convert::TryFrom;

#[derive(Debug, Deserialize)]
struct DidDocument {
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethod>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VerificationMethod {
    id: String,
    #[serde(rename = "type")]
    type_: String,
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: Option<PublicKeyJwk>,
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicKeyJwk {
    kty: String,
    crv: String,
    x: String, // Base64URL encoded public key
}

pub struct DidResolver {
    client: Client,
}

impl DidResolver {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub async fn resolve_did_web(&self, did: &str) -> Result<VerifyingKey> {
        // 1. Parse did:web:domain
        if !did.starts_with("did:web:") {
            return Err(anyhow!("Unsupported DID method. Only did:web is supported."));
        }
        
        let rest = &did["did:web:".len()..];
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.is_empty() {
             return Err(anyhow!("Invalid DID format"));
        }

        let domain_raw = parts[0];
        // Decode URL encoding for domain (e.g. %3A -> :)
        let domain = percent_encoding::percent_decode_str(domain_raw).decode_utf8()?.to_string();

        // Path segments (if any)
        let path = parts[1..].join("/");
        
        // Scheme selection: HTTP for localhost, HTTPS otherwise
        let scheme = if domain.starts_with("localhost") || domain.starts_with("127.0.0.1") {
            "http"
        } else {
            "https"
        };

        let url = if path.is_empty() {
            format!("{}://{}/.well-known/did.json", scheme, domain)
        } else {
            format!("{}://{}/{}/did.json", scheme, domain, path)
        };
        
        // 2. Fetch
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Failed to fetch DID document: {}", resp.status()));
        }
        
        let doc: DidDocument = resp.json().await?;
        
        // 3. Find valid key
        for vm in doc.verification_method {
            if let Some(jwk) = vm.public_key_jwk {
                if jwk.kty == "OKP" && jwk.crv == "Ed25519" {
                    let bytes = base64_url_decode(&jwk.x)?;
                    return VerifyingKey::try_from(bytes.as_slice()).map_err(|_| anyhow!("Invalid public key length"));
                }
            }
        }

        Err(anyhow!("No supported Ed25519 public key found in DID document."))
    }
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(input).map_err(|e| anyhow!("Base64 decode error: {}", e))
}
