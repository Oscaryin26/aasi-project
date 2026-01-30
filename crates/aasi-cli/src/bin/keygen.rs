use ed25519_dalek::{SigningKey};
use std::fs;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

fn main() {
    let key_bytes = fs::read("identity_key.bin").expect("Read key");
    let signing_key = SigningKey::try_from(key_bytes.as_slice()).expect("Parse key");
    let verifying_key = signing_key.verifying_key();
    let bytes = verifying_key.as_bytes();
    
    let x = URL_SAFE_NO_PAD.encode(bytes);
    
    println!("{{");
    println!("  \"kty\": \"OKP\",");
    println!("  \"crv\": \"Ed25519\",");
    println!("  \"x\": \"{}\"", x);
    println!("}}");
}
