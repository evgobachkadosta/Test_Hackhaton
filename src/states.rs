use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

/// JWK public key (RSA, n/e in base64url).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub e: String,
    pub n: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// A node that has been cached by the background crawl.
#[derive(Debug, Clone)]
pub struct CachedNode {
    pub public_key: Jwk,
    /// Full trust path from this issuer down to the cached node.
    pub path: Vec<String>,
    pub cached_at: u64,
    pub ttl: u64,
    pub expires_at: u64,
    /// "local" → verify JWT ourselves using cached pubkey.
    /// "call"  → forward the token to the child's /verify_token.
    pub verification_delegation: String,
}

pub struct IssuerState {
    pub issuer_id: String,
    pub display_name: String,
    /// PKCS8 PEM — fed into jsonwebtoken's EncodingKey.
    pub private_key_pem: String,
    pub public_key_jwk: Jwk,
    pub ttl: u64,
    pub claims: Vec<String>,
    /// "local" or "call" — served in /.well-known/ftp-issuer metadata.
    pub verification_delegation: String,

    pub trusts: RwLock<HashSet<String>>,
    pub parents: RwLock<HashSet<String>>,
    /// Keyed by issuer_id; rebuilt on every background crawl.
    pub trust_cache: RwLock<HashMap<String, CachedNode>>,
    /// Spent token nullifiers (MD5 of raw JWT string — good enough for PoC).
    pub nullifiers: RwLock<HashSet<String>>,

    pub http_client: reqwest::Client,
}

pub type SharedIssuerState = Arc<IssuerState>;

/// JWT claims for FTP tokens issued by this node.
#[derive(Debug, Serialize, Deserialize)]
pub struct FtpJwtClaims {
    pub iss: String,
    pub exp: usize,
    pub claim: String,
}