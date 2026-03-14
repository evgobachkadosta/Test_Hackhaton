use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub e: String,
    pub n: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CachedNode {
    pub public_key: Jwk,
    pub path: Vec<String>,
    pub cached_at: u64,
    pub ttl: u64,
    pub verification_delegation: String,
}

pub struct IssuerState {
    pub issuer_id: String,
    pub display_name: String,
    /// PKCS8 PEM for jsonwebtoken
    pub private_key_pem: String,
    pub public_key_jwk: Jwk,
    pub ttl: u64,
    pub claim: String,
    pub verification_delegation: String,

    pub trusts: RwLock<HashSet<String>>,
    pub parents: RwLock<HashSet<String>>,
    pub trust_cache: RwLock<HashMap<String, CachedNode>>,
    // TODO MD5
    pub nullifiers: RwLock<HashSet<String>>,

    pub http_client: reqwest::Client,
}

pub type SharedIssuerState = Arc<IssuerState>;

/// JWT claims for FCTP tokens issued by this node.
#[derive(Debug, Serialize, Deserialize)]
pub struct FtpJwtClaims {
    pub iss: String,
    pub exp: usize,
    pub claim: String,
    pub sub: String,
    pub jti: String
}
