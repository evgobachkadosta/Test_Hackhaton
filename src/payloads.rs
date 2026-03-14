use serde::{Deserialize, Serialize};
use crate::states::Jwk;

// ── Issuer metadata ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct IssuerMetadataResponse {
    pub issuer_id: String,
    pub display_name: String,
    /// "local" or "call".
    pub verification_delegation: String,
    pub public_key: Jwk,
    pub token_formats: Vec<String>,
    pub claims: Vec<String>,
    pub trusts: Vec<String>,
    pub parents: Vec<String>,
    pub ttl: u64,
}

// ── /register_parent ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterParentRequest {
    pub parent_id: String,
    /// Parent's public key — used to verify the signature JWT below.
    pub public_key: Jwk,
    /// RS256 JWT signed by the parent's private key.
    /// Claims: { iss: parent_id, sub: child_id, exp: <short> }
    /// The `sub` must equal this node's issuer_id.
    pub signature: String,
}

/// Claims carried inside the register_parent signature JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterParentClaims {
    pub iss: String,  // parent_id
    pub sub: String,  // child_id (this node's issuer_id)
    pub exp: usize,
}

// ── /exchange_token ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeTokenRequest {
    pub child_token: String,
    pub child_token_type: String,
    pub child_issuer_id: String,
    pub claim: String,
}

// ── /verify_token ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
    pub token_type: String,
    pub claim: String,
    pub nonce: Option<String>,
}

// ── /issue_token (demo-only) ───────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueTokenRequest {
    pub claim: String,
}