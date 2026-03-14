use serde::{Deserialize, Serialize};
use crate::states::Jwk;

#[derive(Debug, Serialize, Deserialize)]
pub struct IssuerMetadataResponse {
    pub issuer_id: String,
    pub display_name: String,
    pub verification_delegation: String,
    pub public_key: Jwk,
    pub token_formats: Vec<String>,
    pub claim: String,
    pub trusts: Vec<String>,
    pub parents: Vec<String>,
    pub ttl: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeTokenRequest {
    pub child_token: String,
    pub child_token_type: String,
    pub child_issuer_id: String,
    pub claim: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
    pub token_type: String,
    pub claim: String,
    pub nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueTokenRequest {
    pub claim: String,
}