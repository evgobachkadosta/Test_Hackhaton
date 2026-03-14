use axum::{extract::State, Json, http::StatusCode};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{Signer, SignatureEncoding};
use rsa::pkcs8::DecodePrivateKey;
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::payloads::{
    ExchangeTokenRequest, IssueTokenRequest, IssuerMetadataResponse,
    VerifyTokenRequest,
};
use crate::states::{FtpJwtClaims, SharedIssuerState};


fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn issue_jwt(state: &SharedIssuerState, claim: &str, subject: &str) -> Result<(String, usize), StatusCode> {
    let exp = now_secs() as usize + state.ttl as usize;
    let claims = FtpJwtClaims { iss: state.issuer_id.clone(), exp, claim: claim.to_string(), sub: subject.to_string(), jti: Uuid::new_v4().to_string()};
    let key = EncodingKey::from_rsa_pem(state.private_key_pem.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token = encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((token, exp))
}

fn decoding_key_for(n: &str, e: &str) -> Result<DecodingKey, StatusCode> {
    DecodingKey::from_rsa_components(n, e).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn fctp_validation(issuer_id: &str) -> Validation {
    let mut v = Validation::new(Algorithm::RS256);
    v.validate_aud = false;
    v.set_issuer(&[issuer_id]);
    v
}

pub async fn get_metadata(State(state): State<SharedIssuerState>) -> Json<IssuerMetadataResponse> {
    let trusts:  Vec<String> = state.trusts.read().await.iter().cloned().collect();
    let parents: Vec<String> = state.parents.read().await.iter().cloned().collect();
    Json(IssuerMetadataResponse {
        issuer_id: state.issuer_id.clone(),
        display_name: state.display_name.clone(),
        verification_delegation: state.verification_delegation.clone(),
        public_key: state.public_key_jwk.clone(),
        token_formats: vec!["jwt".to_string()],
        claim: state.claim.clone(),
        trusts,
        parents,
        ttl: state.ttl,
    })
}

pub async fn exchange_token(
    State(state): State<SharedIssuerState>,
    Json(payload): Json<ExchangeTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let child_node = {
        let cache = state.trust_cache.read().await;
        cache.get(&payload.child_issuer_id).cloned().ok_or_else(|| {
            tracing::warn!("{}: exchange_token - '{}' not in trust cache", state.issuer_id, payload.child_issuer_id);
            StatusCode::FORBIDDEN
        })?
    };

    if child_node.verification_delegation == "call" {
        tracing::info!(
            "{}: delegation=call - forwarding to {}/verify_token",
            state.issuer_id, payload.child_issuer_id
        );
        let url  = format!("{}/verify_token", payload.child_issuer_id);
        let body = serde_json::json!({
            "token":      payload.child_token,
            "token_type": payload.child_token_type,
            "claim":      payload.claim,
        });
        let resp = state.http_client.post(&url).json(&body).send().await
            .map_err(|e| { tracing::error!("{}: delegation HTTP error: {}", state.issuer_id, e); StatusCode::BAD_GATEWAY })?;

        if !resp.status().is_success() {
            tracing::warn!("{}: child /verify_token returned {}", state.issuer_id, resp.status());
            return Err(StatusCode::FORBIDDEN);
        }
        let result: serde_json::Value = resp.json().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

        if !result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false) {
            tracing::warn!("{}: child reported token invalid", state.issuer_id);
            return Err(StatusCode::FORBIDDEN);
        }
        let returned = result.get("claim").and_then(|c| c.as_str()).unwrap_or("");
        if returned != payload.claim {
            tracing::warn!("{}: claim mismatch after delegation (got '{}', wanted '{}')", state.issuer_id, returned, payload.claim);
            return Err(StatusCode::FORBIDDEN);
        }
    } else {
        return Err(StatusCode::BAD_REQUEST);
    }

    let (fresh_token, expires_at) = issue_jwt(&state, &payload.claim, "user")?;
    tracing::info!("{}: 🎫 issued fresh token for '{}' (child: '{}')", state.issuer_id, payload.claim, payload.child_issuer_id);

    Ok(Json(serde_json::json!({
        "token":      fresh_token,
        "token_type": "jwt",
        "claim":      payload.claim,
        "issuer_id":  state.issuer_id,
        "expires_at": expires_at,
        "trust_path": child_node.path,
    })))
}

pub async fn verify_token(
    State(state): State<SharedIssuerState>,
    Json(payload): Json<VerifyTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let dk = decoding_key_for(&state.public_key_jwk.n, &state.public_key_jwk.e)?;
    let token_data = decode::<FtpJwtClaims>(&payload.token, &dk, &fctp_validation(&state.issuer_id))
        .map_err(|e| { tracing::warn!("{}: verify_token invalid JWT: {}", state.issuer_id, e); StatusCode::FORBIDDEN })?;

    if now_secs() as usize > token_data.claims.exp {
        tracing::warn!("{}: expired token for expiry time {} on current time {}", state.issuer_id, token_data.claims.exp, now_secs() as usize);
        return Err(StatusCode::FORBIDDEN);
    }

    if token_data.claims.claim != payload.claim {
        tracing::warn!("{}: verify_token claim mismatch (token='{}', request='{}')", state.issuer_id, token_data.claims.claim, payload.claim);
        return Err(StatusCode::FORBIDDEN);
    }

    let mut hasher = Sha256::new();
    hasher.update(payload.token.as_bytes());
    let nullifier = format!("{:x}", hasher.finalize());

    if !state.nullifiers.write().await.insert(nullifier) {
        tracing::warn!("{}: verify_token token already spent (replay attempt)", state.issuer_id);
        return Err(StatusCode::FORBIDDEN);
    }

    // TODO actually sign with key
    let nonce_sig = if let Some(nonce) = payload.nonce {
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(&state.private_key_pem)
            .map_err(|e| {
                tracing::error!("{}: failed to parse private key for signing: {}", state.issuer_id, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            
        let signing_key = SigningKey::<Sha256>::new(private_key);
        
        let data_to_sign = format!("{}:{}:{}", state.issuer_id, payload.token, nonce);
        
        // Sign and Base64 encode
        let signature = signing_key.sign(data_to_sign.as_bytes());
        Some(STANDARD.encode(signature.to_bytes()))
    } else {
        None
    };
    tracing::info!("{}: ✅ verified token for claim '{}'", state.issuer_id, token_data.claims.claim);

    Ok(Json(serde_json::json!({
        "valid":       true,
        "claim":       token_data.claims.claim,
        "issuer_id":   state.issuer_id,
        "verified_at": now_secs(),
        "nonce_sig":   nonce_sig,
    })))
}

pub async fn issue_token(
    State(state): State<SharedIssuerState>,
    Json(payload): Json<IssueTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if state.claim != payload.claim {
        tracing::warn!("{}: issue_token claim '{}' not supported", state.issuer_id, payload.claim);
        return Err(StatusCode::FORBIDDEN);
    }
    let (token, expires_at) = issue_jwt(&state, &payload.claim, "user")?;
    tracing::info!("{}: 🪙  minted leaf token for claim '{}'", state.issuer_id, payload.claim);
    Ok(Json(serde_json::json!({
        "token":      token,
        "token_type": "jwt",
        "issuer_id":  state.issuer_id,
        "claim":      payload.claim,
        "expires_at": expires_at,
    })))
}
