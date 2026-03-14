use axum::{extract::State, Json, http::StatusCode};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::payloads::{
    ExchangeTokenRequest, IssueTokenRequest, IssuerMetadataResponse,
    VerifyTokenRequest,
};
use crate::states::{FtpJwtClaims, SharedIssuerState};

// ── helpers ────────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn issue_jwt(state: &SharedIssuerState, claim: &str, subject: &str) -> Result<(String, usize), StatusCode> {
    let exp = now_secs() as usize + state.ttl as usize;
    let claims = FtpJwtClaims { iss: state.issuer_id.clone(), exp, claim: claim.to_string(), sub: subject.to_string(),  jti: rand::random()};
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

// ── GET /.well-known/fctp-issuer ───────────────────────────────────────────────

pub async fn get_metadata(State(state): State<SharedIssuerState>) -> Json<IssuerMetadataResponse> {
    let trusts:  Vec<String> = state.trusts.read().await.iter().cloned().collect();
    let parents: Vec<String> = state.parents.read().await.iter().cloned().collect();
    Json(IssuerMetadataResponse {
        issuer_id: state.issuer_id.clone(),
        display_name: state.display_name.clone(),
        verification_delegation: state.verification_delegation.clone(),
        public_key: state.public_key_jwk.clone(),
        token_formats: vec!["jwt".to_string()],
        claims: state.claims.clone(),
        trusts,
        parents,
        ttl: state.ttl,
    })
}

// ── POST /exchange_token ───────────────────────────────────────────────────────
//
// Single-hop exchange.  Two verification paths depending on the child node's
// verification_delegation field in the trust cache:
//
//   "local" — verify the JWT here using the cached public key.
//   "call"  — forward the token to the child's /verify_token endpoint.
//             The child handles nullification, which is required when tokens
//             cannot be verified locally (e.g. blinded schemes, or when the
//             child wants to enforce one-time use at its own boundary).

pub async fn exchange_token(
    State(state): State<SharedIssuerState>,
    Json(payload): Json<ExchangeTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // 1. Trust cache lookup ────────────────────────────────────────────────────
    let child_node = {
        let cache = state.trust_cache.read().await;
        cache.get(&payload.child_issuer_id).cloned().ok_or_else(|| {
            tracing::warn!("{}: exchange_token — '{}' not in trust cache", state.issuer_id, payload.child_issuer_id);
            StatusCode::FORBIDDEN
        })?
    };

    // 2. Verification ──────────────────────────────────────────────────────────
    if child_node.verification_delegation == "call" {
        tracing::info!(
            "{}: delegation=call — forwarding to {}/verify_token",
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

    // 3. Issue fresh token signed by this issuer ───────────────────────────────
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

// ── POST /verify_token ─────────────────────────────────────────────────────────
//
// Verify a token issued by *this* node.  Burns a nullifier on first use.
// Also the endpoint called by parents when delegation="call".

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

    // Nullifier = MD5 of the raw JWT bytes.  First use burns it.
    let nullifier = format!("{:x}", md5::compute(payload.token.as_bytes()));
    if !state.nullifiers.write().await.insert(nullifier) {
        tracing::warn!("{}: verify_token token already spent (replay attempt)", state.issuer_id);
        return Err(StatusCode::FORBIDDEN);
    }

    // In production sign the nonce with our private key here — the client can
    // then verify the RP actually made this call (liveness proof).
    let nonce_sig = payload.nonce.map(|n| format!("sig_over_{}", n));
    tracing::info!("{}: ✅ verified token for claim '{}'", state.issuer_id, token_data.claims.claim);

    Ok(Json(serde_json::json!({
        "valid":       true,
        "claim":       token_data.claims.claim,
        "issuer_id":   state.issuer_id,
        "verified_at": now_secs(),
        "nonce_sig":   nonce_sig,
    })))
}

// ── POST /issue_token  (demo only — no real auth) ──────────────────────────────

pub async fn issue_token(
    State(state): State<SharedIssuerState>,
    Json(payload): Json<IssueTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !state.claims.contains(&payload.claim) {
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
