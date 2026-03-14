mod handlers;
mod payloads;
mod states;
mod transitive_crawler;

use axum::{routing::{get, post}, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::traits::PublicKeyParts;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use payloads::RegisterParentClaims;
use states::{IssuerState, Jwk, SharedIssuerState};

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "ftp-node", about = "FTP Issuer Node (PoC)")]
struct Args {
    /// Public base URL, e.g. http://localhost:3000  (no trailing slash)
    #[arg(long)]
    issuer_id: String,

    /// Human-readable display name
    #[arg(long)]
    display_name: String,

    /// TCP port to listen on
    #[arg(long)]
    port: u16,

    /// Issuer IDs this node directly trusts (repeat for multiple)
    #[arg(long)]
    trusts: Vec<String>,

    /// Claims this node can issue (repeat for multiple)
    #[arg(long)]
    claims: Vec<String>,

    /// Cache / token TTL in seconds
    #[arg(long, default_value = "3600")]
    ttl: u64,

    /// How parents should verify our tokens: "local" or "call"
    #[arg(long, default_value = "local")]
    verification_delegation: String,
}

// ── Entry point ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();

    tracing::info!(
        "Starting '{}' ({}) on :{}", args.display_name, args.issuer_id, args.port
    );
    tracing::info!("  trusts:     {:?}", args.trusts);
    tracing::info!("  claims:     {:?}", args.claims);
    tracing::info!("  delegation: {}", args.verification_delegation);

    // ── RSA-2048 key generation ────────────────────────────────────────────────
    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .expect("RSA-2048 keygen failed");
    let public_key  = rsa::RsaPublicKey::from(&private_key);

    use pkcs8::EncodePrivateKey;
    let pem_doc = private_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .expect("PKCS8 PEM export failed");
    let private_key_pem: String = (*pem_doc).clone();
    let jwk = build_jwk(&public_key, &args.issuer_id);

    // ── Shared state ───────────────────────────────────────────────────────────
    let trusts: HashSet<String> = args.trusts.iter().cloned().collect();
    let state: SharedIssuerState = Arc::new(IssuerState {
        issuer_id:   args.issuer_id.clone(),
        display_name: args.display_name.clone(),
        private_key_pem,
        public_key_jwk: jwk,
        ttl:   args.ttl,
        claims: args.claims.clone(),
        verification_delegation: args.verification_delegation.clone(),
        trusts:      RwLock::new(trusts.clone()),
        parents:     RwLock::new(HashSet::new()),
        trust_cache: RwLock::new(HashMap::new()),
        nullifiers:  RwLock::new(HashSet::new()),
        http_client: reqwest::Client::new(),
    });

    // ── Background task ────────────────────────────────────────────────────────
    // 1. Wait for all nodes to bind their ports.
    // 2. Sign and POST register_parent to each direct child.
    // 3. Run first trust-cache crawl.
    // 4. Re-crawl every TTL seconds to pick up topology changes.
    {
        let bg   = state.clone();
        let kids: Vec<String> = trusts.into_iter().collect();
        let ttl  = args.ttl;
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            for child_id in &kids {
                register_with_child(&bg, child_id).await;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            transitive_crawler::execute_crawl(bg.clone()).await;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(ttl)).await;
                transitive_crawler::execute_crawl(bg.clone()).await;
            }
        });
    }

    // ── Router ─────────────────────────────────────────────────────────────────
    let app = Router::new()
        .route("/.well-known/ftp-issuer", get(handlers::get_metadata))
        .route("/register_parent",        post(handlers::register_parent))
        .route("/exchange_token",         post(handlers::exchange_token))
        .route("/verify_token",           post(handlers::verify_token))
        .route("/issue_token",            post(handlers::issue_token)) // demo only
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.port);
    tracing::info!("🌐 '{}' listening on {}", args.display_name, addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind failed");
    axum::serve(listener, app).await.expect("server error");
}

// ── register_with_child ────────────────────────────────────────────────────────
//
// Build a registration JWT  { iss: our_id, sub: child_id, exp: now+5min }
// signed with our private key, then POST it to the child's /register_parent.
// The child verifies the signature and checks sub == its own issuer_id.

async fn register_with_child(state: &SharedIssuerState, child_id: &str) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let claims = RegisterParentClaims {
        iss: state.issuer_id.clone(),
        sub: child_id.to_string(),
        exp: now + 300,
    };
    let enc_key = match EncodingKey::from_rsa_pem(state.private_key_pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => { tracing::error!("register_with_child: key error: {}", e); return; }
    };
    let sig = match encode(&Header::new(Algorithm::RS256), &claims, &enc_key) {
        Ok(s) => s,
        Err(e) => { tracing::error!("register_with_child: sign error: {}", e); return; }
    };
    let body = serde_json::json!({
        "parent_id":  state.issuer_id,
        "public_key": state.public_key_jwk,
        "signature":  sig,
    });
    let url = format!("{}/register_parent", child_id);

    for attempt in 1u64..=5 {
        match state.http_client.post(&url).json(&body).send().await {
            Ok(r) if r.status().is_success() => {
                tracing::info!("✅ '{}' registered as parent of '{}'", state.issuer_id, child_id);
                return;
            }
            Ok(r) => {
                tracing::warn!("register_with_child: '{}' rejected: {}", child_id, r.status());
                return;
            }
            Err(e) => {
                tracing::warn!("register_with_child: attempt {}/5 → {}: {}", attempt, child_id, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(attempt)).await;
            }
        }
    }
    tracing::error!("❌ failed to register as parent of '{}' after 5 attempts", child_id);
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn build_jwk(public_key: &rsa::RsaPublicKey, issuer_id: &str) -> Jwk {
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    Jwk {
        kty: "RSA".to_string(),
        n:   URL_SAFE_NO_PAD.encode(&n_bytes),
        e:   URL_SAFE_NO_PAD.encode(&e_bytes),
        kid: Some(format!("{}-key", issuer_id)),
    }
}