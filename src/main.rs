mod handlers;
mod payloads;
mod states;
mod transitive_crawler;

use axum::{routing::{get, post}, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use rsa::traits::PublicKeyParts;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use states::{IssuerState, Jwk, SharedIssuerState};

#[derive(Parser, Debug)]
#[command(name = "fctp-node", about = "FCTP Issuer")]
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

    /// Issuer IDs this node directly trusts
    #[arg(long)]
    trusts: Vec<String>,

    /// Issuer IDs that are parents of this node
    #[arg(long)]
    parents: Vec<String>,

    // The claim this Issuer gives
    #[arg(long)]
    claim: String,

    /// Cache / public key TTL in seconds
    #[arg(long, default_value = "3600")]
    ttl: u64,

    // How parents should verify the tokens of this issuer
    // Currently only supports 'call' mode
    #[arg(long, default_value = "call")]
    verification_delegation: String,
}

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
    tracing::info!("  parents:    {:?}", args.parents);
    tracing::info!("  claim:     {:?}", args.claim);
    tracing::info!("  delegation: {}", args.verification_delegation);

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

    let trusts:  HashSet<String> = args.trusts.iter().cloned().collect();
    let parents: HashSet<String> = args.parents.iter().cloned().collect();

    let state: SharedIssuerState = Arc::new(IssuerState {
        issuer_id:   args.issuer_id.clone(),
        display_name: args.display_name.clone(),
        private_key_pem,
        public_key_jwk: jwk,
        ttl:   args.ttl,
        claim: args.claim.clone(),
        verification_delegation: args.verification_delegation.clone(),
        trusts:      RwLock::new(trusts),
        parents:     RwLock::new(parents),
        trust_cache: RwLock::new(HashMap::new()),
        nullifiers:  RwLock::new(HashSet::new()),
        http_client: reqwest::Client::new(),
    });

    // Background crawl
    {
        let bg  = state.clone();
        let ttl = args.ttl;
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            transitive_crawler::execute_crawl(bg.clone()).await;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(ttl)).await;
                transitive_crawler::execute_crawl(bg.clone()).await;
            }
        });
    }

    let app = Router::new()
        .route("/.well-known/fctp-issuer", get(handlers::get_metadata))
        .route("/exchange_token",          post(handlers::exchange_token))
        .route("/verify_token",            post(handlers::verify_token))
        .route("/issue_token",             post(handlers::issue_token)) // demo only
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.port);
    tracing::info!("🌐 '{}' listening on {}", args.display_name, addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind failed");
    axum::serve(listener, app).await.expect("server error");
}

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
