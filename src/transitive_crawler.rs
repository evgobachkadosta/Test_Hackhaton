use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::payloads::IssuerMetadataResponse;
use crate::states::{CachedNode, SharedIssuerState};

/// Returns true if the scheme+authority (origin) of `fetched_url` exactly
/// matches the scheme+authority declared as `issuer_id` in the metadata.
/// Per spec §4.1 Origin Matching Rule.
fn origins_match(fetched_url: &str, declared_issuer_id: &str) -> bool {
    fn extract_origin(url: &str) -> Option<&str> {
        // Expect "scheme://authority/path" — origin is everything up to the
        // third slash (or end of string if no path slash exists).
        let after_scheme = url.find("://").map(|i| i + 3)?;
        let rest = &url[after_scheme..];
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let origin_end = after_scheme + authority_end;
        // Include the scheme prefix: url[..origin_end]
        Some(&url[..origin_end])
    }

    match (extract_origin(fetched_url), extract_origin(declared_issuer_id)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Rebuild the transitive trust cache via iterative BFS.
/// Iterative (not async-recursive) to avoid &mut-across-await Send errors.
pub async fn execute_crawl(state: SharedIssuerState) {
    let direct_trusts: Vec<String> = state.trusts.read().await.iter().cloned().collect();
    let mut new_cache: HashMap<String, CachedNode> = HashMap::new();
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(state.issuer_id.clone()); // never crawl ourselves

    let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
    for child_id in &direct_trusts {
        queue.push_back((child_id.clone(), vec![state.issuer_id.clone(), child_id.clone()]));
    }

    while let Some((target_id, path)) = queue.pop_front() {
        if visited.contains(&target_id) {
            continue;
        }
        visited.insert(target_id.clone());

        let url = format!("{}/.well-known/fctp-issuer", target_id);
        let metadata: IssuerMetadataResponse = match state.http_client.get(&url).send().await {
            Err(e) => { eprintln!("[WARN]  crawl: GET {} failed: {}", url, e); continue; }
            Ok(resp) => match resp.json::<IssuerMetadataResponse>().await {
                Err(e) => { eprintln!("[WARN]  crawl: parse {} failed: {}", url, e); continue; }
                Ok(m) => m,
            },
        };

        // ── Origin Matching Rule (spec §4.1) ───────────────────────────────────
        // The origin of the URL we fetched MUST match the issuer_id declared
        // in the returned metadata. Prevents a compromised node from injecting
        // a foreign issuer_id into the trust cache.
        if !origins_match(&url, &metadata.issuer_id) {
            eprintln!(
                "[WARN]  crawl: origin mismatch for '{}' — declared issuer_id '{}' does not match fetch origin; skipping",
                url, metadata.issuer_id
            );
            continue;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        new_cache.insert(target_id.clone(), CachedNode {
            public_key: metadata.public_key,
            path: path.clone(),
            cached_at: now,
            ttl: metadata.ttl,
            expires_at: now + metadata.ttl,
            verification_delegation: metadata.verification_delegation,
        });

        for grandchild_id in metadata.trusts {
            if !visited.contains(&grandchild_id) {
                let mut new_path = path.clone();
                new_path.push(grandchild_id.clone());
                queue.push_back((grandchild_id, new_path));
            }
        }
    }

    let n = new_cache.len();
    *state.trust_cache.write().await = new_cache;
    println!("[INFO]  {}: crawl complete — {} node(s) cached", state.issuer_id, n);
}
