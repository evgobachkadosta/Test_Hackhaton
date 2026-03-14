use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::payloads::IssuerMetadataResponse;
use crate::states::{CachedNode, SharedIssuerState};

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

        let url = format!("{}/.well-known/ftp-issuer", target_id);
        let metadata: IssuerMetadataResponse = match state.http_client.get(&url).send().await {
            Err(e) => { eprintln!("[WARN]  crawl: GET {} failed: {}", url, e); continue; }
            Ok(resp) => match resp.json::<IssuerMetadataResponse>().await {
                Err(e) => { eprintln!("[WARN]  crawl: parse {} failed: {}", url, e); continue; }
                Ok(m) => m,
            },
        };

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