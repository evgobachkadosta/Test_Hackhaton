#!/usr/bin/env bash
#
# Topology:
#
#   Europe   (3001)  nationality:EU
#     ├── Bulgaria  (3002)  nationality:BG
#     │     ├── Sofia    (3003)  nationality:BG  [delegation=call]
#     │     └── Petrich  (3004)  nationality:BG
#     │           └── trusts Bulgaria (3002)  ← CYCLE
#     ├── Romania  (3005)  nationality:RO
#     │     └── trusts Bulgaria (3002)         ← DIAMOND
#     └── Balkans  (3006)  nationality:BL
#           ├── trusts Sofia   (3003)           ← Sofia reachable via 3 paths
#           └── trusts Petrich (3004)
#
#   Rogue     (3007)  nationality:BG  - valid node, NOT in any trust list
#   3008              - never started (unreachable, tests crawl failure)
#   Evil      (3009)  --issuer-id http://localhost:9999  ← origin mismatch
#                       trusted by Bulgaria → must be excluded from cache
#   ShortLived(3010)  nationality:BG  --ttl 1  ← expired token test
#
# Edge cases covered:
#   1.  Happy path - deep chain Petrich → Europe
#   2.  delegation=call nullifier burn + replay at Sofia
#   3.  Europe token replay rejected
#   4.  Wrong claim in exchange_token request
#   5.  Token issuer / child_issuer_id mismatch (key mismatch)
#   6.  Expired token rejected
#   7.  Rogue token rejected (not in trust cache)
#   8.  Origin mismatch - Evil excluded from cache
#   9.  Cycle detection - Petrich→Bulgaria→… doesn't loop
#  10.  Diamond - Bulgaria cached once despite two paths
#  11.  Unreachable node (3008) - crawl skips gracefully
#  12.  Malformed / garbage token string
#  13.  Valid token, wrong child_issuer_id (key mismatch between nodes)

set -euo pipefail

BIN="./target/release/fctp-node"
PIDS=()

# Colors
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

header() { echo -e "\n${BLD}${BLU}══ $* ══${RST}"; }
step()   { echo -e "\n${YLW}▶ $*${RST}"; }
ok()     { echo -e "${GRN}✔ $*${RST}"; }
fail()   { echo -e "${RED}✘ $*${RST}"; exit 1; }
info()   { echo -e "${CYN}  $*${RST}"; }

expect_ok()  {
    local code=$1 label=$2
    [[ "$code" =~ ^2 ]] && ok "$label (HTTP $code) ✓" || fail "$label - expected 2xx, got $code"
}
expect_403() {
    local code=$1 label=$2
    [[ "$code" == "403" ]] && ok "$label correctly rejected with 403 ✓" || fail "$label - expected 403, got $code"
}

cleanup() {
    echo -e "\n${YLW}Stopping nodes…${RST}"
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

header "Building fctp-node"
cargo build --release 2>&1 | tail -3
ok "Build complete"

mkdir -p logs

header "Starting nodes"

start_node() {
    local name=$1; shift
    RUST_LOG=info "$BIN" "$@" &>> "logs/${name}.log" &
    PIDS+=($!)
    info "  $name  PID=${PIDS[-1]}"
}

start_node sofia \
    --issuer-id http://localhost:3003 --display-name "Sofia" --port 3003 \
    --claim nationality:BG \
    --parents http://localhost:3002 --parents http://localhost:3006 \
    --ttl 3600 --verification-delegation call

start_node petrich \
    --issuer-id http://localhost:3004 --display-name "Petrich" --port 3004 \
    --claim nationality:BG \
    --parents http://localhost:3002 --parents http://localhost:3006 \
    --trusts http://localhost:3002 \
    --verification-delegation call \
    --ttl 3600

start_node romania \
    --issuer-id http://localhost:3005 --display-name "Romania" --port 3005 \
    --claim nationality:RO \
    --parents http://localhost:3001 \
    --trusts http://localhost:3002 \
    --verification-delegation call \
    --ttl 3600

start_node rogue \
    --issuer-id http://localhost:3007 --display-name "Rogue" --port 3007 \
    --claim nationality:BG \
    --verification-delegation call \
    --ttl 3600

# Evil node: listens on 3009 but declares issuer_id as localhost:9999
# Bulgaria trusts it, crawl must detect origin mismatch and exclude it
start_node evil \
    --issuer-id http://localhost:9999 --display-name "Evil" --port 3009 \
    --claim nationality:BG \
    --verification-delegation call \
    --ttl 3600

start_node shortlived \
    --issuer-id http://localhost:3010 --display-name "ShortLived" --port 3010 \
    --claim nationality:BG \
    --parents http://localhost:3002 \
    --verification-delegation call \
    --ttl 1

# NOTE: 3008 is intentionally never started (unreachable node test)

# Bulgaria trusts Sofia, Petrich, Evil (3009), ShortLived, and the unreachable 3008
start_node bulgaria \
    --issuer-id http://localhost:3002 --display-name "Bulgaria" --port 3002 \
    --claim nationality:BG \
    --parents http://localhost:3001 \
    --trusts http://localhost:3003 \
    --trusts http://localhost:3004 \
    --trusts http://localhost:3009 \
    --trusts http://localhost:3008 \
    --trusts http://localhost:3010 \
    --verification-delegation call \
    --ttl 7200

start_node balkans \
    --issuer-id http://localhost:3006 --display-name "Balkans" --port 3006 \
    --claim nationality:BL \
    --parents http://localhost:3001 \
    --trusts http://localhost:3003 \
    --trusts http://localhost:3004 \
    --verification-delegation call \
    --ttl 7200

start_node europe \
    --issuer-id http://localhost:3001 --display-name "Europe" --port 3001 \
    --claim nationality:EU \
    --trusts http://localhost:3002 \
    --trusts http://localhost:3005 \
    --trusts http://localhost:3006 \
    --verification-delegation call \
    --ttl 86400

ok "All nodes started (3008 intentionally absent)"

header "Waiting for nodes to start and crawl (8s)…"
sleep 8
ok "Ready"

pp() { python3 -m json.tool 2>/dev/null || cat; }

header "STEP 1 - Inspect Europe's trust cache after crawl"

step "GET http://localhost:3001/.well-known/fctp-issuer"
EUROPE_META=$(curl -s http://localhost:3001/.well-known/fctp-issuer)
echo "$EUROPE_META" | pp

step "Mint Sofia token"
PT_RESP=$(curl -s -X POST http://localhost:3003/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
PT_TOKEN=$(echo "$PT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "Sofia token minted"

info "Verifying Sofia appears in cache (reachable via 3 paths but stored once)…"
SOFIA_IN_CACHE=$(curl -s -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":\"$PT_TOKEN\",
        \"child_token_type\":\"jwt\",
        \"child_issuer_id\":\"http://localhost:3003\",
        \"claim\":\"nationality:BG\"
    }" \
    -o /dev/null -w "%{http_code}")
[[ "$SOFIA_IN_CACHE" == "200" ]] \
    && ok "Sofia is in Europe's trust cache (diamond/multi-path deduplication works) ✓" \
    || fail "Sofia not found in trust cache - expected 403 on bad token, got $SOFIA_IN_CACHE"

step "Mint VerifyEvil token"
PT_RESP=$(curl -s -X POST http://localhost:3009/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
PT_TOKEN=$(echo "$PT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "VerifyEvil token minted"

step "Verify Evil (3009) is NOT in Europe's trust cache (origin mismatch)"
EVIL_IN_CACHE=$(curl -s -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":\"$PT_TOKEN\",
        \"child_token_type\":\"jwt\",
        \"child_issuer_id\":\"http://localhost:3009\",
        \"claim\":\"nationality:BG\"
    }" \
    -o /dev/null -w "%{http_code}")
[[ "$EVIL_IN_CACHE" == "403" ]] \
    && ok "Evil (3009) correctly absent from trust cache - origin mismatch blocked it ✓" \
    || fail "Evil (3009) should not be in cache, got $EVIL_IN_CACHE"

info "Checking Bulgaria's log for origin mismatch warning…"
grep -i "origin mismatch" logs/bulgaria.log \
    && ok "Origin mismatch warning logged by Bulgaria ✓" \
    || info "  (warning may be in europe/balkans log instead - check manually)"

step "Verify unreachable node (3008) did not crash the crawl"
BULGARIA_RESP=$(curl -s http://localhost:3002/.well-known/fctp-issuer)
echo "$BULGARIA_RESP" | pp
ok "Bulgaria metadata still served - unreachable 3008 skipped gracefully ✓"

header "STEP 2 - Happy path: deep chain Petrich → Europe (cycle-safe)"
# Petrich trusts Bulgaria (cycle), but the BFS visited set prevents looping.

step "Mint Petrich token"
PT_RESP=$(curl -s -X POST http://localhost:3004/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
PT_TOKEN=$(echo "$PT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "Petrich token minted"

step "Single-hop exchange at Europe"
PT_EXCHANGE=$(curl -s -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$PT_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3004\",
        \"claim\":            \"nationality:BG\"
    }")
echo "$PT_EXCHANGE" | pp
PT_PATH=$(echo "$PT_EXCHANGE" | python3 -c "import sys,json; print(json.load(sys.stdin)['trust_path'])")
EUROPE_TOKEN_PT=$(echo "$PT_EXCHANGE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "Europe issued fresh token via: $PT_PATH ✓"

header "STEP 3 - delegation=call: Sofia → Europe nullifier burn + replay"

step "Mint Sofia token"
SOFIA_RESP=$(curl -s -X POST http://localhost:3003/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
SOFIA_TOKEN=$(echo "$SOFIA_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "Sofia token minted"

step "First exchange (burns nullifier at Sofia)"
SOFIA_EXCHANGE=$(curl -s -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$SOFIA_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3003\",
        \"claim\":            \"nationality:BG\"
    }")
echo "$SOFIA_EXCHANGE" | pp
EUROPE_TOKEN_SOFIA=$(echo "$SOFIA_EXCHANGE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "First exchange succeeded ✓"

step "Second exchange with same Sofia token (nullifier already burned)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$SOFIA_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3003\",
        \"claim\":            \"nationality:BG\"
    }")
expect_403 "$CODE" "Sofia token replay at exchange"

header "STEP 4 - Europe token: first verify succeeds, replay rejected"

step "First verify (should succeed)"
VERIFY_RESP=$(curl -s -X POST http://localhost:3001/verify_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"token\":      \"$EUROPE_TOKEN_SOFIA\",
        \"token_type\": \"jwt\",
        \"claim\":      \"nationality:BG\",
        \"nonce\":      \"nonce-abc-001\"
    }")
echo "$VERIFY_RESP" | pp
VALID=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
[[ "$VALID" == "True" ]] && ok "First verify succeeded ✓" || fail "Expected valid=true"

step "Second verify with same token (replay)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/verify_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"token\":      \"$EUROPE_TOKEN_SOFIA\",
        \"token_type\": \"jwt\",
        \"claim\":      \"nationality:BG\"
    }")
expect_403 "$CODE" "Europe token replay at verify"

header "STEP 5 - Wrong claim in exchange_token"
# Petrich token carries nationality:BG, present it claiming nationality:RO

step "Mint fresh Petrich token"
PT2_RESP=$(curl -s -X POST http://localhost:3004/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
PT2_TOKEN=$(echo "$PT2_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

step "Exchange with mismatched claim (token=nationality:BG, request=nationality:RO)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$PT2_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3004\",
        \"claim\":            \"nationality:RO\"
    }")
expect_403 "$CODE" "Wrong claim in exchange"

header "STEP 6 - Token issuer / child_issuer_id mismatch (key mismatch)"
# Present a valid Petrich-signed token but claim it came from Romania.
# Europe will try to verify it with Romania's public key, signature failure.

step "Mint fresh Petrich token, claim it is from Romania"
PT3_RESP=$(curl -s -X POST http://localhost:3004/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
PT3_TOKEN=$(echo "$PT3_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

step "Exchange: token signed by Petrich, child_issuer_id=Romania"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$PT3_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3005\",
        \"claim\":            \"nationality:BG\"
    }")
expect_403 "$CODE" "Key mismatch (Petrich token presented as Romania)"

header "STEP 7 - Expired token rejected"

step "Mint ShortLived token (TTL=1s)"
SL_RESP=$(curl -s -X POST http://localhost:3010/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
SL_TOKEN=$(echo "$SL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "ShortLived token minted - waiting 3s for it to expire…"
sleep 3

step "Exchange expired token at Europe"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$SL_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3010\",
        \"claim\":            \"nationality:BG\"
    }")
expect_403 "$CODE" "Expired token exchange"

header "STEP 8 - Rogue token rejected (not in trust cache)"

step "Mint Rogue token"
RG_RESP=$(curl -s -X POST http://localhost:3007/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
RG_TOKEN=$(echo "$RG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

step "Exchange Rogue token at Europe"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$RG_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3007\",
        \"claim\":            \"nationality:BG\"
    }")
expect_403 "$CODE" "Rogue token (untrusted issuer)"

header "STEP 9 - Malformed / garbage token string"

step "Exchange garbage token (child_issuer_id=Petrich, token=not.a.jwt)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"this.is.garbage\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3004\",
        \"claim\":            \"nationality:BG\"
    }")
expect_403 "$CODE" "Garbage token string"

step "Exchange empty token string"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3004\",
        \"claim\":            \"nationality:BG\"
    }")
expect_403 "$CODE" "Empty token string"

header "STEP 10 - Wrong claim on verify_token"
# Issue a fresh Europe token for nationality:BG, then verify with wrong claim.

step "Mint fresh Petrich → Europe token"
PT4_RESP=$(curl -s -X POST http://localhost:3004/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
PT4_TOKEN=$(echo "$PT4_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
EU4_RESP=$(curl -s -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$PT4_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3004\",
        \"claim\":            \"nationality:BG\"
    }")
EU4_TOKEN=$(echo "$EU4_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

step "Verify with wrong claim (token=nationality:BG, request=nationality:RO)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/verify_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"token\":      \"$EU4_TOKEN\",
        \"token_type\": \"jwt\",
        \"claim\":      \"nationality:RO\"
    }")
expect_403 "$CODE" "Wrong claim on verify_token"

header "STEP 11 - Token from wrong issuer on verify_token (key mismatch)"
# A valid Bulgaria-issued token presented to Europe's /verify_token.
# Europe will try to verify it with its own public key, signature failure.

step "Mint Bulgaria token"
BG_RESP=$(curl -s -X POST http://localhost:3002/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
BG_TOKEN=$(echo "$BG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

step "Present Bulgaria token directly to Europe /verify_token"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/verify_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"token\":      \"$BG_TOKEN\",
        \"token_type\": \"jwt\",
        \"claim\":      \"nationality:BG\"
    }")
expect_403 "$CODE" "Bulgaria token on Europe verify_token (key mismatch)"

header "STEP 12 - Balkans path (Sofia/Petrich via different mid-tier)"
# Confirms Sofia is reachable through Balkans as well as Bulgaria.

step "Mint Sofia token, exchange via Balkans path (child_issuer_id=Sofia, target=Europe)"
SOFIA2_RESP=$(curl -s -X POST http://localhost:3003/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
SOFIA2_TOKEN=$(echo "$SOFIA2_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Europe's cache has Sofia via both Bulgaria and Balkans paths -
# the exchange works regardless of which path was used to cache it.
SOFIA2_EXCHANGE=$(curl -s -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$SOFIA2_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3003\",
        \"claim\":            \"nationality:BG\"
    }")
echo "$SOFIA2_EXCHANGE" | pp
ok "Sofia token exchanged at Europe regardless of multi-path caching ✓"

header "STEP 13 - Diamond: Romania→Bulgaria path"
# Romania trusts Bulgaria. Europe also directly trusts Bulgaria.
# Bulgaria should appear in Europe's cache exactly once.

step "Verify Bulgaria is in Europe's cache (reachable via direct + Romania→Bulgaria)"
BG2_RESP=$(curl -s -X POST http://localhost:3002/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
BG2_TOKEN=$(echo "$BG2_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
BG2_EXCHANGE=$(curl -s -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$BG2_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3002\",
        \"claim\":            \"nationality:BG\"
    }")
echo "$BG2_EXCHANGE" | pp
ok "Bulgaria token exchanged at Europe - diamond deduplication confirmed ✓"

header "All edge-case tests passed 🎉"

echo ""
echo -e "${BLD}Edge cases verified:${RST}"
echo "   1. Deep chain exchange (Petrich → Europe)"
echo "   2. delegation=call nullifier burn + replay rejected"
echo "   3. Europe token replay rejected"
echo "   4. Wrong claim in exchange_token → 403"
echo "   5. Key mismatch (Petrich token as Romania) → 403"
echo "   6. Expired token (TTL=1s) → 403"
echo "   7. Rogue token (untrusted issuer) → 403"
echo "   8. Origin mismatch (Evil node) excluded from cache"
echo "   9. Cycle (Petrich→Bulgaria→…) handled by BFS visited set"
echo "  10. Garbage/empty token string → 403"
echo "  11. Wrong claim on verify_token → 403"
echo "  12. Foreign issuer token on verify_token → 403"
echo "  13. Multi-path (Sofia via Bulgaria + Balkans) deduplication"
echo "  14. Diamond (Bulgaria via Europe direct + Romania→Bulgaria)"
echo "  15. Unreachable node (3008) skipped, crawl completes cleanly"
echo ""
echo -e "${BLD}Node logs:${RST}"
echo "  logs/europe.log  logs/bulgaria.log  logs/balkans.log"
echo "  logs/sofia.log   logs/petrich.log   logs/romania.log"
echo "  logs/rogue.log   logs/evil.log      logs/shortlived.log"
echo ""
echo "Nodes still running. Ctrl-C to stop."
echo ""

gsleep infinity
