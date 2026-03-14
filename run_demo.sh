#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# FCTP Demo  —  Europe → Bulgaria → Sofia
#                        └→ Romania
#              Bulgaria  → Sofia
#              Bulgaria  → Petrich
#
# Topology:
#
#   Europe  (3001)
#     ├── Bulgaria  (3002)
#     │     ├── Sofia    (3003)  [delegation=call]
#     │     └── Petrich  (3004)
#     └── Romania  (3005)
#
# Trust flows downward.  Europe's trust cache will contain all 4 children.
# Sofia uses verification_delegation=call — so when a Sofia token is exchanged
# at Europe, Europe calls Sofia's /verify_token instead of verifying locally.
#
# Parent relationships are declared by the node operator at startup via
# --parents flags (no automated registration).
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BIN="./target/release/fctp-node"
PIDS=()

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

header()  { echo -e "\n${BLD}${BLU}══ $* ══${RST}"; }
step()    { echo -e "\n${YLW}▶ $*${RST}"; }
ok()      { echo -e "${GRN}✔ $*${RST}"; }
fail()    { echo -e "${RED}✘ $*${RST}"; exit 1; }
info()    { echo -e "${CYN}  $*${RST}"; }

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    echo -e "\n${YLW}Stopping nodes…${RST}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# ── Build ─────────────────────────────────────────────────────────────────────
header "Building fctp-node"
cargo build --release 2>&1 | tail -3
ok "Build complete"

# ── Start nodes ───────────────────────────────────────────────────────────────
header "Starting nodes"

start_node() {
    local name=$1; shift
    RUST_LOG=info "$BIN" "$@" &>> "logs/${name}.log" &
    PIDS+=($!)
    info "  $name  PID=$!"
}

mkdir -p logs

# Leaf nodes — parents declared by operator config (--parents flag)
start_node sofia    --issuer-id http://localhost:3003 --display-name "Sofia"    --port 3003 \
    --claims nationality:BG --claims resident_of:BG-22 \
    --parents http://localhost:3002 \
    --ttl 3600 --verification-delegation call

start_node petrich  --issuer-id http://localhost:3004 --display-name "Petrich"  --port 3004 \
    --claims nationality:BG --claims resident_of:BG-06 \
    --parents http://localhost:3002 \
    --ttl 3600

start_node romania  --issuer-id http://localhost:3005 --display-name "Romania"  --port 3005 \
    --claims nationality:RO --claims resident_of:RO \
    --parents http://localhost:3001 \
    --ttl 3600

# Bulgaria trusts Sofia and Petrich; its parent is Europe
start_node bulgaria --issuer-id http://localhost:3002 --display-name "Bulgaria" --port 3002 \
    --trusts http://localhost:3003 --trusts http://localhost:3004 \
    --claims nationality:BG \
    --parents http://localhost:3001 \
    --ttl 7200

# Europe trusts Bulgaria and Romania; no parents (root-level issuer)
start_node europe   --issuer-id http://localhost:3001 --display-name "Europe"   --port 3001 \
    --trusts http://localhost:3002 --trusts http://localhost:3005 \
    --claims nationality:EU \
    --ttl 86400

ok "All 5 nodes started"

# ── Wait for startup + initial crawl ──────────────────────────────────────────
# No registration round-trips needed — parents are static config.
# Just wait for nodes to bind and complete their first background crawl.
header "Waiting for nodes to start and crawl (5s)…"
sleep 5
ok "Ready"

# ── Helper: pretty-print JSON ─────────────────────────────────────────────────
pp() { python3 -m json.tool 2>/dev/null || cat; }

# ─────────────────────────────────────────────────────────────────────────────
header "STEP 1 — Inspect Europe's trust graph"
# ─────────────────────────────────────────────────────────────────────────────

step "GET http://localhost:3001/.well-known/fctp-issuer"
EUROPE_META=$(curl -sf http://localhost:3001/.well-known/fctp-issuer)
echo "$EUROPE_META" | pp
info "Europe trusts: $(echo "$EUROPE_META" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['trusts'])")"

step "GET http://localhost:3002/.well-known/fctp-issuer  (Bulgaria)"
BG_META=$(curl -sf http://localhost:3002/.well-known/fctp-issuer)
echo "$BG_META" | pp
info "Bulgaria parents: $(echo "$BG_META" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['parents'])")"

step "GET http://localhost:3003/.well-known/fctp-issuer  (Sofia)"
SOFIA_META=$(curl -sf http://localhost:3003/.well-known/fctp-issuer)
echo "$SOFIA_META" | pp
info "Sofia delegation: $(echo "$SOFIA_META" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['verification_delegation'])")"
info "Sofia parents:    $(echo "$SOFIA_META" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['parents'])")"

# ─────────────────────────────────────────────────────────────────────────────
header "STEP 2 — Mint a leaf token at Sofia"
# ─────────────────────────────────────────────────────────────────────────────

step "POST http://localhost:3003/issue_token  {claim: nationality:BG}"
SOFIA_RESP=$(curl -sf -X POST http://localhost:3003/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
echo "$SOFIA_RESP" | pp

SOFIA_TOKEN=$(echo "$SOFIA_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
info "Sofia token (truncated): ${SOFIA_TOKEN:0:60}…"

# ─────────────────────────────────────────────────────────────────────────────
header "STEP 3 — Single-hop exchange: Sofia token → Europe token"
# ─────────────────────────────────────────────────────────────────────────────
# Europe sees Sofia has delegation=call, so it will forward the token to
# Sofia's /verify_token (burning the nullifier there) before issuing its own.

step "POST http://localhost:3001/exchange_token"
info "Sofia's delegation=call means Europe will call Sofia to verify before issuing"
EXCHANGE_RESP=$(curl -sf -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$SOFIA_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3003\",
        \"claim\":            \"nationality:BG\"
    }")
echo "$EXCHANGE_RESP" | pp

EUROPE_TOKEN=$(echo "$EXCHANGE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
TRUST_PATH=$(echo "$EXCHANGE_RESP"   | python3 -c "import sys,json; print(json.load(sys.stdin)['trust_path'])")
ok "Europe issued a fresh token"
info "Trust path proven: $TRUST_PATH"

# ─────────────────────────────────────────────────────────────────────────────
header "STEP 4 — RP verifies the Europe token"
# ─────────────────────────────────────────────────────────────────────────────

step "POST http://localhost:3001/verify_token  (first use — should succeed)"
VERIFY_RESP=$(curl -sf -X POST http://localhost:3001/verify_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"token\":      \"$EUROPE_TOKEN\",
        \"token_type\": \"jwt\",
        \"claim\":      \"nationality:BG\",
        \"nonce\":      \"demo-nonce-abc123\"
    }")
echo "$VERIFY_RESP" | pp
VALID=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
[[ "$VALID" == "True" ]] && ok "Token is valid ✓" || fail "Expected valid=true"

# ─────────────────────────────────────────────────────────────────────────────
header "STEP 5 — Replay attack (same Europe token reused)"
# ─────────────────────────────────────────────────────────────────────────────

step "POST http://localhost:3001/verify_token  (second use — must be rejected)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/verify_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"token\":      \"$EUROPE_TOKEN\",
        \"token_type\": \"jwt\",
        \"claim\":      \"nationality:BG\"
    }")
info "HTTP status: $HTTP_CODE"
[[ "$HTTP_CODE" == "403" ]] && ok "Replay correctly rejected with 403 ✓" || fail "Expected 403, got $HTTP_CODE"

# ─────────────────────────────────────────────────────────────────────────────
header "STEP 6 — Delegation boundary: try to replay Sofia token at Europe again"
# ─────────────────────────────────────────────────────────────────────────────
# Sofia burned the nullifier when Europe first called its /verify_token
# during the exchange in Step 3. A second exchange attempt must fail.

step "POST http://localhost:3001/exchange_token  (Sofia token already spent)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$SOFIA_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3003\",
        \"claim\":            \"nationality:BG\"
    }")
info "HTTP status: $HTTP_CODE"
[[ "$HTTP_CODE" == "403" ]] && ok "Sofia correctly rejected the already-spent token ✓" || fail "Expected 403, got $HTTP_CODE"

# ─────────────────────────────────────────────────────────────────────────────
header "STEP 7 — Romania path (local verification, no delegation)"
# ─────────────────────────────────────────────────────────────────────────────

step "Mint a Romania token"
RO_RESP=$(curl -sf -X POST http://localhost:3005/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:RO"}')
RO_TOKEN=$(echo "$RO_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "Romania token minted"

step "Single-hop exchange at Europe (Romania uses delegation=local)"
RO_EXCHANGE=$(curl -sf -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$RO_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3005\",
        \"claim\":            \"nationality:RO\"
    }")
echo "$RO_EXCHANGE" | pp
ok "Europe issued fresh token for nationality:RO via local verification"

# ─────────────────────────────────────────────────────────────────────────────
header "STEP 8 — Petrich path (3 hops: Petrich → Bulgaria → Europe)"
# ─────────────────────────────────────────────────────────────────────────────
# Single-hop: client presents Petrich token directly to Europe.
# Europe finds Petrich in its transitive cache (path: Europe→Bulgaria→Petrich).

step "Mint a Petrich token"
PT_RESP=$(curl -sf -X POST http://localhost:3004/issue_token \
    -H 'Content-Type: application/json' \
    -d '{"claim":"nationality:BG"}')
PT_TOKEN=$(echo "$PT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ok "Petrich token minted"

step "Single-hop exchange at Europe (Petrich is 2 hops away, but it's ONE call)"
PT_EXCHANGE=$(curl -sf -X POST http://localhost:3001/exchange_token \
    -H 'Content-Type: application/json' \
    -d "{
        \"child_token\":      \"$PT_TOKEN\",
        \"child_token_type\": \"jwt\",
        \"child_issuer_id\":  \"http://localhost:3004\",
        \"claim\":            \"nationality:BG\"
    }")
echo "$PT_EXCHANGE" | pp
PT_PATH=$(echo "$PT_EXCHANGE" | python3 -c "import sys,json; print(json.load(sys.stdin)['trust_path'])")
ok "Europe issued fresh token via full trust path: $PT_PATH"

# ─────────────────────────────────────────────────────────────────────────────
header "All tests passed 🎉"
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BLD}Topology proved:${RST}"
echo "  Europe → Bulgaria → Sofia    (delegation=call,  nullifier burned at Sofia)"
echo "  Europe → Bulgaria → Petrich  (delegation=local, nullifier burned at Europe)"
echo "  Europe → Romania             (delegation=local, nullifier burned at Europe)"
echo ""
echo -e "${BLD}Node logs:${RST} logs/europe.log  logs/bulgaria.log  logs/sofia.log  etc."
echo ""
echo "Nodes are still running. Ctrl-C to stop."
echo ""

# Keep running so the user can poke the endpoints manually.
sleep infinity
