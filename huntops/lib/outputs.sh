#!/usr/bin/env bash
# HuntOps — per-domain deliverables for the bug bounty hunter:
#   $W/$DOMAIN.txt       findings sheet (confirmed + top candidates + counts)
#   $W/info-$DOMAIN.txt  recon dossier (assets, tech, endpoints, attack angles)
#   $W/intel-$DOMAIN.txt HIGH-VALUE INTEL — deep attack surface map, tech stack,
#                        prioritized manual testing checklist, evidence chains.
#                        ALWAYS written; this is the "gold mine" when vulns=0.
set -u

OUT_FINDINGS="$W/$DOMAIN.txt"
OUT_INFO="$W/info-$DOMAIN.txt"
OUT_INTEL="$W/intel-$DOMAIN.txt"

run_outputs() {
  log "generating per-domain deliverables"
  _out_findings
  _out_info
  _out_intel
  ok "deliverables -> $OUT_FINDINGS | $OUT_INFO | $OUT_INTEL"
}

# ---- $DOMAIN.txt : bug-bounty findings sheet ---------------------------------
_out_findings() {
  local nf=0 nc=0 ni=0
  [ -f "$FINDINGS" ]  && nf=$(count_lines "$FINDINGS")
  [ -f "$CANDIDATES" ] && nc=$(count_lines "$CANDIDATES")
  [ -f "$INFOFILE" ]  && ni=$(count_lines "$INFOFILE")

  {
    echo "============================================================"
    echo " HuntOps findings — $DOMAIN"
    echo " Scan: $(date '+%Y-%m-%d %H:%M')  mode: $MODE  tool: v$HUNTOPS_VERSION"
    echo " Confirmed: $nf   Candidates: $nc   Info/excluded: $ni"
    echo "============================================================"
    echo
    echo "## CONFIRMED FINDINGS (report these)"
    if [ "$nf" -gt 0 ]; then
      sed 's/|/ | /g' "$FINDINGS"
    else
      echo "  (none)"
    fi
    echo
    echo "## TOP CANDIDATES (verify before reporting, sorted by CVSS)"
    if [ "$nc" -gt 0 ]; then
      # CAND|class|host|title|conf|evidence|repro|ref|cvss|tag — sort by cvss desc
      sort -t'|' -k9,9nr "$CANDIDATES" | head -40 | while IFS='|' read -r kind cls host title conf ev repro ref cvss tag; do
        printf '  [%s] %s %s — %s\n' "${cvss:-?}" "$cls" "$host" "$title"
        [ -n "${repro:-}" ] && printf '      repro: %s\n' "$repro"
      done
    else
      echo "  (none)"
    fi
    echo
    echo "## INFO / PROGRAM-EXCLUDED"
    [ "$ni" -gt 0 ] && sed 's/|/ | /g' "$INFOFILE" | head -30 || echo "  (none)"
    echo
    echo "## ASSET SUMMARY"
    local subs live hist params
    subs=$(count_lines "$W/subdomains/final-resolved.txt")
    live=$(count_lines "$W/web/live-urls.txt")
    hist=$(count_lines "$W/urls/historical.txt")
    params=$(count_lines "$W/urls/param-urls.txt")
    echo "  subdomains=$subs  live_web=$live  historical_urls=$hist  param_urls=$params"
    echo
    echo "Full details: $W/report/huntops-report.html"
    echo "Recon dossier: $OUT_INFO"
  } > "$OUT_FINDINGS"
}

# ---- info-$DOMAIN.txt : recon dossier for the hunter --------------------------
_out_info() {
  local subs live hist params jsapi nendpoints ncnames nadmin nssrf nidor
  subs=$(count_lines "$W/subdomains/final-resolved.txt")
  live=$(count_lines "$W/web/live-urls.txt")
  hist=$(count_lines "$W/urls/historical.txt")
  params=$(count_lines "$W/urls/param-urls.txt")
  jsapi=$(count_lines "$W/urls/api-endpoints.txt")
  nendpoints=$(count_lines "$W/js/endpoints.txt")
  # count non-empty lines only — wc -l counts a lone "\n" file as 1.
  # NB: grep -c prints "0" but still exits 1 on no matches, so a bare
  # "|| echo 0" would append a second 0. Default AFTER capture instead.
  ncnames=$(grep -c . "$W/takeover-candidates.txt" 2>/dev/null || echo 0)
  ncnames=$(echo "$ncnames" | tr -d '\n')
  # CANDIDATES may not exist when running the dd engine (no HuntOps candidates
  # stream) — default to 0 so the integer comparisons below never blow up.
  nadmin=$(grep -ac "|admin-access|" "$CANDIDATES" 2>/dev/null || echo 0)
  nadmin=$(echo "$nadmin" | tr -d '\n')
  nssrf=$(grep -ac "|ssrf|" "$CANDIDATES" 2>/dev/null || echo 0)
  nssrf=$(echo "$nssrf" | tr -d '\n')
  nidor=$(grep -ac "|idor-manual|" "$CANDIDATES" 2>/dev/null || echo 0)
  nidor=$(echo "$nidor" | tr -d '\n')

  {
    echo "============================================================"
    echo " HuntOps recon dossier — $DOMAIN"
    echo " Scan: $(date '+%Y-%m-%d %H:%M')  mode: $MODE  tool: v$HUNTOPS_VERSION"
    echo " Use this to drive manual testing — every angle below is a lead."
    echo "============================================================"
    echo
    echo "## 1. ASSET INVENTORY ($subs validated subdomains)"
    if [ "$subs" -gt 0 ]; then
      echo "  $(paste -sd' ' "$W/subdomains/final-resolved.txt")"
    else
      echo "  (none)"
    fi
    echo
    echo "## 2. LIVE WEB HOSTS ($live) — status | title | server | tech | WAF"
    if [ -f "$W/web/live.txt" ]; then
      sed 's/^/  /' "$W/web/live.txt"
    else
      echo "  (no httpx probe)"
    fi
    [ -f "$W/web/waf.txt" ] && { echo "  --- WAF ---"; sed 's/^/  /' "$W/web/waf.txt" | head -15; }
    echo
    echo "## 3. PORTS / SERVICES"
    if [ -s "$W/ports/services.txt" ]; then
      sed 's/^/  /' "$W/ports/services.txt" | head -40
    elif [ -s "$W/ports/naabu.txt" ]; then
      echo "  (open ports, no service versions — naabu)"
      sed 's/^/  /' "$W/ports/naabu.txt" | head -40
    else
      echo "  (port scan produced nothing)"
    fi
    echo
    echo "## 4. HISTORICAL ATTACK SURFACE"
    echo "  historical_urls=$hist  api_endpoints=$jsapi  param_urls=$params  js_endpoints=$nendpoints"
    echo "  --- interesting historical endpoints (api/admin/internal) ---"
    grep -aiE "api|admin|internal|dev|staging|graphql|actuator|swagger|upload|debug" \
      "$W/urls/historical.txt" 2>/dev/null | head -25 | sed 's/^/  /' || echo "  (none)"
    [ -s "$W/js/endpoints.txt" ] && { echo "  --- JS endpoints ---"; sed 's/^/  /' "$W/js/endpoints.txt" | head -25; }
    echo
    echo "## 5. SUBDOMAIN TAKEOVER CANDIDATES (CNAMEs)"
    if grep -q . "$W/takeover-candidates.txt" 2>/dev/null; then
      sed 's/^/  /' "$W/takeover-candidates.txt"
    else
      echo "  (none)"
    fi
    echo
    echo "## 6. SUGGESTED ATTACK ANGLES (auto-derived)"
    [ "$nidor" -gt 0 ]  && echo "  - IDOR: $nidor enumerable-numeric params — retest with --test-account <you@email> and only IDs you OWN"
    [ "$nssrf" -gt 0 ]  && echo "  - SSRF: $nssrf fetch/redirect params — point each at an interact.sh canary"
    [ "$nadmin" -gt 0 ] && echo "  - AuthZ: $nadmin admin/debug paths on live hosts — check for unauthenticated exposure"
    [ "$ncnames" -gt 0 ] && echo "  - Takeover: $ncnames dangling CNAMEs — register the external host and verify"
    echo "  - TLS: run testssl.sh against each live host IP:443 (already done by this tool)"
    echo "  - Params: $params param-carrying URLs — feed into your fuzzer with auth"
    echo "  - Historical: review the $hist URLs for leaked endpoints/credentials"
    echo
    echo "Screenshots: $W/report/screenshots/"
    echo "Raw data: $W/{subdomains,ports,web,content,js,urls,vuln,osint,cve}/"
  } > "$OUT_INFO"
}

# ---- intel-$DOMAIN.txt : HIGH-VALUE INTEL (the gold mine when vulns=0) ---------
# This file captures EVERYTHING that could help an ethical hacker manually find bugs.
# Technology deep-dive, attack surface map, evidence chains, prioritized checklist.
_out_intel() {
  local subs live hist params jsapi nendpoints ncnames
  subs=$(count_lines "$W/subdomains/final-resolved.txt")
  live=$(count_lines "$W/web/live-urls.txt")
  hist=$(count_lines "$W/urls/historical.txt")
  params=$(count_lines "$W/urls/param-urls.txt")
  jsapi=$(count_lines "$W/urls/api-endpoints.txt")
  nendpoints=$(count_lines "$W/js/endpoints.txt")
  ncnames=$(grep -c . "$W/takeover-candidates.txt" 2>/dev/null || echo 0)

  # Collect tech fingerprint details
  local tech_details=""
  if [ -f "$W/web/httpx.jsonl" ]; then
    tech_details=$(jq -r '.url + " | " + (.tech // []) + " | " + (.server // "unknown") + " | " + (.waf // "none")' "$W/web/httpx.jsonl" 2>/dev/null | sed 's/\[//g; s/\]//g; s/"//g; s/,/ /g')
  fi

  # Collect CVE matches
  local cve_matches=""
  if [ -f "$W/findings/candidates.txt" ]; then
    cve_matches=$(grep -i cve "$W/findings/candidates.txt" 2>/dev/null | head -20 | sed 's/^/  /')
  fi

  # Collect strategy engine findings
  local strategy_summary=""
  if [ -f "$W/strategy/strategy.log" ]; then
    strategy_summary=$(grep -E "STRATEGY ▸|HIT" "$W/strategy/strategy.log" 2>/dev/null | head -20 | sed 's/^/  /')
  fi

  # Collect interesting parameters (by category)
  local redirect_params lfi_params sqli_params idor_params ssrf_params graphql_params
  redirect_params=$(grep -aiE "next|url|redirect|dest|return|callback" "$W/urls/param-urls.txt" 2>/dev/null | head -10)
  lfi_params=$(grep -aiE "file|path|page|include|template|document|view" "$W/urls/param-urls.txt" 2>/dev/null | head -10)
  sqli_params=$(grep -aiE "id|query|search|filter|sort|order" "$W/urls/param-urls.txt" 2>/dev/null | head -10)
  idor_params=$(grep -aiE "user|account|subscriber|member|order|file|doc|invoice|payment" "$W/urls/param-urls.txt" 2>/dev/null | head -10)
  ssrf_params=$(grep -aiE "url|uri|fetch|proxy|feed|webhook|callback" "$W/urls/param-urls.txt" 2>/dev/null | head -10)
  graphql_params=$(grep -aiE "graphql|query|mutation" "$W/urls/param-urls.txt" 2>/dev/null | head -10)

  # Collect exposed admin/debug paths found
  local admin_paths=""
  if [ -f "$W/web/live.txt" ]; then
    admin_paths=$(grep -iE "admin|debug|actuator|console|swagger|telescope|horizon|nova" "$W/web/live.txt" 2>/dev/null | head -15)
  fi

  # Collect CORS findings
  local cors_findings=""
  if [ -f "$W/findings/candidates.txt" ]; then
    cors_findings=$(grep -i cors "$W/findings/candidates.txt" 2>/dev/null | head -10 | sed 's/^/  /')
  fi

  # Collect secrets exposure
  local secrets_exposure=""
  if [ -f "$W/urls/secrets.txt" ] && [ -s "$W/urls/secrets.txt" ]; then
    secrets_exposure=$(head -20 "$W/urls/secrets.txt" | sed 's/^/  [SECRET] /')
  fi

  # Collect TLS findings
  local tls_findings=""
  if [ -f "$W/vuln/testssl.json" ]; then
    tls_findings=$(jq -r '.[] | select(.severity=="HIGH" or .severity=="CRITICAL" or .severity=="MEDIUM") | .id + ": " + .finding' "$W/vuln/testssl.json" 2>/dev/null | head -10 | sed 's/^/  /')
  fi

  # Collect open ports with services
  local port_details=""
  if [ -f "$W/ports/services.txt" ]; then
    port_details=$(head -30 "$W/ports/services.txt" | sed 's/^/  /')
  elif [ -f "$W/ports/naabu.txt" ]; then
    port_details=$(head -30 "$W/ports/naabu.txt" | sed 's/^/  /')
  fi

  # Collect JS analysis
  local js_analysis=""
  if [ -f "$W/js/endpoints.txt" ]; then
    js_analysis=$(grep -iE "api|secret|key|token|password|admin|debug|internal" "$W/js/endpoints.txt" 2>/dev/null | head -15 | sed 's/^/  /')
  fi

  {
    echo "============================================================"
    echo " HuntOps HIGH-VALUE INTEL — $DOMAIN"
    echo " Scan: $(date '+%Y-%m-%d %H:%M')  mode: $MODE  tool: v$HUNTOPS_VERSION"
    echo " This file contains EVERYTHING valuable — even if vulns=0."
    echo " Use it to drive manual testing. Every line is a lead."
    echo "============================================================"
    echo
    echo "## EXECUTIVE SUMMARY"
    echo "  Domain: $DOMAIN"
    echo "  Subdomains validated: $subs"
    echo "  Live web hosts: $live"
    echo "  Historical URLs: $hist"
    echo "  Parameterized URLs: $params"
    echo "  API endpoints discovered: $jsapi"
    echo "  JS endpoints extracted: $nendpoints"
    echo "  Takeover candidates: $ncnames"
    echo "  Strategy engine findings: $(grep -c 'HIT' "$W/strategy/strategy.log" 2>/dev/null || echo 0)"
    echo
    echo "============================================================"
    echo "## 1. TECHNOLOGY STACK DEEP-DIVE (httpx fingerprinting)"
    echo "  Use this to target framework-specific vulns & config issues"
    echo
    if [ -n "$tech_details" ]; then
      echo "$tech_details" | sed 's/^/  /'
    else
      echo "  (no httpx data — run web_probe phase)"
    fi
    echo
    echo "============================================================"
    echo "## 2. OPEN PORTS & SERVICES (attack surface for infra bugs)"
    if [ -n "$port_details" ]; then
      echo "$port_details"
    else
      echo "  (no port data — run port_scan phase)"
    fi
    echo
    echo "============================================================"
    echo "## 3. TLS/SSL CONFIGURATION (testssl.sh results)"
    if [ -n "$tls_findings" ]; then
      echo "$tls_findings"
    else
      echo "  (no TLS data — run tls_scan phase)"
    fi
    echo
    echo "============================================================"
    echo "## 4. CVE CORRELATION (service versions -> known CVEs)"
    if [ -n "$cve_matches" ]; then
      echo "$cve_matches"
    else
      echo "  (no CVE matches — versions not vulnerable or no version data)"
    fi
    echo
    echo "============================================================"
    echo "## 5. STRATEGY ENGINE FINDINGS (Ebb & Flow adaptive hunting)"
    if [ -n "$strategy_summary" ]; then
      echo "$strategy_summary"
    else
      echo "  (strategy engine not run or no findings)"
    fi
    echo
    echo "============================================================"
    echo "## 6. HIGH-VALUE PARAMETER CATEGORIES (prioritized for fuzzing)"
    echo "  [REDIRECT PARAMS] — open redirect -> SSRF -> LFI chain"
    [ -n "$redirect_params" ] && echo "$redirect_params" | sed 's/^/    /' || echo "    (none)"
    echo
    echo "  [LFI PARAMS] — local file inclusion"
    [ -n "$lfi_params" ] && echo "$lfi_params" | sed 's/^/    /' || echo "    (none)"
    echo
    echo "  [SQLI PARAMS] — SQL injection candidates"
    [ -n "$sqli_params" ] && echo "$sqli_params" | sed 's/^/    /' || echo "    (none)"
    echo
    echo "  [IDOR PARAMS] — numeric/sequential object IDs"
    [ -n "$idor_params" ] && echo "$idor_params" | sed 's/^/    /' || echo "    (none)"
    echo
    echo "  [SSRF PARAMS] — fetch/proxy/url parameters"
    [ -n "$ssrf_params" ] && echo "$ssrf_params" | sed 's/^/    /' || echo "    (none)"
    echo
    echo "  [GRAPHQL PARAMS] — GraphQL endpoints"
    [ -n "$graphql_params" ] && echo "$graphql_params" | sed 's/^/    /' || echo "    (none)"
    echo
    echo "============================================================"
    echo "## 7. EXPOSED ADMIN / DEBUG / SENSITIVE PATHS"
    if [ -n "$admin_paths" ]; then
      echo "$admin_paths" | sed 's/^/  /'
    else
      echo "  (none found — check historical URLs manually)"
    fi
    echo
    echo "============================================================"
    echo "## 8. CORS MISCONFIGURATION CANDIDATES"
    if [ -n "$cors_findings" ]; then
      echo "$cors_findings"
    else
      echo "  (none found — run intel phase for full CORS testing)"
    fi
    echo
    echo "============================================================"
    echo "## 9. SECRETS / API KEY EXPOSURE (JS, responses, historical)"
    if [ -n "$secrets_exposure" ]; then
      echo "$secrets_exposure"
    else
      echo "  (no secrets detected in scanned sources)"
    fi
    echo
    echo "============================================================"
    echo "## 10. SUBDOMAIN TAKEOVER CANDIDATES (dangling CNAMEs)"
    if grep -q . "$W/takeover-candidates.txt" 2>/dev/null; then
      sed 's/^/  /' "$W/takeover-candidates.txt"
    else
      echo "  (none found)"
    fi
    echo
    echo "============================================================"
    echo "## 11. JAVASCRIPT ANALYSIS (endpoints, secrets, internal refs)"
    if [ -n "$js_analysis" ]; then
      echo "$js_analysis"
    else
      echo "  (no interesting JS findings — check $W/js/endpoints.txt manually)"
    fi
    echo
    echo "============================================================"
    echo "## 12. PRIORITIZED MANUAL TESTING CHECKLIST"
    echo "  Rank these by impact. Every item below is actionable."
    echo
    echo "  1. AUTHENTICATION / AUTHORIZATION"
    echo "     [ ] Test IDOR on all numeric params (use --test-account for high-confidence)"
    echo "     [ ] Check for broken object-level auth (BOLA) on API endpoints"
    echo "     [ ] Test JWT: alg:none, weak secret, kid injection, JWKS spoofing"
    echo "     [ ] Check for session fixation / weak session config"
    echo "     [ ] Test privilege escalation via role/permission params"
    echo
    echo "  2. INPUT VALIDATION / INJECTION"
    echo "     [ ] Fuzz all param categories above with payloads from data/words/"
    echo "     [ ] Test redirect params -> SSRF -> LFI chain (Strategy S2)"
    echo "     [ ] Test SSTI on template engine params (Jinja2, Twig, Freemarker, etc.)"
    echo "     [ ] Test SQLi on id/query/search params (time-based, boolean, error)"
    echo "     [ ] Test GraphQL: introspection, mutations, depth/complexity limits"
    echo
    echo "  3. SERVER / CONFIGURATION"
    echo "     [ ] Check exposed admin/debug/actuator/swagger paths (Strategy S1)"
    echo "     [ ] Verify CORS: arbitrary origin + credentials (Strategy S4)"
    echo "     [ ] Check for cloud storage bucket exposure (Strategy S5)"
    echo "     [ ] Test subdomain takeover candidates (Strategy S8)"
    echo "     [ ] Verify security headers (CSP, HSTS, X-Frame-Options, etc.)"
    echo
    echo "  4. BUSINESS LOGIC / RACE CONDITIONS"
    echo "     [ ] Test race on refer/invite/claim/checkout/payment endpoints (Strategy S7)"
    echo "     [ ] Test coupon/giftcard/referral code reuse"
    echo "     [ ] Test password reset token reuse / prediction"
    echo "     [ ] Test file upload: type validation, path traversal, execution"
    echo
    echo "  5. INFRASTRUCTURE / SUPPLY CHAIN"
    echo "     [ ] Check TLS config against testssl.sh findings"
    echo "     [ ] Verify CVE matches — attempt safe PoC if --no-dos not set"
    echo "     [ ] Scan for exposed .git, .env, backup files in historical URLs"
    echo "     [ ] Check for outdated npm/pip/maven dependencies in JS/endpoints"
    echo
    echo "  6. SECRETS / INTELLIGENCE"
    echo "     [ ] Review all found secrets — rotate immediately if real"
    echo "     [ ] Search historical URLs for API keys, tokens, passwords"
    echo "     [ ] Check JS files for hardcoded secrets, internal endpoints"
    echo
    echo "============================================================"
    echo "## 13. REPRODUCTION COMMANDS (copy-paste for manual testing)"
    echo
    echo "  # Redirect chain test"
    echo "  curl -skI 'https://TARGET/?next=//evil.example.com'"
    echo
    echo "  # LFI test"
    echo "  curl -sk 'https://TARGET/?file=../../../../etc/passwd'"
    echo
    echo "  # SSTI test (Jinja2/Twig)"
    echo "  curl -sk 'https://TARGET/?name={{7*7}}'"
    echo
    echo "  # GraphQL introspection"
    echo "  curl -sk -X POST 'https://TARGET/graphql' -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'"
    echo
    echo "  # CORS test"
    echo "  curl -sk -H 'Origin: https://evil.example.com' -D - 'https://TARGET/'"
    echo
    echo "  # JWT alg:none forge (Python)"
    echo "  python3 -c \"import base64,json; h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode(); p=base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=').decode(); print(h+'.'+p+'.')\""
    echo
    echo "  # Race condition (Turbo Intruder / racelyzer)"
    echo "  # POST to /claim /invite /checkout with same payload N times in parallel"
    echo
    echo "  # Subdomain takeover verification"
    echo "  dig +short CANDIDATE_SUBDOMAIN"
    echo "  dig +short CNAME_TARGET"
    echo
    echo "  # Cloud bucket listability"
    echo "  curl -sk 'http://BUCKET.s3.amazonaws.com/'"
    echo "  curl -sk 'https://BUCKET.storage.googleapis.com/'"
    echo
    echo "============================================================"
    echo "## 14. RAW DATA LOCATIONS (for your own tooling)"
    echo "  Subdomains:     $W/subdomains/final-resolved.txt"
    echo "  Live web:       $W/web/live-urls.txt"
    echo "  HTTPX JSONL:    $W/web/httpx.jsonl"
    echo "  Historical:     $W/urls/historical.txt"
    echo "  Param URLs:     $W/urls/param-urls.txt"
    echo "  API endpoints:  $W/urls/api-endpoints.txt"
    echo "  JS endpoints:   $W/js/endpoints.txt"
    echo "  Secrets:        $W/urls/secrets.txt"
    echo "  Ports:          $W/ports/services.txt"
    echo "  CVE DB:         $W/cve/cve-db.txt"
    echo "  Candidates:     $W/findings/candidates.txt"
    echo "  Confirmed:      $W/findings/findings.txt"
    echo "  Strategy log:   $W/strategy/strategy.log"
    echo "  Takeover:       $W/takeover-candidates.txt"
    echo "  Screenshots:    $W/report/screenshots/"
    echo "  HTML report:    $W/report/huntops-report.html"
    echo
    echo "============================================================"
    echo "END OF HIGH-VALUE INTEL"
    echo "Generated by HuntOps v$HUNTOPS_VERSION"
  } > "$OUT_INTEL"
}
