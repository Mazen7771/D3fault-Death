#!/usr/bin/env bash
# HuntOps — OSINT layer: free no-key external lookups + optional keyed ones.
set -u

OI="$W/osint"
mkdir -p "$OI"

run_intel() {
  log "OSINT lookups (free, no-key)"
  _intel_passive_dns
  _intel_historical_cc
  _intel_internetdb
  _intel_keyed
  ok "OSINT done -> $OI"
}

_intel_passive_dns() {
  local out="$OI/passive-dns.txt"
  : > "$out"
  {
    curl -sk --max-time 60 "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' 2>/dev/null
    curl -sk --max-time 45 "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | cut -d, -f1
    curl -sk --max-time 45 "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" | jq -r '.passive_dns[].hostname' 2>/dev/null
    curl -sk --max-time 45 "https://jldc.me/anubis/subdomains/$DOMAIN" | jq -r '.[]' 2>/dev/null
  } >> "$out"
  extract_hostnames < "$out" | sort -u > "$OI/passive-dns-clean.txt"
  ok "passive DNS: $(count_lines "$OI/passive-dns-clean.txt") hostnames"
}

_intel_historical_cc() { # Common Crawl index query (no key)
  local idx out="$OI/commoncrawl.txt"
  idx=$(curl -sk --max-time 30 "https://index.commoncrawl.org/collinfo.json" | jq -r '.[0].id' 2>/dev/null)
  [ -z "$idx" ] && { warn "commoncrawl index unavailable"; return 0; }
  : > "$out"
  for cc in "${DOMAIN}" "*.${DOMAIN}"; do
    curl -sk --max-time 60 "https://index.commoncrawl.org/${idx}-index?url=${cc}/*&output=json" \
      | jq -r '.url' 2>/dev/null >> "$out"
  done
  sort -u -o "$out" "$out"
  ok "Common Crawl (${idx}): $(count_lines "$out") URLs"
}

_intel_internetdb() { # InternetDB — only meaningful for non-CDN origin IPs
  local ip
  ip=$(dig +short "$DOMAIN" A 2>/dev/null | grep -E "^[0-9.]+$" | head -1)
  [ -z "$ip" ] && return 0
  local r; r=$(curl -sk --max-time 20 "https://internetdb.shodan.io/$ip" 2>/dev/null)
  if [ -n "$r" ]; then
    echo "$r" > "$OI/internetdb.json"
    add_info intel "$DOMAIN" "InternetDB: $ip" "$(jq -c . "$OI/internetdb.json" 2>/dev/null | head -c 400)" "https://internetdb.shodan.io/$ip"
    ok "InternetDB: $ip (note: CDN IPs give little)"
  fi
}

_intel_keyed() { # optional; no-op with explicit warn if key missing
  if [ -n "${SHODAN_KEY:-}" ]; then
    curl -sk --max-time 30 "https://api.shodan.io/shodan/host/search?query=ssl.cert.subject.cn:$DOMAIN&key=$SHODAN_KEY" \
      > "$OI/shodan.json" 2>/dev/null && ok "shodan lookup done"
  fi
  if [ -n "${SECURITYTRAILS_KEY:-}" ]; then
    curl -sk --max-time 30 "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains" -H "APIKEY: $SECURITYTRAILS_KEY" \
      > "$OI/securitytrails.json" 2>/dev/null && ok "securitytrails lookup done"
  fi
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -sk --max-time 30 "https://api.github.com/search/code?q=%22$DOMAIN%22&per_page=50" -H "Authorization: Bearer $GITHUB_TOKEN" \
      > "$OI/github-code.json" 2>/dev/null && ok "github code search done"
  fi
  [ -n "${SHODAN_KEY:-}${SECURITYTRAILS_KEY:-}${GITHUB_TOKEN:-}${VIRUSTOTAL_KEY:-}${CENSYS_ID:-}" ] || true
}
