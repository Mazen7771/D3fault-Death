#!/usr/bin/env bash
# HuntOps — live web probing, fingerprinting, WAF detection, screenshots.
set -u

WB="$W/web"
mkdir -p "$WB"

_find_httpx() {
  # Kali names ProjectDiscovery's httpx "httpx-toolkit"; prefer it, then the
  # go-installed binary, then any `httpx` on PATH (not the python one).
  tool_exists httpx-toolkit && { echo httpx-toolkit; return; }
  [ -x "$HOME/go/bin/httpx" ] && { echo "$HOME/go/bin/httpx"; return; }
  tool_exists httpx && { echo httpx; return; }
  echo ""
}

run_recon_web() {
  local hosts="$W/subdomains/final-resolved.txt"
  [ -f "$hosts" ] || { warn "no hosts — run subdomains first"; return 0; }
  local HX; HX=$(_find_httpx)

  # ---- live probe -------------------------------------------------------------
  if [ -n "$HX" ]; then
    log "httpx live probe"
    timeout -k 30 600 "$HX" -l "$hosts" -sc -title -tech-detect -server -cdn -location \
      -follow-redirects -silent -threads "$HOST_BUDGET" -o "$WB/live.txt" 2>/dev/null \
      || warn "httpx failed"
  else
    warn "httpx missing — curl fallback"
    : > "$WB/live.txt"
    while read -r h; do
      code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$h/" 2>/dev/null)
      [ "$code" != "000" ] && echo "https://$h [$code]"
    done < "$hosts" > "$WB/live.txt"
  fi
  [ "$(count_lines "$WB/live.txt")" -eq 0 ] && { warn "no live web hosts"; return 0; }
  ok "live web hosts: $(count_lines "$WB/live.txt")"

  # hosts-only list for downstream phases
  awk '{print $1}' "$WB/live.txt" | sed 's/\[.*//' | sort -u > "$WB/live-urls.txt"

  # ---- fingerprint ------------------------------------------------------------
  if tool_exists whatweb; then
    log "whatweb fingerprint"
    timeout -k 30 600 whatweb -q -i "$WB/live-urls.txt" > "$WB/whatweb.txt" 2>/dev/null || warn "whatweb failed"
  fi
  if tool_exists wafw00f; then
    log "wafw00f WAF detection"
    timeout -k 30 600 wafw00f -i "$WB/live-urls.txt" -o "$WB/waf.txt" 2>/dev/null || warn "wafw00f failed"
  fi

  # ---- screenshots ------------------------------------------------------------
  if tool_exists gowitness; then
    log "gowitness screenshots"
    mkdir -p "$W/report/screenshots"
    timeout -k 30 900 gowitness scan file -f "$WB/live-urls.txt" --screenshot-path "$W/report/screenshots" \
      >/dev/null 2>&1 || warn "gowitness failed"
  fi

  # ---- security.txt / robots.txt harvest (feeds candidates + content) ---------
  : > "$W/urls/robots.txt"
  head -5 "$WB/live-urls.txt" | while read -r u; do
    curl -sk --max-time 15 "$u/robots.txt" >> "$W/urls/robots.txt" 2>/dev/null
  done
  ok "web recon done -> $WB"
}
