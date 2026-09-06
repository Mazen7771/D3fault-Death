#!/usr/bin/env bash
# HuntOps — content discovery (ffuf/gobuster) + historical URL mining.
set -u

CT="$W/content"
UR="$W/urls"
mkdir -p "$CT" "$UR"

run_recon_content() {
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || { warn "no live hosts — run web recon first"; return 0; }

  # ---- content discovery -------------------------------------------------------
  if tool_exists ffuf && [ -f "$WLD_WEB" ]; then
    local wordlist="$WLD_WEB"
    [ "$MODE_DEEP" = 1 ] && [ -f "$WLD_WEB_MEDIUM" ] && wordlist="$WLD_WEB_MEDIUM"
    log "ffuf content discovery (medium: $wordlist)"
    : > "$CT/ffuf.txt"
    # Hosts are fuzzed in PARALLEL (xargs -P $CONCURRENCY) — the old loop ran
    # 23 hosts × ~3 min sequentially, a ~70-min phase. Concurrency stays polite
    # (3 ffufs max), but wall-clock drops ~5x. Per-host json is name-collision-safe.
    _ffuf_host() { # url
      local u="$1" fn fr
      [ -z "$u" ] && return 0
      fn=$(printf '%s' "$u" | tr '/:?#&=%' '_' | tr -s '_')
      fr="${FUF_RATE:-50}"
      [ "${NO_DOS:-0}" = 1 ] && fr="${FUF_RATE_NO_DOS:-150}"
      # NB: extraction must run even when ffuf exits non-zero — a rate-limited
      # scan times out (300s) on big wordlists all the time, and `|| return`
      # would silently drop every result of those hosts. jq reads whatever
      # partial json ffuf wrote before the SIGKILL.
      timeout -k 30 300 ffuf -u "$u/FUZZ" -w "$wordlist" -rate "$fr" -t 20 -mc 200,201,204,301,302,307,308,401,403 \
        -ac -o "$CT/ffuf-$fn.json" >/dev/null 2>&1
      [ -s "$CT/ffuf-$fn.json" ] || return 0
      jq -r '.results[]? | "\(.status) \(.url)"' "$CT/ffuf-$fn.json" 2>/dev/null >> "$CT/ffuf.txt"
    }
    export -f _ffuf_host
    export wordlist CT FUF_RATE FUF_RATE_NO_DOS NO_DOS
    command cat "$live" | head -n "$HOST_BUDGET" \
      | xargs -P "${CONCURRENCY:-3}" -I{} bash -c '_ffuf_host "$1"' _ {}
    sort -u -o "$CT/ffuf.txt" "$CT/ffuf.txt"
    ok "content discovery: $(count_lines "$CT/ffuf.txt") URLs"
  elif tool_exists gobuster; then
    warn "ffuf missing — gobuster fallback"
    command cat "$live" | xargs -P "${CONCURRENCY:-3}" -I{} bash -c \
      'timeout -k 30 300 gobuster dir -u "$1" -w "$WLD_WEB" -q -k -t 20 2>/dev/null >> "$CT/gobuster.txt" || true' _ {}
  fi

  # ---- historical URLs ----------------------------------------------------------
  : > "$UR/historical.txt"
  if tool_exists gau; then
    log "gau historical URLs (capped $GAU_CAP)"
    timeout "$GAU_TIMEOUT" gau --threads 3 --subs "$DOMAIN" 2>/dev/null | head -n "$GAU_CAP" >> "$UR/historical.txt"
  fi
  if tool_exists waybackurls; then
    log "waybackurls"
    timeout "$WAYBACK_TIMEOUT" waybackurls "$DOMAIN" 2>/dev/null | head -n "$GAU_CAP" >> "$UR/historical.txt"
  fi
  # archive.org CDX directly (robust fallback + extra coverage)
  log "archive.org CDX"
  curl -sk --max-time 120 "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=json&fl=original&collapse=urlkey&limit=100000" \
    | jq -r '.[1:][][]' 2>/dev/null | head -n "$GAU_CAP" >> "$UR/historical.txt"
  sort -u -o "$UR/historical.txt" "$UR/historical.txt"
  ok "historical URLs: $(count_lines "$UR/historical.txt")"

  # ---- parse historical into useful lists --------------------------------------
  grep -aiE "\.(js|mjs)(\?|$)" "$UR/historical.txt" | sort -u > "$UR/js-files.txt"
  grep -aiE "api|graphql|/v[0-9]/" "$UR/historical.txt" | grep -aiE "\.(json|aspx?|php|do|action|jsp)" \
    | sort -u > "$UR/api-endpoints.txt"
  grep -a "=" "$UR/historical.txt" | sort -u > "$UR/param-urls.txt"
  ok "historical: $(count_lines "$UR/js-files.txt") JS files, $(count_lines "$UR/api-endpoints.txt") API endpoints, $(count_lines "$UR/param-urls.txt") param URLs"

  # ---- secrets regex over historical -------------------------------------------
  grep -aiE "api[_-]?key|apikey|secret|token|bearer|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_|ghp_[A-Za-z0-9]{36}|xox[baprs]-" \
    "$UR/historical.txt" | sort -u > "$UR/secrets.txt"
  [ "$(count_lines "$UR/secrets.txt")" -gt 0 ] && ok "potential secrets in URLs: $(count_lines "$UR/secrets.txt")"
}
