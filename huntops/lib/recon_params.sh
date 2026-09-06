#!/usr/bin/env bash
# HuntOps — parameter discovery (arjun + crawl harvest) + gf filtering.
set -u

PR="$W/urls"
mkdir -p "$PR"

run_recon_params() {
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || { warn "no live hosts"; return 0; }

  # ---- arjun on API-ish endpoints ----------------------------------------------
  # Filter out ad-tracking / UTM / referral-only landing URLs (huge query strings
  # of junk params) — they waste arjun. Prioritize API/graphql/dynamic endpoints.
  : > "$PR/arjun.txt"
  if tool_exists arjun; then
    log "arjun parameter discovery"
    local targets="$PR/arjun-targets.txt"
    {
      [ -f "$PR/api-endpoints.txt" ] && grep -aE "=" "$PR/api-endpoints.txt"
      [ -f "$PR/param-urls.txt" ] && grep -aE "=" "$PR/param-urls.txt"
    } 2>/dev/null \
      | grep -avE "hsa_|gad_|gad_source|gbraid|wbraid|fbclid|gclid|mc_cid|mc_eid|utm_|igshid|ref=|via=|promo_code|source=referral" \
      | sort -u | head -3 > "$targets"
    [ "$(count_lines "$targets")" -gt 0 ] || cp "$PR/param-urls.txt" "$targets"
    while read -r u; do
      [ -z "$u" ] && continue
      timeout -k 30 300 arjun -u "$u" --stable -q 2>/dev/null >> "$PR/arjun.txt" || true
    done < "$targets"
  fi

  # ---- harvest params from katana/ffuf/historical URLs --------------------------
  : > "$PR/params.txt"
  local pools="$JS/katana.txt $CT/ffuf.txt $PR/historical.txt"
  for p in $pools; do
    [ -f "$p" ] && grep -aoE "[?&][a-zA-Z0-9_\[\]]+=" "$p" 2>/dev/null | tr -d '?&=' >> "$PR/params.txt"
  done
  sort -u -o "$PR/params.txt" "$PR/params.txt"
  ok "parameters discovered: $(count_lines "$PR/params.txt")"

  # ---- gf filters for high-value classes ----------------------------------------
  if tool_exists gf; then
    for cls in idor ssrf redirect; do
      [ -f "$PR/param-urls.txt" ] && gf "$cls" < "$PR/param-urls.txt" 2>/dev/null > "$PR/gf-$cls.txt" || true
    done
  fi

  # ---- write the master param-URL list (has a value we can fuzz) ----------------
  grep -aE "=" "$PR/historical.txt" "$PR/api-endpoints.txt" "$JS/endpoints.txt" 2>/dev/null \
    | grep -aoE "https?://[^ ]+" | sort -u > "$PR/param-urls.txt"
  ok "param URLs: $(count_lines "$PR/param-urls.txt")"
}
