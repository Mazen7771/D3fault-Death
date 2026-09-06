#!/usr/bin/env bash
# HuntOps — JS harvesting: crawl for JS, extract endpoints, hunt secrets.
set -u

JS="$W/js"
mkdir -p "$JS"

run_recon_js() {
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || { warn "no live hosts"; return 0; }
  local jslist="$W/urls/js-files.txt"

  # ---- collect JS files ---------------------------------------------------------
  : > "$JS/all-js.txt"
  if tool_exists katana; then
    log "katana crawl (JS + endpoints)"
    timeout -k 30 900 katana -list "$live" -jc -kf all -d 3 -silent -c 10 \
      -o "$JS/katana.txt" 2>/dev/null || warn "katana failed"
    grep -aE "\.(js|mjs)(\?|$)" "$JS/katana.txt" >> "$JS/all-js.txt" 2>/dev/null
  fi
  # command cat: on this box bare `cat` can be aliased to Bacula's `bat` in some
  # shells — never let that write usage text into our data files.
  [ -f "$jslist" ] && command cat "$jslist" >> "$JS/all-js.txt"
  sort -u -o "$JS/all-js.txt" "$JS/all-js.txt"
  ok "JS files collected: $(count_lines "$JS/all-js.txt")"

  # ---- endpoint extraction from JS bodies ---------------------------------------
  : > "$JS/endpoints.txt"
  local dl="$JS/downloaded"
  mkdir -p "$dl"
  head -50 "$JS/all-js.txt" | while read -r u; do
    [ -z "$u" ] && continue
    fn=$(sanitize_name "$u")
    curl -sk --max-time 20 "$u" > "$dl/$fn.js" 2>/dev/null
    # endpoint-ish strings: "/path", "/api/path", relative URLs
    grep -aoE '"/[a-zA-Z0-9_/.-]{2,}"' "$dl/$fn.js" 2>/dev/null \
      | tr -d '"' | sed 's#^#/#' | sort -u >> "$JS/endpoints.txt"
  done
  sort -u -o "$JS/endpoints.txt" "$JS/endpoints.txt"
  ok "endpoints extracted from JS: $(count_lines "$JS/endpoints.txt")"

  # ---- secret scan ---------------------------------------------------------------
  : > "$W/urls/secrets.txt"
  local all_js_bodies="$dl"/*.js
  # gf patterns
  if tool_exists gf; then
    command cat "$all_js_bodies" 2>/dev/null | gf secrets 2>/dev/null >> "$W/urls/secrets.txt" || true
    command cat "$all_js_bodies" 2>/dev/null | gf aws-keys 2>/dev/null >> "$W/urls/secrets.txt" || true
  fi
  # gitleaks
  if tool_exists gitleaks; then
    command cat "$all_js_bodies" 2>/dev/null | gitleaks detect --no-git --pipe --redact 2>/dev/null \
      | grep -aE "Secret|Finding" >> "$W/urls/secrets.txt" || true
  fi
  # regex sweep
  command cat "$all_js_bodies" 2>/dev/null \
    | grep -aoE "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24}|sk-[A-Za-z0-9]{24,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|api[_-]?key['\"]?\s*[:=]\s*['\"][0-9A-Za-z_-]{16,}['\"]" \
    >> "$W/urls/secrets.txt" 2>/dev/null
  sort -u -o "$W/urls/secrets.txt" "$W/urls/secrets.txt"
  [ "$(count_lines "$W/urls/secrets.txt")" -gt 0 ] && ok "potential secrets: $(count_lines "$W/urls/secrets.txt")"
}
