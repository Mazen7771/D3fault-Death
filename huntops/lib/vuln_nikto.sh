#!/usr/bin/env bash
# HuntOps — nikto scan, results passed through the program-exclusion filter.
set -u

VN="$W/vuln"
mkdir -p "$VN"

run_vuln_nikto() {
  tool_exists nikto || { warn "nikto missing"; return 0; }
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || { warn "no live hosts"; return 0; }
  [ "$(count_lines "$live")" -eq 0 ] && return 0

  # Hosts run in PARALLEL (xargs -P $CONCURRENCY); per-host json avoids races.
  # The old loop ran 10 hosts × up to 600s sequentially — a ~2h worst case that
  # routinely died on the timeout of the first slow host. The subshell only runs
  # nikto (external binary); parsing happens back in the parent, so the exported
  # function needs no core.sh helpers.
  _nikto_host() { # url
    local u="$1" fn
    [ -z "$u" ] && return 0
    fn=$(printf '%s' "$u" | tr '/:?#&=%' '_' | tr -s '_')
    echo "[dbg] nikto $u"
    timeout -k 30 600 nikto -h "$u" -nointeractive -Tuning x -Format json -o "$VN/nikto-$fn.json" >/dev/null 2>&1 \
      || true
  }
  export -f _nikto_host
  export VN
  command cat "$live" | head -n 10 \
    | xargs -P "${CONCURRENCY:-3}" -I{} bash -c '_nikto_host "$1"' _ {}
  for j in "$VN"/nikto-*.json; do
    [ -s "$j" ] && _parse_nikto "$j"
  done
  ok "nikto done -> $VN"
}

_parse_nikto() {
  local f="$1"
  jq -r '.vulnerabilities[]? | "\(.osvdb)|\(.msg)"' "$f" 2>/dev/null | while IFS='|' read -r osvdb msg; do
    [ -z "$msg" ] && continue
    if is_excluded "$msg"; then
      add_info nikto "$f" "nikto: ${msg:0:120}" "$msg" "https://cirt.net/Nikto2"
    else
      add_finding Medium nikto "$f" "nikto: ${msg:0:120}" "$msg" "https://cirt.net/Nikto2"
    fi
  done
}
