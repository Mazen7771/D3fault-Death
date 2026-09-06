#!/usr/bin/env bash
# HuntOps — sqlmap on parameters that pass a cheap SQLi smoke test. Capped.
set -u

VN="$W/vuln"
mkdir -p "$VN"

# smoke test: a single-quote + comment pair that flips the response for a real DB param
_sqli_smoke() { # url-with-param  -> 0 if candidate
  local u="$1" base code0 code1
  base="${u%%\?*}"
  code0=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 12 "$u" 2>/dev/null)
  code1=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 12 "${u}'" 2>/dev/null)
  [ "$code0" != "$code1" ]
}

run_vuln_sqlmap() {
  [ "$MODE_DEEP" = 1 ] && [ "$NO_DOS" = 0 ] && { warn "sqlmap deep skipped (add --no-dos)"; return 0; }
  tool_exists sqlmap || tool_exists ghauri || { warn "sqlmap/ghauri missing"; return 0; }

  local targets="$W/urls/param-urls.txt"
  [ -f "$targets" ] || { warn "no param URLs"; return 0; }

  local count=0
  while read -r u; do
    [ -z "$u" ] && continue
    [ "$count" -ge "$SQLMAP_CAP" ] && { warn "sqlmap cap reached ($SQLMAP_CAP)"; break; }
    grep -aqE "=" <<< "$u" || continue
    log "sqlmap smoke test: ${u:0:90}"
    if _sqli_smoke "$u"; then
      count=$((count+1))
      log "  smoke positive → sqlmap $u"
      if tool_exists sqlmap; then
        timeout -k 30 600 sqlmap -u "$u" --batch --level 1 --risk 1 --smart --random-agent --threads 2 \
          --flush-session --output-dir "$VN/sqlmap-$count" >/dev/null 2>&1 \
          && _parse_sqlmap "$VN/sqlmap-$count" "$u"
      elif tool_exists ghauri; then
        timeout -k 30 600 ghauri -u "$u" --batch --level 1 --risk 1 --output-dir "$VN/sqlmap-$count" >/dev/null 2>&1 \
          && _parse_sqlmap "$VN/sqlmap-$count" "$u"
      fi
    fi
  done < "$targets"
  ok "sqlmap done (ran on $count targets)"
}

_parse_sqlmap() { # outputdir, url
  local d="$1" u="$2"
  # Only a real injection marker is a CONFIRMED finding. "sqlmap identified" alone
  # appears in logs even for clean targets, so it is demoted to a low candidate.
  local hits
  hits=$(grep -raiE "is vulnerable|parameter [^ ]+ (is injectable|type:)" "$d" 2>/dev/null | head -3)
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" | while read -r line; do
      add_finding Critical sqlmap "$u" "SQL injection confirmed" "$line" "https://sqlmap.org"
    done
    return 0
  fi
  if grep -rqaiE "sqlmap identified|injectable|heuristic" "$d" 2>/dev/null; then
    add_candidate sqli "$u" "Possible SQLi (sqlmap inconclusive)" low \
      "sqlmap ran but produced no confirmed injection marker — verify manually" \
      "# sqlmap -u '$u' --batch --level 1 --risk 1" "https://sqlmap.org" "9.8" sqlmap
  fi
}
