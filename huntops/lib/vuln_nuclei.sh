#!/usr/bin/env bash
# HuntOps — nuclei runs per tag-set, JSONL parsed into confirmed/candidate streams.
# Policy: Critical/High with a real HTTP matcher -> CONFIRMED; else CANDIDATE.
set -u

VN="$W/vuln"
mkdir -p "$VN"

NUCLEI_TAG_SETS=(
  "cve:cve"
  "kev:kev,vkev"
  "xss:xss"
  "sqli:sqli"
  "ssrf:ssrf"
  "lfi:lfi,traversal"
  "exposure:exposure,misconfig"
  "takeover:takeover"
  "api:api,graphql"
  "jwt:jwt"
)

run_vuln_nuclei() {
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || { warn "no live hosts"; return 0; }
  tool_exists nuclei || { warn "nuclei missing"; return 0; }

  # Rate/timeout decided at RUNTIME: NO_DOS is parsed after config.sh sources,
  # so apply the no-dos variants here where NO_DOS is guaranteed correct.
  local rl="${NUCLEI_RATE:-15}" tmo="${NUCLEI_TIMEOUT:-3600}"
  [ "${NO_DOS:-0}" = 1 ] && { rl="${NUCLEI_RATE_NO_DOS:-100}"; tmo="${NUCLEI_TIMEOUT_NO_DOS:-5400}"; }
  if [ "${NO_DOS:-0}" != 1 ]; then
    warn "polite nuclei mode (rl $rl, ${tmo}s/tag) — coverage is PARTIAL by design; use --no-dos for exhaustive nuclei"
  fi

  local base=(nuclei -l "$live" -rl "$rl" -c "$NUCLEI_CONCURRENCY"
              -bulk-size 25 -timeout 8 -stats -si 1800 -duc -jsonl "${AUTH_ARGS[@]}")

  local entry tagset tags out
  for entry in "${NUCLEI_TAG_SETS[@]}"; do
    tagset="${entry%%:*}"; tags="${entry##*:}"
    out="$VN/nuclei-$tagset.jsonl"
    log "nuclei [$tags]"
    timeout "$tmo" "${base[@]}" -tags "$tags" -o "$out" 2>/dev/null \
      || warn "nuclei [$tags] failed/timeout"
    [ -f "$out" ] && _parse_nuclei "$out"
  done
  ok "nuclei done -> $VN"
}

# Parse one nuclei JSONL file into the confirmed/candidate/info streams.
_parse_nuclei() {
  local f="$1"
  {
    python3 - "$f" "$DOMAIN" "$EXCLUSIONS" <<'PYEOF'
import json, sys, re
f, domain, excl = sys.argv[1], sys.argv[2], sys.argv[3]
def excluded(detail):
    try:
        for pat in open(excl, encoding='utf-8', errors='ignore'):
            pat = pat.split('#')[0].strip()
            if pat and re.search(pat, detail, re.I):
                return True
    except Exception: pass
    return False
for line in open(f, encoding='utf-8', errors='ignore'):
    line = line.strip()
    if not line: continue
    try: j = json.loads(line)
    except Exception: continue
    info = j.get('info', {})
    sev = str(info.get('severity', 'info')).lower()
    name = info.get('name', j.get('template-id', ''))
    host = j.get('host', j.get('matched-at', ''))
    matcher = j.get('matcher-name', '')
    extracted = j.get('extracted-results', [])
    detail = f"{j.get('template-id','')} {name} {matcher} {' '.join(map(str,extracted[:3]))}"
    sev_cvss = {'critical':'9.8','high':'8.1','medium':'5.3','low':'3.1','info':'0.0'}
    cvss = sev_cvss.get(sev, '0.0')
    if excluded(detail):
        print('INFO|nuclei|%s|%s|program-excluded: %s|nuclei' % (host, name, detail))
    elif sev in ('critical', 'high') and matcher:
        print('FIND|%s|nuclei|%s|%s|%s|nuclei' % (sev.title(), host, name, detail))
    else:
        print('CAND|automated-scan|%s|%s|low|%s|# %s|nuclei|%s|nuclei' % (host, name, detail, ' '.join(map(str,extracted[:3])), cvss))
PYEOF
  } | while IFS='|' read -r kind a b c d e f g h i; do
    case "$kind" in
      FIND) add_finding "$a" "$b" "$c" "$d" "$e" "$f" ;;
      CAND) add_candidate "$a" "$b" "$c" "$d" "$e" "$f" "$g" "$h" "$i" ;;
      INFO) add_info "$a" "$b" "$c" "$d" "$e" ;;
    esac
  done
}
