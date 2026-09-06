#!/usr/bin/env bash
# HuntOps — TLS/SSL layer: runs testssl.sh on each live host's IP:443 and
# routes its findings into the confirmed / candidate / info streams.
#   CRITICAL/HIGH -> confirmed finding (unless program-excluded)
#   MEDIUM/LOW    -> candidate       (unless program-excluded)
#   INFO          -> info   ;   OK ("not vulnerable") -> dropped as noise
set -u

VT="$W/vuln"
mkdir -p "$VT"

_sev_cvss() { case "$1" in CRITICAL) echo 9.8;; HIGH) echo 8.1;; MEDIUM) echo 5.3;; LOW) echo 3.1;; *) echo 0.0;; esac; }

run_vuln_tls() {
  [ "${TLS_ENABLE:-auto}" = "off" ] && { dbg "TLS disabled (--no-ssl)"; return 0; }
  [ -x "$TESTSSL_BIN" ] || { warn "testssl.sh not found at $TESTSSL_BIN — skipping TLS (set TESTSSL_BIN)"; return 0; }
  local live="$W/web/live-urls.txt"
  [ -f "$live" ] || { warn "no live hosts — skipping TLS"; return 0; }

  local n=0 ip host
  while read -r host; do
    [ -z "$host" ] && continue
    # live-urls.txt may carry a scheme (http://www.coda.com) — strip it so dig
    # and testssl see a bare hostname.
    host="${host#https://}"; host="${host#http://}"; host="${host%/}"
    n=$((n+1))
    [ "$n" -gt "$TLS_HOST_CAP" ] && { dbg "TLS host cap ($TLS_HOST_CAP) reached"; break; }
    ip=$(dig +short "$host" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    [ -z "$ip" ] && { dbg "no A record for $host — skipping TLS"; continue; }
    log "testssl $host ($ip:443)"
    local json="$VT/testssl-$host.json" logf="$VT/testssl-$host.log"
    # shellcheck disable=SC2086
    timeout -k 30 600 bash "$TESTSSL_BIN" --ip=one $TLS_SCAN_OPTS \
      --jsonfile-pretty "$json" --logfile "$logf" "$host" >/dev/null 2>&1 \
      || warn "testssl $host failed/timeout"
    _parse_testssl "$host" "$json" "$logf"
  done < "$live"
  ok "testssl done -> $VT"
}

_parse_testssl() { # host json logf
  local host="$1" json="$2" logf="$3"
  # Python emits severity|id|finding|cve|cwe|ref rows from the pretty JSON,
  # falling back to scraping the logfile when the JSON is missing/partial/corrupt
  # (e.g. testssl died on repeated TCP-connect problems against a CDN edge).
  local rows
  rows=$(python3 - "$host" "$json" "$logf" <<'PY'
import json, sys, re
host, path, logf = sys.argv[1], sys.argv[2], sys.argv[3]
rows = []
def emit(sev, fid, finding, cves, cwes):
    sev = str(sev).upper()
    if sev == 'OK':
        return  # "not vulnerable" — pure noise, skip
    rows.append("|".join([
        sev, fid or 'tls',
        (finding or '').strip().replace('|', ' ')[:220],
        ','.join(cves or []), ','.join(cwes or []),
        "testssl report: " + logf,
    ]))
try:
    d = json.load(open(path))
    for s in (d.get('scanResult') or []):
        # testssl 3.3dev calls it "vulnerabilities"; older builds "findings".
        for arr in (s.get('vulnerabilities'), s.get('findings')):
            if not arr:
                continue
            for f in arr:
                emit(f.get('severity'), f.get('id'),
                     f.get('finding'), f.get('cve'), f.get('cwe'))
        # protocol table also carries severity (e.g. TLS1 offered = LOW)
        for f in (s.get('protocols') or []):
            if f.get('severity') not in (None, 'OK', 'INFO'):
                emit(f.get('severity'), f.get('id'),
                     "%s: %s" % (f.get('id'), f.get('finding')), None, None)
except Exception:
    # partial JSON: scrape rated finding lines from the log. Accept both
    # "(HIGH) text" and "HIGH | text" and "HIGH text" forms.
    try:
        for line in open(logf, errors='replace'):
            if line.lstrip().startswith('#') or 'not offered (OK)' in line:
                continue
            m = re.search(r'\((CRITICAL|HIGH|MEDIUM|LOW)\)\s*[:|]?\s*(.{10,})', line) \
                or re.search(r'^\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*[|]\s*(.{10,})', line) \
                or re.search(r'\((CRITICAL|HIGH|MEDIUM|LOW)\)\s*(.{10,})', line)
            if m:
                rows.append("|".join([m.group(1), "scraped",
                                      m.group(2).strip().lstrip(':').strip()[:200].replace('|', ' '),
                                      "", "", logf]))
    except Exception:
        pass
for r in rows:
    print(r)
PY
)
  [ -z "$rows" ] && return 0
  printf '%s\n' "$rows" | while IFS='|' read -r sev fid finding cve cwe ref; do
    [ -z "$sev" ] && continue
    case "$sev" in
      CRITICAL|HIGH)
        if is_excluded "$finding"; then
          add_info testssl "$host" "$fid" "program-excluded: $finding" "$ref"
        else
          add_finding "$sev" testssl "$host" "$fid" "$finding${cve:+, CVE: $cve}" "$ref"
        fi ;;
      MEDIUM|LOW)
        if is_excluded "$finding"; then
          add_info testssl "$host" "$fid" "program-excluded: $finding" "$ref"
        else
          add_candidate "tls-misconfig" "$host" "$fid ($sev)" low "$finding" "$ref" "$ref" "$(_sev_cvss "$sev")" tls
        fi ;;
      INFO|OK)
        add_info testssl "$host" "$fid" "$finding" "$ref" ;;
    esac
  done
}
