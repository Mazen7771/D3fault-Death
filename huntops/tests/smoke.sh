#!/usr/bin/env bash
# HuntOps smoke suite — fast, offline regression checks.
#
# Usage:
#   tests/smoke.sh                 run static + unit checks (no network)
#   tests/smoke.sh -w <workdir>    also validate a real run's artifacts
#   tests/smoke.sh -v              verbose (print each check name)
#
# Exits non-zero if any check fails. Each check prints `ok <name>` / `FAIL <name>`.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
VERBOSE=0; W_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    -w) W_DIR="$2"; shift 2 ;;
    -v) VERBOSE=1; shift ;;
    *)  echo "usage: smoke.sh [-v] [-w workdir]"; exit 2 ;;
  esac
done

PASS=0; FAIL=0
chk() { # name, cond
  if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); [ "$VERBOSE" = 1 ] && echo "  ok $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1"; fi
}
note() { [ "$VERBOSE" = 1 ] && echo "  .. $1"; }

echo "== 1. static syntax =="
syntax_fail=0
while IFS= read -r f; do
  bash -n "$f" 2>/dev/null || { echo "  FAIL bash -n $f"; syntax_fail=1; }
done < <(find . -name '*.sh' -type f)
chk "bash -n all scripts" $syntax_fail

echo "== 2. core unit checks =="
TMP="$(mktemp -d)"
export HUNTOPS_ROOT="$ROOT"
source config/config.sh
source config/wordlists.conf
source lib/core.sh
export TARGET=x.com DOMAIN=x.com CUSTOM_OUT="$TMP" MODE=quick
setup_target

# 2a. esc_rec sanitises pipes and newlines
r1=$(esc_rec 'a|b|c');   [ "$r1" = 'a│b│c' ]; chk "esc_rec pipe→│" $?
r2=$(esc_rec $'line1\nline2'); [ "$r2" = 'line1 line2' ]; chk "esc_rec newline→space" $?

# 2b. hostile input: pipes + newlines in every field must NOT break field counts
FINDINGS="$TMP/f.txt"; CANDIDATES="$TMP/c.txt"; INFOFILE="$TMP/i.txt"
: > "$FINDINGS"; : > "$CANDIDATES"; : > "$INFOFILE"
add_finding Critical testssl host "TLS | broken" $'new\nline' "http://ref | x"
add_candidate tls-misconfig host "Cand | title" low $'evid\nence' "curl | x" "ref|2" "5.3" tls
add_info tool host "Info|title" "detail" "ref"
nf=$(awk -F'|' '{print NF}' "$FINDINGS" | sort -u | tr '\n' ' '); nf=${nf% }
nc=$(awk -F'|' '{print NF}' "$CANDIDATES" | sort -u | tr '\n' ' '); nc=${nc% }
ni=$(awk -F'|' '{print NF}' "$INFOFILE" | sort -u | tr '\n' ' '); ni=${ni% }
[ "$nf" = "6" ]; chk "finding record = 6 fields (got '$nf')" $?
[ "$nc" = "10" ]; chk "candidate record = 10 fields (got '$nc')" $?
[ "$ni" = "6" ]; chk "info record = 6 fields (got '$ni')" $?
cls=$(head -1 "$CANDIDATES" | cut -d'|' -f1)
[ "$cls" = "CAND" ]; chk "candidate first field intact (got '$cls')" $?

# 2c. amass gate: skip when libpostal data missing (avoids sudo prompt)
source lib/recon_subdomains.sh
if [ -e /usr/share/libpostal/transliteration ] || [ -d /var/lib/libpostal ]; then
  _amass_ready; chk "amass gate (data present)" $?
else
  _amass_ready; [ $? -ne 0 ]; chk "amass gate (data missing → skip)" $?
fi

# 2d. brute-fallback: wordlist lines get the domain appended (massdns-less path)
out=$(printf 'www\napi\n' | awk -v d=example.com '{print $1"."d}')
[ "$out" = $'www.example.com\napi.example.com' ]; chk "dnsx brute fallback appends domain" $?

# 2e. ffuf timeout must NOT discard results: ffuf exits non-zero on timeout
# (rate-limited scans) but still wrote a partial json — extraction must run.
CT2="$TMP/ct"; mkdir -p "$CT2"; : > "$CT2/ffuf.txt"
_ffuf_timeout_test() {
  false 2>/dev/null   # "ffuf fails"
  printf '%s' '{"results":[{"status":403,"url":"http://a.com/checkout"}]}' > "$CT2/ffuf-a_com.json"
  [ -s "$CT2/ffuf-a_com.json" ] || return 0
  jq -r '.results[]? | "\(.status) \(.url)"' "$CT2/ffuf-a_com.json" 2>/dev/null >> "$CT2/ffuf.txt"
}
_ffuf_timeout_test
grep -q "403 http://a.com/checkout" "$CT2/ffuf.txt"; chk "ffuf timeout still extracts json results" $?

# 2f. CVE version matching: apache 2.4.49 is vulnerable (ge;lt 2.4.49;2.4.50),
# 2.4.52 is patched. Uses the seeded DB, exercises ver_cmp.
source lib/cve.sh
CV2="$TMP/cve"; mkdir -p "$CV2"
CV="$CV2" _seed_cve_db   # _seed_cve_db and _cve_match read $CV/cve-db.txt
CANDIDATES="$TMP/cve-c.txt"; : > "$CANDIDATES"
_cve_match apache 2.4.49 "nmap test"
grep -q "CVE-2021-41773" "$CANDIDATES"; chk "cve: apache 2.4.49 matched" $?
: > "$CANDIDATES"
_cve_match apache 2.4.52 "nmap test"
[ -s "$CANDIDATES" ]; chk "cve: apache 2.4.52 NOT matched" $([ ! -s "$CANDIDATES" ]; echo $?)
: > "$CANDIDATES"
_cve_match openssh 6.7 "nmap test"
grep -q "CVE-2018-15473" "$CANDIDATES"; chk "cve: openssh 6.7 matched" $?

# 2g. colour hygiene: empty colour vars => 0 ESC bytes
C_RST=""; C_GRN=""; C_YLW=""; C_RED=""; C_CYN=""
out=$(ok "x"; warn "y"; log "z")
n=$(printf '%s' "$out" | od -c | grep -c '033')
[ "$n" -eq 0 ]; chk "no ESC bytes under no-color (got $n)" $?

echo "== 3. phase ledger =="
PHASE_START=123; PHASE_DUR=5; phase_mark recon_test 0
if [ -s "$PHASE_STATUS" ]; then
  hdr=$(/bin/sed -n 1p "$PHASE_STATUS")
  [ "$hdr" = "phase	start	exit	dur_s" ]; chk "ledger header written" $?
  grep -q "recon_test	123	0	5" "$PHASE_STATUS"; chk "ledger row appended" $?
else
  chk "ledger file non-empty" 1
fi

echo "== 4. testssl parser (JSON + logfile fallback) =="
source lib/vuln_tls.sh
FINDINGS="$TMP/f.txt"; CANDIDATES="$TMP/c.txt"; INFOFILE="$TMP/i.txt"
# real 3.3dev structure: vulnerabilities array + protocol table
printf '%s\n' '{"scanResult":[{"vulnerabilities":[{"id":"h1","severity":"HIGH","finding":"TLS1.0 offered"},{"id":"m1","severity":"MEDIUM","finding":"weak cipher"},{"id":"ok1","severity":"OK","finding":"not vulnerable"}],"protocols":[{"id":"SSLv3","severity":"LOW","finding":"offered"}]}]}' > "$TMP/t.json"
: > "$FINDINGS"; : > "$CANDIDATES"; : > "$INFOFILE"
_parse_testssl h "$TMP/t.json" /dev/null
grep -q "^HIGH|testssl|h|h1|TLS1.0 offered" "$FINDINGS"; chk "testssl vulnerabilities HIGH→finding" $?
grep -q "CAND|tls-misconfig|h|m1 (MEDIUM)" "$CANDIDATES"; chk "testssl vulnerabilities MEDIUM→candidate" $?
grep -q "CAND|tls-misconfig|h|SSLv3 (LOW)" "$CANDIDATES"; chk "testssl protocol LOW→candidate" $?
! grep -q "ok1" "$FINDINGS" "$CANDIDATES"; chk "testssl OK rows skipped (noise)" $?
# older structure: findings array
printf '%s\n' '{"scanResult":[{"findings":[{"id":"f1","severity":"HIGH","finding":"TLS1.0 offered"}]}]}' > "$TMP/t2.json"
: > "$FINDINGS"; : > "$CANDIDATES"
_parse_testssl h "$TMP/t2.json" /dev/null
grep -q "^HIGH|testssl|h|f1|TLS1.0 offered" "$FINDINGS"; chk "testssl findings-array fallback HIGH→finding" $?
# logfile fallback for missing/corrupt JSON
printf 'found (HIGH) TLS 1.0 on 443\n' > "$TMP/t.log"
: > "$FINDINGS"; : > "$CANDIDATES"
_parse_testssl h "$TMP/nonexistent.json" "$TMP/t.log"
grep -q "scraped.*TLS 1.0" "$FINDINGS"; chk "testssl logfile fallback HIGH→finding" $?

echo "== 5. CLI exit codes =="
./huntops.sh -h >/dev/null 2>&1; rc=$?
[ "$rc" -eq 0 ]; chk "help exits 0" $?
./huntops.sh --bogus >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ]; chk "unknown arg exits 2" $?
./huntops.sh --no-terminal </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ]; chk "missing target exits 2" $?

if [ -n "$W_DIR" ]; then
  echo "== 6. real-run artifacts ($W_DIR) =="
  [ -s "$W_DIR/logs/phase-status.tsv" ]; chk "phase-status.tsv non-empty" $?
  [ -s "$W_DIR/logs/verbose.log" ]; chk "verbose.log non-empty" $?
  [ -f "$W_DIR/logs/debug.log" ]; chk "debug.log exists" $?
  # Find the domain from the deliverable files (they're named <domain>.txt, not info-<domain>.txt)
  dom=$(find "$W_DIR" -maxdepth 1 -name '*.txt' -not -name 'assetfinder.txt' -not -name 'certspotter.txt' -not -name 'crtsh.txt' -not -name 'subfinder.txt' -not -name 'info-*.txt' -exec basename {} \; | sed 's/\.txt$//' | head -1)
  [ -n "$dom" ] && [ -f "$W_DIR/$dom.txt" ]; chk "findings sheet exists ($dom.txt)" $?
  [ -n "$dom" ] && [ -f "$W_DIR/info-$dom.txt" ]; chk "recon dossier exists (info-$dom.txt)" $?
  if [ -f "$W_DIR/findings/candidates.txt" ]; then
    bad=0
    while IFS= read -r line; do
      n=$(awk -F'|' '{print NF}' <<< "$line")
      [ "$n" -eq 10 ] || { bad=$((bad+1)); [ "$VERBOSE" = 1 ] && echo "    bad-field-count cand: $line"; }
    done < "$W_DIR/findings/candidates.txt"
    chk "all candidate records have 10 fields (bad=$bad)" $([ "$bad" -eq 0 ]; echo $?)
  fi
  [ -f "$W_DIR/report/huntops-report.html" ]; chk "html report exists" $?
  [ -f "$W_DIR/report/summary.md" ]; chk "md report exists" $?
else
  note "(no -w workdir given, skipping artifact checks)"
fi

rm -rf "$TMP"
echo ""
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
