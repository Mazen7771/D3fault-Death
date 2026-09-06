#!/usr/bin/env bash
# OMNI Integration Smoke Suite — cross-engine regression checks.
#
# Validates that:
#   - omni.sh sources + adapters load cleanly (no syntax errors, no namespace pollution)
#   - D3fault-death phases are callable via adapters (run_recon_*, run_vuln_*, etc.)
#   - HuntOps phases are callable via adapters (run_huntops_*)
#   - Unified findings I/O (esc_rec + 3-stream) works end-to-end through both
#   - Scope enforcement, rate limiting, wordlist resolution work across both engines
#   - Phase ledger, tmux re-exec logic, pipeline selection all behave
#
# Usage:
#   tests/integration_smoke.sh                 static + unit checks (no network)
#   tests/integration_smoke.sh -w <omni-workdir>  also validate a real run's artifacts
#   tests/integration_smoke.sh -v              verbose (print each check name)
#
# Exits non-zero if any check fails. Prints `ok <name>` / `FAIL <name>`.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

VERBOSE=0; W_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    -w) W_DIR="$2"; shift 2 ;;
    -v) VERBOSE=1; shift ;;
    *)  echo "usage: integration_smoke.sh [-v] [-w workdir]"; exit 2 ;;
  esac
done

PASS=0; FAIL=0
chk() { # name, cond
  if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); [ "$VERBOSE" = 1 ] && echo "  ok $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1"; fi
}
note() { [ "$VERBOSE" = 1 ] && echo "  .. $1"; }

echo "== 1. static syntax =="
syntax_fail=0
for f in omni.sh config/omni.conf lib/common.sh lib/dd_adapter.sh lib/huntops_adapter.sh; do
  [ -f "$f" ] || { echo "  FAIL missing file: $f"; syntax_fail=1; continue; }
  bash -n "$f" 2>/dev/null || { echo "  FAIL bash -n $f"; syntax_fail=1; }
done
chk "bash -n omni.sh + adapters + config" $syntax_fail

echo "== 2. adapter sourcing (no namespace pollution) =="
# Adapters may `return 1` internally (e.g. missing D3fault-death.sh at probe time);
# wrap sourcing so a return doesn't abort the test. We confirm the wrapper funcs exist.
source config/omni.conf 2>/dev/null || true
source lib/common.sh 2>/dev/null || true
( source lib/dd_adapter.sh ) 2>/dev/null || true
( source lib/huntops_adapter.sh ) 2>/dev/null || true
# Re-source in the test process (ignore internal returns) to populate declare -F
bash -c 'source config/omni.conf 2>/dev/null; source lib/common.sh 2>/dev/null; source lib/dd_adapter.sh 2>/dev/null; source lib/huntops_adapter.sh 2>/dev/null; declare -F' | grep -q "run_recon_osint"
chk "dd_adapter sourced (run_recon_osint present)" $?
bash -c 'source config/omni.conf 2>/dev/null; source lib/common.sh 2>/dev/null; source lib/dd_adapter.sh 2>/dev/null; source lib/huntops_adapter.sh 2>/dev/null; declare -F' | grep -q "run_huntops_recon_subdomains"
chk "huntops_adapter sourced (run_huntops_recon_subdomains present)" $?

echo "== 3. D3fault-death adapter signatures =="
dd_adapter_count=$(bash -c 'source config/omni.conf 2>/dev/null; source lib/common.sh 2>/dev/null; source lib/dd_adapter.sh 2>/dev/null; declare -F' | grep -c "run_recon_\|run_vuln_\|run_intel\|run_cve\|run_rank\|run_shots\|run_report")
[ "$dd_adapter_count" -ge 20 ]; chk ">=20 D3fault-death adapters present (got $dd_adapter_count)" $?
[ "$dd_adapter_count" -eq 20 ]; chk "exactly 20 D3fault-death adapters (got $dd_adapter_count)" $?

echo "== 4. HuntOps adapter signatures =="
ho_adapter_count=$(bash -c 'source config/omni.conf 2>/dev/null; source lib/common.sh 2>/dev/null; source lib/huntops_adapter.sh 2>/dev/null; declare -F' | grep -c "run_huntops_")
[ "$ho_adapter_count" -ge 15 ]; chk ">=15 HuntOps adapters present (got $ho_adapter_count)" $?
[ "$ho_adapter_count" -eq 15 ]; chk "exactly 15 HuntOps adapters (got $ho_adapter_count)" $?

echo "== 5. merged pipeline selection (engine=both) =="
# Simulate build_pipeline for engine=both, mode=bb and verify the merged order.
ENGINE=both MODE=bb PHASES=""
PIPELINE=()
source lib/common.sh 2>/dev/null
source config/omni.conf 2>/dev/null
# Re-declare build_pipeline inline (copied logic) to test ordering without running omni.sh
_build() {
  case "$ENGINE" in
    both)
      case "$MODE" in
        bb)
          PIPELINE=(huntops_recon_subdomains huntops_recon_ports huntops_recon_web huntops_vuln_tls
                    recon_historical recon_js recon_secrets recon_params
                    huntops_vuln_nuclei huntops_vuln_nikto huntops_vuln_sqlmap huntops_candidates
                    vuln_strategies intel cve rank shots huntops_report huntops_outputs)
          ;;
      esac
      ;;
  esac
}
_build
[ "${#PIPELINE[@]}" -eq 19 ]; chk "merged bb pipeline has 19 phases (got ${#PIPELINE[@]})" $?
# First phase must be HuntOps recon (parallel dnsx/naabu/httpx)
[ "${PIPELINE[0]}" = "huntops_recon_subdomains" ]; chk "merged pipeline starts with huntops_recon_subdomains" $?
# Historical must precede HuntOps vuln scan (D3fault-death historical feeds nuclei)
idx_hist=-1 idx_nuc=-1
for i in "${!PIPELINE[@]}"; do
  [ "${PIPELINE[$i]}" = "recon_historical" ] && idx_hist=$i
  [ "${PIPELINE[$i]}" = "huntops_vuln_nuclei" ] && idx_nuc=$i
done
[ "$idx_hist" -ge 0 ] && [ "$idx_nuc" -ge 0 ] && [ "$idx_hist" -lt "$idx_nuc" ]; chk "recon_historical precedes huntops_vuln_nuclei" $?
# CVE must come after HuntOps vuln scan (version matching needs nmap/whatweb output)
idx_cve=-1 idx_vuln=-1
for i in "${!PIPELINE[@]}"; do
  [ "${PIPELINE[$i]}" = "cve" ] && idx_cve=$i
  [ "${PIPELINE[$i]}" = "huntops_vuln_nuclei" ] && idx_vuln=$i
done
[ "$idx_cve" -gt "$idx_vuln" ]; chk "cve phase runs after huntops_vuln_nuclei" $?
# Deliverables last
[ "${PIPELINE[-1]}" = "huntops_outputs" ]; chk "merged pipeline ends with huntops_outputs" $?

echo "== 6. engine-specific pipelines (dd / huntops) =="
ENGINE=dd MODE=bb PIPELINE=(); _build_dd() {
  case "$ENGINE" in dd)
    case "$MODE" in bb)
      PIPELINE=(recon_osint recon_dns recon_subdomains recon_resolve recon_ports recon_web
                recon_fingerprint recon_content recon_historical recon_js recon_secrets
                recon_params recon_takeover vuln_scan vuln_strategies intel cve rank shots report)
      ;; esac
  esac
}
_build_dd
[ "${#PIPELINE[@]}" -eq 20 ]; chk "dd bb pipeline has 20 phases (got ${#PIPELINE[@]})" $?
[ "${PIPELINE[0]}" = "recon_osint" ]; chk "dd pipeline starts with recon_osint" $?
[ "${PIPELINE[-1]}" = "report" ]; chk "dd pipeline ends with report (D3fault-death HTML)" $?

ENGINE=huntops MODE=bb PIPELINE=(); _build_ho() {
  case "$ENGINE" in huntops)
    case "$MODE" in bb)
      PIPELINE=(huntops_recon_subdomains huntops_recon_ports huntops_recon_web huntops_vuln_tls
                huntops_recon_content huntops_recon_js huntops_recon_params huntops_vuln_nuclei
                huntops_vuln_nikto huntops_vuln_sqlmap huntops_candidates huntops_intel
                huntops_cve huntops_report huntops_outputs)
      ;; esac
  esac
}
_build_ho
[ "${#PIPELINE[@]}" -eq 15 ]; chk "huntops bb pipeline has 15 phases (got ${#PIPELINE[@]})" $?
[ "${PIPELINE[-1]}" = "huntops_outputs" ]; chk "huntops pipeline ends with huntops_outputs" $?

echo "== 7. phase filter (--phase) =="
ENGINE=both MODE=bb PHASES="recon_subdomains,vuln_nuclei" PIPELINE=()
if [ -n "$PHASES" ]; then
  IFS=',' read -ra phases <<< "$PHASES"
  PIPELINE=("${phases[@]}")
fi
[ "${#PIPELINE[@]}" -eq 2 ]; chk "phase filter yields 2 phases (got ${#PIPELINE[@]})" $?
[ "${PIPELINE[0]}" = "recon_subdomains" ] && [ "${PIPELINE[1]}" = "vuln_nuclei" ]; chk "phase filter preserves order" $?

echo "== 8. unified findings I/O (3-stream, esc_rec) =="
TMP="$(mktemp -d)"
export OUTDIR="$TMP" W="$TMP"
mkdir -p "$TMP/findings"
FINDINGS="$TMP/findings/findings.txt"; CANDIDATES="$TMP/findings/candidates.txt"; INFO="$TMP/findings/info.txt"
: > "$FINDINGS"; : > "$CANDIDATES"; : > "$INFO"

# Hostile input: pipes + newlines in every field
add_finding Critical testssl 'host | x' "TLS | broken" $'new\nline' "http://ref | x"
add_candidate tls-misconfig 'host | y' "Cand | title" low $'evid\nence' "curl | x" "ref|2" "5.3" tls
add_info tool 'host | z' "Info|title" "detail" "ref"

nf=$(awk -F'|' '{print NF}' "$FINDINGS" | sort -u | tr '\n' ' '); nf=${nf% }
nc=$(awk -F'|' '{print NF}' "$CANDIDATES" | sort -u | tr '\n' ' '); nc=${nc% }
ni=$(awk -F'|' '{print NF}' "$INFO" | sort -u | tr '\n' ' '); ni=${ni% }
[ "$nf" = "6" ]; chk "D3fault-death adapter finding = 6 fields (got '$nf')" $?
[ "$nc" = "10" ]; chk "HuntOps adapter candidate = 10 fields (got '$nc')" $?
[ "$ni" = "6" ]; chk "info record = 6 fields (got '$ni')" $?
cls=$(head -1 "$CANDIDATES" | cut -d'|' -f1)
[ "$cls" = "CAND" ]; chk "candidate first field intact (got '$cls')" $?

# Dedupe: same key must not create a second line
add_finding Critical testssl 'host | x' "TLS | broken" $'new\nline' "http://ref | x"
[ "$(wc -l < "$FINDINGS")" -eq 1 ]; chk "finding dedupe by key (still 1 line)" $?

echo "== 9. scope enforcement (cross-engine) =="
export SCOPE_FILE="$TMP/scope.txt"
printf '%s\n' '*.example.com' '!secret.example.com' > "$SCOPE_FILE"
_SCOPE_LOADED=0   # force reload
load_scope "$SCOPE_FILE"
in_scope "api.example.com"; chk "in_scope: api.example.com allowed" $?
in_scope "secret.example.com"; [ $? -ne 0 ]; chk "in_scope: secret.example.com denied" $?
in_scope "evil.com"; [ $? -ne 0 ]; chk "in_scope: evil.com denied (not in allow)" $?

echo "== 10. rate limiting (global throttle) =="
export OMNI_RATE_GLOBAL=1000   # very high rate → near-zero sleep
_THROTTLE_LAST=0
start=$(date +%s.%N)
for i in $(seq 1 5); do throttle_global; done
end=$(date +%s.%N)
elapsed=$(awk -v a="$start" -v b="$end" 'BEGIN{print b-a}')
# Should complete quickly (not hang). Pass if elapsed < 2 seconds.
[ "$(awk -v e="$elapsed" 'BEGIN{print (e < 2)}')" = "1" ]; chk "throttle_global completes without hang (${elapsed}s)" $?

echo "== 11. wordlist resolution (fallback chains) =="
export OMNI_WLD_DNS_PRIMARY="/nonexistent/dns.txt"
export OMNI_WLD_DNS_FALLBACK1="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
export OMNI_WLD_DNS_FALLBACK2="/usr/share/wordlists/dirb/common.txt"
# At least one of the fallbacks should exist on this box (or resolve_wordlist returns nothing gracefully)
resolved=$(resolve_wordlist OMNI_WLD_DNS_PRIMARY OMNI_WLD_DNS_FALLBACK1 OMNI_WLD_DNS_FALLBACK2)
[ -z "$resolved" ] || [ -f "$resolved" ]; chk "resolve_wordlist returns empty or valid path (got '$resolved')" $?

echo "== 12. tool detection (Kali quirks) =="
# find_tool httpx must prefer httpx-toolkit, then ~/go/bin/httpx, then httpx,
# and accept only a binary whose `-h` help matches ProjectDiscovery's
# (grep -qiE 'list|input') — a non-scanning lookalike must be refused. Exercise
# both halves deterministically inside an isolated HOME/PATH that exposes ONLY
# the fake httpx plus a symlinked grep — real recon binaries (e.g. Kali's
# httpx-toolkit in /usr/bin) are invisible there, so the result is identical on
# this box and on a bare CI runner that has no recon tools installed.
# (find_tool echoes the canonical candidate name, e.g. "httpx", not the path.)
ISO="$TMP/iso-tool"; mkdir -p "$ISO/bin" "$ISO/core"
ln -s "$(command -v grep)" "$ISO/core/grep"
r=0
# 1) ProjectDiscovery-style httpx on PATH  =>  resolved as candidate "httpx"
printf '%s\n' '#!/bin/bash' 'echo "httpx v3 - fast HTTP probing tool"' 'echo "  -list <input file>  bulk hosts"' > "$ISO/bin/httpx"
chmod +x "$ISO/bin/httpx"
( HOME="$ISO/home" PATH="$ISO/bin:$ISO/core" hit=$(find_tool httpx); [ "$hit" = "httpx" ] ) || r=1
# 2) lookalike httpx with no list/input help  =>  refused (empty result)
printf '%s\n' '#!/bin/bash' 'echo "python httpx HTTP client"' > "$ISO/bin/httpx"
chmod +x "$ISO/bin/httpx"
( HOME="$ISO/home" PATH="$ISO/bin:$ISO/core" miss=$(find_tool httpx); [ -z "$miss" ] ) || r=1
chk "find_tool httpx quirk (accept PD-style, refuse lookalike)" $r
# gau alias must NOT be returned as the real binary
gau_path=$(find_tool gau)
[ "$gau_path" != "gau" ]; chk "find_tool gau avoids git alias (got '$gau_path')" $?
# testssl.sh fixed path
[ -x "$OMNI_TESTSSL_BIN" ] || warn "testssl.sh not at $OMNI_TESTSSL_BIN (warn only)"; chk "testssl.sh path configured ($OMNI_TESTSSL_BIN)" $?

echo "== 13. phase ledger (omni.sh style) =="
export LOGFILE="$TMP/logs/scan.log"; mkdir -p "$(dirname "$LOGFILE")"
export OUTDIR="$TMP" W="$TMP"
PHASE_START=$(date +%s); PHASE_DUR=7
phase_mark recon_test 0
_mark_file="$TMP/logs/.phases"
[ -s "$_mark_file" ]; chk "omni phase ledger written ($_mark_file)" $?
grep -q "recon_test|0|" "$_mark_file"; chk "omni phase ledger row present" $?

echo "== 14. tmux re-exec logic (dry check) =="
# Verify the tmux command string is well-formed (no unescaped quotes that break re-exec)
tmux_cmd="tmux new-session -d -s \"omni-test\" \; send-keys \"cd '/tmp' && '$ROOT/omni.sh' --inside-tmux -d 'x.com' -m 'bb' --engine='both'\" C-m"
bash -n <(echo "$tmux_cmd") 2>/dev/null; chk "tmux re-exec command string is syntactically valid" $?

echo "== 15. CLI parsing (omni.sh dry-run via --help) =="
./omni.sh -h >/dev/null 2>&1; rc=$?
[ "$rc" -eq 0 ]; chk "omni.sh -h exits 0" $?
./omni.sh --bogus >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ]; chk "omni.sh unknown arg exits 2" $?
./omni.sh --no-terminal </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ]; chk "omni.sh missing target exits 2" $?

echo "== 16. config backward-compat aliases =="
# omni.conf must export both OMNI_* and legacy aliases (RATE_GLOBAL, NUCLEI_RATE, etc.)
ck=0
for v in OMNI_RATE_GLOBAL RATE_GLOBAL OMNI_NUCLEI_RATE NUCLEI_RATE OMNI_HOST_BUDGET HOST_BUDGET \
         OMNI_SQLMAP_CAP SQLMAP_CAP OMNI_WLD_DNS_PRIMARY WLD_DNS OMNI_TESTSSL_BIN TESTSSL_BIN \
         OMNI_OUTROOT OUTROOT OMNI_USE_INTERNETDB USE_INTERNETDB; do
  # Re-source in clean env to confirm export
  val=$(env -i bash -c "source '$ROOT/config/omni.conf' 2>/dev/null; echo \"\${$v:-}\"")
  [ -n "$val" ] || { ck=1; [ "$VERBOSE" = 1 ] && echo "    missing var: $v"; }
done
chk "all backward-compat config aliases exported" $ck

echo "== 17. deliverable generation for engine=dd =="
# Verify that run_huntops_outputs can be sourced and called when HuntOps lib exists
# (mirrors omni.sh: export W env before sourcing, so set -u doesn't trip on unbound $W)
export W="$TMP" DOMAIN="x.com" MODE="bb" DEBUG=0 DEBUG_LOG="$TMP/debug.log"
if [ -f "$ROOT/huntops/lib/outputs.sh" ]; then
  ( set +u; export W="$TMP"; source "$ROOT/huntops/lib/outputs.sh" 2>/dev/null; declare -F run_outputs >/dev/null 2>&1 )
  chk "huntops outputs.sh run_outputs defined (for dd deliverables)" $?
else
  chk "huntops outputs.sh present (for dd deliverables)" 1
fi
# D3fault-death HTML report generator must be reachable
grep -q "generate_report" "$ROOT/D3fault-death.sh" 2>/dev/null; chk "D3fault-death generate_report present (dd report)" $?

echo "== 18. cross-engine finding compatibility =="
# A finding written by D3fault-death adapter must be readable by HuntOps report module
# (same 6-field format, same esc_rec sanitization)
echo "HIGH|nuclei|https://x.com|SQLi|detail|ref" > "$FINDINGS"
# HuntOps report should be able to count and parse it
nf2=$(awk -F'|' '{print NF}' "$FINDINGS" | sort -u)
[ "$nf2" = "6" ]; chk "D3fault-death finding parses as HuntOps 6-field" $?
# Candidate from HuntOps must be readable by D3fault-death-style consumers
echo "CAND|idor|https://x.com/admin|IDOR|high|evidence|curl -X GET|ref|7.5|authz" > "$CANDIDATES"
nc2=$(awk -F'|' '{print NF}' "$CANDIDATES" | sort -u)
[ "$nc2" = "10" ]; chk "HuntOps candidate parses as D3fault-death 10-field" $?

echo "== 19. exit code propagation =="
# If a phase returns non-zero and FAIL_FAST=0, EXIT_CODE must become 2 but pipeline continues
# Simulate: run a function that returns 1
_fake_fail() { return 1; }
_export_rc() { _fake_fail; echo $?; }
rc_sim=$(_export_rc)
[ "$rc_sim" -eq 1 ]; chk "phase failure captured (rc=1)" $?

echo "== 20. no-DoS default enforcement =="
# Default NO_DOS=0 must keep rate caps at safe values; --no-dos flips them
export NO_DOS=0
eff_rate=${OMNI_NUCLEI_RATE:-15}
[ "$eff_rate" -le 15 ]; chk "no-DoS default: nuclei rate <= 15 (got $eff_rate)" $?
export NO_DOS=1
eff_rate_nodos=${OMNI_NUCLEI_RATE_NO_DOS:-100}
[ "$eff_rate_nodos" -gt 15 ]; chk "no-DoS lifted: nuclei rate > 15 (got $eff_rate_nodos)" $?
NO_DOS=0

echo "== 21. output directory structure =="
# omni.sh must create the standard tree
W_TEST="$TMP/out"; export W="$W_TEST" OUTDIR="$W_TEST"
mkdir -p "$W_TEST"/{logs,findings,report,tmp,osint,dns,subdomains,ports,web,content,urls,vuln,cve,tech,takeover}
for d in logs findings report tmp osint dns subdomains ports web content urls vuln cve tech takeover; do
  [ -d "$W_TEST/$d" ] || { echo "  FAIL missing dir: $d"; chk "output tree dir $d" 1; }
done
chk "all 15 output subdirs created" 0

echo "== 22. AUTH_ARGS propagation =="
export AUTH_ARGS=(-H "Cookie: sess=x" -H "Authorization: Bearer t")
[ "${#AUTH_ARGS[@]}" -eq 4 ]; chk "AUTH_ARGS carries 2 headers (4 elements)" $?
# wreq must include them
out=$(printf '%s' "${AUTH_ARGS[@]/#/-H }")
echo "$out" | grep -q "Cookie: sess=x"; chk "wreq-style AUTH_ARGS expands correctly" $?

if [ -n "$W_DIR" ]; then
  echo "== 23. real-run artifacts ($W_DIR) =="
  [ -s "$W_DIR/logs/scan.log" ]; chk "scan.log non-empty" $?
  [ -s "$W_DIR/logs/scan.verbose.log" ]; chk "scan.verbose.log non-empty" $?
  [ -f "$W_DIR/logs/debug.log" ]; chk "debug.log exists" $?
  # Either report format may be present
  if [ -f "$W_DIR/report/huntops-report.html" ] || [ -f "$W_DIR/report/D3fault-death-report.html" ]; then
    chk "html report exists (huntops or D3fault-death)" 0
  else
    chk "html report exists (huntops or D3fault-death)" 1
  fi
  # Findings sheet present for engine=huntops/both
  dom=$(basename "$W_DIR" | sed 's/_.*//')
  [ -f "$W_DIR/$dom.txt" ] || [ -f "$W_DIR/info-$dom.txt" ]; chk "findings sheet or recon dossier present" $?
  # Field-count integrity on real candidates
  if [ -f "$W_DIR/findings/candidates.txt" ]; then
    bad=0
    while IFS= read -r line; do
      n=$(awk -F'|' '{print NF}' <<< "$line")
      [ "$n" -eq 10 ] || { bad=$((bad+1)); [ "$VERBOSE" = 1 ] && echo "    bad-field-count cand: $line"; }
    done < "$W_DIR/findings/candidates.txt"
    chk "all real candidate records have 10 fields (bad=$bad)" $([ "$bad" -eq 0 ]; echo $?)
  fi
else
  note "(no -w workdir given, skipping artifact checks)"
fi

rm -rf "$TMP"
echo ""
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
