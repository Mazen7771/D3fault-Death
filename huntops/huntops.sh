#!/usr/bin/env bash
# HuntOps — general-purpose, auto-mode bug-bounty recon + vuln scanner.
#   ./huntops.sh -d target.com [-m quick|bb|deep] [-s scope.txt] [-H 'Cookie: x']
#                  [--test-account user@x] [-o outdir] [-v|--debug] [--no-terminal] [-i]
# Auto mode is the default: NO prompts. Runs the whole pipeline unattended, with
# live tmux windows (main | verbose | behind-scenes) by default.
set -u

HUNTOPS_ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$HUNTOPS_ROOT/config/config.sh"
source "$HUNTOPS_ROOT/config/wordlists.conf"
[ -f "$HUNTOPS_ROOT/config/keys.conf" ] && source "$HUNTOPS_ROOT/config/keys.conf"
source "$HUNTOPS_ROOT/lib/core.sh"   # log/warn/ok/err, tool_exists, add_*, throttle
source "$HUNTOPS_ROOT/lib/ui.sh"     # interactive_menu, launch_live_windows (tmux)

# ---- CLI ---------------------------------------------------------------------
MODE="bb"; TARGET=""; CUSTOM_OUT=""; TEST_ACCOUNT=""
FAIL_FAST=0; DO_INSTALL=0; NO_DOS=0; MODE_DEEP=0; MODE_QUICK=0; SCOPE_FILE=""
VERBOSE=0; DEBUG=0; NO_TERMINAL=0; MENU=0; NO_COLOR=0; INSIDE_TMUX=0
TLS_ENABLE="auto"
PIPELINE_TYPE="legacy"  # legacy | adapter | auto
ADAPTERS_CONFIG=""
LIST_ADAPTERS=0
PHASE_FILTER=""
ORIG_ARGS=("$@")

usage() { # [exit-code]
  cat <<'EOF'
HuntOps v1.0.0 — auto-mode bug-bounty recon + vulnerability scanner

USAGE:
  ./huntops.sh -d target.com [options]
  ./huntops.sh -t 1.2.3.4    [options]
  ./huntops.sh               interactive setup menu
  ./huntops.sh -i            install/verify tools + templates, then exit

OPTIONS:
  -d DOMAIN          target domain (root + subdomains auto-in-scope)
  -t IP              target IP address
  -m MODE            quick | bb (default) | deep
  -s FILE            program scope file (allow / deny / !deny)
  -H HEADER          auth header, repeatable (Cookie:/Authorization:)
  -o DIR             custom output directory
  --test-account EMAIL      only fire IDOR/authz candidates for this account
  --ssl | --no-ssl          force / disable testssl.sh TLS phase (auto)
  -v, --verbose      live terminal view of scan steps (tmux, on by default)
  --debug            behind-the-scenes raw view of every tool call
  --no-terminal      disable the auto tmux live windows (scripts/CI)
  --no-color         disable ANSI colour output
  --menu             force the interactive setup menu
  --no-dos           allow full -p- port scans / deep sqlmap / huge wordlists
  --fail-fast        abort pipeline on first phase failure
  -i                 install missing tools + nuclei templates, then exit

  # Adapter Pipeline Options (NEW)
  --pipeline TYPE    pipeline type: legacy (default) | adapter | auto
  --adapters-config  custom adapters.yaml path
  --list-adapters    list registered adapters and status
  --phase-filter     comma-separated phases to run (e.g., recon,vuln_scan)

  -h, --help         show this help

EXAMPLES:
  ./huntops.sh -d example.com                        # bb recon + vuln scan (legacy)
  ./huntops.sh -d example.com -m deep --no-dos       # exhaustive run (legacy)
  ./huntops.sh -t 1.2.3.4 -s scope.txt --ssl         # IP target, force TLS
  ./huntops.sh --debug --no-terminal -d example.com  # raw view, no tmux
  ./huntops.sh -d example.com --pipeline adapter     # new adapter-based pipeline
  ./huntops.sh -d example.com --pipeline adapter --phase-filter recon,vuln_scan
  ./huntops.sh --list-adapters                       # show adapter registry
EOF
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -d) TARGET="$2"; shift 2 ;;
    -t) TARGET="$2"; shift 2 ;;
    -m) MODE="$2"; shift 2 ;;
    -s) SCOPE_FILE="$2"; shift 2 ;;
    -H) AUTH_ARGS+=(-H "$2"); shift 2 ;;
    -o) CUSTOM_OUT="$2"; shift 2 ;;
    --test-account) TEST_ACCOUNT="$2"; shift 2 ;;
    --ssl) TLS_ENABLE="on"; shift ;;
    --no-ssl) TLS_ENABLE="off"; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    --debug) DEBUG=1; VERBOSE=1; shift ;;
    --no-terminal) NO_TERMINAL=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    --menu) MENU=1; shift ;;
    --inside-tmux) INSIDE_TMUX=1; NO_TERMINAL=1; shift ;;
    --no-dos) NO_DOS=1; shift ;;
    --fail-fast) FAIL_FAST=1; shift ;;
    -i) DO_INSTALL=1; shift ;;
    --pipeline) PIPELINE_TYPE="$2"; shift 2 ;;
    --adapters-config) ADAPTERS_CONFIG="$2"; shift 2 ;;
    --list-adapters) LIST_ADAPTERS=1; shift ;;
    --phase-filter) PHASE_FILTER="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 2 ;;
  esac
done

case "$MODE" in
  quick) MODE_QUICK=1; PIPELINE=("${PIPELINE_QUICK[@]}") ;;
  deep)  MODE_DEEP=1;  PIPELINE=("${PIPELINE_DEEP[@]}") ;;
  bb|full) PIPELINE=("${PIPELINE_BB[@]}") ;;
  *) echo "unknown mode: $MODE" >&2; usage 2 ;;
esac

# Handle adapter pipeline type
case "$PIPELINE_TYPE" in
  legacy) ;;
  adapter|auto)
    # Source the orchestrator and run adapter pipeline
    source "$HUNTOPS_ROOT/lib/orchestrator.sh"
    source "$HUNTOPS_ROOT/lib/findings_sink.sh"
    # Use default config if not specified
    ADAPTERS_CONFIG="${ADAPTERS_CONFIG:-$HUNTOPS_ROOT/config/adapters.yaml}"
    PIPELINE_CONFIG="${PIPELINE_CONFIG:-$HUNTOPS_ROOT/config/pipeline.yaml}"
    ;;
  *) echo "unknown pipeline type: $PIPELINE_TYPE" >&2; usage 2 ;;
esac

# colour suppression (NO_COLOR flag or non-tty output)
if [ "$NO_COLOR" = 1 ] || [ ! -t 1 ]; then
  C_RST=''; C_RED=''; C_GRN=''; C_YLW=''; C_BLU=''; C_CYN=''
fi

# ---- install-only mode -------------------------------------------------------
if [ "$DO_INSTALL" = 1 ]; then
  source "$HUNTOPS_ROOT/lib/install.sh"
  do_install
  exit $?
fi

# ---- list adapters mode -------------------------------------------------------
if [ "$LIST_ADAPTERS" = 1 ]; then
  source "$HUNTOPS_ROOT/lib/orchestrator.sh"
  source "$HUNTOPS_ROOT/lib/adapter_interface.sh"
  ADAPTERS_CONFIG="${ADAPTERS_CONFIG:-$HUNTOPS_ROOT/config/adapters.yaml}"
  orchestrator_parse_adapters "$ADAPTERS_CONFIG" || exit 1
  echo "Registered Adapters:"
  echo "===================="
  for entry in "${ADAPTER_META[@]}"; do
    IFS='|' read -r name type path caps enabled priority req_key api_key_env binary <<< "$entry"
    printf "  %-20s | %-4s | %-12s | priority: %s | api_key: %s\n" "$name" "$type" "$caps" "$priority" "$req_key"
    [ "$enabled" = "false" ] && echo "    (disabled)"
    [ -n "$api_key_env" ] && [ -z "${!api_key_env:-}" ] && echo "    MISSING API KEY: $api_key_env"
  done
  exit 0
fi

# ---- target sanity -----------------------------------------------------------
if [ -z "$TARGET" ]; then
  if [ "$MENU" = 1 ] || [ -t 1 ]; then interactive_menu; else usage 2; fi
fi
if is_ip "$TARGET"; then
  DOMAIN="$TARGET"; TARGET_IP="$TARGET"
else
  TARGET="${TARGET#https://}"; TARGET="${TARGET#http://}"; TARGET="${TARGET%/}"
  DOMAIN="$(derive_root "$TARGET")"
fi
load_scope

# ---- live tmux windows (auto by default) -------------------------------------
# Launches a 3-window tmux session: main scan, verbose steps, behind-the-scenes.
# Re-execs itself inside tmux with --inside-tmux + a pinned -o workdir, then
# attaches. Disabled with --no-terminal, in CI (non-tty), or when already inside.
if [ "$NO_TERMINAL" = 0 ] && [ "$INSIDE_TMUX" = 0 ] && command -v tmux >/dev/null 2>&1 && [ -t 1 ]; then
  launch_live_windows   # never returns (attach → exit)
fi

setup_target

# ---- Run Adapter Pipeline (if selected) --------------------------------------
if [ "$PIPELINE_TYPE" = "adapter" ] || [ "$PIPELINE_TYPE" = "auto" ]; then
  log "Starting adapter-based pipeline for target: $TARGET (mode: $MODE)"

  # Export phase filter for orchestrator (MUST be set BEFORE init - orchestrator_parse_pipeline reads it)
  export PHASE_FILTER="${PHASE_FILTER:-}"

  # Initialize orchestrator
  orchestrator_init "$ADAPTERS_CONFIG" "$PIPELINE_CONFIG" || {
    err "Failed to initialize orchestrator"
    exit 1
  }

  # Build opts JSON (script-scope, not local — this block is not a function)
  OPTS_JSON=$(printf '{}' | jq --arg mode "$MODE" \
    --arg no_dos "$NO_DOS" \
    --arg test_account "$TEST_ACCOUNT" \
    --arg target "$TARGET" \
    --arg workdir "$W" \
    '. + {mode: $mode, no_dos: ($no_dos == "1"), test_account: $test_account, target: $target, workdir: $workdir}' 2>/dev/null || echo "{}")

  EXIT_CODE=0
  # Run pipeline
  if orchestrator_run "$TARGET" "$W" "$MODE" "$OPTS_JSON"; then
    log "Adapter pipeline completed successfully"
  else
    err "Adapter pipeline completed with failures"
    EXIT_CODE=2
  fi

  orchestrator_cleanup

  # Generate final reports using the adapter report generator
  if [ -f "$HUNTOPS_ROOT/lib/report.sh" ]; then
    source "$HUNTOPS_ROOT/lib/report.sh"
    run_report || { err "report generation failed"; EXIT_CODE=1; }
  fi
  if [ -f "$HUNTOPS_ROOT/lib/outputs.sh" ]; then
    source "$HUNTOPS_ROOT/lib/outputs.sh"
    run_outputs || { err "deliverables generation failed"; EXIT_CODE=1; }
  fi
  log "done. report: $W/report/huntops-report.html  (summary: $W/report/summary.md)"
  ok "deliverables: $W/$DOMAIN.txt  +  $W/info-$DOMAIN.txt"
  [ "$EXIT_CODE" = 0 ] && ok "scan complete (exit 0)" || err "scan completed with phase failures (exit $EXIT_CODE)"
  exit "$EXIT_CODE"
fi

# ASCII logo banner
logo="HuntOps"
[ "$MODE_DEEP" = 1 ] && logo="HuntOps • DEEP"
[ "$MODE_QUICK" = 1 ] && logo="HuntOps • QUICK"
printf '%s\n%s\n' \
  "$C_CYN" \
  "  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗ ██████╗ ██████╗ ███████╗" \
  "  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝" \
  "  ███████║██║   ██║██╔██╗ ██║   ██║   ██║   ██║██████╔╝███████╗" \
  "  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██║   ██║██╔═══╝ ╚════██║" \
  "  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝██║     ███████║" \
  "  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚══════╝" \
  "$C_RST" | sed 's/^  //'
log "HuntOps v$HUNTOPS_VERSION — target: $TARGET  mode: $MODE"
log "workdir: $W"
[ "$MODE_DEEP" = 1 ] && ok "deep mode: DNS brute-force + full port scan + heavy wordlists"
[ "$NO_DOS" = 0 ] && ok "no-DoS defaults active (add --no-dos to enable heavy scans)"

# ---- pre-flight --------------------------------------------------------------
preflight() {
  local missing=0
  for t in curl nmap nuclei jq dig; do
    tool_exists "$t" || { err "hard-dependency missing: $t"; missing=1; }
  done
  [ $missing -eq 1 ] && { err "run ./huntops.sh -i first"; exit 2; }
  if tool_exists nuclei; then
    local tc; tc=$(find ~/.local/share/nuclei-templates ~/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l)
    [ "${tc:-0}" -lt 100 ] && warn "nuclei templates low ($tc) — run './huntops.sh -i' to download the full library"
  fi
  [ -x "${TESTSSL_BIN:-/nonexistent}" ] || warn "testssl.sh not found ($TESTSSL_BIN) — TLS phase will be skipped (set TESTSSL_BIN)"
  # Bacula ships a `bat` GUI under /usr/sbin:/sbin that can shadow the syntax-
  # highlighter `bat` some tools shell out to, and some shells alias cat→bat.
  # Detect the filesystem shadow so output corruption is explainable up front.
  local b bin
  b=$(command -v bat 2>/dev/null || true)
  case "$b" in /usr/sbin/*|/sbin/*) warn "PATH 'bat' is Bacula's GUI ($b) — tools calling 'bat' as a pager may emit garbage; huntops uses 'command' for all external calls";; esac
  local disk; disk=$(df -m "$HUNTOPS_ROOT" | awk 'NR==2{print $4}')
  [ "${disk:-0}" -lt 2000 ] && warn "low disk: ${disk}MB free"
}
preflight

# ---- run pipeline ------------------------------------------------------------
EXIT_CODE=0
for phase in "${PIPELINE[@]}"; do
  lib="$HUNTOPS_ROOT/lib/$phase.sh"
  if [ ! -f "$lib" ]; then warn "missing module $phase — skipping"; continue; fi
  source "$lib"
  if ! declare -F "run_${phase}" >/dev/null; then warn "$phase: no run_${phase}() — skipping"; continue; fi

  PHASE_START=$(date +%s)
  banner_phase "PHASE: $phase"
  dbg ">>> phase start: $phase"
  rc=0
  if [ "$DEBUG" = 1 ]; then
    # capture raw phase stdout/stderr into the behind-the-scenes debug log while
    # still streaming to the terminal
    set -o pipefail
    run_${phase} 2>&1 | tee -a "$DEBUG_LOG"
    rc=${PIPESTATUS[0]}
    set +o pipefail
  else
    run_${phase}
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    if [ "$FAIL_FAST" = 1 ]; then err "phase $phase FAILED (fail-fast)"; exit 3; fi
    err "phase $phase FAILED — continuing"
    EXIT_CODE=2
  fi
  PHASE_DUR=$(( $(date +%s) - PHASE_START ))
  phase_mark "$phase" "$EXIT_CODE"
  dbg ">>> phase done: $phase (${PHASE_DUR}s)"
done

# ---- final report + per-domain deliverables ----------------------------------
if [ -f "$HUNTOPS_ROOT/lib/report.sh" ]; then
  source "$HUNTOPS_ROOT/lib/report.sh"
  run_report || err "report generation failed"
fi
if [ -f "$HUNTOPS_ROOT/lib/outputs.sh" ]; then
  source "$HUNTOPS_ROOT/lib/outputs.sh"
  run_outputs || err "deliverables generation failed"
fi

log "done. report: $W/report/huntops-report.html  (summary: $W/report/summary.md)"
ok "deliverables: $W/$DOMAIN.txt  +  $W/info-$DOMAIN.txt"
[ "$EXIT_CODE" = 0 ] && ok "scan complete (exit 0)" || err "scan completed with phase failures (exit $EXIT_CODE)"
exit "$EXIT_CODE"
