#!/usr/bin/env bash
# OMNI — Unified Bug Bounty Recon + Vulnerability Scanner
# Integrates D3fault-death.sh (monolithic) + HuntOps (modular) into a single CLI.
# Usage: ./omni.sh -d target.com [--engine=dd|huntops|both] [-m quick|bb|deep] [options]

set -u

OMNI_ROOT="$(cd "$(dirname "$0")" && pwd)"
export OMNI_ROOT

# ---- Source unified config + common utilities ----
source "$OMNI_ROOT/config/omni.conf"
source "$OMNI_ROOT/lib/common.sh"

# ---- CLI Parsing ----
ENGINE="both"           # dd | huntops | both
MODE="bb"               # quick | bb | deep
TARGET=""
CUSTOM_OUT=""
TEST_ACCOUNT=""
SCOPE_FILE=""
AUTH_ARGS=()
DO_INSTALL=0
NO_DOS=0
FAIL_FAST=0
VERBOSE=0
DEBUG=0
NO_TERMINAL=0
NO_COLOR=0
MENU=0
INSIDE_TMUX=0
PHASES=""             # comma-separated phase subset
DELIVERABLES="all"    # all | findings | report | deliverables
TLS_ENABLE="auto"

usage() {
    cat <<'EOF'
OMNI v1.0.0 — Unified Bug Bounty Recon + Vulnerability Scanner
Integrates D3fault-death (monolithic) + HuntOps (modular)

USAGE:
  ./omni.sh -d target.com [options]
  ./omni.sh -t 1.2.3.4    [options]
  ./omni.sh               interactive setup menu
  ./omni.sh -i            install/verify tools for both engines, then exit

ENGINES:
  --engine=dd       D3fault-death only (chronological pipeline)
  --engine=huntops  HuntOps only (modular, tmux live windows)
  --engine=both     Merged optimal pipeline (default)

MODES:
  -m quick          Fast first pass (~minutes)
  -m bb             Bug bounty full (default)
  -m deep           Exhaustive (needs --no-dos for heavy scans)

OPTIONS:
  -d DOMAIN         Target domain (root + subdomains auto-in-scope)
  -t IP             Target IP address
  -o DIR            Custom output directory
  -s FILE           Program scope file (allow / deny / !deny)
  -H HEADER         Auth header, repeatable (Cookie:/Authorization:)
  --test-account EMAIL   Only fire IDOR/authz candidates for this account
  --ssl | --no-ssl  Force / disable testssl.sh TLS phase (auto)
  -v, --verbose     Live terminal view of scan steps
  --debug           Behind-the-scenes raw view of every tool call
  --no-terminal     Disable tmux live windows (scripts/CI)
  --no-color        Disable ANSI colour output
  --menu            Force interactive setup menu
  --no-dos          Allow full -p- port scans / deep sqlmap / huge wordlists
  --fail-fast       Abort pipeline on first phase failure
  --phase=LIST      Comma-separated phase subset (e.g. recon_subdomains,vuln_nuclei)
  --deliverables=X  all | findings | report | deliverables (default: all)
  -i                Install missing tools + nuclei templates for both engines, then exit
  -h, --help        Show this help

EXAMPLES:
  ./omni.sh -d example.com                           # both engines, bb mode
  ./omni.sh -d example.com --engine=huntops -m quick # HuntOps only, quick
  ./omni.sh -d example.com --engine=dd -m bb         # D3fault-death only, bb
  ./omni.sh -d example.com --phase=recon_subdomains,vuln_nuclei
  ./omni.sh -d example.com -m deep --no-dos          # exhaustive, both engines
  ./omni.sh --debug --no-terminal -d example.com     # raw view, no tmux
  ./omni.sh -i                                       # install tools for both
EOF
    exit "${1:-0}"
}

# Parse args
# Supports both "--flag value" and "--flag=value" syntax.
while [ $# -gt 0 ]; do
    # Normalize --flag=value → --flag value before case matching
    case "$1" in
        --*=*)
            _eq_args="$1"
            set -- "$(printf '%s' "$_eq_args" | cut -d= -f1)" "$(printf '%s' "$_eq_args" | cut -d= -f2-)" "${@:2}"
            ;;
    esac
    case "$1" in
        --engine) ENGINE="$2"; shift 2 ;;
        -d) TARGET="$2"; shift 2 ;;
        -t) TARGET="$2"; shift 2 ;;
        -m) MODE="$2"; shift 2 ;;
        -o) CUSTOM_OUT="$2"; shift 2 ;;
        -s) SCOPE_FILE="$2"; shift 2 ;;
        -H) AUTH_ARGS+=(-H "$2"); shift 2 ;;
        --test-account) TEST_ACCOUNT="$2"; shift 2 ;;
        --ssl) TLS_ENABLE="on"; shift ;;
        --no-ssl) TLS_ENABLE="off"; shift ;;
        -v|--verbose) VERBOSE=1; shift ;;
        --debug) DEBUG=1; VERBOSE=1; shift ;;
        --no-terminal) NO_TERMINAL=1; shift ;;
        --no-color) NO_COLOR=1; shift ;;
        --menu) MENU=1; shift ;;
        --no-dos) NO_DOS=1; shift ;;
        --fail-fast) FAIL_FAST=1; shift ;;
        --phase) PHASES="$2"; shift 2 ;;
        --deliverables) DELIVERABLES="$2"; shift 2 ;;
        -i) DO_INSTALL=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown arg: $1" >&2; usage 2 ;;
    esac
done

# Validate engine
case "$ENGINE" in dd|huntops|both) ;; *) err "unknown engine: $ENGINE (dd|huntops|both)"; usage 2 ;; esac

# Validate mode
case "$MODE" in quick|bb|deep) ;; *) err "unknown mode: $MODE (quick|bb|deep)"; usage 2 ;; esac

# Color suppression
if [ "$NO_COLOR" = 1 ] || [ ! -t 1 ]; then
    C_RST=''; C_RED=''; C_GRN=''; C_YLW=''; C_BLU=''; C_CYN=''; C_MAG=''; C_WHT=''
fi

# ---- Install-only mode ----
if [ "$DO_INSTALL" = 1 ]; then
    log "Installing tools for both engines..."
    # D3fault-death install
    if [ -f "$OMNI_ROOT/D3fault-death.sh" ]; then
        log "Running D3fault-death installer..."
        bash "$OMNI_ROOT/D3fault-death.sh" -i
    fi
    # HuntOps install
    if [ -f "$OMNI_ROOT/huntops/lib/install.sh" ]; then
        log "Running HuntOps installer..."
        source "$OMNI_ROOT/huntops/lib/install.sh"
        do_install
    fi
    ok "Installation complete for both engines"
    exit 0
fi

# ---- Target sanity ----
if [ -z "$TARGET" ]; then
    if [ "$MENU" = 1 ] || [ -t 1 ]; then
        # Simple interactive prompt
        echo -e "${C_CYN}Enter target (domain or IP):${C_RST}"
        read -r TARGET
        [ -z "$TARGET" ] && { err "No target given"; exit 1; }
    else
        err "No target specified. Use -d <domain> or -t <ip>"
        usage 2
    fi
fi

# Normalize target
if is_ip "$TARGET"; then
    DOMAIN="$TARGET"; TARGET_IP="$TARGET"
else
    TARGET="${TARGET#https://}"; TARGET="${TARGET#http://}"; TARGET="${TARGET%/}"
    DOMAIN="$(derive_root "$TARGET")"
fi

load_scope "$SCOPE_FILE"

# ---- Output directory ----
if [ -n "$CUSTOM_OUT" ]; then
    W="$CUSTOM_OUT"
else
    W="$OMNI_OUTROOT/${DOMAIN}_$(date +%Y%m%d-%H%M%S)"
fi
export W
mkdir -p "$W"/{logs,findings,report,tmp,osint,dns,subdomains,ports,web,content,urls,vuln,cve,tech,takeover}

# Override log paths for common.sh
export LOGFILE="$W/logs/scan.log"
export VERBOSE_LOG="$W/logs/scan.verbose.log"
export DEBUG_LOG="$W/logs/debug.log"
: > "$LOGFILE"; : > "$VERBOSE_LOG"; : > "$DEBUG_LOG"

# Export for subshells
export DOMAIN TARGET_IP MODE SCOPE_FILE AUTH_ARGS TEST_ACCOUNT
export NO_DOS FAIL_FAST VERBOSE DEBUG NO_TERMINAL NO_COLOR
export TLS_ENABLE
export OMNI_ROOT OUTDIR="$W"
export START_TIME="$(date +%s)"

# ---- ASCII Banner ----
logo="OMNI"
[ "$MODE" = "deep" ] && logo="OMNI • DEEP"
[ "$MODE" = "quick" ] && logo="OMNI • QUICK"
printf '%s\n%s\n' \
  "$C_CYN" \
  "  ██████╗  ██████╗ ███╗   ██╗███████╗██╗  ██╗███████╗██████╗ " \
  "  ██╔══██╗██╔═══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██╔══██╗" \
  "  ██████╔╝██║   ██║██╔██╗ ██║█████╗  ███████║█████╗  ██████╔╝" \
  "  ██╔══██╗██║   ██║██║╚██╗██║██╔══╝  ██╔══██║██╔══╝  ██╔═══╝ " \
  "  ██║  ██║╚██████╔╝██║ ╚████║███████╗██║  ██║███████╗██║     " \
  "  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     " \
  "$C_RST" | sed 's/^  //'
log "OMNI v1.0.0 — target: $TARGET  mode: $MODE  engine: $ENGINE"
log "workdir: $W"
[ "$MODE" = "deep" ] && ok "deep mode: DNS brute-force + full port scan + heavy wordlists"
[ "$NO_DOS" = 0 ] && ok "no-DoS defaults active (add --no-dos to enable heavy scans)"

# ---- Pre-flight checks ----
preflight() {
    local missing=0
    for t in curl nmap nuclei jq dig; do
        tool_exists "$t" || { err "hard-dependency missing: $t"; missing=1; }
    done
    [ $missing -eq 1 ] && { err "run ./omni.sh -i first"; exit 2; }
    if tool_exists nuclei; then
        local tc; tc=$(find ~/.local/share/nuclei-templates ~/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l)
        [ "${tc:-0}" -lt 100 ] && warn "nuclei templates low ($tc) — run './omni.sh -i' to download the full library"
    fi
    [ -x "${OMNI_TESTSSL_BIN:-/nonexistent}" ] || warn "testssl.sh not found ($OMNI_TESTSSL_BIN) — TLS phase will be skipped"
    # Bacula bat check
    local b; b=$(command -v bat 2>/dev/null || true)
    case "$b" in /usr/sbin/*|/sbin/*) warn "PATH 'bat' is Bacula's GUI ($b) — tools calling 'bat' as pager may emit garbage";; esac
    local disk; disk=$(df -m "$OMNI_ROOT" | awk 'NR==2{print $4}')
    [ "${disk:-0}" -lt 2000 ] && warn "low disk: ${disk}MB free"
}
preflight

# ---- Pipeline Selection ----
# Build pipeline based on engine + mode + phase filter
PIPELINE=()

build_pipeline() {
    local engine="$1" mode="$2"
    local phases=()

    if [ -n "$PHASES" ]; then
        # User-specified phase subset
        IFS=',' read -ra phases <<< "$PHASES"
        PIPELINE=("${phases[@]}")
        return
    fi

    case "$engine" in
        dd)
            # D3fault-death phases (via adapters)
            case "$mode" in
                quick)
                    PIPELINE=(recon_osint recon_subdomains recon_resolve recon_ports recon_web recon_fingerprint recon_content vuln_scan cve rank report)
                    ;;
                bb)
                    PIPELINE=(recon_osint recon_dns recon_subdomains recon_resolve recon_ports recon_web recon_fingerprint recon_content recon_historical recon_js recon_secrets recon_params recon_takeover vuln_scan vuln_strategies intel cve rank shots report)
                    ;;
                deep)
                    PIPELINE=(recon_osint recon_dns recon_subdomains recon_resolve recon_ports recon_web recon_fingerprint recon_content recon_historical recon_js recon_secrets recon_params recon_takeover vuln_scan vuln_strategies intel cve rank shots report)
                    ;;
            esac
            ;;
        huntops)
            # HuntOps phases (via adapters)
            case "$mode" in
                quick)
                    PIPELINE=(huntops_recon_subdomains huntops_recon_web huntops_vuln_tls huntops_vuln_nuclei huntops_report huntops_outputs)
                    ;;
                bb)
                    PIPELINE=(huntops_recon_subdomains huntops_recon_ports huntops_recon_web huntops_vuln_tls huntops_recon_content huntops_recon_js huntops_recon_params huntops_vuln_nuclei huntops_vuln_nikto huntops_vuln_sqlmap huntops_candidates huntops_intel huntops_cve huntops_report huntops_outputs)
                    ;;
                deep)
                    PIPELINE=(huntops_recon_subdomains huntops_recon_ports huntops_recon_web huntops_vuln_tls huntops_recon_content huntops_recon_js huntops_recon_params huntops_vuln_nuclei huntops_vuln_nikto huntops_vuln_sqlmap huntops_candidates huntops_intel huntops_cve huntops_report huntops_outputs)
                    ;;
            esac
            ;;
        both)
            # MERGED OPTIMAL PIPELINE
            # Recon: HuntOps (better parallelism, dnsx/naabu/httpx)
            # Historical URLs: D3fault-death (more sources)
            # JS/Secrets/Params + Strategy/Intel: D3fault-death (unique engines)
            # Vuln Scan: HuntOps (rate-limited, --no-dos aware)
            # Candidates: HuntOps (10-field with repro curl)
            # CVE: D3fault-death (version-aware DB)
            # Rank/Shots: D3fault-death (priority + screenshots)
            # Report/Deliverables: HuntOps (target.txt + info-target.txt + HTML)
            case "$mode" in
                quick)
                    PIPELINE=(
                        huntops_recon_subdomains
                        huntops_recon_web
                        huntops_vuln_tls
                        huntops_vuln_nuclei
                        huntops_report
                        huntops_outputs
                    )
                    ;;
                bb)
                    PIPELINE=(
                        huntops_recon_subdomains
                        huntops_recon_ports
                        huntops_recon_web
                        huntops_vuln_tls
                        # D3fault-death historical URLs (more sources)
                        recon_historical
                        # D3fault-death JS/Secrets/Params (strategy + intel engines)
                        recon_js
                        recon_secrets
                        recon_params
                        # HuntOps vuln scan (nuclei/nikto/sqlmap with rate limiting)
                        huntops_vuln_nuclei
                        huntops_vuln_nikto
                        huntops_vuln_sqlmap
                        # HuntOps candidates (IDOR/JWT/GraphQL/SSRF/race/cloud/CORS/takeover/secrets)
                        huntops_candidates
                        # D3fault-death Strategy + Intel engines
                        vuln_strategies
                        intel
                        # D3fault-death CVE correlation
                        cve
                        # D3fault-death ranking + screenshots
                        rank
                        shots
                        # HuntOps deliverables + report
                        huntops_report
                        huntops_outputs
                    )
                    ;;
                deep)
                    PIPELINE=(
                        huntops_recon_subdomains
                        huntops_recon_ports
                        huntops_recon_web
                        huntops_vuln_tls
                        huntops_recon_content
                        # D3fault-death historical (more sources: CertSpotter, VT, ST, CC)
                        recon_historical
                        # D3fault-death JS/Secrets/Params + Strategy/Intel
                        recon_js
                        recon_secrets
                        recon_params
                        recon_takeover
                        # HuntOps vuln scan
                        huntops_vuln_nuclei
                        huntops_vuln_nikto
                        huntops_vuln_sqlmap
                        # HuntOps candidates
                        huntops_candidates
                        # D3fault-death Strategy + Intel
                        vuln_strategies
                        intel
                        # D3fault-death CVE
                        cve
                        # D3fault-death rank + shots
                        rank
                        shots
                        # HuntOps deliverables
                        huntops_report
                        huntops_outputs
                    )
                    ;;
            esac
            ;;
    esac
}

build_pipeline "$ENGINE" "$MODE"
log "Pipeline: ${PIPELINE[*]}"

# ---- Source adapters ----
source "$OMNI_ROOT/lib/dd_adapter.sh"
source "$OMNI_ROOT/lib/huntops_adapter.sh"

# ---- tmux live windows (HuntOps style, for engine=huntops or both) ----
if [ "$NO_TERMINAL" = 0 ] && [ "$INSIDE_TMUX" = 0 ] && command -v tmux >/dev/null 2>&1 && [ -t 1 ]; then
    if [ "$ENGINE" = "huntops" ] || [ "$ENGINE" = "both" ]; then
        # Re-exec inside tmux with pinned workdir
        log "Launching tmux live windows (main | verbose | behind-scenes)..."
        exec tmux new-session -d -s "omni-$DOMAIN" \; \
            send-keys "cd '$W' && '$0' --inside-tmux -d '$TARGET' -m '$MODE' --engine='$ENGINE' ${SCOPE_FILE:+-s '$SCOPE_FILE'} ${AUTH_ARGS[@]/#/-H } ${TEST_ACCOUNT:+--test-account '$TEST_ACCOUNT'} ${NO_DOS:+--no-dos} ${FAIL_FAST:+--fail-fast} ${VERBOSE:+-v} ${DEBUG:+--debug} ${PHASES:+--phase '$PHASES'} ${DELIVERABLES:+--deliverables '$DELIVERABLES'}" C-m \; \
            split-window -h -p 35 "tail -n 0 -f '$VERBOSE_LOG'" \; \
            split-window -v -p 50 "tail -n 0 -f '$DEBUG_LOG'" \; \
            select-pane -t 0 \; \
            attach \;
    fi
fi

# ---- Run Pipeline ----
EXIT_CODE=0
for phase in "${PIPELINE[@]}"; do
    # Check if phase function exists
    if ! declare -F "run_${phase}" >/dev/null; then
        warn "phase $phase: no run_${phase}() — skipping"
        continue
    fi

    PHASE_START=$(date +%s)
    banner_phase "PHASE: $phase"
    dbg ">>> phase start: $phase"

    rc=0
    if [ "$DEBUG" = 1 ]; then
        set -o pipefail
        run_${phase} 2>&1 | tee -a "$DEBUG_LOG"
        rc=${PIPESTATUS[0]}
        set +o pipefail
    else
        run_${phase}
        rc=$?
    fi

    if [ "$rc" -ne 0 ]; then
        if [ "$FAIL_FAST" = 1 ]; then
            err "phase $phase FAILED (fail-fast)"
            exit 3
        fi
        err "phase $phase FAILED — continuing"
        EXIT_CODE=2
    fi
    PHASE_DUR=$(( $(date +%s) - PHASE_START ))
    phase_mark "$phase" "$EXIT_CODE"
    dbg ">>> phase done: $phase (${PHASE_DUR}s)"
done

# ---- Final Deliverables (if not already run via pipeline) ----
# The pipeline includes huntops_report/huntops_outputs for engine=huntops/both
# For engine=dd, we need to ensure deliverables are generated.
# HuntOps deliverables need finding-stream globals (FINDINGS/CANDIDATES/INFOFILE),
# which are only set by HuntOps' setup_target(). Since dd engine doesn't call it,
# we initialize them here to point at D3fault-death's artifact layout.
if [ "$ENGINE" = "dd" ]; then
    # Map HuntOps finding streams to D3fault-death artifact paths
    export FINDINGS="$OUTDIR/findings/findings.txt"
    export CANDIDATES="${CANDIDATES:-$OUTDIR/findings/candidates.txt}"
    export INFOFILE="${INFOFILE:-$OUTDIR/findings/info.txt}"
    export HUNTOPS_VERSION="${HUNTOPS_VERSION:-1.0.0}"
    if [ "$DELIVERABLES" = "all" ] || [ "$DELIVERABLES" = "report" ]; then
        if declare -F run_report >/dev/null; then
            run_report
        fi
    fi
    if [ "$DELIVERABLES" = "all" ] || [ "$DELIVERABLES" = "deliverables" ]; then
        # Generate HuntOps-style deliverables from D3fault-death findings
        if [ -f "$OMNI_ROOT/huntops/lib/outputs.sh" ]; then
            source "$OMNI_ROOT/huntops/lib/outputs.sh"
            run_outputs
        fi
    fi
fi

log "done. workdir: $W"
if [ -f "$W/report/huntops-report.html" ]; then
    ok "HTML report: $W/report/huntops-report.html"
elif [ -f "$W/report/D3fault-death-report.html" ]; then
    ok "HTML report: $W/report/D3fault-death-report.html"
fi
ok "summary: $W/report/summary.md"
[ -f "$W/$DOMAIN.txt" ] && ok "deliverable: $W/$DOMAIN.txt"
[ -f "$W/info-$DOMAIN.txt" ] && ok "deliverable: $W/info-$DOMAIN.txt"
[ "$EXIT_CODE" = 0 ] && ok "scan complete (exit 0)" || err "scan completed with phase failures (exit $EXIT_CODE)"

exit "$EXIT_CODE"