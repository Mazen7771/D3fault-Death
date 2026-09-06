#!/usr/bin/env bash
# OMNI — D3fault-death Phase Adapters
# Wraps each D3fault-death phase as a HuntOps-compatible run_<phase>() module.
# Each adapter sets up D3fault-death globals from HuntOps context, then calls the phase.

# Source D3fault-death functions (selective to avoid running MAIN)
# We'll source the whole script but guard the MAIN block
_DD_SCRIPT="${OMNI_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/D3fault-death.sh"
[ -f "$_DD_SCRIPT" ] || { err "D3fault-death.sh not found at $_DD_SCRIPT"; return 1; }

# Preserve OMNI globals before sourcing D3fault-death — it defines these as globals
# which would overwrite our workdir and logging paths.
# Lines 59-62 in D3fault-death.sh: MODE="bb", DOMAIN="", IP="", OUTDIR="" (default globals)
# Lines 115-121: R,G,Y,B,C,W,M,NC (colors), LOGFILE="", VERBOSE_LOG="", INTERRUPTED=0, TMP_DIR=""
# The extracted function file re-declares all of these, so we save/restore them.
_OMNI_W="${W:-}"
_OMNI_LOGFILE="${LOGFILE:-}"
_OMNI_VERBOSE_LOG="${VERBOSE_LOG:-}"
_OMNI_INTERRUPTED="${INTERRUPTED:-}"
_OMNI_TMP_DIR="${TMP_DIR:-}"
_OMNI_OUTDIR="${OUTDIR:-}"
_OMNI_DOMAIN="${DOMAIN:-}"
_OMNI_IP="${IP:-}"
_OMNI_MODE="${MODE:-}"
# Color constants (R,G,Y,B,C,M,NC) - save if set, but D3fault-death will redefine them
# We only need to restore W (used as workdir); others are cosmetic

# Extract just the function definitions (everything before MAIN)
# Using a subshell to avoid polluting current namespace with D3fault-death globals
_DD_FUNCS=$(mktemp)
awk '/^# MAIN/,/^exit 0/ {next} {print}' "$_DD_SCRIPT" > "$_DD_FUNCS"
source "$_DD_FUNCS"
rm -f "$_DD_FUNCS"

# Restore OMNI globals after sourcing D3fault-death functions
W="$_OMNI_W"
LOGFILE="$_OMNI_LOGFILE"
VERBOSE_LOG="$_OMNI_VERBOSE_LOG"
INTERRUPTED="$_OMNI_INTERRUPTED"
TMP_DIR="$_OMNI_TMP_DIR"
OUTDIR="$_OMNI_OUTDIR"
DOMAIN="$_OMNI_DOMAIN"
IP="$_OMNI_IP"
MODE="$_OMNI_MODE"

#------------------------------------------------------------------------------
# Adapter: recon_osint -> phase_osint
#------------------------------------------------------------------------------
run_recon_osint() {
    [ -z "$DOMAIN" ] && { warn "recon_osint: no domain"; return 0; }
    banner_phase "RECON: OSINT (whois / DNS / theHarvester)"
    # D3fault-death expects these globals
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _VT_API_KEY="${VT_API_KEY:-$OMNI_VT_API_KEY}" _ST_API_KEY="${ST_API_KEY:-$OMNI_ST_API_KEY}"
    local _HARVESTER_SOURCES="${HARVESTER_SOURCES:-crtsh,dnsdumpster,duckduckgo,hackertarget,otx,rapiddns,urlscan,bing,google}"
    # Run in subshell to isolate globals
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export VT_API_KEY="$_VT_API_KEY" ST_API_KEY="$_ST_API_KEY" HARVESTER_SOURCES="$_HARVESTER_SOURCES"
        export MAX_RESOLVE RESOLVE_PARALLEL SQLMAP_CAP GAU_CAP GAU_TIMEOUT WAYBACK_TIMEOUT
        export NUCLEI_TIMEOUT RANK_CAP SHOT_TIMEOUT PARAM_TEST_CAP HOST_CONCURRENCY
        export USE_INTERNETDB USE_COMMONCRAWL LIVE_TERMINATOR
        phase_osint
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_dns -> phase_dns
#------------------------------------------------------------------------------
run_recon_dns() {
    [ -z "$DOMAIN" ] && { warn "recon_dns: no domain"; return 0; }
    banner_phase "RECON: DNS Enumeration (dnsrecon / dnsenum)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _WLD_DNS="$(resolve_wordlist OMNI_WLD_DNS_PRIMARY OMNI_WLD_DNS_FALLBACK1 OMNI_WLD_DNS_FALLBACK2)"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export WLD_DNS="$_WLD_DNS"
        phase_dns
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_subdomains -> phase_subdomains
#------------------------------------------------------------------------------
run_recon_subdomains() {
    [ -z "$DOMAIN" ] && { warn "recon_subdomains: no domain"; return 0; }
    banner_phase "RECON: Subdomain Discovery (subfinder/amass/crt.sh/assetfinder/VT/ST)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _WLD_DNS="$(resolve_wordlist OMNI_WLD_DNS_PRIMARY OMNI_WLD_DNS_FALLBACK1 OMNI_WLD_DNS_FALLBACK2)"
    local _VT_API_KEY="${VT_API_KEY:-$OMNI_VT_API_KEY}" _ST_API_KEY="${ST_API_KEY:-$OMNI_ST_API_KEY}"
    local _TAKEOVER_PROVIDERS="${TAKEOVER_PROVIDERS:-}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export WLD_DNS="$_WLD_DNS" VT_API_KEY="$_VT_API_KEY" ST_API_KEY="$_ST_API_KEY"
        export TAKEOVER_PROVIDERS="$_TAKEOVER_PROVIDERS"
        export SCOPE_FILE
        phase_subdomains
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_resolve -> phase_resolve
#------------------------------------------------------------------------------
run_recon_resolve() {
    banner_phase "RECON: Resolve Hostnames -> IPs"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _IP="$IP" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _MAX_RESOLVE="${MAX_RESOLVE:-$OMNI_MAX_RESOLVE}" _RESOLVE_PARALLEL="${RESOLVE_PARALLEL:-$OMNI_RESOLVE_PARALLEL}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" IP="$_IP" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export MAX_RESOLVE="$_MAX_RESOLVE" RESOLVE_PARALLEL="$_RESOLVE_PARALLEL"
        export SCOPE_FILE
        phase_resolve
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_ports -> phase_ports
#------------------------------------------------------------------------------
run_recon_ports() {
    banner_phase "RECON: Port & Service Scanning (nmap + InternetDB)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _IP="$IP" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _USE_INTERNETDB="${USE_INTERNETDB:-$OMNI_USE_INTERNETDB}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" IP="$_IP" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export USE_INTERNETDB="$_USE_INTERNETDB"
        phase_ports
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_web -> phase_web_probe
#------------------------------------------------------------------------------
run_recon_web() {
    banner_phase "RECON: Live Web Probe (httpx)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _IP="$IP" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _AUTH_ARGS=("${AUTH_ARGS[@]:-}")
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" IP="$_IP" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export AUTH_ARGS=("${_AUTH_ARGS[@]}")
        phase_web_probe
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_fingerprint -> phase_fingerprint
#------------------------------------------------------------------------------
run_recon_fingerprint() {
    banner_phase "RECON: Fingerprinting (whatweb / wafw00f)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _HOST_CONCURRENCY="${HOST_CONCURRENCY:-$OMNI_HOST_CONCURRENCY}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export HOST_CONCURRENCY="$_HOST_CONCURRENCY"
        phase_fingerprint
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_content -> phase_content
#------------------------------------------------------------------------------
run_recon_content() {
    banner_phase "RECON: Content Discovery (ffuf/gobuster/dirb)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _WLD_WEB="$(resolve_wordlist OMNI_WLD_WEB_PRIMARY OMNI_WLD_WEB_FALLBACK1 OMNI_WLD_WEB_FALLBACK2)"
    local _WLD_WEB2="$(resolve_wordlist OMNI_WLD_WEB_FALLBACK1 OMNI_WLD_WEB_PRIMARY OMNI_WLD_WEB_FALLBACK2)"
    local _HOST_CONCURRENCY="${HOST_CONCURRENCY:-$OMNI_HOST_CONCURRENCY}"
    local _AUTH_ARGS=("${AUTH_ARGS[@]:-}")
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export WLD_WEB="$_WLD_WEB" WLD_WEB2="$_WLD_WEB2" HOST_CONCURRENCY="$_HOST_CONCURRENCY"
        export AUTH_ARGS=("${_AUTH_ARGS[@]}")
        phase_content
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_historical -> phase_historical
#------------------------------------------------------------------------------
run_recon_historical() {
    [ -z "$DOMAIN" ] && { warn "recon_historical: no domain"; return 0; }
    banner_phase "RECON: Historical URLs (gau/waybackurls/CommonCrawl)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _GAU_CAP="${GAU_CAP:-$OMNI_GAU_CAP}" _GAU_TIMEOUT="${GAU_TIMEOUT:-$OMNI_GAU_TIMEOUT}"
    local _WAYBACK_TIMEOUT="${WAYBACK_TIMEOUT:-$OMNI_WAYBACK_TIMEOUT}"
    local _USE_COMMONCRAWL="${USE_COMMONCRAWL:-$OMNI_USE_COMMONCRAWL}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export GAU_CAP="$_GAU_CAP" GAU_TIMEOUT="$_GAU_TIMEOUT" WAYBACK_TIMEOUT="$_WAYBACK_TIMEOUT"
        export USE_COMMONCRAWL="$_USE_COMMONCRAWL"
        phase_historical
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_js -> phase_js
#------------------------------------------------------------------------------
run_recon_js() {
    banner_phase "RECON: JS & Endpoint Extraction (katana/gospider/fallback)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _HOST_CONCURRENCY="${HOST_CONCURRENCY:-$OMNI_HOST_CONCURRENCY}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export HOST_CONCURRENCY="$_HOST_CONCURRENCY"
        phase_js
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_secrets -> phase_secrets
#------------------------------------------------------------------------------
run_recon_secrets() {
    banner_phase "RECON: JS Secret Hunting (AWS/GitHub/Slack/JWT/keys)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _HOST_CONCURRENCY="${HOST_CONCURRENCY:-$OMNI_HOST_CONCURRENCY}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export HOST_CONCURRENCY="$_HOST_CONCURRENCY"
        phase_secrets
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_params -> phase_params
#------------------------------------------------------------------------------
run_recon_params() {
    banner_phase "RECON: Parameter Discovery (arjun + fallback)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _HOST_CONCURRENCY="${HOST_CONCURRENCY:-$OMNI_HOST_CONCURRENCY}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export HOST_CONCURRENCY="$_HOST_CONCURRENCY"
        phase_params
    )
}

#------------------------------------------------------------------------------
# Adapter: recon_takeover -> phase_takeover
#------------------------------------------------------------------------------
run_recon_takeover() {
    banner_phase "RECON: Subdomain Takeover & Exposure Candidates"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _HOST_CONCURRENCY="${HOST_CONCURRENCY:-$OMNI_HOST_CONCURRENCY}"
    local _TAKEOVER_PROVIDERS="${TAKEOVER_PROVIDERS:-}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export HOST_CONCURRENCY="$_HOST_CONCURRENCY"
        export TAKEOVER_PROVIDERS="$_TAKEOVER_PROVIDERS"
        export SCOPE_FILE
        phase_takeover
    )
}

#------------------------------------------------------------------------------
# Adapter: vuln_scan -> phase_vuln
#------------------------------------------------------------------------------
run_vuln_scan() {
    banner_phase "VULN: Vulnerability Scanning (nuclei/nikto/sqlmap/wpscan)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-$OMNI_NUCLEI_TIMEOUT}"
    local _SQLMAP_CAP="${SQLMAP_CAP:-$OMNI_SQLMAP_CAP}"
    local _AUTH_ARGS=("${AUTH_ARGS[@]:-}")
    local _RUN_SQLMAP=0
    case "$MODE" in bb) _RUN_SQLMAP=1 ;; esac
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export NUCLEI_TIMEOUT="$_NUCLEI_TIMEOUT" SQLMAP_CAP="$_SQLMAP_CAP" RUN_SQLMAP="$_RUN_SQLMAP"
        export AUTH_ARGS=("${_AUTH_ARGS[@]}")
        phase_vuln
    )
}

#------------------------------------------------------------------------------
# Adapter: vuln_strategies -> phase_strategies
#------------------------------------------------------------------------------
run_vuln_strategies() {
    banner_phase "VULN: Strategy Engine (Ebb & Flow attack-vector hunting)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _PARAM_TEST_CAP="${PARAM_TEST_CAP:-$OMNI_PARAM_TEST_CAP}"
    local _RANK_CAP="${RANK_CAP:-$OMNI_RANK_CAP}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export PARAM_TEST_CAP="$_PARAM_TEST_CAP" RANK_CAP="$_RANK_CAP"
        phase_strategies
    )
}

#------------------------------------------------------------------------------
# Adapter: intel -> phase_intel
#------------------------------------------------------------------------------
run_intel() {
    banner_phase "INTEL: Signal-Driven Decision Engine (OWASP Top 10 2025)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _PARAM_TEST_CAP="${PARAM_TEST_CAP:-$OMNI_PARAM_TEST_CAP}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export PARAM_TEST_CAP="$_PARAM_TEST_CAP"
        phase_intel
    )
}

#------------------------------------------------------------------------------
# Adapter: cve -> phase_cve
#------------------------------------------------------------------------------
run_cve() {
    banner_phase "CVE: Correlation (version matching + searchsploit + InternetDB)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _USE_INTERNETDB="${USE_INTERNETDB:-$OMNI_USE_INTERNETDB}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export USE_INTERNETDB="$_USE_INTERNETDB"
        phase_cve
    )
}

#------------------------------------------------------------------------------
# Adapter: rank -> phase_rank
#------------------------------------------------------------------------------
run_rank() {
    banner_phase "RANK: Target Prioritization"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _RANK_CAP="${RANK_CAP:-$OMNI_RANK_CAP}"
    local _MAX_PORTS_LIST="${MAX_PORTS_LIST:-$OMNI_MAX_PORTS_LIST}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export RANK_CAP="$_RANK_CAP" MAX_PORTS_LIST="$_MAX_PORTS_LIST"
        phase_rank
    )
}

#------------------------------------------------------------------------------
# Adapter: shots -> phase_shots
#------------------------------------------------------------------------------
run_shots() {
    banner_phase "SHOTS: Screenshots (gowitness)"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _SHOT_TIMEOUT="${SHOT_TIMEOUT:-$OMNI_SHOT_TIMEOUT}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export SHOT_TIMEOUT="$_SHOT_TIMEOUT"
        phase_shots
    )
}

#------------------------------------------------------------------------------
# Adapter: report -> generate_report
#------------------------------------------------------------------------------
run_report() {
    banner_phase "REPORT: HTML Report Generation"
    local _OUTDIR="$OUTDIR" _DOMAIN="$DOMAIN" _IP="$IP" _MODE="$MODE" _LOGFILE="$LOGFILE" _VERBOSE_LOG="$VERBOSE_LOG"
    local _VERSION="${VERSION:-2.0.0}" _AUTHOR="${AUTHOR:-ZOLDEK}" _GITHUB="${GITHUB:-https://github.com/Mazen7771}" _LINKEDIN="${LINKEDIN:-linkedin.com/in/mazen-basher}"
    local _START_TIME="${START_TIME:-$(date +%s)}" _WATCH_DIR="${WATCH_DIR:-}"
    local _RANK_CAP="${RANK_CAP:-$OMNI_RANK_CAP}"
    (
        export OUTDIR="$_OUTDIR" DOMAIN="$_DOMAIN" IP="$_IP" MODE="$_MODE" LOGFILE="$_LOGFILE" VERBOSE_LOG="$_VERBOSE_LOG"
        export VERSION="$_VERSION" AUTHOR="$_AUTHOR" GITHUB="$_GITHUB" LINKEDIN="$_LINKEDIN"
        export START_TIME="$_START_TIME" WATCH_DIR="$_WATCH_DIR" RANK_CAP="$_RANK_CAP"
        export SCOPE_FILE
        generate_report
    )
}