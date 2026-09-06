#!/usr/bin/env bash
# OMNI — HuntOps Phase Adapters
# Exposes HuntOps phases callable from D3fault-death or omni.sh pipeline.
# Each adapter sets up HuntOps context and calls the HuntOps run_<phase>().

_HO_ROOT="${OMNI_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/huntops"
[ -d "$_HO_ROOT" ] || { err "HuntOps not found at $_HO_ROOT"; return 1; }

# Source HuntOps config (idempotent) — DO NOT source core.sh here!
# core.sh overwrites phase_mark() with a version that requires PHASE_STATUS,
# which is only set inside adapter subshells. Sourcing it at top-level breaks
# the main omni.sh loop's phase_mark() call (line 425) which uses common.sh's version.
source "$_HO_ROOT/config/config.sh" 2>/dev/null || true
source "$_HO_ROOT/config/wordlists.conf" 2>/dev/null || true
[ -f "$_HO_ROOT/config/keys.conf" ] && source "$_HO_ROOT/config/keys.conf" 2>/dev/null || true
# source "$_HO_ROOT/lib/core.sh" 2>/dev/null || true  # DISABLED — only inside subshells
# source "$_HO_ROOT/lib/ui.sh" 2>/dev/null || true     # DISABLED — only inside subshells

# setup_target must run in the adapter's subshell before any module that reads
# $PHASE_STATUS / $FINDINGS / $CANDIDATES. HuntOps normally calls it in huntops.sh
# before the pipeline loop; omni.sh's adapter subshells need it per-phase.
setup_target() {
    export CUSTOM_OUT="$W"
    setup_target
}

#------------------------------------------------------------------------------
# Adapter: vuln_nuclei -> HuntOps run_vuln_nuclei
#------------------------------------------------------------------------------
run_huntops_nuclei() {
    banner_phase "VULN: Nuclei (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _NUCLEI_RATE="${NUCLEI_RATE:-$OMNI_NUCLEI_RATE}" _NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-$OMNI_NUCLEI_CONCURRENCY}"
    local _NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-$OMNI_NUCLEI_TIMEOUT}"
    local _AUTH_ARGS=("${AUTH_ARGS[@]:-}") _NO_DOS="${NO_DOS:-0}"
    # HuntOps lib/vuln_nuclei.sh reads these from config/env
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export NUCLEI_RATE="$_NUCLEI_RATE" NUCLEI_CONCURRENCY="$_NUCLEI_CONCURRENCY"
        export NUCLEI_TIMEOUT="$_NUCLEI_TIMEOUT" NO_DOS="$_NO_DOS"
        export AUTH_ARGS=("${_AUTH_ARGS[@]}")
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        # Source and run
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/vuln_nuclei.sh"
        PHASE_START=$(date +%s)
        run_vuln_nuclei
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_nuclei" "$rc"
    )
}

#------------------------------------------------------------------------------
# Adapter: vuln_tls -> HuntOps run_vuln_tls (testssl.sh)
#------------------------------------------------------------------------------
run_huntops_tls() {
    banner_phase "VULN: TLS (testssl.sh via HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _TESTSSL_BIN="${TESTSSL_BIN:-$OMNI_TESTSSL_BIN}" _TLS_HOST_CAP="${TLS_HOST_CAP:-$OMNI_TLS_HOST_CAP}"
    local _TLS_SCAN_OPTS="${TLS_SCAN_OPTS:-$OMNI_TLS_SCAN_OPTS}" _TLS_ENABLE="${TLS_ENABLE:-auto}"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export TESTSSL_BIN="$_TESTSSL_BIN" TLS_HOST_CAP="$_TLS_HOST_CAP"
        export TLS_SCAN_OPTS="$_TLS_SCAN_OPTS" TLS_ENABLE="$_TLS_ENABLE"
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/vuln_tls.sh"
        PHASE_START=$(date +%s)
        run_vuln_tls
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_tls" "$rc"
    )
}

#------------------------------------------------------------------------------
# Adapter: vuln_nikto -> HuntOps run_vuln_nikto
#------------------------------------------------------------------------------
run_huntops_nikto() {
    banner_phase "VULN: Nikto (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _AUTH_ARGS=("${AUTH_ARGS[@]:-}")
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export AUTH_ARGS=("${_AUTH_ARGS[@]}")
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/vuln_nikto.sh"
        PHASE_START=$(date +%s)
        run_vuln_nikto
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_nikto" "$rc"
    )
}

#------------------------------------------------------------------------------
# Adapter: vuln_sqlmap -> HuntOps run_vuln_sqlmap
#------------------------------------------------------------------------------
run_huntops_sqlmap() {
    banner_phase "VULN: SQLMap (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _SQLMAP_CAP="${SQLMAP_CAP:-$OMNI_SQLMAP_CAP}" _AUTH_ARGS=("${AUTH_ARGS[@]:-}")
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export SQLMAP_CAP="$_SQLMAP_CAP" AUTH_ARGS=("${_AUTH_ARGS[@]}")
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/vuln_sqlmap.sh"
        PHASE_START=$(date +%s)
        run_vuln_sqlmap
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_sqlmap" "$rc"
    )
}

#------------------------------------------------------------------------------
# Adapter: candidates -> HuntOps run_candidates (IDOR/JWT/GraphQL/SSRF/race/cloud/CORS/takeover/secrets)
#------------------------------------------------------------------------------
run_huntops_candidates() {
    banner_phase "CANDIDATES: Attack Surface Classification (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _TEST_ACCOUNT="${TEST_ACCOUNT:-}" _NO_DOS="${NO_DOS:-0}"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export TEST_ACCOUNT="$_TEST_ACCOUNT" NO_DOS="$_NO_DOS"
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/candidates.sh"
        PHASE_START=$(date +%s)
        run_candidates
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_candidates" "$rc"
    )
}

#------------------------------------------------------------------------------
# Adapter: intel -> HuntOps run_intel (if exists, else no-op)
#------------------------------------------------------------------------------
run_huntops_intel() {
    if [ ! -f "$_HO_ROOT/lib/intel.sh" ]; then
        warn "HuntOps intel.sh not found; skipping"
        return 0
    fi
    banner_phase "INTEL: HuntOps Signal Engine"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export CUSTOM_OUT="$_W"  # Tell HuntOps setup_target() to use OMNI's workdir
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        DOMAIN="$_DOMAIN"  # Restore DOMAIN (setup_target doesn't set it, and core.sh line 86 resets it)
        source "$_HO_ROOT/lib/intel.sh"
        PHASE_START=$(date +%s)
        run_intel
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_intel" "$rc"
    )
}

#------------------------------------------------------------------------------
# Adapter: cve -> HuntOps run_cve (if exists, else no-op)
#------------------------------------------------------------------------------
run_huntops_cve() {
    if [ ! -f "$_HO_ROOT/lib/cve.sh" ]; then
        warn "HuntOps cve.sh not found; skipping"
        return 0
    fi
    banner_phase "CVE: HuntOps Correlation"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export CUSTOM_OUT="$_W"  # Tell HuntOps setup_target() to use OMNI's workdir
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        DOMAIN="$_DOMAIN"  # Restore DOMAIN (setup_target doesn't set it, and core.sh line 86 resets it)
        source "$_HO_ROOT/lib/cve.sh"
        PHASE_START=$(date +%s)
        run_cve
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_cve" "$rc"
    )
}

#------------------------------------------------------------------------------
# Adapter: outputs -> HuntOps run_outputs (deliverables: target.txt + info-target.txt)
#------------------------------------------------------------------------------
run_huntops_outputs() {
    banner_phase "OUTPUTS: Deliverables (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export CUSTOM_OUT="$_W"  # Tell HuntOps setup_target() to use OMNI's workdir
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        DOMAIN="$_DOMAIN"  # Restore DOMAIN (setup_target doesn't set it, and core.sh line 86 resets it)
        source "$_HO_ROOT/lib/outputs.sh"
        PHASE_START=$(date +%s)
        run_outputs
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_outputs" "$rc"
    )
}

#------------------------------------------------------------------------------
# Adapter: report -> HuntOps run_report (HTML report)
#------------------------------------------------------------------------------
run_huntops_report() {
    banner_phase "REPORT: HTML (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export CUSTOM_OUT="$_W"  # Tell HuntOps setup_target() to use OMNI's workdir
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        DOMAIN="$_DOMAIN"  # Restore DOMAIN (setup_target doesn't set it, and core.sh line 86 resets it)
        source "$_HO_ROOT/lib/report.sh"
        PHASE_START=$(date +%s)
        run_report
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_report" "$rc"
    )
}

#------------------------------------------------------------------------------
# Recon Adapters (HuntOps recon_* phases)
#------------------------------------------------------------------------------
run_huntops_recon_subdomains() {
    banner_phase "RECON: Subdomains (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _MODE_DEEP="${MODE_DEEP:-0}" _MODE_QUICK="${MODE_QUICK:-0}" _NO_DOS="${NO_DOS:-0}"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export MODE_DEEP="$_MODE_DEEP" MODE_QUICK="$_MODE_QUICK" NO_DOS="$_NO_DOS"
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/recon_subdomains.sh"
        PHASE_START=$(date +%s)
        run_recon_subdomains
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_recon_subdomains" "$rc"
    )
}

run_huntops_recon_ports() {
    banner_phase "RECON: Ports (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _MODE_DEEP="${MODE_DEEP:-0}" _NO_DOS="${NO_DOS:-0}"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export MODE_DEEP="$_MODE_DEEP" NO_DOS="$_NO_DOS"
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/recon_ports.sh"
        PHASE_START=$(date +%s)
        run_recon_ports
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_recon_ports" "$rc"
    )
}

run_huntops_recon_web() {
    banner_phase "RECON: Web (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _AUTH_ARGS=("${AUTH_ARGS[@]:-}")
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export AUTH_ARGS=("${_AUTH_ARGS[@]}")
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/recon_web.sh"
        PHASE_START=$(date +%s)
        run_recon_web
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_recon_web" "$rc"
    )
}

run_huntops_recon_content() {
    banner_phase "RECON: Content (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    local _MODE_DEEP="${MODE_DEEP:-0}" _NO_DOS="${NO_DOS:-0}"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export MODE_DEEP="$_MODE_DEEP" NO_DOS="$_NO_DOS"
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/core.sh"
        setup_target
        source "$_HO_ROOT/lib/recon_content.sh"
        PHASE_START=$(date +%s)
        run_recon_content
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_recon_content" "$rc"
    )
}

run_huntops_recon_js() {
    banner_phase "RECON: JS (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/recon_js.sh"
        PHASE_START=$(date +%s)
        run_recon_js
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_recon_js" "$rc"
    )
}

run_huntops_recon_params() {
    banner_phase "RECON: Params (HuntOps)"
    local _W="$W" _DOMAIN="$DOMAIN" _MODE="$MODE" _DEBUG="$DEBUG" _DEBUG_LOG="$DEBUG_LOG"
    (
        export W="$_W" DOMAIN="$_DOMAIN" MODE="$_MODE" DEBUG="$_DEBUG" DEBUG_LOG="$_DEBUG_LOG"
        export TARGET="$_DOMAIN"
        export HUNTOPS_ROOT="$_HO_ROOT" OUTROOT="${OMNI_OUTROOT:-$_HO_ROOT/output}"
        source "$_HO_ROOT/lib/recon_params.sh"
        PHASE_START=$(date +%s)
        run_recon_params
        local rc=$?
        PHASE_DUR=$(( $(date +%s) - PHASE_START ))
        phase_mark "huntops_recon_params" "$rc"
    )
}