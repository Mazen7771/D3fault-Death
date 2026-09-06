#!/usr/bin/env bash
# HuntOps — global configuration (sourced by huntops.sh and lib/*.sh)
# All values overridable via environment variables.

export HUNTOPS_VERSION="1.0.0"
# Honor an externally-set HUNTOPS_ROOT (huntops.sh sets it from $0); compute a
# robust default otherwise (BASH_SOURCE empty under zsh / non-bash shells).
if [ -z "${HUNTOPS_ROOT:-}" ]; then
  if [ -n "${BASH_SOURCE:-}" ]; then
    export HUNTOPS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  else
    export HUNTOPS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  fi
fi

# ---- Pipeline manifests (data-driven phase ordering) -------------------------
# vuln_tls (testssl.sh) runs right after recon_web so live-urls.txt exists.
# report then outputs (per-domain deliverables) are terminal.
export PIPELINE_BB=(
  recon_subdomains recon_ports recon_web vuln_tls recon_content recon_js recon_params
  vuln_nuclei vuln_nikto vuln_sqlmap candidates intel cve report outputs
)
export PIPELINE_QUICK=(recon_subdomains recon_web vuln_tls vuln_nuclei report outputs)
# deep reuses the bb manifest; MODE_DEEP toggles heavier behaviour inside phases
export PIPELINE_DEEP=(recon_subdomains recon_ports recon_web vuln_tls recon_content recon_js recon_params
  vuln_nuclei vuln_nikto vuln_sqlmap candidates intel cve report outputs)

# ---- Global rate / concurrency caps (ethics-first defaults, no-DoS) ----------
export RATE_GLOBAL=${RATE_GLOBAL:-10}          # req/s global ceiling for curl loops
export CONCURRENCY=${CONCURRENCY:-3}           # parallel tool-chains (low-RAM box)
export HOST_BUDGET=${HOST_BUDGET:-25}          # max concurrent hosts per tool
# nuclei rate: polite by default. --no-dos lifts it (see lib/vuln_nuclei.sh) so
# big tag sets (cve, exposure) complete within their timeout instead of being
# cut off mid-run. NOTE: NO_DOS is parsed AFTER config.sh is sourced, so the
# no-dos values are applied at runtime in the module, not here.
export NUCLEI_RATE=${NUCLEI_RATE:-15}
export NUCLEI_RATE_NO_DOS=${NUCLEI_RATE_NO_DOS:-100}
export NUCLEI_CONCURRENCY=${NUCLEI_CONCURRENCY:-10}
# --no-dos lifts ffuf/naabu too. Applied at runtime in their modules (NO_DOS is
# parsed after config sources, same pattern as the nuclei runtime resolution).
export FUF_RATE=${FUF_RATE:-50}                # ffuf -rate
export FUF_RATE_NO_DOS=${FUF_RATE_NO_DOS:-150}
export NAABU_RATE=${NAABU_RATE:-1000}          # naabu -rate
export NAABU_RATE_NO_DOS=${NAABU_RATE_NO_DOS:-5000}
export MASS_RATE=${MASS_RATE:-1000}            # masscan --rate
export SHUFFLED_THREADS=${SHUFFLED_THREADS:-100}
# dnsx brute-fallback sample (top-N of the frequency-ordered Jhaddix list) used
# when massdns is missing; real subdomains cluster at the head of the list.
export DNSX_BRUTE_SAMPLE=${DNSX_BRUTE_SAMPLE:-100000}
export XARGS_PARALLEL=${XARGS_PARALLEL:-4}     # ~ nproc

# ---- Caps --------------------------------------------------------------------
export SQLMAP_CAP=${SQLMAP_CAP:-5}
export PERM_CAP=${PERM_CAP:-300000}            # max permuted subdomain candidates
export GAU_CAP=${GAU_CAP:-5000}
export WAYBACK_TIMEOUT=${WAYBACK_TIMEOUT:-120}
# Per-tag timeout must give the polite rate room to work: at rl 15 the cve tag
# (thousands of templates) needs >30 min, so 1800s always timed out empty. 3600s
# lets the first tags actually finish. --no-dos lifts both rate and this cap.
export NUCLEI_TIMEOUT=${NUCLEI_TIMEOUT:-3600}
export NUCLEI_TIMEOUT_NO_DOS=${NUCLEI_TIMEOUT_NO_DOS:-5400}
export LOW_YIELD_THRESHOLD=${LOW_YIELD_THRESHOLD:-5}   # validated hosts before we warn
export MIN_MEM_FREE_MB=${MIN_MEM_FREE_MB:-500}          # skip heavy stages below this

# ---- Strategy Engine (Ebb & Flow) ----------------------------------------------
export STRATEGY_LIVE_CAP=${STRATEGY_LIVE_CAP:-50}       # max live hosts to probe
export STRATEGY_PARAM_CAP=${STRATEGY_PARAM_CAP:-30}     # max param URLs to test
export STRATEGY_TIMEOUT=${STRATEGY_TIMEOUT:-30}         # per-request timeout (seconds)

# ---- testssl.sh (TLS layer) --------------------------------------------------
export TESTSSL_BIN="${TESTSSL_BIN:-/home/mazin/tools/testssl_tool/testssl.sh}"
export TLS_HOST_CAP=${TLS_HOST_CAP:-10}        # max hosts testssl runs against
export TLS_SCAN_OPTS="${TLS_SCAN_OPTS:--p -s -U -P -S --fast}"

# ---- Wordlists ---------------------------------------------------------------
export WLD_DNS="/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
export WLD_DNS_TOP="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
export WLD_WEB="/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"
export WLD_WEB_MEDIUM="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
# Default to the curated fast resolver list (dnsx over the 12k-line public list
# was ~10x slower). Fall back to the full list if fast one is missing.
if [ -f "$HUNTOPS_ROOT/config/resolvers-fast.txt" ]; then
  export RESOLVERS="$HUNTOPS_ROOT/config/resolvers-fast.txt"
else
  export RESOLVERS="$HUNTOPS_ROOT/config/resolvers.txt"
fi

# ---- Output ------------------------------------------------------------------
export OUTROOT="${OUTROOT:-$HUNTOPS_ROOT/output}"
