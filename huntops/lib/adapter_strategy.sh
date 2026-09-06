#!/usr/bin/env bash
# HuntOps — Strategy Engine Adapter
# Wraps the Ebb & Flow strategy engine (lib/strategy.sh) and conforms to the
# adapter contract. Reads context from previous phases, runs all 10 strategies,
# emits JSON Lines findings to stdout for the unified findings sink.

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"
source "$(dirname "${BASH_SOURCE[0]}")/core.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/strategy"
  # Ensure core findings sinks are available (they're initialized in setup_target)
  # Strategy writes directly via add_finding / add_candidate which use $FINDINGS, $CANDIDATES
  return 0
}

adapter_name() {
  echo "strategy_engine"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "strategy attack-vector low-hanging param-injection api-graphql cors cloud-storage auth-bypass race takeover secrets cve-poc"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  # Strategy engine is pure bash + curl + standard utils; always available
  return 0
}

adapter_health_check() {
  echo "strategy_engine v1.0.0 ready (bash + curl)"
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")

  # Source the strategy engine core
  source "$HUNTOPS_ROOT/lib/strategy.sh"

  # Expose workdir variables expected by strategy.sh
  export W="$outdir"
  export TARGET="$target"
  export MODE="${MODE:-bb}"
  export NO_DOS="${NO_DOS:-0}"
  export STRATEGY_LIVE_CAP="${STRATEGY_LIVE_CAP:-50}"
  export STRATEGY_PARAM_CAP="${STRATEGY_PARAM_CAP:-30}"
  export STRATEGY_TIMEOUT="${STRATEGY_TIMEOUT:-30}"
  export IMPACT_CLASSES="${IMPACT_CLASSES:-$HUNTOPS_ROOT/data/impact-classes.conf}"
  export EXCLUSIONS="${EXCLUSIONS:-$HUNTOPS_ROOT/data/program-exclusions.txt}"

  # Required input files from previous phases (should exist)
  local live_urls="$outdir/web/live-urls.txt"
  local param_urls="$outdir/urls/param-urls.txt"
  local tech_file="$outdir/tech/tech.txt"
  local cve_matches="$outdir/cve/cve-matches.txt"
  local cnames_file="$outdir/subdomains/cnames.txt"
  local secrets_file="$outdir/secrets/secrets.txt"

  # Verify we have at least some context
  if [ ! -f "$live_urls" ] && [ ! -f "$param_urls" ]; then
    adapter_warn "No live-urls.txt or param-urls.txt found — strategy engine needs web probe context"
  fi

  adapter_log "Starting strategy engine (Ebb & Flow) for $target"

  # Run the strategy engine
  timeout -k 30 "$max_duration" run_strategy

  local exit_code=$?
  if [ $exit_code -eq 124 ] || [ $exit_code -eq 137 ]; then
    adapter_warn "Strategy engine timed out after ${max_duration}s"
  elif [ $exit_code -ne 0 ]; then
    adapter_warn "Strategy engine exited with code $exit_code"
  fi

  adapter_log "Strategy engine completed"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan