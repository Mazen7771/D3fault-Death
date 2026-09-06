#!/usr/bin/env bash
# HuntOps — Intel Engine Adapter
# Wraps lib/intel.sh for security intelligence gathering (headers, CORS, methods, cookies, clickjacking)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# Source the original intel.sh for its functions
INTEL_LIB="$(dirname "${BASH_SOURCE[0]}")/intel.sh"
[ -f "$INTEL_LIB" ] && source "$INTEL_LIB"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/intel"
  return 0
}

adapter_name() {
  echo "intel_engine"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "intel headers cors methods clickjacking cookies"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  # Check if required tools are available
  adapter_tool_exists "curl" || { adapter_warn "curl not found"; return 1; }
  return 0
}

adapter_health_check() {
  echo "Intel engine ready"
  return 0
}

adapter_scan() {
  # adapter_scan <target> <outdir> <opts_json>
  # Runs the OSINT layer (lib/intel.sh) and emits a finding per discovered
  # asset / exposure. Uses the REAL functions from intel.sh — not the
  # check_* names that were mistakenly referenced (they never existed).
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration input_file

  # lib/intel.sh relies on these globals being set (set here so the adapter
  # works standalone and inside the orchestrator).
  export DOMAIN="$target"
  export W="$outdir"
  export OI="$outdir/osint"
  mkdir -p "$OI"

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../web_probe/httpx.txt")

  local count=0

  # Run the OSINT layer functions (real implementation in lib/intel.sh)
  if declare -f _intel_passive_dns >/dev/null; then
    _intel_passive_dns 2>/dev/null
    if [ -f "$OI/passive-dns-clean.txt" ]; then
      while IFS= read -r host; do
        [ -z "$host" ] && continue
        emit_finding "info" "$host" "Subdomain (passive DNS)" \
          "candidate" "Discovered via crt.sh / hackertarget / OTX / anubis" \
          "curl -s \"https://crt.sh/?q=%25.$host&output=json\"" \
          "intel:passive-dns" "" "intel,osint,subdomain"
        count=$((count + 1))
      done < "$OI/passive-dns-clean.txt"
    fi
  fi

  if declare -f _intel_historical_cc >/dev/null; then
    _intel_historical_cc 2>/dev/null
    if [ -f "$OI/commoncrawl.txt" ]; then
      local n; n=$(count_lines "$OI/commoncrawl.txt")
      [ "$n" -gt 0 ] && {
        emit_finding "info" "$target" "Historical URLs (Common Crawl)" \
          "candidate" "$n URLs discovered for recon" \
          "curl -s \"https://index.commoncrawl.org/\" " \
          "intel:historical" "" "intel,osint,historical"
        count=$((count + 1))
      }
    fi
  fi

  if declare -f _intel_internetdb >/dev/null; then
    _intel_internetdb 2>/dev/null
    if [ -f "$OI/internetdb.json" ]; then
      emit_finding "info" "$target" "InternetDB exposure (Shodan)" \
        "candidate" "Service/port exposure data available" \
        "curl -s \"https://internetdb.shodan.io/$(dig +short "$target" A | head -1)\"" \
        "intel:internetdb" "" "intel,osint,shodan"
      count=$((count + 1))
    fi
  fi

  if declare -f _intel_keyed >/dev/null; then
    _intel_keyed 2>/dev/null
    for f in "$OI/shodan.json" "$OI/securitytrails.json" "$OI/github-code.json"; do
      [ -f "$f" ] && {
        emit_finding "info" "$target" "Keyed OSINT: $(basename "$f")" \
          "candidate" "External API enrichment data collected" \
          "curl -s \"$(basename "$f")\"" \
          "intel:keyed" "" "intel,osint,keyed"
        count=$((count + 1))
      }
    done
  fi

  adapter_log "Intel engine found $count issues"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan