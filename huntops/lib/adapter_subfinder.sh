#!/usr/bin/env bash
# HuntOps — Subfinder Adapter
# Wraps subfinder for subdomain enumeration
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/subfinder"
  return 0
}

adapter_name() {
  echo "subfinder"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon subdomains"
}

adapter_requires_api_key() {
  return 1  # No API key required
}

adapter_is_available() {
  if ! adapter_tool_exists "subfinder"; then
    adapter_warn "subfinder not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  subfinder -version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads rate_limit

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")
  threads=$(parse_opt "$opts_json" "threads" "10")
  rate_limit=$(parse_opt "$opts_json" "rate_limit" "100")

  local output_file="$outdir/subfinder.txt"
  local cmd="subfinder -d \"$target\" -o \"$output_file\" -t $threads -rate-limit $rate_limit -silent"

  # Add recursive if enabled
  local recursive
  recursive=$(parse_opt "$opts_json" "recursive" "true")
  [ "$recursive" = "true" ] && cmd+=" -recursive"

  # Add all sources if enabled
  local all_sources
  all_sources=$(parse_opt "$opts_json" "all_sources" "true")
  [ "$all_sources" = "true" ] && cmd+=" -all"

  adapter_log "Running subfinder on $target"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "subfinder exited with code $rc"
  fi

  # Process results and emit findings
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r subdomain; do
      [ -z "$subdomain" ] && continue
      # Each discovered subdomain is a finding
      emit_finding "info" "$subdomain" "Subdomain discovered: $subdomain" \
        "confirmed" "Found via subfinder" \
        "curl -I https://$subdomain" \
        "subfinder:subdomain" "" "recon,subdomain"
      count=$((count + 1))
    done < "$output_file"
    adapter_log "subfinder found $count subdomains"
  fi

  return 0
}

# Export for subshell use
export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan