#!/usr/bin/env bash
# HuntOps — Assetfinder Adapter
# Wraps assetfinder for subdomain enumeration
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/assetfinder"
  return 0
}

adapter_name() {
  echo "assetfinder"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon subdomains"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "assetfinder"; then
    adapter_warn "assetfinder not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  assetfinder -h 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration subsonly

  max_duration=$(parse_opt "$opts_json" "max_duration" "120")
  subsonly=$(parse_opt "$opts_json" "subs_only" "true")

  local output_file="$outdir/assetfinder.txt"
  local cmd="assetfinder"

  [ "$subsonly" = "true" ] && cmd+=" --subs-only"
  cmd+=" \"$target\" > \"$output_file\""

  adapter_log "Running assetfinder on $target"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "assetfinder exited with code $rc"
  fi

  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r subdomain; do
      [ -z "$subdomain" ] && continue
      emit_finding "info" "$subdomain" "Subdomain discovered: $subdomain" \
        "confirmed" "Found via assetfinder" \
        "curl -I https://$subdomain" \
        "assetfinder:subdomain" "" "recon,subdomain"
      count=$((count + 1))
    done < "$output_file"
    adapter_log "assetfinder found $count subdomains"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan