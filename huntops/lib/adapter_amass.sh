#!/usr/bin/env bash
# HuntOps — Amass Adapter
# Wraps amass for subdomain enumeration
# Includes libpostal guard to prevent sudo prompt on tty
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/amass"
  return 0
}

adapter_name() {
  echo "amass"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon subdomains"
}

adapter_requires_api_key() {
  return 1  # No API key required (but can use if available)
}

# Check if amass is available and libpostal is provisioned
# Amass on Debian sudo-prompts for libpostal data on tty; we must guard against this
adapter_is_available() {
  if ! adapter_tool_exists "amass"; then
    adapter_warn "amass not found in PATH"
    return 1
  fi

  # Check if libpostal is provisioned (amass will hang on tty otherwise)
  # We can test with a quick enum that times out if libpostal missing
  if ! _amass_libpostal_ready; then
    adapter_warn "amass: libpostal not provisioned (run with -i to install)"
    return 1
  fi

  return 0
}

# Internal: Check if amass libpostal data is available
# Runs a quick test with timeout to avoid hanging
_amass_libpostal_ready() {
  # Use a short timeout test - if it hangs >5s, libpostal is missing
  timeout 5 amass enum -passive -d example.com -nocolor -silent >/dev/null 2>&1
  return $?
}

adapter_health_check() {
  _amass_libpostal_ready && amass version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration passive_only config_file

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")
  passive_only=$(parse_opt "$opts_json" "passive_only" "true")
  config_file=$(parse_opt "$opts_json" "config_file" "")

  local output_file="$outdir/amass.txt"
  local cmd="amass enum -d \"$target\" -o \"$output_file\" -nocolor -silent"

  # Passive mode (no brute force) - safer and faster
  [ "$passive_only" = "true" ] && cmd+=" -passive"

  # Config file if provided
  [ -n "$config_file" ] && [ -f "$config_file" ] && cmd+=" -config \"$config_file\""

  # API keys from env if available
  # Amass reads from config file, but we can pass via env
  # (amass uses API keys from ~/.config/amass/config.ini)

  adapter_log "Running amass on $target (passive: $passive_only)"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "amass exited with code $rc"
  fi

  # Process results and emit findings
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r subdomain; do
      [ -z "$subdomain" ] && continue
      emit_finding "info" "$subdomain" "Subdomain discovered: $subdomain" \
        "confirmed" "Found via amass" \
        "curl -I https://$subdomain" \
        "amass:subdomain" "" "recon,subdomain"
      count=$((count + 1))
    done < "$output_file"
    adapter_log "amass found $count subdomains"
  fi

  return 0
}

# Export for subshell use
export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan