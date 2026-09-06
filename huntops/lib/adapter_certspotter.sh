#!/usr/bin/env bash
# HuntOps — CertSpotter Adapter
# Queries CertSpotter API for certificate transparency subdomain enumeration
# Requires CERTSPOTTER_API_KEY for authenticated requests (higher rate limits)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/certspotter"
  return 0
}

adapter_name() {
  echo "certspotter"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon subdomains"
}

adapter_requires_api_key() {
  return 0  # Optional API key for higher limits
}

adapter_is_available() {
  if ! adapter_tool_exists "curl"; then
    adapter_warn "curl not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  local api_key="${CERTSPOTTER_API_KEY:-}"
  local url="https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names"
  if [ -n "$api_key" ]; then
    curl -s -H "Authorization: Bearer $api_key" "$url" | head -c 100
  else
    curl -s "$url" | head -c 100
  fi
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration api_key

  max_duration=$(parse_opt "$opts_json" "max_duration" "120")
  api_key="${CERTSPOTTER_API_KEY:-}"

  local output_file="$outdir/certspotter.txt"
  local url="https://api.certspotter.com/v1/issuances?domain=$target&include_subdomains=true&expand=dns_names"

  local cmd="curl -s"
  [ -n "$api_key" ] && cmd+=" -H \"Authorization: Bearer $api_key\""
  cmd+=" \"$url\" > \"$output_file\""

  adapter_log "Querying CertSpotter for $target"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "CertSpotter query exited with code $rc"
  fi

  if [ -f "$output_file" ] && [ -s "$output_file" ]; then
    if command -v jq >/dev/null 2>&1; then
      local count=0
      # Parse JSON array of issuances
      jq -r '.[].dns_names[]' "$output_file" 2>/dev/null | while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        subdomain=$(echo "$subdomain" | sed 's/^\*\.//')
        emit_finding "info" "$subdomain" "Subdomain discovered via CT: $subdomain" \
          "confirmed" "Found in certificate transparency logs (CertSpotter)" \
          "curl -I https://$subdomain" \
          "certspotter:subdomain" "" "recon,subdomain,ct"
        count=$((count + 1))
      done
      adapter_log "CertSpotter found $count unique subdomains"
    fi
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan