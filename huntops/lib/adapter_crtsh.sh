#!/usr/bin/env bash
# HuntOps — crt.sh Adapter
# Queries crt.sh for certificate transparency subdomain enumeration
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/crtsh"
  return 0
}

adapter_name() {
  echo "crtsh"
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
  if ! adapter_tool_exists "curl"; then
    adapter_warn "curl not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  curl -s "https://crt.sh/?q=%25.example.com&output=json" | head -c 100
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration

  max_duration=$(parse_opt "$opts_json" "max_duration" "120")

  local output_file="$outdir/crtsh.txt"
  local url="https://crt.sh/?q=%25.$target&output=json"

  adapter_log "Querying crt.sh for $target"
  adapter_run_cmd "$max_duration" curl -s "$url" > "$output_file"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "crt.sh query exited with code $rc"
  fi

  if [ -f "$output_file" ] && [ -s "$output_file" ]; then
    local count=0
    if command -v jq >/dev/null 2>&1; then
      # crt.sh returns a JSON array: parse it as a whole, not line-by-line
      local name_values
      name_values=$(jq -r '.[].name_value // empty' "$output_file" 2>/dev/null)
      if [ -n "$name_values" ]; then
        echo "$name_values" | while IFS= read -r name_value; do
          [ -z "$name_value" ] && continue
          # name_value can contain multiple subdomains separated by newlines
          echo "$name_value" | while IFS= read -r subdomain; do
            [ -z "$subdomain" ] && continue
            # Remove wildcards
            subdomain=$(echo "$subdomain" | sed 's/^\*\.//')
            emit_finding "info" "$subdomain" "Subdomain discovered via CT: $subdomain" \
              "confirmed" "Found in certificate transparency logs (crt.sh)" \
              "curl -I https://$subdomain" \
              "crtsh:subdomain" "" "recon,subdomain,ct"
          done
        done
        count=$(echo "$name_values" | tr '\n' '\n' | sed 's/^\*\.//' | sort -u | wc -l)
        adapter_log "crt.sh found $count unique subdomains"
      fi
    fi
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan