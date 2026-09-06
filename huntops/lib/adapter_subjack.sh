#!/usr/bin/env bash
# HuntOps — Subjack Adapter
# Subdomain takeover detection using fingerprints
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/subjack"
  return 0
}

adapter_name() {
  echo "subjack"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "takeover subdomain cname"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "subjack"; then
    adapter_warn "subjack not found in PATH"
    return 1
  fi
  # Check for fingerprints file
  local fingerprints="${SUBJACK_FINGERPRINTS:-$HOME/.subjack/fingerprints.json}"
  if [ ! -f "$fingerprints" ]; then
    adapter_warn "subjack fingerprints not found at $fingerprints (download from haccer/subjack)"
    return 1
  fi
  return 0
}

adapter_health_check() {
  subjack -version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")
  threads=$(parse_opt "$opts_json" "threads" "10")

  local output_file="$outdir/subjack.txt"
  local fingerprints="${SUBJACK_FINGERPRINTS:-$HOME/.subjack/fingerprints.json}"

  # Get subdomains from recon phase
  local subdomain_file="$outdir/../subdomains/final-resolved.txt"
  if [ ! -f "$subdomain_file" ] || [ ! -s "$subdomain_file" ]; then
    adapter_warn "No subdomains found for takeover check"
    return 0
  fi

  # Run subjack
  local cmd="subjack -w \"$subdomain_file\" -c \"$fingerprints\" -o \"$output_file\" -t $threads -ssl -timeout 30"

  adapter_log "Running subjack on $(wc -l < "$subdomain_file") subdomains"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then
    adapter_warn "subjack exited with code $rc"
  fi

  # Process results
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      # subjack output format: subdomain [CNAME] [VULNERABLE] [SERVICE]
      local subdomain cname vulnerable service
      subdomain=$(echo "$line" | awk '{print $1}')
      cname=$(echo "$line" | awk '{print $2}' | sed 's/\[//;s/\]//')
      vulnerable=$(echo "$line" | grep -c "\[VULNERABLE\]")
      service=$(echo "$line" | sed -n 's/.*\[\([A-Z]*\)\].*/\1/p')

      if [ "$vulnerable" -gt 0 ]; then
        emit_finding "high" "$subdomain" "Subdomain takeover: $service" "confirmed" \
          "CNAME: $cname points to unclaimed $service" \
          "dig +short $subdomain; dig +short $cname" \
          "subjack:takeover:$service" "7.5" "takeover,subdomain,cname"
        count=$((count + 1))
      fi
    done < "$output_file"
    adapter_log "subjack found $count takeover candidates"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan