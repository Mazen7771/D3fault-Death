#!/usr/bin/env bash
# HuntOps — Subzy Adapter
# Fast subdomain takeover detection
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/subzy"
  return 0
}

adapter_name() {
  echo "subzy"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "takeover subdomain cname fingerprint"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "subzy"; then
    adapter_warn "subzy not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  subzy -version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")
  threads=$(parse_opt "$opts_json" "threads" "10")

  local output_file="$outdir/subzy.txt"

  # Get subdomains from recon phase
  local subdomain_file="$outdir/../subdomains/final-resolved.txt"
  if [ ! -f "$subdomain_file" ] || [ ! -s "$subdomain_file" ]; then
    adapter_warn "No subdomains found for takeover check"
    return 0
  fi

  # Run subzy
  local cmd="subzy -targets \"$subdomain_file\" -output \"$output_file\" -concurrency $threads -timeout 10 -verify_ssl -hide_fails"

  adapter_log "Running subzy on $(wc -l < "$subdomain_file") subdomains"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then
    adapter_warn "subzy exited with code $rc"
  fi

  # Process results
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      # subzy output: [VULNERABLE] subdomain -> service (CNAME)
      if echo "$line" | grep -q "\[VULNERABLE\]"; then
        local subdomain=$(echo "$line" | sed -n 's/.*\[VULNERABLE\] \(.*\) -> .*/\1/p')
        local service=$(echo "$line" | sed -n 's/.* -> \(.*\) (.*/\1/p')
        local cname=$(echo "$line" | sed -n 's/.*(\(.*\)).*/\1/p')

        emit_finding "high" "$subdomain" "Subdomain takeover: $service" "confirmed" \
          "Verified takeover: $subdomain -> $service (CNAME: $cname)" \
          "dig +short $subdomain; dig +short $cname" \
          "subzy:takeover:$service" "7.5" "takeover,subdomain,cname,fingerprint"
        count=$((count + 1))
      fi
    done < "$output_file"
    adapter_log "subzy found $count verified takeover candidates"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan