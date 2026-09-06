#!/usr/bin/env bash
# HuntOps — DNSx Adapter
# Wraps dnsx for DNS resolution and validation
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/dnsx"
  return 0
}

adapter_name() {
  echo "dnsx"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon dns validation"
}

adapter_requires_api_key() {
  return 1  # No API key required
}

adapter_is_available() {
  if ! adapter_tool_exists "dnsx"; then
    adapter_warn "dnsx not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  dnsx -version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads rate_limit resolvers input_file

  max_duration=$(parse_opt "$opts_json" "max_duration" "900")
  threads=$(parse_opt "$opts_json" "threads" "500")
  rate_limit=$(parse_opt "$opts_json" "rate_limit" "1000")
  resolvers=$(parse_opt "$opts_json" "resolvers" "")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../recon/subdomains.txt")

  local output_file="$outdir/dnsx.txt"
  local cmd="dnsx -silent -t $threads -rl $rate_limit -o \"$output_file\""

  # Add resolvers if provided
  [ -n "$resolvers" ] && [ -f "$resolvers" ] && cmd+=" -r \"$resolvers\""

  # Add common options
  cmd+=" -a -aaaa -cname -ns -mx -txt -soa -ptr"
  cmd+=" -resp -resp-only"

  # If input file exists, use it; else use target
  if [ -f "$input_file" ]; then
    cmd="command cat \"$input_file\" | $cmd"
  else
    cmd="echo \"$target\" | $cmd"
  fi

  adapter_log "Running dnsx on targets from $input_file"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "dnsx exited with code $rc"
  fi

  # Process results and emit findings
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      # Parse dnsx output format: host [A: 1.2.3.4] [AAAA: ...]
      local host
      host=$(echo "$line" | awk '{print $1}')
      [ -z "$host" ] && continue

      emit_finding "info" "$host" "DNS records resolved: $line" \
        "confirmed" "DNS resolution via dnsx" \
        "dnsx -json $host" \
        "dnsx:dns" "" "recon,dns,validation"
      count=$((count + 1))
    done < "$output_file"
    adapter_log "dnsx resolved $count hosts"
  fi

  return 0
}

# Export for subshell use
export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan