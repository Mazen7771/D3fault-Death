#!/usr/bin/env bash
# HuntOps — Naabu Adapter
# Wraps naabu for fast port scanning
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/naabu"
  return 0
}

adapter_name() {
  echo "naabu"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon portscan"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "naabu"; then
    adapter_warn "naabu not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  naabu -version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration rate ports input_file top_ports

  max_duration=$(parse_opt "$opts_json" "max_duration" "1800")
  rate=$(parse_opt "$opts_json" "rate" "1000")
  ports=$(parse_opt "$opts_json" "ports" "top-1000")
  top_ports=$(parse_opt "$opts_json" "top_ports" "1000")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../dns_validation/dnsx.txt")

  local output_file="$outdir/naabu.jsonl"
  local cmd="naabu -silent -json -o \"$output_file\" -rate $rate"

  # Port specification
  if [ "$ports" = "top-1000" ] || [ "$ports" = "top" ]; then
    cmd+=" -top-ports $top_ports"
  else
    cmd+=" -p \"$ports\""
  fi

  # Input: resolved hosts from dnsx
  if [ -f "$input_file" ]; then
    cmd+=" -l \"$input_file\""
  else
    cmd+=" -host \"$target\""
  fi

  adapter_log "Running naabu on targets from $input_file"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "naabu exited with code $rc"
  fi

  # Process results - naabu outputs JSONL
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      if command -v jq >/dev/null 2>&1; then
        local host port protocol
        host=$(echo "$line" | jq -r '.host // .ip // ""')
        port=$(echo "$line" | jq -r '.port // 0')
        protocol=$(echo "$line" | jq -r '.protocol // "tcp"')

        [ -z "$host" ] && continue

        emit_finding "info" "$host" "Open port: $host:$port ($protocol)" \
          "confirmed" "Port $port/$protocol open on $host" \
          "nc -zv $host $port" \
          "naabu:port" "" "recon,portscan,open"
        count=$((count + 1))
      fi
    done < "$output_file"
    adapter_log "naabu found $count open ports"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan