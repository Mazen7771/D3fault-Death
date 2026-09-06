#!/usr/bin/env bash
# HuntOps — Nmap Adapter
# Wraps nmap for detailed port scanning and service enumeration
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/nmap"
  return 0
}

adapter_name() {
  echo "nmap"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon portscan service"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "nmap"; then
    adapter_warn "nmap not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  nmap --version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration timing ports input_file scripts

  max_duration=$(parse_opt "$opts_json" "max_duration" "1800")
  timing=$(parse_opt "$opts_json" "timing" "4")  # -T4 aggressive
  ports=$(parse_opt "$opts_json" "ports" "top-1000")
  scripts=$(parse_opt "$opts_json" "scripts" "default,vuln")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../dns_validation/dnsx.txt")

  local output_file="$outdir/nmap.xml"
  local cmd="nmap -T$timing -oX \"$output_file\""

  # Port specification
  if [ "$ports" = "top-1000" ] || [ "$ports" = "top" ]; then
    cmd+=" --top-ports 1000"
  elif [ "$ports" = "all" ]; then
    cmd+=" -p-"
  else
    cmd+=" -p \"$ports\""
  fi

  # Service detection and scripts
  cmd+=" -sV --version-intensity 5"
  [ -n "$scripts" ] && cmd+=" --script=\"$scripts\""

  # Input: resolved hosts from dnsx
  if [ -f "$input_file" ]; then
    cmd+=" -iL \"$input_file\""
  else
    cmd+=" \"$target\""
  fi

  adapter_log "Running nmap on targets from $input_file"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "nmap exited with code $rc"
  fi

  # Process results - parse nmap XML
  if [ -f "$output_file" ]; then
    local count=0
    # Use xmlstarlet if available, else grep/sed fallback
    if command -v xmlstarlet >/dev/null 2>&1; then
      # Extract hosts with open ports
      xmlstarlet sel -t -m "//host[ports/port/state/@state='open']" \
        -v "address/@addr" -o "|" \
        -v "ports/port/@portid" -o "|" \
        -v "ports/port/service/@name" -o "|" \
        -v "ports/port/service/@product" -o "|" \
        -v "ports/port/service/@version" -o "|" \
        -v "ports/port/service/@extrainfo" -n \
        "$output_file" 2>/dev/null | while IFS='|' read -r host port name product version extrainfo; do
        [ -z "$host" ] && continue
        local evidence="Port $port/$name open"
        [ -n "$product" ] && evidence="$evidence | $product"
        [ -n "$version" ] && evidence="$evidence $version"
        [ -n "$extrainfo" ] && evidence="$evidence ($extrainfo)"

        emit_finding "info" "$host" "Service: $name on port $port" \
          "confirmed" "$evidence" \
          "nmap -p $port -sV $host" \
          "nmap:service" "" "recon,portscan,service"
        count=$((count + 1))
      done
    else
      # Fallback: simple grep
      grep -oP '(?<=<address addr=")[^"]*' "$output_file" | while IFS= read -r host; do
        [ -z "$host" ] && continue
        emit_finding "info" "$host" "Host discovered by nmap" \
          "confirmed" "Host is up (nmap)" \
          "nmap -sV $host" \
          "nmap:host" "" "recon,host"
        count=$((count + 1))
      done
    fi
    adapter_log "nmap found $count services"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan