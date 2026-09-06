#!/usr/bin/env bash
# HuntOps — Nikto Adapter
# Wraps nikto for web server vulnerability scanning
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/nikto"
  return 0
}

adapter_name() {
  echo "nikto"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "vuln web"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "nikto"; then
    adapter_warn "nikto not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  nikto -Version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration ports input_file tuning

  max_duration=$(parse_opt "$opts_json" "max_duration" "1800")
  ports=$(parse_opt "$opts_json" "ports" "80,443,8080,8443")
  tuning=$(parse_opt "$opts_json" "tuning" "123bde")  # Skip DoS tests by default
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../web_probe/httpx.txt")

  # Nikto scans one host at a time
  if [ -f "$input_file" ]; then
    local count=0
    while IFS= read -r url; do
      [ -z "$url" ] && continue
      local host
      host=$(echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*$||' | sed -E 's|:.*$||')
      [ -z "$host" ] && continue

      local output_file="$outdir/nikto_${host}.txt"
      local cmd="nikto -host \"$url\" -output \"$output_file\" -Format txt -Tuning $tuning"

      # Port specification
      cmd+=" -port \"$ports\""

      adapter_log "Running nikto on $url"
      adapter_run_cmd "$max_duration" bash -c "$cmd"
      local rc=$?

      if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
        adapter_warn "nikto exited with code $rc on $url"
      fi

      # Parse nikto output
      if [ -f "$output_file" ]; then
        while IFS= read -r line; do
          [ -z "$line" ] && continue
          # Nikto output format: + OSVDB-XXXXX: Description
          if echo "$line" | grep -q "^+ "; then
            local desc
            desc=$(echo "$line" | sed 's/^+ //')
            local osvdb
            osvdb=$(echo "$desc" | grep -oE 'OSVDB-[0-9]+' | head -1)
            local ref="nikto:scan"
            [ -n "$osvdb" ] && ref="$ref:$osvdb"

            # Determine impact from description keywords
            local impact_class="medium"
            echo "$desc" | grep -qi "sql injection\|xss\|rce\|remote code" && impact_class="high"
            echo "$desc" | grep -qi "directory traversal\|file inclusion\|lfi\|rfi" && impact_class="high"
            echo "$desc" | grep -qi "info\|disclosure\|version\|header" && impact_class="low"

            emit_finding "$impact_class" "$host" "Nikto: $desc" \
              "candidate" "$desc" \
              "nikto -host $url" \
              "$ref" "" "nikto,web"
            count=$((count + 1))
          fi
        done < "$output_file"
      fi
    done < "$input_file"
    adapter_log "nikto found $count issues across all hosts"
  else
    adapter_warn "No input file for nikto: $input_file"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan