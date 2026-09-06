#!/usr/bin/env bash
# HuntOps — SQLMap Adapter
# Wraps sqlmap for SQL injection detection and exploitation
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/sqlmap"
  return 0
}

adapter_name() {
  echo "sqlmap"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "vuln sqli params"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "sqlmap"; then
    adapter_warn "sqlmap not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  sqlmap --version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration level risk threads input_file batch

  max_duration=$(parse_opt "$opts_json" "max_duration" "1800")
  level=$(parse_opt "$opts_json" "level" "1")       # 1-5
  risk=$(parse_opt "$opts_json" "risk" "1")         # 1-3
  threads=$(parse_opt "$opts_json" "threads" "1")   # Single-threaded for safety
  batch=$(parse_opt "$opts_json" "batch" "true")    # Non-interactive
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../web_probe/httpx.txt")

  # sqlmap needs URLs with parameters to test
  if [ -f "$input_file" ]; then
    local count=0
    while IFS= read -r url; do
      [ -z "$url" ] && continue

      local host
      host=$(echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*$||' | sed -E 's|:.*$||')
      [ -z "$host" ] && continue

      # Check if URL has parameters
      if ! echo "$url" | grep -q "?"; then
        continue
      fi

      local output_dir="$outdir/sqlmap_${host//\//_}"
      mkdir -p "$output_dir"

      local cmd="sqlmap -u \"$url\" --batch --level=$level --risk=$risk --threads=$threads"
      cmd+=" --output-dir=\"$output_dir\" --flush-session --fresh-queries"
      cmd+=" --disable-coloring --answers=\"follow=N\""

      # Add tamper scripts if specified
      local tamper
      tamper=$(parse_opt "$opts_json" "tamper" "")
      [ -n "$tamper" ] && cmd+=" --tamper=\"$tamper\""

      adapter_log "Running sqlmap on $url"
      adapter_run_cmd "$max_duration" bash -c "$cmd"
      local rc=$?

      if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
        adapter_warn "sqlmap exited with code $rc on $url"
      fi

      # Parse sqlmap output (log file)
      local log_file="$output_dir/log"
      if [ -f "$log_file" ]; then
        # Look for injection findings
        while IFS= read -r line; do
          if echo "$line" | grep -qi "parameter.*is vulnerable\|injectable\|sql injection"; then
            local param
            param=$(echo "$line" | grep -oE 'parameter [^ ]+' | sed 's/parameter //' | head -1)
            local type
            type=$(echo "$line" | grep -oE 'Type: [^ ]+' | sed 's/Type: //' | head -1)

            emit_finding "high" "$host" "SQL Injection in parameter: $param" \
              "confirmed" "sqlmap confirmed $type injection in $param" \
              "sqlmap -u \"$url\" --batch --level=$level --risk=$risk" \
              "sqlmap:sqli" "8.5" "sqli,sqlmap,cwe-89"
            count=$((count + 1))
          fi
        done < "$log_file"
      fi
    done < "$input_file"
    adapter_log "sqlmap found $count SQL injection vulnerabilities"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan