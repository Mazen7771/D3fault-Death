#!/usr/bin/env bash
# HuntOps — Feroxbuster Adapter
# Recursive content discovery with screenshot support
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/feroxbuster"
  return 0
}

adapter_name() {
  echo "feroxbuster"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "content fuzzing dirs recursive screenshots"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "feroxbuster"; then
    adapter_warn "feroxbuster not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  feroxbuster --version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads rate_limit wordlist

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")
  threads=$(parse_opt "$opts_json" "threads" "10")
  rate_limit=$(parse_opt "$opts_json" "rate_limit" "50")
  wordlist=$(parse_opt "$opts_json" "wordlist" "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")

  local output_file="$outdir/feroxbuster.txt"
  local json_output="$outdir/feroxbuster.json"

  local cmd="feroxbuster -u \"$target\" -w \"$wordlist\" -t $threads --rate-limit $rate_limit -o \"$output_file\" --json -q --no-state"

  # Recursive scanning
  local recursive
  recursive=$(parse_opt "$opts_json" "recursive" "true")
  [ "$recursive" = "true" ] && cmd+=" -r"

  # Extensions
  local extensions
  extensions=$(parse_opt "$opts_json" "extensions" "php,html,js,txt,json,xml,asp,aspx,jsp")
  [ -n "$extensions" ] && cmd+=" -x $extensions"

  # Status codes to ignore
  local filter_status
  filter_status=$(parse_opt "$opts_json" "filter_status" "404,403")
  [ -n "$filter_status" ] && cmd+=" -C $filter_status"

  adapter_log "Running feroxbuster on $target"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "feroxbuster exited with code $rc"
  fi

  # Process results - feroxbuster outputs JSON lines when --json flag used
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      # Try to parse JSON output if available
      local url status content_length
      url=$(echo "$line" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p')
      status=$(echo "$line" | sed -n 's/.*"status":\([0-9]*\).*/\1/p')
      content_length=$(echo "$line" | sed -n 's/.*"content_length":\([0-9]*\).*/\1/p')

      if [ -n "$url" ]; then
        local title="Discovered path: $url"
        [ -n "$status" ] && title="$title (HTTP $status)"
        [ -n "$content_length" ] && title="$title [$content_length bytes]"

        emit_finding "info" "$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)" \
          "$title" "confirmed" \
          "Found via feroxbuster recursive scan" \
          "curl -I \"$url\"" \
          "feroxbuster:content" "" "content,fuzzing,recursive"
        count=$((count + 1))
      fi
    done < "$output_file"
    adapter_log "feroxbuster found $count paths"
  fi

  # Also check for screenshots if taken
  if [ -d "$outdir/screenshots" ]; then
    local shot_count=$(find "$outdir/screenshots" -name "*.png" 2>/dev/null | wc -l)
    [ "$shot_count" -gt 0 ] && adapter_log "feroxbuster captured $shot_count screenshots"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan