#!/usr/bin/env bash
# HuntOps — FFUF Adapter
# Wraps ffuf for directory/file fuzzing
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# FFUF has issues with SIGTERM on this box, use timeout -k 30
adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/ffuf"
  return 0
}

adapter_name() {
  echo "ffuf"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "content fuzzing dirs"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "ffuf"; then
    adapter_warn "ffuf not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  ffuf -V 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration rate threads wordlist extensions input_file

  max_duration=$(parse_opt "$opts_json" "max_duration" "1800")
  rate=$(parse_opt "$opts_json" "rate" "50")
  threads=$(parse_opt "$opts_json" "threads" "40")
  wordlist=$(parse_opt "$opts_json" "wordlist" "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
  extensions=$(parse_opt "$opts_json" "extensions" "php,html,js,txt,bak,zip,old,orig")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../web_probe/httpx.txt")

  if [ -f "$input_file" ]; then
    local count=0
    while IFS= read -r url; do
      [ -z "$url" ] && continue

      local host
      host=$(echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*$||' | sed -E 's|:.*$||')
      [ -z "$host" ] && continue

      local output_file="$outdir/ffuf_${host//\//_}.json"
      local cmd="ffuf -u \"$url/FUZZ\" -w \"$wordlist\" -o \"$output_file\" -of json"
      cmd+=" -rate $rate -t $threads -timeout 10 -maxtime $max_duration"
      cmd+=" -mc 200,204,301,302,307,401,403,405,500"
      [ -n "$extensions" ] && cmd+=" -e \"$extensions\""

      adapter_log "Running ffuf on $url"
      adapter_run_cmd "$max_duration" bash -c "$cmd"
      local rc=$?

      if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
        adapter_warn "ffuf exited with code $rc on $url"
      fi

      # Parse ffuf JSON output
      if [ -f "$output_file" ]; then
        if command -v jq >/dev/null 2>&1; then
          jq -r '.results[] | select(.status==200 or .status==301 or .status==302 or .status==403) | "\(.url)|\(.status)|\(.length)|\(.words)"' "$output_file" 2>/dev/null | while IFS='|' read -r found_url status length words; do
            [ -z "$found_url" ] && continue
            emit_finding "info" "$host" "Directory/File found: $found_url" \
              "confirmed" "HTTP $status | Length: $length | Words: $words" \
              "curl -I \"$found_url\"" \
              "ffuf:content" "" "content,fuzzing,dir"
            count=$((count + 1))
          done
        fi
      fi
    done < "$input_file"
    adapter_log "ffuf found $count directories/files"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan