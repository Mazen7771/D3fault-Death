#!/usr/bin/env bash
# HuntOps — Gobuster Adapter
# Wraps gobuster for directory/file/DNS fuzzing
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/gobuster"
  return 0
}

adapter_name() {
  echo "gobuster"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "content fuzzing dirs dns"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "gobuster"; then
    adapter_warn "gobuster not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  gobuster version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration mode wordlist threads extensions input_file

  max_duration=$(parse_opt "$opts_json" "max_duration" "1800")
  mode=$(parse_opt "$opts_json" "mode" "dir")  # dir, dns, vhost
  wordlist=$(parse_opt "$opts_json" "wordlist" "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
  threads=$(parse_opt "$opts_json" "threads" "50")
  extensions=$(parse_opt "$opts_json" "extensions" "php,html,js,txt,bak,zip,old,orig")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../web_probe/httpx.txt")

  if [ -f "$input_file" ]; then
    local count=0
    while IFS= read -r url; do
      [ -z "$url" ] && continue

      local host
      host=$(echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*$||' | sed -E 's|:.*$||')
      [ -z "$host" ] && continue

      local output_file="$outdir/gobuster_${host//\//_}.txt"
      local cmd="gobuster $mode -u \"$url\" -w \"$wordlist\" -o \"$output_file\" -t $threads -q"

      [ "$mode" = "dir" ] && [ -n "$extensions" ] && cmd+=" -x \"$extensions\""
      [ "$mode" = "dns" ] && cmd="gobuster dns -d \"$host\" -w \"$wordlist\" -o \"$output_file\" -t $threads -q"

      adapter_log "Running gobuster $mode on $url"
      adapter_run_cmd "$max_duration" bash -c "$cmd"
      local rc=$?

      if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
        adapter_warn "gobuster exited with code $rc on $url"
      fi

      # Parse gobuster output
      if [ -f "$output_file" ]; then
        while IFS= read -r line; do
          [ -z "$line" ] && continue
          # Gobuster output: /path (Status: 200) [Size: 1234]
          local found_path status size
          found_path=$(echo "$line" | sed -n 's/^\([^ ]*\) .*/\1/p')
          status=$(echo "$line" | sed -n 's/.*Status: \([0-9]*\).*/\1/p')
          size=$(echo "$line" | sed -n 's/.*Size: \([0-9]*\).*/\1/p')

          [ -z "$found_path" ] && continue

          local found_url="${url%/}${found_path}"
          emit_finding "info" "$host" "Directory/File found: $found_url" \
            "confirmed" "HTTP $status | Size: $size" \
            "curl -I \"$found_url\"" \
            "gobuster:content" "" "content,fuzzing,dir"
          count=$((count + 1))
        done < "$output_file"
      fi
    done < "$input_file"
    adapter_log "gobuster found $count directories/files"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan