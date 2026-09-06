#!/usr/bin/env bash
# HuntOps — WSRecon Adapter
# WebSocket security recon
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/wsrecon"
  return 0
}

adapter_name() {
  echo "wsrecon"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon websocket ws wss"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "wsrecon"; then
    adapter_warn "wsrecon not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  wsrecon --version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")
  threads=$(parse_opt "$opts_json" "threads" "10")

  # Get live URLs from web probe phase
  local live_urls_file="$outdir/../web/live-urls.txt"
  if [ ! -f "$live_urls_file" ] || [ ! -s "$live_urls_file" ]; then
    adapter_warn "No live URLs found for WebSocket recon"
    return 0
  fi

  local output_file="$outdir/wsrecon.txt"
  local count=0

  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)

    # Convert HTTP(S) to WS(S)
    local ws_url
    if [[ "$url" == https://* ]]; then
      ws_url="wss://${url#https://}"
    else
      ws_url="ws://${url#http://}"
    fi

    # Run wsrecon
    local cmd="wsrecon -u \"$ws_url\" -o \"$output_file\" -t $threads --timeout 10"

    adapter_log "Running wsrecon on $ws_url"
    adapter_run_cmd "$max_duration" bash -c "$cmd"
    local rc=$?

    if [ $rc -eq 0 ] && [ -f "$output_file" ]; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        if echo "$line" | grep -q "Connected\|Handshake\|Protocol"; then
          emit_finding "info" "$host" "WebSocket endpoint discovered" "confirmed" \
            "$line" \
            "wsrecon -u \"$ws_url\"" \
            "wsrecon:websocket" "" "websocket,ws,wss"
          count=$((count + 1))
        elif echo "$line" | grep -q "Vulnerable\|Issue\|Weak"; then
          emit_finding "medium" "$host" "WebSocket issue: $line" "candidate" \
            "$line" \
            "wsrecon -u \"$ws_url\"" \
            "wsrecon:ws:vuln" "5.0" "websocket,vuln"
          count=$((count + 1))
        fi
      done < "$output_file"
    fi

  done < <(head -20 "$live_urls_file")

  adapter_log "WSRecon found $count WebSocket endpoints"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan