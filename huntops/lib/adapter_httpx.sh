#!/usr/bin/env bash
# HuntOps — HTTPx Adapter
# Wraps httpx (httpx-toolkit on Kali) for HTTP probing and fingerprinting
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# Find httpx binary (Kali uses httpx-toolkit)
HTTPX_BIN=""
for bin in httpx-toolkit httpx ~/go/bin/httpx; do
  if command -v "$bin" >/dev/null 2>&1; then
    HTTPX_BIN="$bin"
    break
  fi
done

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/httpx"
  return 0
}

adapter_name() {
  echo "httpx"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon web http"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  [ -n "$HTTPX_BIN" ] || {
    adapter_warn "httpx/httpx-toolkit not found in PATH"
    return 1
  }
  return 0
}

adapter_health_check() {
  "$HTTPX_BIN" -version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads rate_limit ports input_file

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")
  threads=$(parse_opt "$opts_json" "threads" "50")
  rate_limit=$(parse_opt "$opts_json" "rate_limit" "100")
  ports=$(parse_opt "$opts_json" "ports" "80,443,8080,8443,8000,8888,9443")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../dns_validation/dnsx.txt")

  local output_file="$outdir/httpx.jsonl"
  local cmd="\"$HTTPX_BIN\" -silent -json -o \"$output_file\" -t $threads -rl $rate_limit"

  # Ports
  cmd+=" -ports \"$ports\""

  # Common options
  cmd+=" -title -tech-detect -status-code -content-length -web-server -location"
  cmd+=" -follow-redirects -max-redirects 5"
  cmd+=" -timeout 10 -retries 1"

  # Input: resolved hosts from dnsx
  if [ -f "$input_file" ]; then
    cmd+=" -l \"$input_file\""
  else
    cmd+=" -u \"$target\""
  fi

  adapter_log "Running httpx on targets from $input_file"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "httpx exited with code $rc"
  fi

  # Process results - httpx outputs JSONL
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      if command -v jq >/dev/null 2>&1; then
        local url host status_code title tech webserver
        url=$(echo "$line" | jq -r '.url // ""')
        host=$(echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*$||' | sed -E 's|:.*$||')
        status_code=$(echo "$line" | jq -r '.status_code // 0')
        title=$(echo "$line" | jq -r '.title // ""')
        tech=$(echo "$line" | jq -r '.tech // [] | join(",")')
        webserver=$(echo "$line" | jq -r '.webserver // ""')

        [ -z "$host" ] && continue

        # Emit finding for each live HTTP endpoint
        local evidence="HTTP $status_code"
        [ -n "$title" ] && evidence="$evidence | Title: $title"
        [ -n "$tech" ] && evidence="$evidence | Tech: $tech"
        [ -n "$webserver" ] && evidence="$evidence | Server: $webserver"

        emit_finding "info" "$host" "Live HTTP endpoint: $url" \
          "confirmed" "$evidence" \
          "curl -I \"$url\"" \
          "httpx:live" "" "recon,http,live"
        count=$((count + 1))
      fi
    done < "$output_file"
    adapter_log "httpx found $count live HTTP endpoints"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan