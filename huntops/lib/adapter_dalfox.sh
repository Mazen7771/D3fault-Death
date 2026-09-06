#!/usr/bin/env bash
# HuntOps — Dalfox Adapter
# XSS scanner (DOM, reflected, stored)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/dalfox"
  return 0
}

adapter_name() {
  echo "dalfox"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "vuln xss dom-xss reflected-xss stored-xss"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "dalfox"; then
    adapter_warn "dalfox not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  dalfox version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads rate_limit

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")
  threads=$(parse_opt "$opts_json" "threads" "10")
  rate_limit=$(parse_opt "$opts_json" "rate_limit" "50")

  local output_file="$outdir/dalfox.txt"

  # Build URL list from param urls if available, otherwise use target
  local url_list="$outdir/../urls/param-urls.txt"
  local urls_to_scan=""

  if [ -f "$url_list" ] && [ -s "$url_list" ]; then
    # Use parameterized URLs for XSS testing
    urls_to_scan=$(head -100 "$url_list")
    adapter_log "Dalfox scanning $(echo "$urls_to_scan" | wc -l) parameterized URLs"
  else
    # Fall back to target
    urls_to_scan="$target"
    adapter_log "Dalfox scanning target: $target"
  fi

  local count=0
  while IFS= read -r url; do
    [ -z "$url" ] && continue

    local cmd="dalfox url \"$url\" --worker $threads --delay $rate_limit --output \"$output_file.$count\" --format txt --silence"

    # Add blind XSS callback if configured
    local blind_xss
    blind_xss=$(parse_opt "$opts_json" "blind_xss" "")
    [ -n "$blind_xss" ] && cmd+=" -b $blind_xss"

    # Skip static files
    cmd+=" --skip-static"

    adapter_run_cmd "$max_duration" bash -c "$cmd"
    local rc=$?

    if [ $rc -eq 0 ] || [ $rc -eq 1 ]; then
      # dalfox returns 1 when findings found
      if [ -f "$output_file.$count" ]; then
        while IFS= read -r finding_line; do
          [ -z "$finding_line" ] && continue
          # Parse dalfox output
          if echo "$finding_line" | grep -q "\[POC\]"; then
            local poc=$(echo "$finding_line" | sed 's/.*\[POC\] //')
            local vuln_type=$(echo "$finding_line" | sed -n 's/.*\[\([A-Z]*\)\].*/\1/p')

            local impact="high"
            [ "$vuln_type" = "DOM" ] && impact="medium"
            [ "$vuln_type" = "REFLECTED" ] && impact="high"
            [ "$vuln_type" = "STORED" ] && impact="critical"

            local host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)
            emit_finding "$impact" "$host" "XSS ($vuln_type): $url" "candidate" \
              "Payload: $poc" \
              "curl -sk \"$url\" --data \"$poc\"" \
              "dalfox:xss:$vuln_type" "7.1" "xss,cwe-79,owasp-a03"
            count=$((count + 1))
          fi
        done < "$output_file.$count"
      fi
    elif [ $rc -ne 124 ]; then
      adapter_warn "dalfox exited with code $rc for $url"
    fi

    count=$((count + 1))
    [ $count -ge 50 ] && break  # Limit URLs per scan
  done <<< "$urls_to_scan"

  adapter_log "dalfox completed scan"

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan