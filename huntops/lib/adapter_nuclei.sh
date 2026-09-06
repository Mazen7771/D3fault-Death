#!/usr/bin/env bash
# HuntOps — Nuclei Adapter
# Wraps nuclei for template-based vulnerability scanning
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/nuclei"
  return 0
}

adapter_name() {
  echo "nuclei"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "vuln cve templates"
}

adapter_requires_api_key() {
  return 1  # No API key required (but can use for PDCP)
}

adapter_is_available() {
  if ! adapter_tool_exists "nuclei"; then
    adapter_warn "nuclei not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  nuclei -version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration rate_limit concurrency severity tags templates input_file

  max_duration=$(parse_opt "$opts_json" "max_duration" "3600")
  rate_limit=$(parse_opt "$opts_json" "rate_limit" "15")
  concurrency=$(parse_opt "$opts_json" "concurrency" "10")
  severity=$(parse_opt "$opts_json" "severity" "critical,high,medium")
  tags=$(parse_opt "$opts_json" "tags" "")
  templates=$(parse_opt "$opts_json" "templates" "")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../web_probe/httpx.txt")

  local output_file="$outdir/nuclei.jsonl"
  local cmd="nuclei -silent -jsonl -o \"$output_file\" -rl $rate_limit -c $concurrency"

  # Add severity filter
  [ -n "$severity" ] && cmd+=" -severity \"$severity\""

  # Add tags filter
  [ -n "$tags" ] && cmd+=" -tags \"$tags\""

  # Add templates
  [ -n "$templates" ] && cmd+=" -t \"$templates\""

  # Add exclude tags for DoS/heavy templates if no-dos mode
  local no_dos
  no_dos=$(parse_opt "$opts_json" "no_dos" "false")
  if [ "$no_dos" = "true" ]; then
    cmd+=" -exclude-tags dos,fuzz,intrusive"
  fi

  # Input: live hosts from httpx
  if [ -f "$input_file" ]; then
    cmd+=" -l \"$input_file\""
  else
    cmd+=" -u \"$target\""
  fi

  adapter_log "Running nuclei on targets from $input_file"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "nuclei exited with code $rc"
  fi

  # Process results - nuclei already outputs JSONL
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue

      # Parse nuclei JSON and convert to our format
      local host template_name severity_parsed description matcher_name curl_command
      if command -v jq >/dev/null 2>&1; then
        host=$(echo "$line" | jq -r '.host // .url // ""')
        template_name=$(echo "$line" | jq -r '.template // .template_id // ""')
        severity_parsed=$(echo "$line" | jq -r '.info.severity // "info"')
        description=$(echo "$line" | jq -r '.info.name // .info.description // ""')
        matcher_name=$(echo "$line" | jq -r '.matcher_name // ""')
        curl_command=$(echo "$line" | jq -r '.curl_command // "-"')

        # Normalize host (extract hostname from URL)
        host=$(echo "$host" | sed -E 's|^https?://||' | sed -E 's|/.*$||' | sed -E 's|:.*$||')

        # Map nuclei severity to our impact_class
        local impact_class
        case "$severity_parsed" in
          critical) impact_class="critical" ;;
          high)     impact_class="high" ;;
          medium)   impact_class="medium" ;;
          low)      impact_class="low" ;;
          *)        impact_class="info" ;;
        esac

        # Map confidence: nuclei findings are confirmed
        local confidence="confirmed"

        # CVSS if available
        local cvss31
        cvss31=$(echo "$line" | jq -r '.info.classification.cvss-score // ""')

        # Tags
        local tags_out
        tags_out=$(echo "$line" | jq -r '.info.tags // [] | join(",")')

        emit_finding "$impact_class" "$host" "Nuclei: $template_name - $description" \
          "$confidence" "Matched: $matcher_name" \
          "$curl_command" \
          "nuclei:$template_name" \
          "$cvss31" \
          "nuclei,$tags_out"
        count=$((count + 1))
      fi
    done < "$output_file"
    adapter_log "nuclei found $count vulnerabilities"
  fi

  return 0
}

# Export for subshell use
export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan