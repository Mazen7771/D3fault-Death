#!/usr/bin/env bash
# HuntOps — JS Analyzer Adapter
# JavaScript endpoint/secret extraction (jsluice, mantra)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/js_analyzer"
  return 0
}

adapter_name() {
  echo "js_analyzer"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon js endpoints secrets jsluice mantra"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "jsluice" && ! adapter_tool_exists "mantra"; then
    adapter_warn "No JS analyzers found (jsluice, mantra)"
    return 1
  fi
  return 0
}

adapter_health_check() {
  if adapter_tool_exists "jsluice"; then
    jsluice --version 2>&1 | head -1
  fi
  if adapter_tool_exists "mantra"; then
    mantra --version 2>&1 | head -1
  fi
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")

  # Get JS files from recon phase
  local js_files_file="$outdir/../js/endpoints.txt"
  local js_dir="$outdir/../js/files"

  if [ ! -d "$js_dir" ] || [ -z "$(ls -A "$js_dir" 2>/dev/null)" ]; then
    adapter_warn "No JS files found for analysis"
    return 0
  fi

  local output_file="$outdir/js_analyzer.txt"
  local count=0

  # Run jsluice on JS files
  if adapter_tool_exists "jsluice"; then
    adapter_log "Running jsluice on JS files in $js_dir"
    for js_file in "$js_dir"/*.js; do
      [ -f "$js_file" ] || continue
      local host=$(basename "$js_file" | cut -d'_' -f1)

      # Extract URLs/endpoints
      jsluice urls "$js_file" 2>/dev/null | while IFS= read -r url; do
        [ -z "$url" ] && continue
        emit_finding "info" "$host" "JS endpoint: $url" "confirmed" \
          "Extracted from JavaScript via jsluice" \
          "curl -sk \"$url\"" \
          "jsluice:endpoint" "" "js,endpoint"
        count=$((count + 1))
      done

      # Extract secrets
      jsluice secrets "$js_file" 2>/dev/null | while IFS= read -r secret; do
        [ -z "$secret" ] && continue
        emit_finding "high" "$host" "Secret in JS: $(echo "$secret" | cut -d' ' -f1)" "candidate" \
          "Found in JavaScript file: $secret" \
          "# Review JS file: $js_file" \
          "jsluice:secret" "7.5" "js,secret,credentials"
        count=$((count + 1))
      done

      # Extract comments
      jsluice comments "$js_file" 2>/dev/null | while IFS= read -r comment; do
        [ -z "$comment" ] && continue
        if echo "$comment" | grep -qi "todo\|fixme\|hack\|password\|secret\|key\|token\|api"; then
          emit_finding "low" "$host" "Interesting JS comment" "candidate" \
            "$comment" \
            "# Review JS file: $js_file" \
            "jsluice:comment" "" "js,comment"
          count=$((count + 1))
        fi
      done
    done
  fi

  # Run mantra for additional analysis
  if adapter_tool_exists "mantra"; then
    adapter_log "Running mantra on JS files"
    for js_file in "$js_dir"/*.js; do
      [ -f "$js_file" ] || continue
      local host=$(basename "$js_file" | cut -d'_' -f1)

      mantra -i "$js_file" -o "$output_file.mantra" 2>/dev/null
      if [ -f "$output_file.mantra" ] && [ -s "$output_file.mantra" ]; then
        while IFS= read -r line; do
          [ -z "$line" ] && continue
          emit_finding "info" "$host" "Mantra finding: $line" "confirmed" \
            "Mantra analysis of $js_file" \
            "mantra -i \"$js_file\"" \
            "mantra:finding" "" "js,mantra"
          count=$((count + 1))
        done < "$output_file.mantra"
      fi
    done
  fi

  adapter_log "JS analyzer found $count findings"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan