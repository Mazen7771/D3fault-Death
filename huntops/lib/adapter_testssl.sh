#!/usr/bin/env bash
# HuntOps — testssl.sh Adapter
# Wraps testssl.sh for TLS/SSL vulnerability scanning
# Note: This box has testssl.sh at /home/mazin/tools/testssl_tool/testssl.sh (3.3dev)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

TESTSSL_BIN="${TESTSSL_BIN:-/home/mazin/tools/testssl_tool/testssl.sh}"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/testssl"
  return 0
}

adapter_name() {
  echo "testssl"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "tls ssl certs vuln"
}

adapter_requires_api_key() {
  return 1  # No API key required
}

adapter_is_available() {
  if [ ! -x "$TESTSSL_BIN" ]; then
    adapter_warn "testssl.sh not found or not executable at $TESTSSL_BIN"
    return 1
  fi
  return 0
}

adapter_health_check() {
  "$TESTSSL_BIN" --version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration port_start port_end json_output

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")
  port_start=$(parse_opt "$opts_json" "port_start" "1")
  port_end=$(parse_opt "$opts_json" "port_end" "65535")
  json_output="$outdir/testssl.json"

  # Build testssl command
  # This build (3.3dev) emits 'vulnerabilities' in JSON, not 'findings'
  local cmd="\"$TESTSSL_BIN\" --jsonfile \"$json_output\" --quiet"

  # Common options
  cmd+=" --fast --parallel --warnings batch"

  # Port range (testssl can scan multiple ports)
  # Note: testssl expects host:port format
  # We'll scan the target on common ports if not specified
  local ports
  ports=$(parse_opt "$opts_json" "ports" "443,8443,8080,9443")
  for port in ${ports//,/ }; do
    cmd+=" \"${target}:${port}\""
  done

  adapter_log "Running testssl.sh on $target (ports: $ports)"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "testssl.sh exited with code $rc"
  fi

  # Process results - testssl outputs JSON
  if [ -f "$json_output" ]; then
    local count=0
    if command -v jq >/dev/null 2>&1; then
      # Parse testssl JSON output
      # Structure: array of scan results per target
      local findings_json
      findings_json=$(jq -c '.[] | select(.vulnerabilities != null) | .vulnerabilities[]' "$json_output" 2>/dev/null)

      if [ -n "$findings_json" ]; then
        while IFS= read -r vuln; do
          [ -z "$vuln" ] && continue

          local id title severity cve cvss description finding
          id=$(echo "$vuln" | jq -r '.id // ""')
          title=$(echo "$vuln" | jq -r '.finding // .title // ""')
          severity=$(echo "$vuln" | jq -r '.severity // "LOW"')
          cve=$(echo "$vuln" | jq -r '.cve // ""')
          cvss=$(echo "$vuln" | jq -r '.cvss // ""')
          description=$(echo "$vuln" | jq -r '.description // ""')

          # Extract host from the scan result
          local host
          host=$(echo "$vuln" | jq -r '.ip // .host // ""')
          [ -z "$host" ] && host="$target"

          # Map testssl severity to our impact_class
          local impact_class
          case "${severity^^}" in
            CRITICAL) impact_class="critical" ;;
            HIGH)     impact_class="high" ;;
            MEDIUM)   impact_class="medium" ;;
            LOW)      impact_class="low" ;;
            *)        impact_class="info" ;;
          esac

          # Confidence: testssl findings are confirmed
          local confidence="confirmed"

          # Build reference
          local ref="testssl:$id"
          [ -n "$cve" ] && ref="$ref:$cve"

          emit_finding "$impact_class" "$host" "TLS: $title" \
            "$confidence" "$description" \
            "testssl.sh --jsonfile - $host" \
            "$ref" \
            "$cvss" \
            "tls,testssl${cve:+,cve}"
          count=$((count + 1))
        done <<< "$findings_json"
      fi

      # Also check for certificate info (expired, self-signed, etc.)
      local cert_issues
      cert_issues=$(jq -c '.[] | select(.certificates != null) | .certificates[] | select(.issuer == .subject or .notAfter < now)' "$json_output" 2>/dev/null)
      if [ -n "$cert_issues" ]; then
        while IFS= read -r cert; do
          [ -z "$cert" ] && continue
          local host cert_subject cert_issuer cert_notafter
          host=$(echo "$cert" | jq -r '.ip // .host // ""')
          [ -z "$host" ] && host="$target"
          cert_subject=$(echo "$cert" | jq -r '.subject // ""')
          cert_issuer=$(echo "$cert" | jq -r '.issuer // ""')
          cert_notafter=$(echo "$cert" | jq -r '.notAfter // ""')

          local impact_class="medium"
          local title="Certificate Issue"
          local evidence=""

          if [ "$cert_subject" = "$cert_issuer" ]; then
            title="Self-Signed Certificate"
            evidence="Certificate is self-signed (subject == issuer)"
          elif [ -n "$cert_notafter" ]; then
            # Check if expired (simplified)
            title="Certificate Expired or Expiring Soon"
            evidence="Certificate notAfter: $cert_notafter"
          fi

          emit_finding "$impact_class" "$host" "TLS: $title" \
            "confirmed" "$evidence" \
            "openssl s_client -connect $host:443 -servername $host </dev/null" \
            "testssl:cert" \
            "" \
            "tls,cert"
          count=$((count + 1))
        done <<< "$cert_issues"
      fi
    fi
    adapter_log "testssl.sh found $count TLS issues"
  fi

  return 0
}

# Export for subshell use
export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan