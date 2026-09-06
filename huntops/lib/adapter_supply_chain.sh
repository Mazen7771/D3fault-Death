#!/usr/bin/env bash
# HuntOps — Supply Chain Adapter
# SBOM generation and vulnerability scanning (grype, syft)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/supply_chain"
  return 0
}

adapter_name() {
  echo "supply_chain"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "vuln sbom dependency grype syft"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "grype" && ! adapter_tool_exists "syft"; then
    adapter_warn "No supply chain tools found (grype, syft)"
    return 1
  fi
  return 0
}

adapter_health_check() {
  if adapter_tool_exists "grype"; then
    grype version 2>&1 | head -1
  fi
  if adapter_tool_exists "syft"; then
    syft version 2>&1 | head -1
  fi
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")

  # Get live URLs from web probe phase
  local live_urls_file="$outdir/../web/live-urls.txt"
  if [ ! -f "$live_urls_file" ] || [ ! -s "$live_urls_file" ]; then
    adapter_warn "No live URLs found for supply chain scanning"
    return 0
  fi

  local count=0

  # Scan each live URL for exposed package files
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)

    # Check for common package manager files
    local package_files=(
      "package.json"
      "package-lock.json"
      "yarn.lock"
      "pnpm-lock.yaml"
      "requirements.txt"
      "requirements.lock"
      "Pipfile"
      "Pipfile.lock"
      "pyproject.toml"
      "pom.xml"
      "build.gradle"
      "gradle.lockfile"
      "go.mod"
      "go.sum"
      "Cargo.toml"
      "Cargo.lock"
      "composer.json"
      "composer.lock"
      "Gemfile"
      "Gemfile.lock"
    )

    for pkg_file in "${package_files[@]}"; do
      local pkg_url="${url%/}/$pkg_file"
      local response=$(timeout -k 10 30 curl -skI "$pkg_url" 2>/dev/null | head -1)

      if echo "$response" | grep -q "200 OK"; then
        # Found package file - download and scan
        local pkg_output="$outdir/${host//./_}_${pkg_file//./_}.json"
        local tmp_file="/tmp/pkg_${host//./_}_${pkg_file//./_}.tmp"

        adapter_log "Found package file: $pkg_url"
        timeout -k 10 30 curl -sk "$pkg_url" -o "$tmp_file" 2>/dev/null

        if [ -s "$tmp_file" ]; then
          # Generate SBOM with syft
          if adapter_tool_exists "syft"; then
            syft "file:$tmp_file" -o json > "$pkg_output.sbom" 2>/dev/null
            if [ -f "$pkg_output.sbom" ] && [ -s "$pkg_output.sbom" ]; then
              emit_finding "info" "$host" "SBOM generated: $pkg_file" "confirmed" \
                "Software Bill of Materials for $pkg_file" \
                "syft file:$tmp_file -o json" \
                "syft:sbom" "" "sbom,supply-chain"
              count=$((count + 1))
            fi
          fi

          # Scan for vulnerabilities with grype
          if adapter_tool_exists "grype"; then
            grype "file:$tmp_file" -o json > "$pkg_output.vulns" 2>/dev/null
            if [ -f "$pkg_output.vulns" ] && [ -s "$pkg_output.vulns" ]; then
              local vulns
              vulns=$(jq -r '.matches[]? | "\(.vulnerability.id)|\(.vulnerability.severity)|\(.artifact.name):\(.artifact.version)"' "$pkg_output.vulns" 2>/dev/null)
              if [ -n "$vulns" ]; then
                while IFS= read -r vuln; do
                  [ -z "$vuln" ] && continue
                  local vid=$(echo "$vuln" | cut -d'|' -f1)
                  local severity=$(echo "$vuln" | cut -d'|' -f2)
                  local artifact=$(echo "$vuln" | cut -d'|' -f3)

                  local impact="medium"
                  case "${severity,,}" in
                    critical) impact="critical" ;;
                    high) impact="high" ;;
                    medium) impact="medium" ;;
                    low) impact="low" ;;
                  esac

                  emit_finding "$impact" "$host" "Dependency vuln: $vid in $artifact" "confirmed" \
                    "Package file: $pkg_file" \
                    "grype file:$tmp_file" \
                    "grype:$vid" "" "supply-chain,dependency,$vid"
                  count=$((count + 1))
                done <<< "$vulns"
              fi
            fi
          fi
        fi
        rm -f "$tmp_file"
      fi
    done

  done < <(head -20 "$live_urls_file")  # Limit to 20 URLs

  adapter_log "Supply chain scanner found $count findings"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan