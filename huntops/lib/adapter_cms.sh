#!/usr/bin/env bash
# HuntOps — CMS Scanner Adapter
# WordPress, Drupal, Joomla vulnerability detection
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/cms"
  return 0
}

adapter_name() {
  echo "cms_scanner"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "vuln cms wordpress drupal joomla detection"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "wpscan" && ! adapter_tool_exists "droopescan" && ! adapter_tool_exists "cmsmap"; then
    adapter_warn "No CMS scanners found (wpscan, droopescan, cmsmap)"
    return 1
  fi
  return 0
}

adapter_health_check() {
  if adapter_tool_exists "wpscan"; then
    wpscan --version 2>&1 | head -1
  elif adapter_tool_exists "droopescan"; then
    droopescan version 2>&1 | head -1
  elif adapter_tool_exists "cmsmap"; then
    cmsmap --version 2>&1 | head -1
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
    adapter_warn "No live URLs found for CMS scanning"
    return 0
  fi

  local count=0

  # Scan each live URL for CMS
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)

    # WordPress via wpscan
    if adapter_tool_exists "wpscan"; then
      local wp_output="$outdir/wpscan_${host//./_}.txt"
      local cmd="wpscan --url \"$url\" --format json --output \"$wp_output\" --batch --disable-tls-checks --max-threads 5"

      local api_token
      api_token=$(parse_opt "$opts_json" "wpscan_api_token" "")
      [ -n "$api_token" ] && cmd+=" --api-token $api_token"

      adapter_log "Running wpscan on $url"
      adapter_run_cmd "$max_duration" bash -c "$cmd"
      local rc=$?

      if [ $rc -eq 0 ] || [ $rc -eq 1 ] || [ $rc -eq 2 ] || [ $rc -eq 3 ] || [ $rc -eq 4 ] || [ $rc -eq 5 ]; then
        # wpscan returns various codes: 0=ok, 1=vulns found, 2=error, etc.
        if [ -f "$wp_output" ]; then
          # Parse JSON output for vulnerabilities
          local vulns
          vulns=$(jq -r '.vulnerabilities[]? | "\(.title)|\(.fixed_in)|\(.references[]?)"' "$wp_output" 2>/dev/null)
          if [ -n "$vulns" ]; then
            while IFS= read -r vuln; do
              [ -z "$vuln" ] && continue
              local title=$(echo "$vuln" | cut -d'|' -f1)
              local fixed=$(echo "$vuln" | cut -d'|' -f2)
              local ref=$(echo "$vuln" | cut -d'|' -f3)

              emit_finding "high" "$host" "WordPress vuln: $title" "confirmed" \
                "Fixed in: $fixed" \
                "wpscan --url \"$url\"" \
                "wpscan:$title" "7.5" "cms,wordpress,cwe-200"
              count=$((count + 1))
            done <<< "$vulns"
          fi

          # Check for version disclosure
          local version
          version=$(jq -r '.version.number // empty' "$wp_output" 2>/dev/null)
          [ -n "$version" ] && emit_finding "info" "$host" "WordPress version: $version" "confirmed" \
            "Detected via wpscan" "wpscan --url \"$url\"" "wpscan:version" "" "cms,wordpress,version"
        fi
      fi
    fi

    # Drupal/Joomla/Other via droopescan
    if adapter_tool_exists "droopescan"; then
      local droop_output="$outdir/droopescan_${host//./_}.txt"
      local cmd="droopescan scan -u \"$url\" --number-threads 5 -o \"$droop_output\""

      adapter_log "Running droopescan on $url"
      adapter_run_cmd "$max_duration" bash -c "$cmd"
      local rc=$?

      if [ $rc -eq 0 ] && [ -f "$droop_output" ]; then
        while IFS= read -r line; do
          if echo "$line" | grep -q "Interesting\|Vulnerable\|Version"; then
            local cms_type=$(echo "$line" | awk '{print $2}')
            emit_finding "medium" "$host" "Droopescan finding: $line" "candidate" \
              "$line" "droopescan scan -u \"$url\"" "droopescan:$cms_type" "5.0" "cms,$cms_type"
            count=$((count + 1))
          fi
        done < "$droop_output"
      fi
    fi

    # CMSmap for additional coverage
    if adapter_tool_exists "cmsmap"; then
      local cmsmap_output="$outdir/cmsmap_${host//./_}.txt"
      local cmd="cmsmap -u \"$url\" -o \"$cmsmap_output\" --batch --threads 5"

      adapter_log "Running cmsmap on $url"
      adapter_run_cmd "$max_duration" bash -c "$cmd"

      if [ -f "$cmsmap_output" ]; then
        while IFS= read -r line; do
          if echo "$line" | grep -q "\[VULN\]\|\[INFO\]"; then
            emit_finding "medium" "$host" "CMSmap: $line" "candidate" \
              "$line" "cmsmap -u \"$url\"" "cmsmap" "5.0" "cms"
            count=$((count + 1))
          fi
        done < "$cmsmap_output"
      fi
    fi

  done < <(head -50 "$live_urls_file")  # Limit to 50 URLs

  adapter_log "CMS scanner found $count findings"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan