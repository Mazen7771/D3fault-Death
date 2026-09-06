#!/usr/bin/env bash
# HuntOps — CVE Engine Adapter
# Wraps lib/cve.sh for CVE correlation from service versions
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# Source the original cve.sh for its functions
CVE_LIB="$(dirname "${BASH_SOURCE[0]}")/cve.sh"
[ -f "$CVE_LIB" ] && source "$CVE_LIB"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/cve"
  return 0
}

adapter_name() {
  echo "cve_engine"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "cve correlation version"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  # Check if CVE database exists or can be built
  return 0
}

adapter_health_check() {
  echo "CVE engine ready"
  return 0
}

# Helper: parse a CVE finding line from lib/cve.sh output (written to $CANDIDATES)
# Format: CAND|IMPACT_CLASS|HOST|TITLE|CONFIDENCE|EVIDENCE|REPRO_CURL|REF|CVSS31|TAG
# We read the candidates file and emit via emit_finding.
_emit_cve_from_candidates() {
  local candidates_file="$1"
  local count=0
  [ -f "$candidates_file" ] || return 0
  while IFS='|' read -r kind impact_class host title confidence evidence repro_curl ref cvss31 tag; do
    [ "$kind" = "CAND" ] || continue
    # Only emit CVE-related ones (tag contains "cve")
    case "$tag" in *cve*) ;;
    *) continue ;;
    esac
    emit_finding "$impact_class" "$host" "$title" \
      "$confidence" "$evidence" \
      "$repro_curl" \
      "$ref" "$cvss31" "$tag"
    count=$((count + 1))
  done < "$candidates_file"
  echo "$count"
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration port_scan_file tech_file

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")
  port_scan_file=$(parse_opt "$opts_json" "port_scan_file" "$outdir/../port_scan/nmap.xml")
  tech_file=$(parse_opt "$opts_json" "tech_file" "$outdir/../web_probe/whatweb.txt")

  # lib/cve.sh expects these globals:
  export DOMAIN="$target"
  export W="$outdir"
  export CV="$outdir/cve"
  mkdir -p "$CV"

  # lib/cve.sh's correlation functions call add_candidate(), which writes to
  # $CANDIDATES and dedups via $KEYS. Neither is set in the adapter context
  # (set -u would crash). Point them at a temp sink inside $CV; the real
  # findings are re-emitted as JSON via _emit_cve_from_candidates below.
  export CANDIDATES="$CV/candidates.tmp"
  export KEYS="$CV/.keys.tmp"
  : > "$CANDIDATES"; : > "$KEYS"

  local count=0

  # Seed the CVE database (creates $CV/cve-db.txt)
  if declare -f _seed_cve_db >/dev/null; then
    _seed_cve_db 2>/dev/null
  fi

  # Correlate from nmap output (uses _cve_from_nmap which calls _cve_match)
  if declare -f _cve_from_nmap >/dev/null && [ -f "$port_scan_file" ]; then
    adapter_log "Correlating CVEs from nmap service versions"
    _cve_from_nmap "$port_scan_file" 2>/dev/null
    count=$((count + $(_emit_cve_from_candidates "$CANDIDATES")))
  fi

  # Correlate from whatweb/tech stack (uses _cve_from_whatweb)
  if declare -f _cve_from_whatweb >/dev/null && [ -f "$tech_file" ]; then
    adapter_log "Correlating CVEs from tech stack"
    _cve_from_whatweb "$tech_file" 2>/dev/null
    count=$((count + $(_emit_cve_from_candidates "$CANDIDATES")))
  fi

  # InternetDB vulnerabilities (Shodan free API)
  if declare -f _cve_internetdb >/dev/null; then
    adapter_log "Correlating CVEs from InternetDB"
    _cve_internetdb "$target" 2>/dev/null
    count=$((count + $(_emit_cve_from_candidates "$CANDIDATES")))
  fi

  # searchsploit lookups (Exploit-DB)
  if declare -f _cve_searchsploit >/dev/null; then
    adapter_log "Querying Exploit-DB via searchsploit"
    _cve_searchsploit "$target" 2>/dev/null
    count=$((count + $(_emit_cve_from_candidates "$CANDIDATES")))
  fi

  adapter_log "CVE engine found $count CVE correlations"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan