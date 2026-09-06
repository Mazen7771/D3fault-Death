#!/usr/bin/env bash
# HuntOps — Candidates Engine Adapter
# Wraps lib/candidates.sh for high-confidence findings (IDOR, JWT, GraphQL, SSRF, race, auth, secrets, cloud, takeover, CORS)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# Source the original candidates.sh for its functions
CANDIDATES_LIB="$(dirname "${BASH_SOURCE[0]}")/candidates.sh"
[ -f "$CANDIDATES_LIB" ] && source "$CANDIDATES_LIB"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/candidates"
  return 0
}

adapter_name() {
  echo "candidates_engine"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "intel params idor jwt graphql ssrf race auth secrets cloud takeover cors"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  adapter_tool_exists "curl" || { adapter_warn "curl not found"; return 1; }
  return 0
}

adapter_health_check() {
  echo "Candidates engine ready"
  return 0
}

# Helper to parse a candidate line (pipe-delimited: title|evidence|repro|ref|cvss|tags)
# and emit via emit_finding. Usage: _emit_candidate <impact> <host> <finding_line> <tags>
_emit_candidate() {
  local impact="$1" host="$2" line="$3" extra_tags="$4"
  local title evidence repro_curl ref cvss tags
  title=$(echo "$line" | cut -d'|' -f1)
  evidence=$(echo "$line" | cut -d'|' -f2)
  repro_curl=$(echo "$line" | cut -d'|' -f3)
  ref=$(echo "$line" | cut -d'|' -f4)
  cvss=$(echo "$line" | cut -d'|' -f5)
  tags=$(echo "$line" | cut -d'|' -f6)
  [ -n "$extra_tags" ] && tags="${tags},${extra_tags}"
  emit_finding "$impact" "$host" "$title" \
    "candidate" "$evidence" \
    "$repro_curl" \
    "$ref" "$cvss" "$tags"
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration input_file test_account

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")
  input_file=$(parse_opt "$opts_json" "input_file" "$outdir/../web_probe/httpx.txt")
  test_account=$(parse_opt "$opts_json" "test_account" "")

  # lib/candidates.sh reads wordlists from these globals (set by config.sh).
  # Ensure they are exported so the sourced functions see them.
  export GRAPHQL_PATHS ADMIN_PATHS REDIRECT_PARAMS SSRG_PARAMS IDOR_PARAMS
  export IMPACT_CLASSES

  local count=0

  if [ -f "$input_file" ]; then
    while IFS= read -r url; do
      [ -z "$url" ] && continue

      local host
      host=$(echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*$||' | sed -E 's|:.*$||')
      [ -z "$host" ] && continue

      adapter_log "Running candidate checks on $url"

      # IDOR/BOLA checks — uses _cand_idor (not check_idor)
      if declare -f _cand_idor >/dev/null; then
        _cand_idor "$url" "$outdir" "$test_account" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "high" "$host" "$finding" "idor,bola"
          count=$((count + 1))
        done
      fi

      # JWT checks — uses _cand_jwt
      if declare -f _cand_jwt >/dev/null; then
        _cand_jwt "$url" "$outdir" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "high" "$host" "$finding" "jwt"
          count=$((count + 1))
        done
      fi

      # GraphQL checks — uses _cand_graphql
      if declare -f _cand_graphql >/dev/null; then
        _cand_graphql "$url" "$outdir" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "high" "$host" "$finding" "graphql"
          count=$((count + 1))
        done
      fi

      # SSRF checks — uses _cand_ssrf
      if declare -f _cand_ssrf >/dev/null; then
        _cand_ssrf "$url" "$outdir" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "high" "$host" "$finding" "ssrf"
          count=$((count + 1))
        done
      fi

      # Race condition checks — uses _cand_race
      if declare -f _cand_race >/dev/null; then
        _cand_race "$url" "$outdir" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "medium" "$host" "$finding" "race"
          count=$((count + 1))
        done
      fi

      # Auth/Authorization checks — uses _cand_admin_authz
      if declare -f _cand_admin_authz >/dev/null; then
        _cand_admin_authz "$url" "$outdir" "$test_account" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "high" "$host" "$finding" "authz"
          count=$((count + 1))
        done
      fi

      # Secrets exposure checks — uses _cand_secrets
      if declare -f _cand_secrets >/dev/null; then
        _cand_secrets "$url" "$outdir" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "critical" "$host" "$finding" "secrets"
          count=$((count + 1))
        done
      fi

      # Cloud bucket checks — uses _cand_cloud
      if declare -f _cand_cloud >/dev/null; then
        _cand_cloud "$url" "$outdir" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "high" "$host" "$finding" "cloud"
          count=$((count + 1))
        done
      fi

      # Subdomain takeover checks — uses _cand_takeover
      if declare -f _cand_takeover >/dev/null; then
        _cand_takeover "$url" "$outdir" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "high" "$host" "$finding" "takeover"
          count=$((count + 1))
        done
      fi

      # CORS checks — uses _cand_cors
      if declare -f _cand_cors >/dev/null; then
        _cand_cors "$url" "$outdir" 2>/dev/null | while IFS= read -r finding; do
          [ -z "$finding" ] && continue
          _emit_candidate "medium" "$host" "$finding" "cors"
          count=$((count + 1))
        done
      fi

    done < "$input_file"
    adapter_log "Candidates engine found $count high-confidence findings"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan