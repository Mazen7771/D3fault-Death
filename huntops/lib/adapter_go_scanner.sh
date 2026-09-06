#!/usr/bin/env bash
# HuntOps — Generic Go Scanner Adapter
# Wraps the d3fault-death Go binary for cloud scanners (Escape, Invicti, Zeropath, Acunetix, Burp, ZAP)
# The Go binary must be built with --adapter flag support
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

# This adapter is a generic wrapper - actual scanner name is passed via ADAPTER_NAME env
ADAPTER_NAME="${ADAPTER_NAME:-}"
GO_BINARY="${GO_BINARY:-d3fault-death}"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/go_scanner"
  return 0
}

adapter_name() {
  [ -n "$ADAPTER_NAME" ] && echo "$ADAPTER_NAME" || echo "go_scanner"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  # Capabilities vary by scanner; defaults
  case "${ADAPTER_NAME,,}" in
    zap)        echo "vuln tls content spider ajax" ;;
    escape)     echo "vuln recon graphql api" ;;
    invicti)    echo "vuln web api daast" ;;
    zeropath)   echo "vuln code sast secrets" ;;
    acunetix)   echo "vuln web network" ;;
    burp)       echo "vuln web manual" ;;
    nuclei)     echo "vuln cve templates" ;;
    *)          echo "vuln" ;;
  esac
}

adapter_requires_api_key() {
  # Cloud scanners require API keys
  case "${ADAPTER_NAME,,}" in
    escape|invicti|zeropath|acunetix|burp) return 0 ;;
    *) return 1 ;;
  esac
}

adapter_is_available() {
  if ! adapter_tool_exists "$GO_BINARY"; then
    adapter_warn "Go binary '$GO_BINARY' not found in PATH. Build with: make -C d3fault-death build"
    return 1
  fi

  # Check if binary supports adapter mode
  if ! "$GO_BINARY" --help 2>&1 | grep -q "\-\-adapter"; then
    adapter_warn "Go binary '$GO_BINARY' doesn't support --adapter flag. Rebuild required."
    return 1
  fi

  # Check API key if required
  if adapter_requires_api_key; then
    local api_key_env
    case "${ADAPTER_NAME,,}" in
      escape)    api_key_env="ESCAPE_API_KEY" ;;
      invicti)   api_key_env="INVICTI_API_KEY" ;;
      zeropath)  api_key_env="ZEROPATH_API_KEY" ;;
      acunetix)  api_key_env="ACUNETIX_API_KEY" ;;
      burp)      api_key_env="BURP_API_KEY" ;;
      *)         api_key_env="" ;;
    esac
    if [ -n "$api_key_env" ] && [ -z "${!api_key_env:-}" ]; then
      adapter_warn "Adapter $ADAPTER_NAME: missing API key ($api_key_env)"
      return 1
    fi
  fi

  return 0
}

adapter_health_check() {
  "$GO_BINARY" --adapter "$ADAPTER_NAME" --health-check 2>&1 | head -5
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration profile scope exclude

  max_duration=$(parse_opt "$opts_json" "max_duration" "3600")
  profile=$(parse_opt "$opts_json" "profile" "full")
  scope=$(parse_opt "$opts_json" "scope" "")
  exclude=$(parse_opt "$opts_json" "exclude_scope" "")

  local output_file="$outdir/${ADAPTER_NAME}.jsonl"
  local cmd="\"$GO_BINARY\" --adapter \"$ADAPTER_NAME\" --target \"$target\" --outdir \"$outdir\" --profile \"$profile\" --max-duration \"$max_duration\""

  [ -n "$scope" ] && cmd+=" --scope \"$scope\""
  [ -n "$exclude" ] && cmd+=" --exclude \"$exclude\""

  # Add no-dos flag if set
  local no_dos
  no_dos=$(parse_opt "$opts_json" "no_dos" "false")
  [ "$no_dos" = "true" ] && cmd+=" --no-dos"

  # Add test account if provided
  local test_account
  test_account=$(parse_opt "$opts_json" "test_account" "")
  [ -n "$test_account" ] && cmd+=" --test-account \"$test_account\""

  # Output format: JSON Lines
  cmd+=" --format jsonl --output \"$output_file\""

  adapter_log "Running Go scanner: $ADAPTER_NAME on $target"
  adapter_run_cmd "$max_duration" bash -c "$cmd"
  local rc=$?

  if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
    adapter_warn "Go scanner $ADAPTER_NAME exited with code $rc"
    # Show stderr for debugging
    [ -f "$output_file" ] && head -20 "$output_file" >&2
  fi

  # Process results - Go binary outputs JSONL directly to output file
  if [ -f "$output_file" ]; then
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      # Pass through - the orchestrator's sink will parse and deduplicate
      # But we need to ensure it's valid JSONL
      echo "$line" | jq empty 2>/dev/null && {
        echo "$line"
        count=$((count + 1))
      }
    done < "$output_file"
    adapter_log "$ADAPTER_NAME found $count findings"
  fi

  return 0
}

# ---- Factory Functions for Specific Scanners --------------------------------
# These create specialized adapters by setting ADAPTER_NAME

# ZAP Adapter
zap_adapter_init() { ADAPTER_NAME="zap" GO_BINARY="${ZAP_BINARY:-d3fault-death}" adapter_init; }
zap_adapter_name() { echo "zap"; }
zap_adapter_version() { echo "1.0.0"; }
zap_adapter_capabilities() { echo "vuln tls content spider ajax"; }
zap_adapter_requires_api_key() { return 1; }
zap_adapter_is_available() { ADAPTER_NAME="zap" adapter_is_available; }
zap_adapter_health_check() { ADAPTER_NAME="zap" adapter_health_check; }
zap_adapter_scan() { ADAPTER_NAME="zap" adapter_scan "$@"; }

# Escape Adapter
escape_adapter_init() { ADAPTER_NAME="escape" GO_BINARY="${ESCAPE_BINARY:-d3fault-death}" adapter_init; }
escape_adapter_name() { echo "escape"; }
escape_adapter_version() { echo "1.0.0"; }
escape_adapter_capabilities() { echo "vuln recon graphql api"; }
escape_adapter_requires_api_key() { return 0; }
escape_adapter_is_available() { ADAPTER_NAME="escape" adapter_is_available; }
escape_adapter_health_check() { ADAPTER_NAME="escape" adapter_health_check; }
escape_adapter_scan() { ADAPTER_NAME="escape" adapter_scan "$@"; }

# Invicti Adapter
invicti_adapter_init() { ADAPTER_NAME="invicti" GO_BINARY="${INVICTI_BINARY:-d3fault-death}" adapter_init; }
invicti_adapter_name() { echo "invicti"; }
invicti_adapter_version() { echo "1.0.0"; }
invicti_adapter_capabilities() { echo "vuln web api daast"; }
invicti_adapter_requires_api_key() { return 0; }
invicti_adapter_is_available() { ADAPTER_NAME="invicti" adapter_is_available; }
invicti_adapter_health_check() { ADAPTER_NAME="invicti" adapter_health_check; }
invicti_adapter_scan() { ADAPTER_NAME="invicti" adapter_scan "$@"; }

# Zeropath Adapter
zeropath_adapter_init() { ADAPTER_NAME="zeropath" GO_BINARY="${ZEROPATH_BINARY:-d3fault-death}" adapter_init; }
zeropath_adapter_name() { echo "zeropath"; }
zeropath_adapter_version() { echo "1.0.0"; }
zeropath_adapter_capabilities() { echo "vuln code sast secrets"; }
zeropath_adapter_requires_api_key() { return 0; }
zeropath_adapter_is_available() { ADAPTER_NAME="zeropath" adapter_is_available; }
zeropath_adapter_health_check() { ADAPTER_NAME="zeropath" adapter_health_check; }
zeropath_adapter_scan() { ADAPTER_NAME="zeropath" adapter_scan "$@"; }

# Acunetix Adapter
acunetix_adapter_init() { ADAPTER_NAME="acunetix" GO_BINARY="${ACUNETIX_BINARY:-d3fault-death}" adapter_init; }
acunetix_adapter_name() { echo "acunetix"; }
acunetix_adapter_version() { echo "1.0.0"; }
acunetix_adapter_capabilities() { echo "vuln web network"; }
acunetix_adapter_requires_api_key() { return 0; }
acunetix_adapter_is_available() { ADAPTER_NAME="acunetix" adapter_is_available; }
acunetix_adapter_health_check() { ADAPTER_NAME="acunetix" adapter_health_check; }
acunetix_adapter_scan() { ADAPTER_NAME="acunetix" adapter_scan "$@"; }

# Burp Adapter
burp_adapter_init() { ADAPTER_NAME="burp" GO_BINARY="${BURP_BINARY:-d3fault-death}" adapter_init; }
burp_adapter_name() { echo "burp"; }
burp_adapter_version() { echo "1.0.0"; }
burp_adapter_capabilities() { echo "vuln web manual"; }
burp_adapter_requires_api_key() { return 0; }
burp_adapter_is_available() { ADAPTER_NAME="burp" adapter_is_available; }
burp_adapter_health_check() { ADAPTER_NAME="burp" adapter_health_check; }
burp_adapter_scan() { ADAPTER_NAME="burp" adapter_scan "$@"; }

# Export all functions
export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan
export -f zap_adapter_init zap_adapter_name zap_adapter_version zap_adapter_capabilities
export -f zap_adapter_requires_api_key zap_adapter_is_available zap_adapter_health_check zap_adapter_scan
export -f escape_adapter_init escape_adapter_name escape_adapter_version escape_adapter_capabilities
export -f escape_adapter_requires_api_key escape_adapter_is_available escape_adapter_health_check escape_adapter_scan
export -f invicti_adapter_init invicti_adapter_name invicti_adapter_version invicti_adapter_capabilities
export -f invicti_adapter_requires_api_key invicti_adapter_is_available invicti_adapter_health_check invicti_adapter_scan
export -f zeropath_adapter_init zeropath_adapter_name zeropath_adapter_version zeropath_adapter_capabilities
export -f zeropath_adapter_requires_api_key zeropath_adapter_is_available zeropath_adapter_health_check zeropath_adapter_scan
export -f acunetix_adapter_init acunetix_adapter_name acunetix_adapter_version acunetix_adapter_capabilities
export -f acunetix_adapter_requires_api_key acunetix_adapter_is_available acunetix_adapter_health_check acunetix_adapter_scan
export -f burp_adapter_init burp_adapter_name burp_adapter_version burp_adapter_capabilities
export -f burp_adapter_requires_api_key burp_adapter_is_available burp_adapter_health_check burp_adapter_scan