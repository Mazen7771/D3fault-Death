#!/usr/bin/env bash
# HuntOps — Outputs Generator Adapter
# Generates deliverables: findings sheet and recon dossier with attack angles
# This is a reporting adapter - doesn't produce findings, consumes them

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# Source the original outputs.sh for its functions
OUTPUTS_LIB="$(dirname "${BASH_SOURCE[0]}")/outputs.sh"
[ -f "$OUTPUTS_LIB" ] && source "$OUTPUTS_LIB"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/outputs"
  return 0
}

adapter_name() {
  echo "outputs_gen"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "outputs dossier attack_angles"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  return 0
}

adapter_health_check() {
  echo "Outputs generator ready"
  return 0
}

adapter_scan() {
  local target="$1" workdir="$2" opts_json="$3"
  local findings_file="$workdir/findings/findings.txt"
  local candidates_file="$workdir/findings/candidates.txt"
  local info_file="$workdir/findings/info.txt"

  adapter_log "Generating deliverables for $target"

  # Generate findings sheet
  if declare -f _out_findings >/dev/null; then
    # Need to set W, DOMAIN, MODE, etc. for the original functions
    export W="$workdir"
    export DOMAIN="$target"
    export MODE="${MODE:-quick}"
    export FINDINGS="$findings_file"
    export CANDIDATES="$candidates_file"
    export INFOFILE="$info_file"
    _out_findings
    adapter_log "Findings sheet generated: $workdir/${target}.txt"
  fi

  # Generate recon dossier with attack angles
  if declare -f _out_info >/dev/null; then
    export W="$workdir"
    export DOMAIN="$target"
    export MODE="${MODE:-quick}"
    export FINDINGS="$findings_file"
    export CANDIDATES="$candidates_file"
    export INFOFILE="$info_file"
    _out_info
    adapter_log "Recon dossier generated: $workdir/info-${target}.txt"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan