#!/usr/bin/env bash
# HuntOps — Report Generator Adapter
# Generates final HTML/Markdown/SARIF reports from findings
# This is a reporting adapter - doesn't produce findings, consumes them

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# Source the original report.sh for its functions
REPORT_LIB="$(dirname "${BASH_SOURCE[0]}")/report.sh"
[ -f "$REPORT_LIB" ] && source "$REPORT_LIB"

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/report"
  return 0
}

adapter_name() {
  echo "report_gen"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "report html markdown sarif"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  return 0
}

adapter_health_check() {
  echo "Report generator ready"
  return 0
}

adapter_scan() {
  local target="$1" workdir="$2" opts_json="$3"
  local findings_file="$workdir/findings/findings.txt"
  local candidates_file="$workdir/findings/candidates.txt"
  local info_file="$workdir/findings/info.txt"
  local report_dir="$workdir/report"

  mkdir -p "$report_dir"

  adapter_log "Generating reports for $target"

  # Need to set W, DOMAIN, MODE, etc. for the original report functions
  export W="$workdir"
  export DOMAIN="$target"
  export MODE="${MODE:-quick}"
  export TARGET="$target"
  export FINDINGS="$findings_file"
  export CANDIDATES="$candidates_file"
  export INFOFILE="$info_file"

  # Generate report using original run_report function
  if declare -f run_report >/dev/null; then
    run_report
    adapter_log "Reports generated in: $report_dir"
  fi

  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan