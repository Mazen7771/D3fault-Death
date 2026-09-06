#!/usr/bin/env bash
# HuntOps — Scanner Adapter Interface
# Contract that ALL scanner adapters (bash or Go) must implement.
# Source this file in each adapter: source "$HUNTOPS_ROOT/lib/adapter_interface.sh"
#
# Every adapter must define these functions:
#   adapter_init              # one-time setup (create dirs, validate deps)
#   adapter_name              # unique name (e.g., "nuclei", "zap", "subfinder")
#   adapter_version           # semantic version string
#   adapter_capabilities      # space-separated: recon|vuln|tls|content|params|intel|cve
#   adapter_requires_api_key  # return 0 if API key required, 1 if not
#   adapter_is_available      # return 0 if ready, 1 if missing (print reason to stderr)
#   adapter_scan              # main entry: adapter_scan <target> <outdir> <opts_json>
#   adapter_health_check      # quick liveness probe (for orchestrator)
#
# Adapter output format (stdout, JSON Lines):
#   {"impact_class":"high","host":"api.example.com","title":"SQL Injection",
#    "confidence":"confirmed","evidence":"' OR 1=1--","repro_curl":"curl -X POST ...",
#    "ref":"nuclei:sqli","cvss31":"8.2","tags":["cwe-89","owasp-a03"]}
#
# Confidence values: "confirmed" | "candidate" | "info"
# Impact class values: "critical" | "high" | "medium" | "low" | "info"
#
# The orchestrator converts JSON Lines → pipe-delimited CANDIDATE format and
# feeds to the unified findings sink (lib/findings_sink.sh).

set -u

# ---- Adapter Interface Contract ------------------------------------------------
# These are NOT implemented here — each adapter MUST override them.
# This file only documents the contract and provides shared helpers.

# adapter_init() {
#   # Called once at startup before any scans
#   # Create output subdirs, validate tool presence, etc.
#   return 0
# }

# adapter_name() {
#   echo "adapter_name"
# }

# adapter_version() {
#   echo "1.0.0"
# }

# adapter_capabilities() {
#   echo "recon vuln"
# }

# adapter_requires_api_key() {
#   return 1  # 0 = requires key, 1 = no key needed
# }

# adapter_is_available() {
#   # Check if tool is installed and functional
#   # Print reason to stderr if not available
#   return 0
# }

# adapter_scan() {
#   local target="$1" outdir="$2" opts_json="$3"
#   # Execute scan, output JSON Lines to stdout
#   return 0
# }

# adapter_health_check() {
#   # Quick probe (e.g., version check, API ping)
#   # Used by orchestrator to verify liveness before scheduling
#   return 0
# }

# ---- Shared Helpers for Adapters ----------------------------------------------

# JSON escape a string for safe embedding in JSON output
# Usage: json_escape "string with \"quotes\" and \n newlines"
json_escape() {
  local input="$1"
  # Escape backslash, quote, newline, carriage return, tab
  printf '%s' "$input" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g; s/\r/\\r/g; s/\t/\\t/g'
}

# Emit a finding as JSON Line to stdout
# Usage: emit_finding "high" "host.example.com" "Title" "confirmed" "evidence" "curl_cmd" "ref" "8.2" "cwe-89,owasp-a03"
emit_finding() {
  local impact_class="$1"
  local host="$2"
  local title="$3"
  local confidence="$4"
  local evidence="$5"
  local repro_curl="$6"
  local ref="$7"
  local cvss31="$8"
  local tags="$9"

  # Validate required fields
  [ -z "$impact_class" ] && { echo '{"error":"missing impact_class"}' >&2; return 1; }
  [ -z "$host" ] && { echo '{"error":"missing host"}' >&2; return 1; }
  [ -z "$title" ] && { echo '{"error":"missing title"}' >&2; return 1; }
  [ -z "$confidence" ] && { echo '{"error":"missing confidence"}' >&2; return 1; }

  # Default empty strings
  evidence="${evidence:-}"
  repro_curl="${repro_curl:--}"
  ref="${ref:-}"
  cvss31="${cvss31:-}"
  tags="${tags:-}"

  # Build JSON using printf (avoids jq dependency in adapters)
  printf '{"impact_class":"%s","host":"%s","title":"%s","confidence":"%s","evidence":"%s","repro_curl":"%s","ref":"%s","cvss31":"%s","tags":"%s"}\n' \
    "$(json_escape "$impact_class")" \
    "$(json_escape "$host")" \
    "$(json_escape "$title")" \
    "$(json_escape "$confidence")" \
    "$(json_escape "$evidence")" \
    "$(json_escape "$repro_curl")" \
    "$(json_escape "$ref")" \
    "$(json_escape "$cvss31")" \
    "$(json_escape "$tags")"
}

# Parse opts_json (simple key=value extraction for common options)
# Usage: parse_opt "$opts_json" "max_duration" "300"
parse_opt() {
  local json="$1" key="$2" default="$3"
  # Simple extraction: {"key":"value"} or {"key":123}
  local val
  val=$(printf '%s' "$json" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p")
  if [ -z "$val" ]; then
    val=$(printf '%s' "$json" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p")
  fi
  printf '%s' "${val:-$default}"
}

# Get current timestamp ISO8601
now_iso() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Log helper (uses core.sh log/ok/warn/err if available, else basic)
adapter_log() {
  if declare -f log >/dev/null 2>&1; then
    log "$@"
  else
    printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"
  fi
}

adapter_ok() {
  if declare -f ok >/dev/null 2>&1; then
    ok "$@"
  else
    printf '[+] %s\n' "$*"
  fi
}

adapter_warn() {
  if declare -f warn >/dev/null 2>&1; then
    warn "$@"
  else
    printf '[!] %s\n' "$*" >&2
  fi
}

adapter_err() {
  if declare -f err >/dev/null 2>&1; then
    err "$@"
  else
    printf '[-] %s\n' "$*" >&2
  fi
}

# Check if a command exists
adapter_tool_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Run command with timeout, capture stdout/stderr
# Usage: adapter_run_cmd 30 "cmd args..."
adapter_run_cmd() {
  local timeout_sec="$1"
  shift
  timeout -k 30 "$timeout_sec" "$@" 2>&1
}

# Export helpers for subshells
export -f json_escape emit_finding parse_opt now_iso
export -f adapter_log adapter_ok adapter_warn adapter_err
export -f adapter_tool_exists adapter_run_cmd