#!/usr/bin/env bash
# HuntOps — Unified Findings Sink
# Centralized deduplication and storage for all adapter findings.
# Source this in orchestrator: source "$HUNTOPS_ROOT/lib/findings_sink.sh"
#
# Input: JSON Lines from adapters (stdout of adapter_scan)
# Output: Pipe-delimited CANDIDATE records in findings/findings.txt
# Dedup key: md5(impact_class|host|title|evidence) — content-based, not identity

set -u

# ---- Global State (set by sink_init) -----------------------------------------
FINDINGS_FILE=""       # $W/findings/findings.txt
KEYS_FILE=""           # $W/findings/.keys
CANDIDATES_FILE=""     # $W/findings/candidates.txt (legacy HuntOps format)
INFO_FILE=""           # $W/findings/info.txt (legacy HuntOps format)

# ---- Initialize Sink ----------------------------------------------------------
# Usage: sink_init <workdir>
sink_init() {
  local workdir="$1"
  mkdir -p "$workdir/findings"
  FINDINGS_FILE="$workdir/findings/findings.txt"
  KEYS_FILE="$workdir/findings/.keys"
  CANDIDATES_FILE="$workdir/findings/candidates.txt"
  INFO_FILE="$workdir/findings/info.txt"

  # Create files if they don't exist
  : > "$FINDINGS_FILE"
  : > "$KEYS_FILE"
  : > "$CANDIDATES_FILE"
  : > "$INFO_FILE"

  # Export for subshells
  export FINDINGS_FILE KEYS_FILE CANDIDATES_FILE INFO_FILE
}

# ---- Record Sanitizer (from core.sh esc_rec) ----------------------------------
# Replaces | with │ (full-width) and collapses newlines to spaces
# Ensures pipe-delimited records stay parseable
sink_sanitize() {
  printf '%s' "$1" | sed 's/|/│/g' | tr '\n' ' '
}

# ---- Dedup Key Generation -----------------------------------------------------
# Key = md5(impact_class|host|title|evidence) - first 12 chars
sink_make_key() {
  local impact_class="$1" host="$2" title="$3" evidence="$4"
  printf '%s|%s|%s|%s' \
    "$(sink_sanitize "$impact_class")" \
    "$(sink_sanitize "$host")" \
    "$(sink_sanitize "$title")" \
    "$(sink_sanitize "$evidence")" \
    | md5sum | cut -c1-12
}

# ---- Core Sink: Add Finding ---------------------------------------------------
# Usage: sink_add_finding <json_line>
# JSON must have: impact_class, host, title, confidence, evidence, repro_curl, ref, cvss31, tags
sink_add_finding() {
  local json_line="$1"
  [ -z "$json_line" ] && return 1

  # Skip non-JSON lines (debug output, warnings, etc.)
  case "$json_line" in
    \{*) ;; # starts with { - looks like JSON
    *) return 1 ;;
  esac

  # Parse JSON fields (using jq if available, else fallback)
  local impact_class host title confidence evidence repro_curl ref cvss31 tags

  if command -v jq >/dev/null 2>&1; then
    impact_class=$(printf '%s' "$json_line" | jq -r '.impact_class // ""' 2>/dev/null)
    host=$(printf '%s' "$json_line" | jq -r '.host // ""' 2>/dev/null)
    title=$(printf '%s' "$json_line" | jq -r '.title // ""' 2>/dev/null)
    confidence=$(printf '%s' "$json_line" | jq -r '.confidence // "candidate"' 2>/dev/null)
    evidence=$(printf '%s' "$json_line" | jq -r '.evidence // ""' 2>/dev/null)
    repro_curl=$(printf '%s' "$json_line" | jq -r '.repro_curl // "-"' 2>/dev/null)
    ref=$(printf '%s' "$json_line" | jq -r '.ref // ""' 2>/dev/null)
    cvss31=$(printf '%s' "$json_line" | jq -r '.cvss31 // ""' 2>/dev/null)
    tags=$(printf '%s' "$json_line" | jq -r '.tags // ""' 2>/dev/null)
  else
    # Fallback: simple grep/sed extraction (less robust)
    impact_class=$(printf '%s' "$json_line" | sed -n 's/.*"impact_class"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    host=$(printf '%s' "$json_line" | sed -n 's/.*"host"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    title=$(printf '%s' "$json_line" | sed -n 's/.*"title"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    confidence=$(printf '%s' "$json_line" | sed -n 's/.*"confidence"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    evidence=$(printf '%s' "$json_line" | sed -n 's/.*"evidence"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    repro_curl=$(printf '%s' "$json_line" | sed -n 's/.*"repro_curl"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    ref=$(printf '%s' "$json_line" | sed -n 's/.*"ref"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    cvss31=$(printf '%s' "$json_line" | sed -n 's/.*"cvss31"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    tags=$(printf '%s' "$json_line" | sed -n 's/.*"tags"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  fi

  # Validate required fields
  [ -z "$impact_class" ] && return 1
  [ -z "$host" ] && return 1
  [ -z "$title" ] && return 1

  # Normalize confidence
  case "$confidence" in
    confirmed|candidate|info) ;;
    *) confidence="candidate" ;;
  esac

  # Generate dedup key
  local key
  key=$(sink_make_key "$impact_class" "$host" "$title" "$evidence")

  # Check if already seen
  if grep -q "^$key$" "$KEYS_FILE" 2>/dev/null; then
    return 1  # duplicate
  fi

  # Record key
  printf '%s\n' "$key" >> "$KEYS_FILE"

  # Sanitize all fields for pipe-delimited storage
  local s_impact_class s_host s_title s_confidence s_evidence s_repro_curl s_ref s_cvss31 s_tags
  s_impact_class=$(sink_sanitize "$impact_class")
  s_host=$(sink_sanitize "$host")
  s_title=$(sink_sanitize "$title")
  s_confidence=$(sink_sanitize "$confidence")
  s_evidence=$(sink_sanitize "$evidence")
  s_repro_curl=$(sink_sanitize "$repro_curl")
  s_ref=$(sink_sanitize "$ref")
  s_cvss31=$(sink_sanitize "$cvss31")
  s_tags=$(sink_sanitize "$tags")

  # Write unified format: CAND|IMPACT_CLASS|HOST|TITLE|CONFIDENCE|EVIDENCE|REPRO_CURL|REF|CVSS31|TAG
  printf 'CAND|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$s_impact_class" "$s_host" "$s_title" "$s_confidence" \
    "$s_evidence" "$s_repro_curl" "$s_ref" "$s_cvss31" "$s_tags" \
    >> "$FINDINGS_FILE"

  # Also write to legacy HuntOps streams for backward compatibility
  sink_write_legacy "$s_impact_class" "$s_host" "$s_title" "$s_confidence" "$s_evidence" "$s_ref" "$s_tags"

  return 0
}

# ---- Legacy HuntOps Format Writers --------------------------------------------
# Maintains compatibility with existing report/outputs generators

sink_write_legacy() {
  local impact_class="$1" host="$2" title="$3" confidence="$4" evidence="$5" ref="$6" tags="$7"

  # Map impact_class + confidence to legacy SEVERITY
  local severity
  case "$confidence" in
    confirmed)
      case "$impact_class" in
        critical) severity="CRITICAL" ;;
        high)     severity="HIGH" ;;
        medium)   severity="MEDIUM" ;;
        low)      severity="LOW" ;;
        *)        severity="INFO" ;;
      esac
      ;;
    candidate)
      # Candidates go to CANDIDATES file (HuntOps format)
      local impact_class_uc
      impact_class_uc=$(printf '%s' "$impact_class" | tr '[:lower:]' '[:upper:]')
      printf 'CAND|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$impact_class_uc" "$host" "$title" "$confidence" "$evidence" "-" "$ref" "-" "$tags" \
        >> "$CANDIDATES_FILE"
      return
      ;;
    info)
      severity="INFO"
      ;;
    *)
      severity="INFO"
      ;;
  esac

  # Write to findings.txt (legacy 6-field: SEVERITY|TOOL|HOST|TITLE|DETAIL|REF)
  local tool="adapter"
  printf '%s|%s|%s|%s|%s|%s\n' \
    "$severity" "$tool" "$host" "$title" "$evidence" "$ref" \
    >> "$FINDINGS_FILE"
}

# ---- Batch Processing ---------------------------------------------------------
# Usage: sink_process_json <json_file>
# Reads JSON Lines from file, feeds each to sink_add_finding
sink_process_json() {
  local json_file="$1"
  [ -f "$json_file" ] || return 1

  local count=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    sink_add_finding "$line" && count=$((count + 1))
  done < "$json_file"

  echo "$count"
}

# Usage: sink_process_stdin
# Reads JSON Lines from stdin (for piping adapter output directly)
sink_process_stdin() {
  local count=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    sink_add_finding "$line" && count=$((count + 1))
  done
  echo "$count"
}

# ---- Stats & Query ------------------------------------------------------------
sink_count() {
  [ -f "$FINDINGS_FILE" ] && wc -l < "$FINDINGS_FILE" | tr -d ' ' || echo 0
}

sink_count_by_severity() {
  local severity="$1"
  [ -f "$FINDINGS_FILE" ] || { echo 0; return; }
  awk -F'|' -v sev="$severity" '$1 == sev {count++} END {print count+0}' "$FINDINGS_FILE"
}

sink_list_findings() {
  [ -f "$FINDINGS_FILE" ] && command cat "$FINDINGS_FILE" || true
}

# Export functions for subshells
export -f sink_init sink_sanitize sink_make_key sink_add_finding
export -f sink_write_legacy sink_process_json sink_process_stdin
export -f sink_count sink_count_by_severity sink_list_findings