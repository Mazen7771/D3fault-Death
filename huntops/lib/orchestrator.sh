#!/usr/bin/env bash
# HuntOps — Pipeline Orchestrator
# Loads adapter registry + pipeline DAG, executes phases with concurrency control.
# Source this in huntops.sh: source "$HUNTOPS_ROOT/lib/orchestrator.sh"
#
# Usage:
#   orchestrator_init <adapters_yaml> <pipeline_yaml>
#   orchestrator_run <target> <workdir> <mode>
#   orchestrator_cleanup

set -u

# Source the adapter interface contract (provides adapter_ok/err/log + json_escape etc.)
HUNTOPS_ROOT="${HUNTOPS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$HUNTOPS_ROOT/lib/adapter_interface.sh" 2>/dev/null || true

# Source core.sh for phase_mark, log/warn/ok/err, etc.
source "$HUNTOPS_ROOT/lib/core.sh" 2>/dev/null || true

# banner_phase may be defined in core.sh (via huntops.sh) — provide fallback
if ! declare -f banner_phase >/dev/null 2>&1; then
  banner_phase() { echo "=== PHASE: $1 ==="; }
fi

# ---- Global State -------------------------------------------------------------
ADAPTERS_YAML=""
PIPELINE_YAML=""
ADAPTER_REGISTRY=()     # Array of adapter names (enabled)
ADAPTER_META=()         # Associative arrays: name->meta (type, path, caps, etc.)
PHASE_ORDER=()          # Topologically sorted phase names
PHASE_DEPS=()           # phase -> depends_on list
PHASE_ADAPTERS=()       # phase -> adapter list
PHASE_TIMEOUT=()        # phase -> timeout seconds
PHASE_PARALLEL=()       # phase -> parallel (true/false)
# NOTE: TARGET/WORKDIR/MODE are set by huntops.sh and passed to orchestrator_run()
# Do NOT reset them here - they are parameters, not global state
FAIL_FAST=0
NO_DOS=0
DEBUG=0
# PHASE_FILTER is set by huntops.sh from CLI --phase-filter; do not reset if already set
: "${PHASE_FILTER:=}"

# Semaphore for concurrency control
SEMAPHORE_FILE=""
MAX_CONCURRENT=3

# ---- YAML Parsing Helpers (using yq if available, else awk/sed) --------------
has_yq() { command -v yq >/dev/null 2>&1; }

# Parse adapters.yaml into associative arrays
# Requires yq for reliable parsing
orchestrator_parse_adapters() {
  local yaml_file="$1"
  [ -f "$yaml_file" ] || { adapter_err "adapters.yaml not found: $yaml_file"; return 1; }

  if ! has_yq; then
    adapter_err "yq is required for parsing adapters.yaml (install: go install github.com/mikefarah/yq/v4@latest)"
    return 1
  fi

  # Get enabled adapter names
  mapfile -t ADAPTER_REGISTRY < <(yq -r '.adapters | to_entries[] | select(.value.enabled == true) | .key' "$yaml_file" 2>/dev/null)

  # Parse metadata for each adapter
  for name in "${ADAPTER_REGISTRY[@]}"; do
    local type path capabilities enabled priority requires_api_key api_key_env binary
    type=$(yq -r ".adapters.$name.type // \"bash\"" "$yaml_file")
    path=$(yq -r ".adapters.$name.path // \"\"" "$yaml_file")
    # Resolve relative paths to absolute using HUNTOPS_ROOT
    if [ -n "$path" ] && [ "${path#/}" = "$path" ]; then
      # Relative path - make it absolute from HUNTOPS_ROOT
      path="$HUNTOPS_ROOT/$path"
    fi
    capabilities=$(yq -r ".adapters.$name.capabilities // [] | join(\" \")" "$yaml_file")
    enabled=$(yq -r ".adapters.$name.enabled // true" "$yaml_file")
    priority=$(yq -r ".adapters.$name.priority // 999" "$yaml_file")
    requires_api_key=$(yq -r ".adapters.$name.requires_api_key // false" "$yaml_file")
    api_key_env=$(yq -r ".adapters.$name.api_key_env // \"\"" "$yaml_file")
    binary=$(yq -r ".adapters.$name.binary // \"\"" "$yaml_file")

    # Store as delimited string (bash 4.3 doesn't have associative arrays in all envs)
    ADAPTER_META+=("$name|$type|$path|$capabilities|$enabled|$priority|$requires_api_key|$api_key_env|$binary")
  done

  # Sort by priority
  IFS=$'\n' ADAPTER_META=($(sort -t'|' -k6 -n <<<"${ADAPTER_META[*]}"))
  unset IFS

  adapter_ok "Loaded ${#ADAPTER_REGISTRY[@]} enabled adapters"
  return 0
}

# Parse pipeline.yaml into phase DAG
# If PHASE_FILTER is set, only include those phases and their transitive dependencies
orchestrator_parse_pipeline() {
  local yaml_file="$1"
  [ -f "$yaml_file" ] || { adapter_err "pipeline.yaml not found: $yaml_file"; return 1; }

  if ! has_yq; then
    adapter_err "yq is required for parsing pipeline.yaml"
    return 1
  fi

  local phase_count
  phase_count=$(yq -r '.phases | length' "$yaml_file" 2>/dev/null || echo 0)
  [ "$phase_count" -eq 0 ] && { adapter_err "No phases defined in pipeline.yaml"; return 1; }

  # First, collect all phases into temporary arrays
  local -a all_names=()
  local -a all_deps=()
  local -a all_adapters=()
  local -a all_timeout=()
  local -a all_parallel=()

  local i
  for ((i=0; i<phase_count; i++)); do
    local name depends_on parallel timeout adapters
    name=$(yq -r ".phases[$i].name" "$yaml_file")
    depends_on=$(yq -r ".phases[$i].depends_on // [] | join(\",\")" "$yaml_file")
    parallel=$(yq -r ".phases[$i].parallel // false" "$yaml_file")
    timeout=$(yq -r ".phases[$i].timeout // 300" "$yaml_file")
    adapters=$(yq -r ".phases[$i].adapters // [] | join(\",\")" "$yaml_file")

    all_names+=("$name")
    all_deps+=("$name|$depends_on")
    all_adapters+=("$name|$adapters")
    all_timeout+=("$name|$timeout")
    all_parallel+=("$name|$parallel")
  done

  # If phase filter is set, compute the closure of filtered phases + their dependencies
  if [ -n "${PHASE_FILTER:-}" ]; then
    adapter_log "Phase filter active at parse time: '$PHASE_FILTER'"
    local -a filter_list=()
    IFS=',' read -ra filter_list <<< "$PHASE_FILTER"
    local -a trimmed_filters=()
    for f in "${filter_list[@]}"; do
      trimmed_filters+=("$(echo "$f" | xargs)")
    done
    filter_list=("${trimmed_filters[@]}")

    # Build dependency graph for transitive closure
    local -A deps_map=()
    for entry in "${all_deps[@]}"; do
      IFS='|' read -r name deps <<< "$entry"
      deps_map["$name"]="$deps"
    done

    # Function to collect transitive dependencies
    local -A included=()
    collect_deps() {
      local phase="$1"
      # Use parameter expansion to avoid set -u unbound variable error
      [ -n "${included[$phase]:-}" ] && return
      included["$phase"]=1
      local deps="${deps_map[$phase]:-}"
      if [ -n "$deps" ]; then
        IFS=',' read -ra dep_arr <<< "$deps"
        for dep in "${dep_arr[@]}"; do
          dep=$(echo "$dep" | xargs)
          [ -n "$dep" ] && collect_deps "$dep"
        done
      fi
    }

    # Collect filtered phases and their dependencies
    for filter in "${filter_list[@]}"; do
      collect_deps "$filter"
    done

    # Filter the arrays to only include phases in the closure
    PHASE_ORDER=()
    PHASE_DEPS=()
    PHASE_ADAPTERS=()
    PHASE_TIMEOUT=()
    PHASE_PARALLEL=()

    for entry in "${all_deps[@]}"; do
      IFS='|' read -r name _ <<< "$entry"
      if [ -n "${included[$name]:-}" ]; then
        PHASE_ORDER+=("$name")
        PHASE_DEPS+=("$entry")
        # Find matching entries in other arrays
        for e in "${all_adapters[@]}"; do IFS='|' read -r n _ <<< "$e"; [ "$n" = "$name" ] && PHASE_ADAPTERS+=("$e") && break; done
        for e in "${all_timeout[@]}"; do IFS='|' read -r n _ <<< "$e"; [ "$n" = "$name" ] && PHASE_TIMEOUT+=("$e") && break; done
        for e in "${all_parallel[@]}"; do IFS='|' read -r n _ <<< "$e"; [ "$n" = "$name" ] && PHASE_PARALLEL+=("$e") && break; done
      fi
    done

    adapter_log "Filtered pipeline to ${#PHASE_ORDER[@]} phases (including deps): ${PHASE_ORDER[*]}"
  else
    # No filter - use all phases
    PHASE_ORDER=("${all_names[@]}")
    PHASE_DEPS=("${all_deps[@]}")
    PHASE_ADAPTERS=("${all_adapters[@]}")
    PHASE_TIMEOUT=("${all_timeout[@]}")
    PHASE_PARALLEL=("${all_parallel[@]}")
  fi

  # Validate DAG (check for cycles via topological sort)
  adapter_log "DEBUG topo_sort: PHASE_DEPS=${PHASE_DEPS[*]}"
  adapter_log "DEBUG topo_sort: PHASE_ORDER before sort=${PHASE_ORDER[*]}"
  orchestrator_topo_sort || return 1

  adapter_ok "Loaded ${#PHASE_ORDER[@]} phases"
  return 0
}

# Topological sort of phases (Kahn's algorithm)
orchestrator_topo_sort() {
  local -A indegree
  local -A adj
  local -A phase_exists

  # Build graph
  for entry in "${PHASE_DEPS[@]}"; do
    IFS='|' read -r name deps <<< "$entry"
    phase_exists["$name"]=1
    indegree["$name"]=0
    if [ -n "$deps" ]; then
      IFS=',' read -ra dep_array <<< "$deps"
      for dep in "${dep_array[@]}"; do
        # Only add edge if the dependency is also in our phase list (filtered)
        local dep_in_list=0
        for p in "${PHASE_ORDER[@]}"; do [ "$p" = "$dep" ] && dep_in_list=1 && break; done
        [ "$dep_in_list" -eq 0 ] && continue
        adj["$dep"]+="$name "
        indegree["$name"]=$((indegree["$name"] + 1))
      done
    fi
  done

  # Queue of nodes with indegree 0
  local queue=()
  for name in "${!indegree[@]}"; do
    [ "${indegree[$name]}" -eq 0 ] && queue+=("$name")
  done

  local sorted=()
  while [ ${#queue[@]} -gt 0 ]; do
    local node="${queue[0]}"
    queue=("${queue[@]:1}")
    sorted+=("$node")

    for neighbor in ${adj[$node]:-}; do
      indegree["$neighbor"]=$((indegree["$neighbor"] - 1))
      [ "${indegree[$neighbor]}" -eq 0 ] && queue+=("$neighbor")
    done
  done

  # Check for cycles
  if [ ${#sorted[@]} -ne ${#indegree[@]} ]; then
    adapter_err "Pipeline DAG has a cycle!"
    return 1
  fi

  PHASE_ORDER=("${sorted[@]}")
  return 0
}

# ---- Adapter Management -------------------------------------------------------

# Get adapter metadata field
# Usage: orchestrator_get_adapter_meta <name> <field_index> (0=type, 1=path, 2=caps, 3=enabled, 4=priority, 5=requires_api_key, 6=api_key_env, 7=binary)
orchestrator_get_adapter_meta() {
  local name="$1" field="$2"
  for entry in "${ADAPTER_META[@]}"; do
    IFS='|' read -r n type path caps enabled priority req_key api_key_env binary <<< "$entry"
    [ "$n" = "$name" ] && {
      case "$field" in
        0) echo "$type" ;;
        1) echo "$path" ;;
        2) echo "$caps" ;;
        3) echo "$enabled" ;;
        4) echo "$priority" ;;
        5) echo "$req_key" ;;
        6) echo "$api_key_env" ;;
        7) echo "$binary" ;;
      esac
      return 0
    }
  done
  return 1
}

# Check if adapter is available (tool installed, API key present)
orchestrator_check_adapter_available() {
  local name="$1"
  local type path requires_api_key api_key_env binary
  type=$(orchestrator_get_adapter_meta "$name" 0)
  path=$(orchestrator_get_adapter_meta "$name" 1)
  requires_api_key=$(orchestrator_get_adapter_meta "$name" 5)
  api_key_env=$(orchestrator_get_adapter_meta "$name" 6)
  binary=$(orchestrator_get_adapter_meta "$name" 7)

  # Check API key if required
  if [ "$requires_api_key" = "true" ] && [ -n "$api_key_env" ]; then
    [ -z "${!api_key_env:-}" ] && {
      adapter_warn "Adapter $name: missing API key ($api_key_env)"
      return 1
    }
  fi

  # For bash adapters, source and call adapter_is_available
  if [ "$type" = "bash" ]; then
    [ -f "$path" ] || { adapter_warn "Adapter $name: not found at $path"; return 1; }
    source "$path"
    if declare -f adapter_is_available >/dev/null; then
      adapter_is_available || return 1
    fi
  fi

  # For Go adapters, check binary exists
  if [ "$type" = "go" ]; then
    if [ -n "$binary" ]; then
      command -v "$binary" >/dev/null 2>&1 || { adapter_warn "Go binary $binary not in PATH"; return 1; }
    fi
  fi

  return 0
}

# Run a single adapter
# Usage: orchestrator_run_adapter <name> <target> <workdir> <opts_json>
orchestrator_run_adapter() {
  local name="$1" target="$2" workdir="$3" opts_json="$4"
  local type path binary
  type=$(orchestrator_get_adapter_meta "$name" 0)
  path=$(orchestrator_get_adapter_meta "$name" 1)
  binary=$(orchestrator_get_adapter_meta "$name" 7)

  local start_time end_time duration
  start_time=$(date +%s)

  adapter_log "Running adapter: $name (type: $type)"

  local output_file="$workdir/findings/.adapter_${name}.jsonl"
  local rc=0

  if [ "$type" = "bash" ]; then
    [ -f "$path" ] || { adapter_err "Adapter script not found: $path"; return 1; }
    source "$path"
    if declare -f adapter_scan >/dev/null; then
      adapter_scan "$target" "$workdir" "$opts_json" > "$output_file" 2>&1
      rc=$?
    else
      adapter_err "Adapter $name: no adapter_scan function"
      rc=1
    fi
  elif [ "$type" = "go" ]; then
    if [ -n "$binary" ] && command -v "$binary" >/dev/null 2>&1; then
      # Call Go binary with adapter mode
      "$binary" --adapter "$name" --target "$target" --workdir "$workdir" --opts "$opts_json" > "$output_file" 2>&1
      rc=$?
    else
      adapter_err "Go binary not found: $binary"
      rc=1
    fi
  else
    adapter_err "Unknown adapter type: $type"
    rc=1
  fi

  end_time=$(date +%s)
  duration=$((end_time - start_time))

  if [ $rc -eq 0 ]; then
    adapter_ok "Adapter $name completed in ${duration}s"
    # Process findings
    if [ -f "$output_file" ]; then
      sink_process_json "$output_file"
    fi
  else
    adapter_err "Adapter $name failed after ${duration}s (exit $rc)"
    [ -f "$output_file" ] && command cat "$output_file" >&2
  fi

  return $rc
}

# ---- Semaphore for Concurrency Control ----------------------------------------
orchestrator_sem_init() {
  local workdir="$1"
  MAX_CONCURRENT="${CONCURRENCY:-3}"
  SEMAPHORE_FILE="$workdir/.semaphore"
  : > "$SEMAPHORE_FILE"
  for ((i=0; i<MAX_CONCURRENT; i++)); do
    echo "slot" >> "$SEMAPHORE_FILE"
  done
}

orchestrator_sem_acquire() {
  local slot
  while true; do
    # Try to get a slot (atomic read+truncate)
    slot=$(head -n1 "$SEMAPHORE_FILE" 2>/dev/null)
    [ -n "$slot" ] && {
      # Remove first line atomically
      sed -i '1d' "$SEMAPHORE_FILE" 2>/dev/null && break
    }
    sleep 0.5
  done
}

orchestrator_sem_release() {
  echo "slot" >> "$SEMAPHORE_FILE"
}

# ---- Phase Execution ----------------------------------------------------------
# Run all adapters for a phase
orchestrator_run_phase() {
  local phase_name="$1" target="$2" workdir="$3" opts_json="$4"
  local adapters_str timeout parallel
  adapters_str=$(orchestrator_get_phase_field "$phase_name" "adapters")
  timeout=$(orchestrator_get_phase_field "$phase_name" "timeout")
  parallel=$(orchestrator_get_phase_field "$phase_name" "parallel")

  [ -z "$adapters_str" ] && { adapter_warn "Phase $phase_name: no adapters defined"; return 0; }

  adapter_log "=== Phase: $phase_name (timeout: ${timeout}s, parallel: $parallel) ==="

  IFS=',' read -ra adapter_list <<< "$adapters_str"
  local available_adapters=()

  # Filter enabled + available adapters
  for adapter in "${adapter_list[@]}"; do
    adapter=$(echo "$adapter" | xargs)  # trim
    [ -z "$adapter" ] && continue
    if orchestrator_check_adapter_available "$adapter"; then
      available_adapters+=("$adapter")
    else
      adapter_warn "Adapter $adapter unavailable, skipping"
    fi
  done

  [ ${#available_adapters[@]} -eq 0 ] && {
    adapter_warn "Phase $phase_name: no available adapters"
    return 0
  }

  adapter_log "Phase $phase_name: running ${#available_adapters[@]} adapters: ${available_adapters[*]}"

  local pids=() results=() rc=0

  if [ "$parallel" = "true" ]; then
    # Parallel execution with semaphore
    for adapter in "${available_adapters[@]}"; do
      orchestrator_sem_acquire
      (
        orchestrator_run_adapter "$adapter" "$target" "$workdir" "$opts_json"
        local adapter_rc=$?
        orchestrator_sem_release
        exit $adapter_rc
      ) &
      pids+=($!)
    done

    # Wait for all with timeout
    local phase_start=$(date +%s)
    for pid in "${pids[@]}"; do
      local remaining=$((timeout - ( $(date +%s) - phase_start )))
      [ $remaining -le 0 ] && { adapter_warn "Phase timeout, killing remaining"; kill $pid 2>/dev/null; rc=1; continue; }
      wait $pid || rc=1
    done
  else
    # Sequential execution - call function directly (no timeout command, adapters have internal timeouts)
    for adapter in "${available_adapters[@]}"; do
      orchestrator_run_adapter "$adapter" "$target" "$workdir" "$opts_json" || rc=1
    done
  fi

  return $rc
}

# Get phase field from parsed arrays
orchestrator_get_phase_field() {
  local phase="$1" field="$2"
  case "$field" in
    adapters)
      for entry in "${PHASE_ADAPTERS[@]}"; do
        IFS='|' read -r name val <<< "$entry"
        [ "$name" = "$phase" ] && { echo "$val"; return; }
      done
      ;;
    timeout)
      for entry in "${PHASE_TIMEOUT[@]}"; do
        IFS='|' read -r name val <<< "$entry"
        [ "$name" = "$phase" ] && { echo "$val"; return; }
      done
      ;;
    parallel)
      for entry in "${PHASE_PARALLEL[@]}"; do
        IFS='|' read -r name val <<< "$entry"
        [ "$name" = "$phase" ] && { echo "$val"; return; }
      done
      ;;
  esac
}

# ---- Main Entry Points --------------------------------------------------------

# Initialize orchestrator
# Usage: orchestrator_init <adapters_yaml> <pipeline_yaml>
orchestrator_init() {
  ADAPTERS_YAML="$1"
  PIPELINE_YAML="$2"

  orchestrator_parse_adapters "$ADAPTERS_YAML" || return 1
  orchestrator_parse_pipeline "$PIPELINE_YAML" || return 1

  adapter_ok "Orchestrator initialized"
  return 0
}

# Run full pipeline
# Usage: orchestrator_run <target> <workdir> <mode> [opts_json]
orchestrator_run() {
  local target_arg="$1"
  local workdir_arg="$2"
  local mode_arg="$3"
  local opts_json="${4:-{}}"

  # Initialize findings sink
  sink_init "$workdir_arg"

  # Initialize semaphore
  orchestrator_sem_init "$workdir_arg"

  # Build opts JSON with mode-specific settings
  local full_opts
  full_opts=$(printf '%s' "$opts_json" | jq --arg mode "$mode_arg" --arg noconfirm "$NO_DOS" '. + {mode: $mode_arg, no_dos: ($noconfirm == "1")}' 2>/dev/null || echo "$opts_json")

  adapter_log "Starting pipeline for target: $target_arg (mode: $mode_arg)"
  adapter_log "Workdir: $workdir_arg"
  adapter_log "Phases: ${PHASE_ORDER[*]}"

  local overall_rc=0
  local phase_start phase_end phase_duration

  # Export PHASE_STATUS for phase_mark (set by huntops.sh via setup_target)
  # If not set, create it
  if [ -z "${PHASE_STATUS:-}" ]; then
    PHASE_STATUS="$workdir_arg/logs/phase-status.tsv"
    export PHASE_STATUS
  fi

  for phase in "${PHASE_ORDER[@]}"; do
    phase_start=$(date +%s)
    export PHASE_START="$phase_start"
    banner_phase "PHASE: $phase" 2>/dev/null || adapter_log "=== PHASE: $phase ==="

    if orchestrator_run_phase "$phase" "$target_arg" "$workdir_arg" "$full_opts"; then
      phase_end=$(date +%s)
      phase_duration=$((phase_end - phase_start))
      export PHASE_DUR="$phase_duration"
      phase_mark "$phase" 0
      adapter_ok "Phase $phase completed in ${phase_duration}s"
    else
      phase_end=$(date +%s)
      phase_duration=$((phase_end - phase_start))
      export PHASE_DUR="$phase_duration"
      phase_mark "$phase" 1
      adapter_err "Phase $phase FAILED after ${phase_duration}s"
      overall_rc=1
      [ "$FAIL_FAST" = "1" ] && break
    fi
  done

  # Final stats
  local total_findings
  total_findings=$(sink_count)
  adapter_log "Pipeline completed. Total findings: $total_findings (exit: $overall_rc)"

  return $overall_rc
}

# Cleanup
orchestrator_cleanup() {
  [ -f "$SEMAPHORE_FILE" ] && rm -f "$SEMAPHORE_FILE"
  # Clean up adapter temp files (WORKDIR may be set by caller)
  if [ -n "${WORKDIR:-}" ]; then
    find "$WORKDIR/findings" -name '.adapter_*.jsonl' -delete 2>/dev/null || true
  fi
}

# Export for subshells
export -f orchestrator_init orchestrator_run orchestrator_cleanup
export -f orchestrator_parse_adapters orchestrator_parse_pipeline
export -f orchestrator_get_adapter_meta orchestrator_check_adapter_available
export -f orchestrator_run_adapter orchestrator_sem_init orchestrator_sem_acquire orchestrator_sem_release
export -f orchestrator_run_phase orchestrator_get_phase_field