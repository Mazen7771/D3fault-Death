#!/usr/bin/env bash
# HuntOps — core library: logging, findings sinks, scope, throttle, helpers.
# Source this first:  source "$HUNTOPS_ROOT/config/config.sh"; source lib/core.sh

# ---- colors / logging --------------------------------------------------------
C_RST=$'\e[0m'; C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YLW=$'\e[33m'; C_BLU=$'\e[34m'; C_CYN=$'\e[36m'
# Live-view streams. Set in setup_target() once $W is known. Every log/ok/warn/err
# is teed (ANSI-stripped) into VERBOSE_LOG; dbg() writes the behind-the-scenes
# stream. --debug also prints dbg() to the terminal.
# NOTE: Do not reset if already exported (OMNI integration sets these before sourcing)
: "${VERBOSE_LOG:=}"
: "${DEBUG_LOG:=}"
DEBUG=${DEBUG:-0}

strip_ansi() { sed -E 's/\x1B\[[0-9;]*[mK]//g'; }
_tee_verbose() { [ -n "$VERBOSE_LOG" ] && { printf '%s\n' "$*" | strip_ansi >> "$VERBOSE_LOG" 2>/dev/null || true; } || true; }

log()  { printf '%s[%s]%s %s\n' "$C_CYN" "$(date +%H:%M:%S)" "$C_RST" "$*"; _tee_verbose "[$(date +%H:%M:%S)] $*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; _tee_verbose "[+] $*"; }
warn() { printf '%s[!]%s %s\n' "$C_YLW" "$C_RST" "$*"; _tee_verbose "[!] $*"; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; _tee_verbose "[x] $*"; }
dbg()  {
  [ -n "$DEBUG_LOG" ] && printf '[dbg] %s\n' "$*" >> "$DEBUG_LOG" 2>/dev/null || true
  [ "$DEBUG" = 1 ] && printf '%s[dbg]%s %s\n' "$C_YLW" "$C_RST" "$*" || true
}
banner_phase() { printf '%s══════════════════════════════════════════════%s\n' "$C_BLU" "$C_RST"; log "→ $*"; }

# Record-field sanitizer: the findings streams are pipe-delimited, so any literal
# '|' in evidence/repro (e.g. curl ... | head -50) must not split the record, and
# embedded newlines must not break it across physical lines. Applied centrally in
# the add_* sinks below so every emitter is fixed at once.
# NB: tr('|'→'│') would emit only the FIRST byte of the multi-byte │ (\342 garbage).
# sed does proper UTF-8 pipe substitution; tr stays for newline collapsing
# (sed strips record separators, so it can't see the newlines).
esc_rec() { printf '%s' "$1" | sed 's/|/│/g' | tr '\n' ' '; }

tool_exists() { command -v "$1" >/dev/null 2>&1; }
count_lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
sanitize_name() { echo "$1" | tr '/:?#&=%' '_' | tr -s '_'; }

# ---- phase status ledger -----------------------------------------------------
# PHASE_STATUS is set inside setup_target (once $W is known). Header is written
# on first write (guard is -s non-empty, because setup_target pre-creates the
# file empty — the old -f guard never fired and the ledger stayed 0 bytes).
phase_mark() { # phase, exit_code
  [ -s "$PHASE_STATUS" ] || printf 'phase\tstart\texit\tdur_s\n' > "$PHASE_STATUS"
  printf '%s\t%s\t%s\t%s\n' "$1" "${PHASE_START:-}" "$2" "${PHASE_DUR:-}" >> "$PHASE_STATUS"
}

# ---- workdir setup -----------------------------------------------------------
setup_target() {
  local ts dir
  ts=$(date +%Y%m%d_%H%M%S)
  if [ -n "$CUSTOM_OUT" ]; then W="$CUSTOM_OUT"; else W="$OUTROOT/$TARGET/$ts"; fi
  mkdir -p "$W"/{logs,findings,subdomains,ports,web,content,urls,js,vuln,candidates,osint,cve,report,secrets}
  FINDINGS="$W/findings/findings.txt"
  CANDIDATES="$W/findings/candidates.txt"
  INFOFILE="$W/findings/info.txt"
  KEYS="$W/findings/.keys"
  : > "$FINDINGS"; : > "$CANDIDATES"; : > "$INFOFILE"; : > "$KEYS"
  PHASE_STATUS="$W/logs/phase-status.tsv"
  VERBOSE_LOG="$W/logs/verbose.log"
  DEBUG_LOG="$W/logs/debug.log"
  : > "$PHASE_STATUS"; : > "$VERBOSE_LOG"; : > "$DEBUG_LOG"
}

# ---- findings sinks (dedup by host|title key) --------------------------------
_add_dedup() {
  local key line="$1" out="$2"
  key=$(printf '%s' "$line" | md5sum | cut -c1-12)
  grep -q "^$key$" "$KEYS" && return 1
  printf '%s\n' "$key" >> "$KEYS"
  printf '%s\n' "$line" >> "$out"
  return 0
}
# add_finding SEVERITY TOOL HOST TITLE DETAIL REF        (6-field, old monolith format)
add_finding() { _add_dedup "$(printf '%s|%s|%s|%s|%s|%s' "$(esc_rec "$1")" "$(esc_rec "$2")" "$(esc_rec "$3")" "$(esc_rec "$4")" "$(esc_rec "$5")" "$(esc_rec "$6")")" "$FINDINGS"; }
# add_candidate IMPACT_CLASS HOST TITLE CONFIDENCE EVIDENCE REPRO_CURL REF CVSS31 TAG
add_candidate() {
  _add_dedup "$(printf 'CAND|%s|%s|%s|%s|%s|%s|%s|%s|%s' "$(esc_rec "$1")" "$(esc_rec "$2")" "$(esc_rec "$3")" "$(esc_rec "$4")" "$(esc_rec "$5")" "$(esc_rec "$6")" "$(esc_rec "$7")" "$(esc_rec "$8")" "$(esc_rec "$9")")" "$CANDIDATES"
}
# add_info TOOL HOST TITLE DETAIL REF
add_info() { _add_dedup "$(printf 'INFO|%s|%s|%s|%s|%s' "$(esc_rec "$1")" "$(esc_rec "$2")" "$(esc_rec "$3")" "$(esc_rec "$4")" "$(esc_rec "$5")")" "$INFOFILE"; }

# ---- scope engine (salvaged from D3fault-death.sh, lines 174-244) -----------
DOMAIN=""  # root domain, set by setup_target
SCOPE_FILE=""
_in_scope_list() { # hostname -> 0/1 by suffix match on $SCOPE_ALLOW/$SCOPE_DENY
  local h="$1"
  for d in "${SCOPE_DENY[@]}"; do [[ "$h" == "$d" || "$h" == *".$d" ]] && return 1; done
  for a in "${SCOPE_ALLOW[@]}"; do
    case "$a" in
      *"*"*) [[ "$h" == $a ]] && return 0 ;;   # glob
      *)     [[ "$h" == "$a" || "$h" == *".$a" ]] && return 0 ;;
    esac
  done
  return 1
}
in_scope() {
  [ ${#SCOPE_ALLOW[@]} -eq 0 ] && return 0
  _in_scope_list "$1"
}
ip2dec() { # a.b.c.d -> int
  local a b c d IFS=.; read -r a b c d <<< "$1"; echo $((a*16777216+b*65536+c*256+d))
}
ip_in_cidr() { # ip, cidr
  local ip="${1%%/*}" cidr="${2##*/}" i_mask net
  i_mask=$((0xffffffff << (32 - cidr) ))
  net=$(( $(ip2dec "${cidr%/*}") & i_mask ))
  [ $(( $(ip2dec "$ip") & i_mask )) -eq "$net" ]
}
filter_scope() { # stdin hostnames -> only in-scope
  while read -r h; do [ -n "$h" ] && in_scope "$h" && echo "$h"; done
}

load_scope() {
  SCOPE_ALLOW=(); SCOPE_DENY=()
  local f="${SCOPE_FILE:-}"
  if [ -n "$f" ] && [ -f "$f" ]; then
    while read -r line; do
      line="${line%%#*}"; line="${line// /}"; [ -z "$line" ] && continue
      case "$line" in
        "!"*) SCOPE_DENY+=("${line#!}") ;;
        *)    SCOPE_ALLOW+=("$line") ;;
      esac
    done < "$f"
  else
    SCOPE_ALLOW=("$DOMAIN")
  fi
}

# ---- target normalization ----------------------------------------------------
derive_root() { # domain -> eTLD+1 (works for com/io/net/co.uk style)
  local d="$1" parts last
  parts=$(awk -F. '{print NF}' <<< "$d")
  last=$(awk -F. '{print $(NF-1)"."$NF}' <<< "$d")
  case "$last" in
    co.uk|com.au|co.jp|com.br|co.in|com.mx|org.uk|net.uk|gov.uk|ac.uk) echo "$(awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}' <<< "$d")" ;;
    *) echo "$last" ;;
  esac
}
is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# ---- throttle (global req/s for curl loops) ---------------------------------
THROTTLE_TS="/tmp/huntops_throttle_$$"
throttle() {
  [ "$RATE_GLOBAL" = "0" ] && return
  local d
  d=$(awk -v r="$RATE_GLOBAL" 'BEGIN{printf "%.3f", 1/r}')
  [ -f "$THROTTLE_TS" ] && sleep "$d"
  date +%s%N > "$THROTTLE_TS"
}

# ---- auth-aware curl wrapper -------------------------------------------------
AUTH_ARGS=()
wreq() { # curl args... ; adds auth headers + throttle + timeout
  throttle
  local args=(-sk --max-time 15 "${AUTH_ARGS[@]}")
  curl "${args[@]}" "$@"
}

# ---- hostname normalizer -----------------------------------------------------
extract_hostnames() { # stdin raw -> clean in-scope hostnames for $DOMAIN
  tr '[:upper:]' '[:lower:]' \
    | sed 's/\*\.//g; s/^\*//' \
    | grep -oE "([a-z0-9]([a-z0-9_-]*[a-z0-9])?\.)+${DOMAIN}" \
    | sed 's/\.$//' | sort -u
}

# ---- memory guard ------------------------------------------------------------
mem_mb_free() { awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo; }
mem_ok() { [ "$(mem_mb_free)" -ge "$MIN_MEM_FREE_MB" ]; }

# ---- version comparator (salvaged D3fault-death lines 1622-1651) -------------
ver_cmp() { # a op b ; op in lt le eq ge gt
  local a="$1" op="$2" b="$3" r
  r=$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)
  case "$op" in
    lt) [ "$a" != "$b" ] && [ "$r" = "$a" ] ;;
    le) [ "$r" = "$a" ] ;;
    eq) [ "$a" = "$b" ] ;;
    ge) [ "$r" = "$b" ] ;;
    gt) [ "$a" != "$b" ] && [ "$r" = "$b" ] ;;
  esac
}

# ---- JSON helpers ------------------------------------------------------------
have_jq() { tool_exists jq; }

# ---- program-exclusion filter ------------------------------------------------
# is_excluded <detail> -> 0 if the detail matches an excluded class
is_excluded() {
  local d="$1"
  while IFS= read -r pat; do
    pat="${pat%%#*}"; [ -z "${pat// }" ] && continue
    grep -qiE "$pat" <<< "$d" && return 0
  done < "$EXCLUSIONS"
  return 1
}
