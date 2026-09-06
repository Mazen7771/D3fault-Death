#!/usr/bin/env bash
# OMNI — Shared utilities for D3fault-death + HuntOps integration
# Sourced by both engines and adapters. All functions have header comments.

#------------------------------------------------------------------------------
# Tool Detection (handles Kali quirks)
#------------------------------------------------------------------------------
find_tool() {
    # find_tool <name> -> prints full path or empty; handles:
    # - httpx: prefers httpx-toolkit (Kali), then ~/go/bin/httpx, then httpx
    # - gau: real binary at ~/go/bin/gau (git alias shadows 'gau')
    # - amass: Debian wrapper that sudo-prompts for libpostal; use _amass_ready()
    # - bat: /usr/sbin/bat is Bacula GUI; skip it
    local name="$1"
    case "$name" in
        httpx)
            for c in httpx-toolkit ~/go/bin/httpx httpx; do
                if command -v "$c" >/dev/null 2>&1 && "$c" -h 2>&1 | grep -qiE 'list|input'; then
                    echo "$c"; return 0
                fi
            done
            return 1
            ;;
        gau)
            if [ -x ~/go/bin/gau ]; then echo ~/go/bin/gau; return 0; fi
            # gau is a git alias on this box; command gau won't work
            return 1
            ;;
        amass)
            # Debian amass wrapper sudo-prompts for libpostal on tty
            # Only return path if _amass_ready() would succeed
            if command -v amass >/dev/null 2>&1; then
                echo "amass"; return 0
            fi
            return 1
            ;;
        bat)
            local b; b=$(command -v bat 2>/dev/null || true)
            case "$b" in /usr/sbin/*|/sbin/*) return 1 ;; esac
            [ -n "$b" ] && echo "$b" || return 1
            ;;
        *)
            command -v "$name" >/dev/null 2>&1 && echo "$(command -v "$name")" || return 1
            ;;
    esac
}

# Check if amass can run without sudo prompt (libpostal provisioned)
_amass_ready() {
    command -v amass >/dev/null 2>&1 || return 1
    [ -t 0 ] && return 1  # on tty, Debian wrapper prompts
    return 0
}

#------------------------------------------------------------------------------
# Wordlist Resolution (fallback chains)
#------------------------------------------------------------------------------
resolve_wordlist() {
    # resolve_wordlist <primary_var> [fallback_var...] -> prints first existing path
    local var
    for var in "$@"; do
        local path="${!var}"
        [ -n "$path" ] && [ -f "$path" ] && { echo "$path"; return 0; }
    done
    return 1
}

#------------------------------------------------------------------------------
# Findings I/O (HuntOps 3-stream format, pipe-delimited, deduped)
#------------------------------------------------------------------------------
# esc_rec — sanitize a field for pipe-delimited records (replaces | and newlines)
esc_rec() {
    printf '%s' "$1" | tr '|' '/' | tr -d '\n\r'
}

# add_finding — confirmed finding (6 fields): SEVERITY|TOOL|HOST|TITLE|DETAIL|REF
add_finding() {
    local sev="$(esc_rec "$1")"
    local tool="$(esc_rec "$2")"
    local host="$(esc_rec "$3")"
    local title="$(esc_rec "$4")"
    local detail="$(esc_rec "$5")"
    local ref="$(esc_rec "$6")"
    local key="${sev}|${tool}|${host}|${title}"
    local findings_file="${OUTDIR:-${W:-.}}/findings/findings.txt"
    mkdir -p "$(dirname "$findings_file")"
    [ -f "$findings_file" ] && grep -qF "${key}|" "$findings_file" 2>/dev/null && return 0
    echo "${key}|${detail}|${ref}" >> "$findings_file"
}

# add_candidate — HuntOps candidate (10 fields): CAND|IMPACT|HOST|TITLE|CONF|EVIDENCE|REPRO|REF|CVSS31|TAG
add_candidate() {
    local impact="$(esc_rec "$1")"
    local host="$(esc_rec "$2")"
    local title="$(esc_rec "$3")"
    local confidence="$(esc_rec "$4")"
    local evidence="$(esc_rec "$5")"
    local repro="$(esc_rec "$6")"
    local ref="$(esc_rec "$7")"
    local cvss31="$(esc_rec "$8")"
    local tag="$(esc_rec "$9")"
    local key="${impact}|${host}|${title}"
    local cand_file="${OUTDIR:-${W:-.}}/findings/candidates.txt"
    mkdir -p "$(dirname "$cand_file")"
    [ -f "$cand_file" ] && grep -qF "${key}|" "$cand_file" 2>/dev/null && return 0
    echo "CAND|${impact}|${host}|${title}|${confidence}|${evidence}|${repro}|${ref}|${cvss31}|${tag}" >> "$cand_file"
}

# add_info — info finding (6 fields): INFO|TOOL|HOST|TITLE|DETAIL|REF
add_info() {
    local tool="$(esc_rec "$1")"
    local host="$(esc_rec "$2")"
    local title="$(esc_rec "$3")"
    local detail="$(esc_rec "$4")"
    local ref="$(esc_rec "$5")"
    local key="${tool}|${host}|${title}"
    local info_file="${OUTDIR:-${W:-.}}/findings/info.txt"
    mkdir -p "$(dirname "$info_file")"
    [ -f "$info_file" ] && grep -qF "${key}|" "$info_file" 2>/dev/null && return 0
    echo "INFO|${tool}|${host}|${title}|${detail}|${ref}" >> "$info_file"
}

#------------------------------------------------------------------------------
# Scope Enforcement (unified: D3fault-death awk bulk + HuntOps arrays)
#------------------------------------------------------------------------------
_SCOPE_ALLOW=()
_SCOPE_DENY=()
_SCOPE_LOADED=0

load_scope() {
    # load_scope [file] -> populates _SCOPE_ALLOW/_SCOPE_DENY
    local file="${1:-${SCOPE_FILE:-}}"
    [ "$_SCOPE_LOADED" = 1 ] && return 0
    _SCOPE_LOADED=1
    [ -z "$file" ] && return 0
    [ ! -r "$file" ] && { warn "scope file not readable: $file"; return 0; }
    local pat
    while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        case "$pat" in \#*) continue ;; esac
        pat=$(echo "$pat" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//')
        case "$pat" in
            \!*) pat="${pat#!}"; [ -n "$pat" ] && _SCOPE_DENY+=("$pat") ;;
            *)   [ -n "$pat" ] && _SCOPE_ALLOW+=("$pat") ;;
        esac
    done < "$file"
}

in_scope() {
    # in_scope <host> -> exit 0 if allowed, 1 if denied
    local host="$1" h
    h=$(echo "$host" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//')
    [ -z "$SCOPE_FILE" ] && return 0
    load_scope
    local pat
    for pat in "${_SCOPE_DENY[@]}"; do
        case "$h" in "$pat"|*."$pat") return 1 ;; esac
    done
    local allowed=0
    for pat in "${_SCOPE_ALLOW[@]}"; do
        if echo "$pat" | grep -q '/'; then
            is_ip "$h" && ip_in_cidr "$h" "$pat" && allowed=1
            continue
        fi
        case "$pat" in
            \*.*) local base="${pat#\*.}"; case "$h" in *."$base"|"$base") allowed=1 ;; esac ;;
            *)    case "$h" in "$pat"|*."$pat") allowed=1 ;; esac ;;
        esac
    done
    [ "$allowed" = 1 ]
}

ip_in_cidr() {
    local ip="$1" cidr="$2" net mask bits ip_dec net_dec
    net="${cidr%/*}"; mask="${cidr#*/}"
    ip_dec=$(ip2dec "$ip") || return 1
    net_dec=$(ip2dec "$net") || return 1
    bits=$((32 - mask))
    [ $((ip_dec >> bits)) -eq $((net_dec >> bits)) ]
}

ip2dec() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    [ -z "$a" ] && return 1
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

filter_scope() {
    # filter_scope <infile> <outfile> — bulk awk filter (O(N))
    local inf="$1" outf="$2"
    [ -z "$SCOPE_FILE" ] && { cp "$inf" "$outf"; return 0; }
    load_scope
    local awk_prog="{ h=tolower(\$1); gsub(/^\./, \"\", h) }"
    for pat in "${_SCOPE_DENY[@]}"; do
        pat=$(echo "$pat" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//')
        [ -n "$pat" ] && awk_prog="${awk_prog} h==\"${pat}\"||h~/\.${pat}\$/ { next }"
    done
    local allowed_pat=""
    for pat in "${_SCOPE_ALLOW[@]}"; do
        pat=$(echo "$pat" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//')
        if echo "$pat" | grep -q '/'; then continue; fi
        case "$pat" in
            \*.*) local base="${pat#\*.}"; allowed_pat="${allowed_pat}h==\"${base}\" || h~/\\.${base}\$/" ;;
            *)    allowed_pat="${allowed_pat}h==\"${pat}\" || h~/\\.${pat}\$/" ;;
        esac
        allowed_pat="${allowed_pat} || "
    done
    if [ -n "$allowed_pat" ]; then
        allowed_pat="${allowed_pat% || }"
        awk_prog="${awk_prog} ${allowed_pat} { print }"
    fi
    awk "$awk_prog" "$inf" > "$outf"
}

#------------------------------------------------------------------------------
# Rate Limiting (ethics-first, shared by both engines)
#------------------------------------------------------------------------------
_THROTTLE_LAST=0
_THROTTLE_HOST_LAST=()

throttle_global() {
    # throttle_global — respects OMNI_RATE_GLOBAL (req/s)
    local rate="${OMNI_RATE_GLOBAL:-10}"
    local min_interval=0
    [ "$rate" -gt 0 ] && min_interval=$(awk -v r="$rate" 'BEGIN{printf "%.3f", 1/r}')
    local now; now=$(date +%s.%N 2>/dev/null || date +%s)
    local elapsed=$(awk -v n="$now" -v l="$_THROTTLE_LAST" 'BEGIN{print n-l}')
    if (( $(awk -v e="$elapsed" -v m="$min_interval" 'BEGIN{print (e < m)}') )); then
        local sleep_t; sleep_t=$(awk -v m="$min_interval" -v e="$elapsed" 'BEGIN{print m-e}')
        sleep "$sleep_t" 2>/dev/null || true
    fi
    _THROTTLE_LAST=$(date +%s.%N 2>/dev/null || date +%s)
}

throttle_host() {
    # throttle_host <host> — respects OMNI_HOST_BUDGET (concurrent per host)
    local host="$1"
    local budget="${OMNI_HOST_BUDGET:-25}"
    # Simple semaphore via temp files
    local sem_dir="${OUTDIR:-${W:-.}}/tmp/throttle"
    mkdir -p "$sem_dir"
    local sem_file="$sem_dir/$host"
    local count=0
    [ -f "$sem_file" ] && count=$(cat "$sem_file" 2>/dev/null || echo 0)
    while [ "$count" -ge "$budget" ]; do
        sleep 0.1
        count=$(cat "$sem_file" 2>/dev/null || echo 0)
    done
    echo $((count + 1)) > "$sem_file"
}

throttle_host_release() {
    local host="$1"
    local sem_dir="${OUTDIR:-${W:-.}}/tmp/throttle"
    local sem_file="$sem_dir/$host"
    [ -f "$sem_file" ] && {
        local count; count=$(cat "$sem_file" 2>/dev/null || echo 1)
        [ "$count" -gt 1 ] && echo $((count - 1)) > "$sem_file" || rm -f "$sem_file"
    }
}

#------------------------------------------------------------------------------
# Temp File Management (isolated per scan)
#------------------------------------------------------------------------------
TMP_DIR=""
tmp_file() {
    # tmp_file [prefix] -> unique path under $TMP_DIR (or /tmp fallback)
    local prefix="${1:-tmp}"
    [ -z "$TMP_DIR" ] && TMP_DIR="${OUTDIR:-${W:-.}}/tmp"
    mkdir -p "$TMP_DIR"
    mktemp "$TMP_DIR/${prefix}.XXXXXX" 2>/dev/null || mktemp "/tmp/${prefix}.XXXXXX"
}

cleanup_tmp() {
    [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR" 2>/dev/null
}
trap 'cleanup_tmp' EXIT

#------------------------------------------------------------------------------
# Logging (unified colors, tee to log files)
#------------------------------------------------------------------------------
# Colors (can be disabled by NO_COLOR=1 or non-tty)
if [ -t 1 ] && [ "${NO_COLOR:-0}" != "1" ]; then
    C_RST="\033[0m"; C_RED="\033[0;31m"; C_GRN="\033[0;32m"
    C_YLW="\033[1;33m"; C_BLU="\033[0;34m"; C_CYN="\033[0;36m"
    C_MAG="\033[0;35m"; C_WHT="\033[1;37m"
else
    C_RST=""; C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_CYN=""; C_MAG=""; C_WHT=""
fi

LOGFILE="${LOGFILE:-${OUTDIR:-${W:-.}}/logs/scan.log}"
VERBOSE_LOG="${VERBOSE_LOG:-${OUTDIR:-${W:-.}}/logs/scan.verbose.log}"
mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null
: > "$LOGFILE"; : > "$VERBOSE_LOG"

log()  { echo -e "${C_CYN}[$(date +%H:%M:%S)]${C_RST} $*" | tee -a "$LOGFILE"; }
vlog() { echo -e "${C_MAG}[$(date +%H:%M:%S)]${C_RST} $*" >> "$VERBOSE_LOG"; [ "${VERBOSE:-0}" = "1" ] && echo -e "${C_MAG}[$(date +%H:%M:%S)]${C_RST} $*"; }
ok()   { echo -e "  ${C_GRN}[+]${C_RST} $*" | tee -a "$LOGFILE"; }
warn() { echo -e "  ${C_YLW}[!]${C_RST} $*" | tee -a "$LOGFILE"; }
err()  { echo -e "  ${C_RED}[-]${C_RST} $*" | tee -a "$LOGFILE"; }

banner_phase() {
    echo -e "\n${C_BLU}══════════════════════════════════════════════════════════════${C_RST}"
    echo -e "${C_BLU}${C_WHT}  $1${C_RST}"
    echo -e "${C_BLU}══════════════════════════════════════════════════════════════${C_RST}" | tee -a "$LOGFILE"
}

dbg() { [ "${DEBUG:-0}" = "1" ] && vlog "DEBUG: $*"; }

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------
tool_exists() { command -v "$1" >/dev/null 2>&1; }

count_lines() {
    local f total=0
    for f in "$@"; do [ -f "$f" ] && total=$((total + $(wc -l < "$f"))); done
    echo "$total"
}

html_esc() { sed -e 's/&/\&/g' -e 's/</\</g' -e 's/>/\>/g' -e 's/"/\"/g'; }

sanitize_name() { echo "$1" | sed 's/[^A-Za-z0-9._:-]/_/g'; }

is_ip() {
    local a b c d
    [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d <<< "$1"
    [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ]
}

derive_root() {
    local d="$1"
    case "$d" in
        *.co.uk|*.org.uk|*.gov.uk|*.ac.uk|*.com.au|*.co.jp|*.com.br|*.co.in|\
        *.co.za|*.com.mx|*.com.tr|*.com.ar|*.com.pe|*.com.co)
            echo "$d" | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}' ;;
        *)  echo "$d" | awk -F. '{print $(NF-1)"."$NF}' ;;
    esac
}

# Authenticated curl wrapper (carries -H headers from CLI)
wreq() {
    if [ ${#AUTH_ARGS[@]:-0} -gt 0 ]; then
        curl -sk --max-time 8 "${AUTH_ARGS[@]}" "$@"
    else
        curl -sk --max-time 8 "$@"
    fi
}

# Version comparator (for CVE correlation) — D3fault-death's battle-tested version
ver_cmp() {
    local a="$1" op="$2" b="$3" ai bi i
    for i in 1 2 3 4 5; do
        ai=$(echo "$a" | awk -F. -v n="$i" '{print (n<=NF)?$n:0}' | grep -oE '^[0-9]+' || echo 0)
        bi=$(echo "$b" | awk -F. -v n="$i" '{print (n<=NF)?$n:0}' | grep -oE '^[0-9]+' || echo 0)
        [ -z "$ai" ] && ai=0; [ -z "$bi" ] && bi=0
        ai=$((10#$ai)); bi=$((10#$bi))
        if [ "$ai" -gt "$bi" ]; then case "$op" in gt|ge) return 0;; *) return 1;; esac; fi
        if [ "$ai" -lt "$bi" ]; then case "$op" in lt|le) return 0;; *) return 1;; esac; fi
    done
    case "$op" in eq|ge|le) return 0;; *) return 1;; esac
}

# Phase mark (for HuntOps dashboard)
phase_mark() {
    local phase="$1" exit_code="$2"
    local mark_file="${OUTDIR:-${W:-.}}/logs/.phases"
    mkdir -p "$(dirname "$mark_file")"
    echo "$phase|$exit_code|$(date +%s)" >> "$mark_file"
}

# Export functions for xargs/bash -c subshells
export -f esc_rec add_finding add_candidate add_info
export -f find_tool resolve_wordlist throttle_global throttle_host throttle_host_release
export -f tmp_file wreq ver_cmp is_ip derive_root sanitize_name html_esc count_lines
export -f in_scope load_scope filter_scope ip_in_cidr ip2dec