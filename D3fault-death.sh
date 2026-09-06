#!/usr/bin/env bash
#===============================================================================
#  D3FAULT-DEATH — Bug Bounty Recon & Vulnerability Scanner
#
#  ██████╗ ██████╗ ███████╗ █████╗ ██╗   ██╗██╗  ████████╗
#  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██║  ╚══██╔══╝
#  ██║  ██║██████╔╝█████╗  ███████║██║   ██║██║     ██║
#  ██║  ██║██╔══██╗██╔══╝  ██╔══██║██║   ██║██║     ██║
#  ██████╔╝██║  ██║██║     ██║  ██║╚██████╔╝███████╗██║
#  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
#
#  Author   : ZOLDEK
#  GitHub   : https://github.com/Mazen7771
#  LinkedIn : linkedin.com/in/mazen-basher
#
#  A chronological, self-feeding recon + vulnerability pipeline for authorized
#  bug bounty work. Every phase consumes the output of the phase before it, so
#  results cascade: OSINT -> DNS -> subdomains -> resolve -> ports -> live web
#  -> fingerprint -> content -> historical URLs -> JS endpoints -> parameters
#  -> vulnerability scan -> CVE correlation -> report.
#
#  USAGE:
#    ./D3fault-death.sh -d example.com                 # bug-bounty scan (default)
#    ./D3fault-death.sh -t 1.2.3.4                     # scan an IP
#    ./D3fault-death.sh -d example.com -m quick        # fast first pass
#    ./D3fault-death.sh -d example.com -m passive      # no active scanning
#    ./D3fault-death.sh -d example.com -m active       # ports/web/vuln only
#    ./D3fault-death.sh -d example.com -m full         # everything (no sqlmap)
#    ./D3fault-death.sh -d example.com -m bb           # everything incl sqlmap
#    ./D3fault-death.sh -d example.com -o /tmp/scan    # custom output dir
#    ./D3fault-death.sh -d example.com -H 'Cookie: ...'   # authenticated testing
#    ./D3fault-death.sh -i                             # install missing tools
#
#  OPTIONS:
#    -d <domain>   Target domain (e.g. example.com)
#    -t <ip>       Target IP address
#    -o <dir>      Output directory (default: ./death_<target>_<date>)
#    -m <mode>     quick | passive | active | full | bb   (default: bb)
#    -i            Install missing tools (apt/go/pip) and exit
#    -h            Show this help
#
#  DISCLAIMER: Authorized use only. This tool actively scans and probes
#  targets. Only run it against systems you own or have written permission
#  to test. Always respect the bug-bounty program scope.
#===============================================================================
set -u   # error on undefined variables (no -e: recon tools fail a lot)

#------------------------------------------------------------------------------
# Global configuration
#------------------------------------------------------------------------------
VERSION="2.0.0"
AUTHOR="ZOLDEK"
GITHUB="https://github.com/Mazen7771"
LINKEDIN="linkedin.com/in/mazen-basher"
START_TIME=$(date +%s)

DO_INSTALL=0
VERBOSE=0
MODE="bb"
DOMAIN=""
IP=""
OUTDIR=""
AUTH_ARGS=()   # repeated -H "Header: value" for authenticated testing

# Pipeline phase flags (set per mode)
RUN_OSINT=0; RUN_DNS=0; RUN_SUB=0; RUN_PORTS=0; RUN_WEB=0; RUN_CONTENT=0
RUN_HIST=0; RUN_JS=0; RUN_PARAM=0; RUN_SECRETS=0; RUN_TAKEOVER=0; RUN_VULN=0
RUN_INTEL=0; RUN_CVE=0; RUN_RANK=0; RUN_SHOT=0; RUN_REPORT=0; RUN_SQLMAP=0
RUN_CANDIDATES=0

# Phase skip flags (overridden by --skip-* CLI options)
SKIP_CONTENT=0; SKIP_PARAMS=0; SKIP_INTEL=0; SKIP_HIST=0
SKIP_JS=0; SKIP_SECRETS=0; SKIP_TAKEOVER=0; SKIP_SQLMAP=0
SKIP_CANDIDATES=0

SCOPE_FILE=""
WATCH_DIR=""
TEST_ACCOUNT=""

# Wordlists (best-effort)
WLD_DNS="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
WLD_WEB="/usr/share/wordlists/dirb/common.txt"
WLD_WEB2="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"

# theHarvester passive sources (curated subset - "all" is too slow)
HARVESTER_SOURCES="crtsh,dnsdumpster,duckduckgo,hackertarget,otx,rapiddns,urlscan,bing,google"

# Parallelism / depth (override via environment)
RESOLVE_PARALLEL="${RESOLVE_PARALLEL:-50}"
MAX_RESOLVE="${MAX_RESOLVE:-15000}"
SQLMAP_CAP="${SQLMAP_CAP:-5}"          # max sqlmap targets in bb mode
GAU_CAP="${GAU_CAP:-5000}"             # max historical URLs to keep
GAU_TIMEOUT="${GAU_TIMEOUT:-180}"      # gau cap (archive APIs can hang)
WAYBACK_TIMEOUT="${WAYBACK_TIMEOUT:-120}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-300}"   # reduced from 1800s (5 min default)
RANK_CAP="${RANK_CAP:-25}"             # how many top targets to list in report
SHOT_TIMEOUT="${SHOT_TIMEOUT:-300}"    # gowitness max seconds
MAX_PORTS_LIST="${MAX_PORTS_LIST:-15}" # ports shown in ranking bonus
PARAM_TEST_CAP="${PARAM_TEST_CAP:-20}" # max parameterized URLs to test in strategies/intel
STRATEGY_TIMEOUT="${STRATEGY_TIMEOUT:-10}"    # per-request timeout for candidate probes

# Host-level concurrency for fingerprint, content, JS phases
HOST_CONCURRENCY="${HOST_CONCURRENCY:-10}"  # parallel hosts in loops

# External data sources (key-gated sources are skipped when the key is unset)
VT_API_KEY="${VT_API_KEY:-}"
ST_API_KEY="${ST_API_KEY:-}"
USE_INTERNETDB="${USE_INTERNETDB:-1}"
USE_COMMONCRAWL="${USE_COMMONCRAWL:-1}"
LIVE_TERMINATOR="${LIVE_TERMINATOR:-1}"   # open an external Terminator live view

# CVE Intelligence Engine (multi-source vulnerability correlation)
CVE_DB_PATH="${CVE_DB_PATH:-${HOME}/.cache/d3fault-death/cve}"   # --cve-db
CVE_WORKERS="${CVE_WORKERS:-5}"          # --cve-workers (parallel lookups)
CVE_CACHE_TTL="${CVE_CACHE_TTL:-86400}"  # --cve-cache-ttl (seconds, default 24h)
NVD_API_KEY="${NVD_API_KEY:-}"           # --nvd-api-key
RUN_CVE_INTEL=1                          # --no-cve to disable

# Colors
R="\033[0;31m"; G="\033[0;32m"; Y="\033[1;33m"; B="\033[0;34m"; C="\033[0;36m"
W="\033[1;37m"; M="\033[0;35m"; NC="\033[0m"

LOGFILE=""
VERBOSE_LOG=""
INTERRUPTED=0

#------------------------------------------------------------------------------
# Logging helpers
#   log()  = the steps (phases, tools launched, results)  -> main terminal + files
#   vlog() = verbose detail (exact commands, per-IP scans, sub-tool activity)
#            -> death.verbose.log always; also the main terminal with -v
#   The external Terminator live window tails the verbose log.
#------------------------------------------------------------------------------
log()  { echo -e "${C}[$(date +%H:%M:%S)]${NC} $*" | tee -a "$LOGFILE"; [ -n "${VERBOSE_LOG:-}" ] && echo -e "${C}[$(date +%H:%M:%S)]${NC} $*" >> "$VERBOSE_LOG"; }
vlog() { [ -n "${VERBOSE_LOG:-}" ] && echo -e "${M}[$(date +%H:%M:%S)]${NC} $*" >> "$VERBOSE_LOG"; [ "$VERBOSE" = "1" ] && echo -e "${M}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "  ${G}[+]${NC} $*" | tee -a "$LOGFILE"; [ -n "${VERBOSE_LOG:-}" ] && echo -e "  ${G}[+]${NC} $*" >> "$VERBOSE_LOG"; }
warn() { echo -e "  ${Y}[!]${NC} $*" | tee -a "$LOGFILE"; [ -n "${VERBOSE_LOG:-}" ] && echo -e "  ${Y}[!]${NC} $*" >> "$VERBOSE_LOG"; }
err()  { echo -e "  ${R}[-]${NC} $*" | tee -a "$LOGFILE"; [ -n "${VERBOSE_LOG:-}" ] && echo -e "  ${R}[-]${NC} $*" >> "$VERBOSE_LOG"; }

#------------------------------------------------------------------------------
# Temp file management (avoids /tmp races across concurrent scans)
#------------------------------------------------------------------------------
TMP_DIR=""
tmp_file() {
    # tmp_file [prefix] -> prints unique temp file path under $TMP_DIR
    # Caller is responsible for cleanup, or rely on exit trap
    local prefix="${1:-tmp}"
    mktemp "$TMP_DIR/${prefix}.XXXXXX" 2>/dev/null || mktemp "/tmp/${prefix}.XXXXXX"
}

cleanup_tmp() {
    [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR" 2>/dev/null
}
trap 'cleanup_tmp' EXIT

#------------------------------------------------------------------------------
# Interrupt handling: one Ctrl+C stops the whole scan.
#   Without a trap, tools run with `|| true` so Ctrl+C only kills the current
#   tool and the script keeps scanning every remaining phase. This handler
#   stops the scan, closes the Terminator live window + tmux dashboard, and
#   kills every child job. A second Ctrl+C force-exits immediately.
#------------------------------------------------------------------------------
interrupt_handler() {
    if [ "$INTERRUPTED" = "1" ]; then exit 130; fi
    INTERRUPTED=1
    echo -e "\n${Y}[!] Ctrl+C received — stopping scan and closing the live view...${NC}" | tee -a "$LOGFILE" 2>/dev/null
    # close the Terminator window (kill the helper process running in it)
    [ -n "${OUTDIR:-}" ] && pkill -f "${OUTDIR}/logs/live-view.sh" 2>/dev/null
    # drop the tmux dashboard session
    command -v tmux >/dev/null 2>&1 && tmux kill-session -t ddeath 2>/dev/null
    # kill all background jobs
    jobs -p 2>/dev/null | xargs -r kill -9 2>/dev/null
    # kill the scan tree. If this script leads its own process group (the normal
    # case when run from a terminal), SIGKILL the whole group so foreground
    # tools die too. Otherwise (e.g. backgrounded / sourced) kill only self.
    local mypgid
    mypgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
    if [ -n "$mypgid" ] && [ "$mypgid" = "$$" ]; then
        kill -9 -- -$$ 2>/dev/null
    else
        kill -9 $$ 2>/dev/null
    fi
    cleanup_tmp
    exit 130
}
trap 'interrupt_handler' INT TERM

banner_phase() {
    echo -e "\n${B}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${B}${W}  $1${NC}"
    echo -e "${B}══════════════════════════════════════════════════════════════${NC}" | tee -a "$LOGFILE"
}

tool_exists() { command -v "$1" >/dev/null 2>&1; }

count_lines() {
    # sums line counts across all matching files (handles globs like nuclei*.txt)
    local f total=0
    for f in "$@"; do
        [ -f "$f" ] && total=$((total + $(wc -l < "$f")))
    done
    echo "$total"
}

html_esc() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

sanitize_name() { echo "$1" | sed 's/[^A-Za-z0-9._:-]/_/g'; }

esc_finding_field() {
    # Sanitize a finding field: replace | and newlines to keep pipe-delimited format intact
    printf '%s' "$1" | tr '|' '/' | tr -d '\n\r'
}

add_finding() {
    # add_finding "SEVERITY" "TOOL" "HOST" "TITLE" "DETAIL" "REF"
    # Normalized, pipe-delimited. '|' and newlines in ALL fields are replaced.
    # Dedup: identical severity|tool|host|title (exact match) lines are only stored once.
    local sev="$(esc_finding_field "$1")"
    local tool="$(esc_finding_field "$2")"
    local host="$(esc_finding_field "$3")"
    local title="$(esc_finding_field "$4")"
    local detail="$(esc_finding_field "$5")"
    local ref="$(esc_finding_field "$6")"
    local key="${sev}|${tool}|${host}|${title}"
    if [ -f "$OUTDIR/findings/findings.txt" ] && \
       grep -qF "${key}|" "$OUTDIR/findings/findings.txt" 2>/dev/null; then
        return 0
    fi
    echo "${key}|${detail}|${ref}" >> "$OUTDIR/findings/findings.txt"
}

#------------------------------------------------------------------------------
# Candidate Engine helpers (ported from HuntOps)
#   CANDIDATE findings: 10-field format
#   CAND|IMPACT_CLASS|HOST|TITLE|CONFIDENCE|EVIDENCE|REPRO_CURL|REF|CVSS31|TAG
#   Content-hash deduplication via $OUTDIR/findings/.keys
#------------------------------------------------------------------------------

esc_candidate_field() {
    # Sanitize a candidate field: replace | and newlines to keep pipe-delimited format intact
    printf '%s' "$1" | tr '|' '/' | tr -d '\n\r'
}

dedup_candidate() {
    # dedup_candidate <content_hash> -> exit 0 if new (not seen), 1 if duplicate
    # Uses $OUTDIR/findings/.keys for content-hash tracking
    local hash="$1"
    local keys_file="$OUTDIR/findings/.keys"
    [ -f "$keys_file" ] && grep -qF "$hash" "$keys_file" 2>/dev/null && return 1
    echo "$hash" >> "$keys_file"
    return 0
}

add_candidate() {
    # add_candidate IMPACT_CLASS HOST TITLE CONFIDENCE EVIDENCE REPRO_CURL REF CVSS31 TAG
    # Emits: CAND|IMPACT_CLASS|HOST|TITLE|CONFIDENCE|EVIDENCE|REPRO_CURL|REF|CVSS31|TAG
    # Content-hash dedup: sha256(CLASS|HOST|TITLE|EVIDENCE)
    local impact_class="$(esc_candidate_field "$1")"
    local host="$(esc_candidate_field "$2")"
    local title="$(esc_candidate_field "$3")"
    local confidence="$(esc_candidate_field "$4")"
    local evidence="$(esc_candidate_field "$5")"
    local repro_curl="$(esc_candidate_field "$6")"
    local ref="$(esc_candidate_field "$7")"
    local cvss31="$(esc_candidate_field "$8")"
    local tag="$(esc_candidate_field "$9")"
    local hash_key
    hash_key=$(printf '%s|%s|%s|%s' "$impact_class" "$host" "$title" "$evidence" | sha256sum | awk '{print $1}')
    dedup_candidate "$hash_key" || return 0
    echo "CAND|${impact_class}|${host}|${title}|${confidence}|${evidence}|${repro_curl}|${ref}|${cvss31}|${tag}" >> "$OUTDIR/findings/candidates.txt"
}

_class_cvss() {
    # _class_cvss <impact_class> -> prints CVSS3.1 vector or empty string
    # Embedded mapping (mirrors HuntOps data/impact-classes.conf)
    case "$1" in
        idor-bola)           echo "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" ;;  # 8.1
        jwt-weak)            echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" ;;  # 9.1
        graphql-introspection) echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" ;;  # 5.3
        ssrf)                echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L" ;;  # 8.2
        open-redirect)       echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" ;;  # 6.1
        race-condition)      echo "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" ;;  # 7.5
        admin-authz)         echo "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" ;;  # 8.8
        secret-exposure)     echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" ;;  # 7.5
        cloud-storage)       echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L" ;;  # 8.2
        subdomain-takeover)  echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" ;;  # 9.8
        cors-misconfig)      echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" ;;  # 6.1
        *)                   echo "" ;;
    esac
}

# Authenticated curl wrapper: every web probe carries the session headers
# given via -H (Cookie / Authorization / etc.) so IDOR & authz tests see the
# app the way a logged-in user does.
wreq() {
    if [ ${#AUTH_ARGS[@]} -gt 0 ]; then
        curl -sk --max-time 8 "${AUTH_ARGS[@]}" "$@"
    else
        curl -sk --max-time 8 "$@"
    fi
}

find_httpx() {
    # Kali ships projectdiscovery httpx as httpx-toolkit; the plain name is the
    # unrelated python3-httpx. Prefer the real one, return chosen command.
    local c
    for c in httpx-toolkit httpx; do
        if command -v "$c" >/dev/null 2>&1 \
           && "$c" -h 2>&1 | grep -qiE 'list|input'; then
            echo "$c"; return 0
        fi
    done
    return 1
}

#------------------------------------------------------------------------------
# Scope enforcement
#   scope file format (one per line):
#     example.com        allow whole domain
#     *.example.com      allow all subdomains
#     !banned.example    deny (overrides allows)
#     1.2.3.0/24         allow CIDR
#   in_scope <host> -> exit 0 if allowed, 1 if not
#------------------------------------------------------------------------------
# Scope rule caches (loaded once via _load_scope_rules)
_SCOPE_ALLOW=()
_SCOPE_DENY=()
_SCOPE_LOADED=0

_load_scope_rules() {
    # Parse SCOPE_FILE once into _SCOPE_ALLOW / _SCOPE_DENY arrays.
    [ "$_SCOPE_LOADED" = 1 ] && return 0
    _SCOPE_LOADED=1
    [ -z "$SCOPE_FILE" ] && return 0
    [ ! -r "$SCOPE_FILE" ] && { warn "scope file not readable: $SCOPE_FILE"; return 0; }
    local pat
    while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        case "$pat" in \#*) continue ;; esac
        pat=$(echo "$pat" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//')
        case "$pat" in
            \!*) pat="${pat#!}"; [ -n "$pat" ] && _SCOPE_DENY+=("$pat") ;;
            *)   [ -n "$pat" ] && _SCOPE_ALLOW+=("$pat") ;;
        esac
    done < "$SCOPE_FILE"
}

in_scope() {
    # in_scope <host> -> exit 0 if host is within scope (deny takes precedence)
    local host="$1" h
    h=$(echo "$host" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//')
    [ -z "$SCOPE_FILE" ] && return 0
    _load_scope_rules

    local pat
    # deny first
    for pat in "${_SCOPE_DENY[@]}"; do
        case "$h" in
            "$pat"|*."$pat") return 1 ;;
        esac
    done

    local allowed=0
    for pat in "${_SCOPE_ALLOW[@]}"; do
        # CIDR
        if echo "$pat" | grep -q '/'; then
            if is_ip "$h" && ip_in_cidr "$h" "$pat"; then allowed=1; fi
            continue
        fi
        case "$pat" in
            \*.*) local base="${pat#\*.}"
                  case "$h" in *."$base"|"$base") allowed=1 ;; esac ;;
            *)    case "$h" in "$pat"|*."$pat") allowed=1 ;; esac ;;
        esac
    done
    [ "$allowed" = 1 ]
}

ip_in_cidr() {
    # ip_in_cidr <ip> <cidr> -> exit 0 if ip is within cidr
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
    # filter_scope <infile> <outfile>: keep only lines whose first token is in scope
    # O(N) by bulk processing with awk instead of per-line in_scope calls
    local inf="$1" outf="$2"
    [ -z "$SCOPE_FILE" ] && { cp "$inf" "$outf"; return 0; }
    _load_scope_rules
    # Build awk program: deny rules first, then allow rules
    local awk_prog="{ h=tolower(\$1); gsub(/^\./, \"\", h) }"
    for pat in "${_SCOPE_DENY[@]}"; do
        pat=$(echo "$pat" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//')
        [ -n "$pat" ] && awk_prog="${awk_prog} h==\"${pat}\"||h~/\.${pat}\$/ { next }"
    done
    local allowed_pat=""
    for pat in "${_SCOPE_ALLOW[@]}"; do
        pat=$(echo "$pat" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//')
        if echo "$pat" | grep -q '/'; then
            # CIDR - handled by in_scope, skip here
            continue
        fi
        case "$pat" in
            \*.*) local base="${pat#\*.}"; allowed_pat="${allowed_pat}h==\"${base}\" || h~/\\.${base}\$/" ;;
            *)    allowed_pat="${allowed_pat}h==\"${pat}\" || h~/\\.${pat}\$/" ;;
        esac
        allowed_pat="${allowed_pat} || "
    done
    if [ -n "$allowed_pat" ]; then
        # Remove trailing " || "
        allowed_pat="${allowed_pat% || }"
        awk_prog="${awk_prog} ${allowed_pat} { print }"
    fi
    awk "$awk_prog" "$inf" > "$outf"
}

#------------------------------------------------------------------------------
# Interactive prompts (easy start: just run the script and enter the URL)
#------------------------------------------------------------------------------

# Arrow-key selection menu. Options come from the global arrays MENU_OPTS
# (parallel MENU_DESC = one-line description per option, optional).
#   arrow_menu <title> <default_index> <result_var>
# Keys: ↑/↓ navigate, Enter pick, q/Esc fall back to the default.
_arrow_render() {
    local sel="$1" i ind col name
    for i in "${!MENU_OPTS[@]}"; do
        if [ "$i" = "$sel" ]; then
            ind="${G}▶${NC}"
            col="${B}${W}"
        else
            ind=" "
            col="${NC}"
        fi
        name=$(printf '%-8s' "${MENU_OPTS[$i]}")
        if [ -n "${MENU_DESC[$i]:-}" ]; then
            printf '  %b  %b%s%b  %b%b\n' "$ind" "$col" "$name" "$NC" "${MENU_DESC[$i]}" "$NC"
        else
            printf '  %b  %b%s%b\n' "$ind" "$col" "$name" "$NC"
        fi
    done
}

arrow_menu() {
    local title="$1" default_idx="$2" key esc esc1 esc2 n
    local -n _result="$3"
    local count="${#MENU_OPTS[@]}"
    local sel="$default_idx"

    [ "$count" -le 0 ] && return 1
    [ "$sel" -lt 0 ] && sel=0
    [ "$sel" -ge "$count" ] && sel=$((count - 1))

    printf '\033[?25l'                    # hide cursor while selecting
    printf '\n%b\n' "$title"
    _arrow_render "$sel"
    while :; do
        key=""
        read -rsn1 key || true
        case "$key" in
            $'\x1b')                      # arrow keys send ESC [ A / B
                esc1=""; esc2=""
                read -rsn1 -t 0.3 esc1 2>/dev/null || true
                read -rsn1 -t 0.3 esc2 2>/dev/null || true
                case "$esc1$esc2" in
                    '[A') sel=$(((sel - 1 + count) % count)) ;;
                    '[B') sel=$(((sel + 1) % count)) ;;
                esac
                ;;
            ''|$'\n'|$'\r') break ;;      # Enter confirms
            [1-9]) n=$((key - 1))         # number key jumps straight to an option
                   if [ "$n" -lt "$count" ]; then sel="$n"; break; fi ;;
            [qQ]) sel="$default_idx"; break ;;   # cancel -> default
        esac
        # redraw in place: up to the first option line, clear, re-render
        printf '\033[%dA\033[J' "$count"
        _arrow_render "$sel"
    done
    printf '\033[?25h\n'                  # restore cursor, leave the menu
    _result="${MENU_OPTS[$sel]}"
    return 0
}

prompt_target() {
    local u=""
    echo
    echo -e "${B}  ╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${B}  ║${NC}  ${W}?  Enter the target you want to scan${NC}"
    echo -e "${B}  ║${NC}  ${C}    domain, IP, or full URL${NC}    ${Y}(e.g. example.com or https://api.site.com/x)${NC}"
    echo -e "${B}  ╚══════════════════════════════════════════════════════════════╝${NC}"
    while [ -z "$u" ]; do
        echo
        printf "  ${G}→${NC} "
        read -r u
        [ -z "$u" ] && echo -e "${Y}    (type a domain or IP, then press Enter)${NC}"
    done
    # normalize: strip scheme, path, trailing slash
    u=$(echo "$u" | sed -E 's|^[a-zA-Z][a-zA-Z0-9+.-]*://||; s|/.*$||; s|/+$||')
    if is_ip "$u"; then IP="$u"; else DOMAIN="$u"; fi
}

prompt_mode() {
    echo
    MENU_OPTS=(bb full quick passive active)
    MENU_DESC=(
        "Full pipeline + sqlmap, secrets, takeover, ranking, screenshots"
        "Everything except sqlmap"
        "Fast first pass (~minutes)"
        "Recon only — no active scanning"
        "Ports, web, content, params + intel testing"
    )
    arrow_menu \
        "${C}? Select scan mode:${NC}  ${Y}(↑/↓ arrows · Enter to pick · q for default ${W}bb${NC}${Y})${NC}" \
        0 MODE
    echo -e "  ${G}✓${NC} Mode: ${W}${MODE}${NC}"
}

# Map the selected mode onto the pipeline phase flags (also re-run after an
# interactive mode pick, since getopts already set the defaults by then).
apply_mode() {
    case "$MODE" in
        quick)   RUN_OSINT=1; RUN_DNS=0;   RUN_SUB=1; RUN_PORTS=1; RUN_WEB=1; RUN_CONTENT=1; RUN_HIST=0; RUN_JS=0; RUN_PARAM=0; RUN_SECRETS=0; RUN_TAKEOVER=0; RUN_VULN=1; RUN_CVE=1; RUN_RANK=1; RUN_SHOT=0; RUN_REPORT=1; RUN_CANDIDATES=0 ;;
        passive) RUN_OSINT=1; RUN_DNS=1;   RUN_SUB=1; RUN_PORTS=0; RUN_WEB=0; RUN_CONTENT=0; RUN_HIST=0; RUN_JS=0; RUN_PARAM=0; RUN_SECRETS=0; RUN_TAKEOVER=0; RUN_VULN=0; RUN_CVE=1; RUN_RANK=0; RUN_SHOT=0; RUN_REPORT=1; RUN_CANDIDATES=0 ;;
        active)  RUN_OSINT=0; RUN_DNS=0;   RUN_SUB=0; RUN_PORTS=1; RUN_WEB=1; RUN_CONTENT=1; RUN_HIST=1; RUN_JS=1; RUN_PARAM=1; RUN_SECRETS=1; RUN_TAKEOVER=1; RUN_VULN=1; RUN_INTEL=1; RUN_CVE=1; RUN_RANK=1; RUN_SHOT=1; RUN_REPORT=1; RUN_CANDIDATES=1 ;;
        full)    RUN_OSINT=1; RUN_DNS=1;   RUN_SUB=1; RUN_PORTS=1; RUN_WEB=1; RUN_CONTENT=1; RUN_HIST=1; RUN_JS=1; RUN_PARAM=1; RUN_SECRETS=1; RUN_TAKEOVER=1; RUN_VULN=1; RUN_INTEL=1; RUN_CVE=1; RUN_RANK=1; RUN_SHOT=1; RUN_REPORT=1; RUN_CANDIDATES=1 ;;
        bb)      RUN_OSINT=1; RUN_DNS=1;   RUN_SUB=1; RUN_PORTS=1; RUN_WEB=1; RUN_CONTENT=1; RUN_HIST=1; RUN_JS=1; RUN_PARAM=1; RUN_SECRETS=1; RUN_TAKEOVER=1; RUN_VULN=1; RUN_INTEL=1; RUN_CVE=1; RUN_RANK=1; RUN_SHOT=1; RUN_REPORT=1; RUN_SQLMAP=1; RUN_CANDIDATES=1 ;;
        *) err "Unknown mode: $MODE (quick|passive|active|full|bb)"; usage ;;
    esac
}

#------------------------------------------------------------------------------
# Version comparator (for CVE correlation)
#   ver_cmp <version_a> <op> <version_b>   -> exit 0 if true
#   ops: eq ne gt ge lt le
#------------------------------------------------------------------------------
ver_cmp() {
    # Compare dotted versions numerically. Each component is reduced to its
    # leading digits so letter suffixes (e.g. 9.3p1, 2.4.49c) compare as the
    # numeric base (9.3, 2.4.49) — avoids false CVE matches on patched builds.
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

#------------------------------------------------------------------------------
# Usage / banner
#------------------------------------------------------------------------------
usage() {
    command cat <<'EOF'
D3FAULT-DEATH - Bug Bounty Recon & Vulnerability Scanner (by ZOLDEK)

USAGE:
  ./D3fault-death.sh                        # interactive (asks for URL + mode)
  ./D3fault-death.sh -d example.com         # bug-bounty scan (default)
  ./D3fault-death.sh -t 1.2.3.4             # scan an IP
  ./D3fault-death.sh -d example.com -m quick
  ./D3fault-death.sh -d example.com -s scope.txt -w last_scan -m bb
  ./D3fault-death.sh -d example.com --skip-content --skip-params --skip-intel  # fast full scan

OPTIONS:
  -d <domain>   Target domain (e.g. example.com)
  -t <ip>       Target IP address
  -o <dir>      Output directory (default: ./death_<target>_<date>)
  -m <mode>     quick | passive | active | full | bb   (default: bb)
  -s <file>     Scope file: one entry per line. Supports example.com,
                *.example.com, !deny.example.com, and IP/CIDR. Hosts not
                in scope are automatically skipped.
  -w <dir>      Watch mode: compare this scan against a previous scan
                output dir; report new subdomains, hosts, ports, findings.
  -H <header>   Repeatable: send this HTTP header on every web probe
                (e.g. "-H 'Cookie: ...'" or "-H 'Authorization: Bearer ...'").
                Enables authenticated testing so IDOR/authz bugs surface.
  -a <email>    Test account email for IDOR/authz high-confidence probes
                (gates Candidate Engine IDOR/BOLA and Admin/AuthZ to HIGH confidence)
  -i            Install missing tools (apt/go/pip) and exit
  -v            Verbose logging
  -h            Show this help

PHASE SKIP FLAGS (override mode defaults):
  --skip-content     Skip content discovery (ffuf/gobuster/dirb) — saves 30-120 min
  --skip-params      Skip parameter discovery (arjun/paraminer) — saves 10-60 min
  --skip-intel       Skip Intel engine (exploit vectors) — saves 10-60 min
  --skip-hist        Skip historical URLs (gau/waybackurls) — saves 5-20 min
  --skip-js          Skip JS endpoint extraction — saves 10-40 min
  --skip-secrets     Skip secret hunting in JS — saves 5-15 min
  --skip-takeover    Skip subdomain takeover checks — saves 2-5 min
  --skip-sqlmap      Skip sqlmap (heavy, mode=bb only) — saves 5-30 min
  --skip-candidates  Skip Candidate Engine (manual-validation leads) — saves 5-15 min

MODES:
  bb        Everything incl sqlmap, secrets, takeover, ranking, screenshots.
            (default)
  full      Everything except sqlmap.
  quick     Fast pass: OSINT, subdomains, top-1000 ports, live probe,
            light nuclei (high+critical), ranking, CVE, report.
  passive   No active scanning: OSINT, DNS, subdomains, resolve, report.
  active    No subdomains: ports, web, content, historical URLs, JS,
            secrets, takeover, vuln scan, ranking, CVE, report.

PIPELINE (each phase feeds the next):
  OSINT -> DNS -> subdomains -> resolve -> ports -> live probe ->
  fingerprint -> content -> historical URLs -> JS endpoints ->
  secrets -> parameters -> takeover -> vulnerability scan ->
  CVE correlation -> ranking -> screenshots -> HTML report

DISCLAIMER: Authorized use only. Actively scans targets; only run against
systems you own or have written permission to test.
EOF
    exit 0
}

print_banner() {
    command cat <<'EOF'
                          ;::::;                  
                        ;::::; :;                   
                      ;:::::'   :;                    
                     ;:::::;     ;.
                    ,:::::'       ;           OOO\\        I hate you,
                    ::::::;       ;          OOOOO\\       You hate me,
                    ;:::::;       ;         OOOOOOOO      We're a disfunctional
                   ,;::::::;     ;'         / OOOOOOO     Family
                 ;:::::::::\`. ,,,;.        /  / DOOOOOO
               .';:::::::::::::::::;,     /  /     DOOOO
              ,::::::;::::::;;;;::::;,   /  /        DOOO
             ;\`::::::\`'::::::;;;::::: ,#/  /          DOOO
             :\`:::::::\`;::::::;;::: ;::#  /            DOOO
             ::\`:::::::\`;:::::::: ;::::# /              DOO
             \`:\`:::::::\`;:::::: ;::::::#/               DOO    
              :::\`:::::::\`;; ;:::::::::##                OO        
              ::::\`:::::::\`;::::::::;:::#                OO
              \`:::::\`::::::::::::;'\`:;::#                O
               \`:::::\`::::::::;' /  / \`:#                     
                ::::::\`:::::;'  /  /   \`#
 ███████╗ ██╗  ██╗ ███████╗ ██╗      ███████╗ ████████╗ ██████╗  ███╗   ██╗
 ██╔════╝ ██║ ██╔╝ ██╔════╝ ██║      ██╔════╝ ╚══██╔══╝ ██╔═══██╗ ████╗  ██║
 ███████╗ █████╔╝  █████╗   ██║      █████╗      ██║    ██║   ██║ ██╔██╗ ██║
 ╚════██║ ██╔═██╗  ██╔══╝   ██║      ██╔══╝      ██║    ██║   ██║ ██║╚██╗██║
 ███████║ ██║  ██╗ ███████╗ ███████╗ ███████╗    ██║    ╚██████╔╝ ██║ ╚████║
 ╚══════╝ ╚═╝  ╚═╝ ╚══════╝ ╚══════╝ ╚══════╝    ╚═╝     ╚═════╝  ╚═╝  ╚═══╝    D3FAULT-DEATH v${VERSION} — Bug Bounty Recon & Vuln Scanner
        by ${AUTHOR}  |  github.com/Mazen7771  |  linkedin.com/in/mazen-basher
EOF
}
#------------------------------------------------------------------------------
# Dependency management
#------------------------------------------------------------------------------
check_deps() {
    local needed_apt=() needed_go=() needed_pip=() c

    # Core
    for c in whois dig host nmap masscan curl jq; do
        tool_exists "$c" || needed_apt+=("$c")
    done

    [ "$RUN_OSINT" = 1 ] && { tool_exists theHarvester || needed_apt+=("theharvester"); }
    [ "$RUN_DNS"   = 1 ] && {
        tool_exists dnsrecon || needed_apt+=("dnsrecon")
        tool_exists dnsenum  || needed_apt+=("dnsenum")
    }
    [ "$RUN_SUB"   = 1 ] && {
        tool_exists subfinder   || needed_apt+=("subfinder")
        tool_exists amass       || needed_apt+=("amass")
        tool_exists sublist3r   || needed_apt+=("sublist3r")
        tool_exists assetfinder || needed_apt+=("assetfinder")
    }
    [ "$RUN_PORTS" = 1 ] && {
        tool_exists nmap    || needed_apt+=("nmap")
        tool_exists masscan || needed_apt+=("masscan")
    }
    [ "$RUN_WEB"   = 1 ] && {
        tool_exists whatweb || needed_apt+=("whatweb")
        tool_exists wafw00f || needed_apt+=("wafw00f")
        tool_exists nikto   || needed_apt+=("nikto")
        tool_exists nuclei  || needed_go+=("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        find_httpx >/dev/null || needed_go+=("github.com/projectdiscovery/httpx/cmd/httpx@latest")
    }
    [ "$RUN_CONTENT" = 1 ] && {
        tool_exists gobuster || needed_apt+=("gobuster")
        tool_exists ffuf     || needed_go+=("github.com/ffuf/ffuf/v2@latest")
        tool_exists dirb     || needed_apt+=("dirb")
        # NEW: Feroxbuster for recursive content discovery
        tool_exists feroxbuster || needed_go+=("github.com/epi052/feroxbuster@latest")
    }
    [ "$RUN_HIST"  = 1 ] && {
        tool_exists gau         || needed_go+=("github.com/lc/gau/v2/cmd/gau@latest")
        tool_exists waybackurls || needed_go+=("github.com/tomnomnom/waybackurls@latest")
    }
    [ "$RUN_PARAM" = 1 ] && {
        tool_exists arjun || needed_pip+=("arjun")
        # NEW: paramspider for deeper param discovery
        tool_exists paramspider || needed_pip+=("paramspider")
    }
    [ "$RUN_VULN"  = 1 ] && {
        tool_exists searchsploit || needed_apt+=("exploitdb")
        tool_exists sqlmap       || needed_apt+=("sqlmap")
        tool_exists wpscan       || needed_apt+=("wpscan")
        # NEW: CMS scanners
        tool_exists droopescan || needed_pip+=("droopescan")
        tool_exists cmsmap     || needed_pip+=("cmsmap")
        # NEW: XSS scanner
        tool_exists dalfox     || needed_go+=("github.com/hahwul/dalfox/v2@latest")
    }
    [ "$RUN_SHOT"  = 1 ] && {
        tool_exists gowitness || needed_go+=("github.com/sensepost/gowitness@latest")
    }
    # NEW: Visual recon (screenshots)
    [ "$RUN_SHOT"  = 1 ] && {
        tool_exists gowitness || needed_go+=("github.com/sensepost/gowitness@latest")
    }
    # NEW: Subdomain takeover
    [ "$RUN_TAKEOVER" = 1 ] && {
        tool_exists subjack || needed_go+=("github.com/haccer/subjack@latest")
        tool_exists subzy   || needed_go+=("github.com/LukaSikic/subzy@latest")
    }
    # NEW: Supply chain / SBOM
    [ "$RUN_CVE" = 1 ] && {
        tool_exists grype || needed_go+=("github.com/anchore/grype/cmd/grype@latest")
        tool_exists syft  || needed_go+=("github.com/anchore/syft/cmd/syft@latest")
    }
    # NEW: API/GraphQL
    [ "$RUN_WEB" = 1 ] && {
        tool_exists kr || needed_go+=("github.com/projectdiscovery/kiterunner/cmd/kr@latest")
    }
    # NEW: WebSocket
    [ "$RUN_WEB" = 1 ] && {
        tool_exists wsrecon || needed_go+=("github.com/nccgroup/wsrecon@latest")
    }
    # NEW: JS Analysis
    [ "$RUN_JS" = 1 ] && {
        tool_exists jsluice || needed_pip+=("jsluice")
        tool_exists mantra  || needed_pip+=("mantra")
    }
    # NEW: JWT attacks
    [ "$RUN_INTEL" = 1 ] && {
        tool_exists jwt_tool || needed_pip+=("jwt_tool")
    }
    # NEW: Cloud recon
    [ "$RUN_OSINT" = 1 ] && {
        tool_exists cloud_enum || needed_pip+=("cloud_enum")
        tool_exists prowler    || needed_pip+=("prowler")
    }

    if [ ${#needed_apt[@]} -gt 0 ] || [ ${#needed_go[@]} -gt 0 ] || [ ${#needed_pip[@]} -gt 0 ]; then
        warn "Missing tools: ${needed_apt[*]} ${needed_go[*]} ${needed_pip[*]}"
        if [ "$DO_INSTALL" = 1 ]; then
            install_deps "${needed_apt[@]}" "${needed_go[@]}" "${needed_pip[@]}"
        else
            warn "Missing tools are skipped gracefully. Install them with:"
            warn "  ./D3fault-death.sh -i"
        fi
    else
        ok "All required tools present."
    fi
}

install_deps() {
    local apt_pkgs=() go_pkgs=() pip_pkgs=() p
    for p in "$@"; do
        case "$p" in
            github.com/*) go_pkgs+=("$p") ;;
            *)            apt_pkgs+=("$p") ;;
        esac
    done
    # theHarvester/pip only for arjun
    pip_pkgs+=("arjun")
    # NEW: Additional pip tools
    pip_pkgs+=("paramspider" "droopescan" "cmsmap" "cloud_enum" "prowler" "jwt_tool" "jsluice" "mantra")
    if [ ${#apt_pkgs[@]} -gt 0 ]; then
        log "apt install: ${apt_pkgs[*]}"
        sudo apt-get update && sudo apt-get install -y "${apt_pkgs[@]}"
    fi
    for g in "${go_pkgs[@]:-}"; do
        [ -z "$g" ] && continue
        log "go install: $g"
        (tool_exists go && go install "$g") || warn "Skipped go install (no Go toolchain) for $g"
    done
    for p in "${pip_pkgs[@]:-}"; do
        [ -z "$p" ] && continue
        log "pip install: $p"
        (tool_exists pip3 && pip3 install --break-system-packages --user "$p") || warn "Skipped pip install for $p"
    done
    log "Installation finished. Re-run the scan."
    exit 0
}

#------------------------------------------------------------------------------
# Target setup
#------------------------------------------------------------------------------
derive_root() {
    local d="$1"
    case "$d" in
        *.co.uk|*.org.uk|*.gov.uk|*.ac.uk|*.com.au|*.co.jp|*.com.br|*.co.in|\
        *.co.za|*.com.mx|*.com.tr|*.com.ar|*.com.pe|*.com.co)
            echo "$d" | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}'
            ;;
        *)  echo "$d" | awk -F. '{print $(NF-1)"."$NF}' ;;
    esac
}

is_ip() {
    # strict IPv4 check with octet range validation
    local a b c d
    [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d <<< "$1"
    [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ]
}

setup_target() {
    if [ -z "$DOMAIN" ] && [ -z "$IP" ]; then
        err "No target specified. Use -d <domain> or -t <ip>"
        usage
    fi
    if [ -n "$DOMAIN" ] && is_ip "$DOMAIN"; then
        warn "-d got an IP; moving it to -t"
        IP="$DOMAIN"; DOMAIN=""
    fi
    DOMAIN_ROOT=""
    if [ -n "$DOMAIN" ] && ! is_ip "$DOMAIN"; then
        DOMAIN_ROOT=$(derive_root "$DOMAIN")
        [ "$DOMAIN_ROOT" != "$DOMAIN" ] && warn "Root domain for scope: $DOMAIN_ROOT"
    fi

    if [ -z "$OUTDIR" ]; then
        local tag="${DOMAIN:-$IP}"
        OUTDIR="./death_${tag}_$(date +%Y%m%d-%H%M%S)"
    fi
    mkdir -p "$OUTDIR"/{logs,osint,dns,subdomains,ports,web,content,urls,vuln,cve,tech,findings,report,tmp}
    TMP_DIR="$OUTDIR/tmp"
    LOGFILE="$OUTDIR/logs/death.log"
    VERBOSE_LOG="$OUTDIR/logs/death.verbose.log"
    : > "$LOGFILE"; : > "$VERBOSE_LOG"

    # Export functions used in xargs bash -c subshells (they must be defined by now)
    export -f tmp_file cleanup_tmp esc_finding_field add_finding wreq find_httpx
    export -f scan_for_secrets intel_hdrs _i _load_scope_rules in_scope
    export -f log vlog ok warn err
    # Export global variables needed by worker subshells
    export LOGFILE VERBOSE_LOG
    mkdir -p "$OUTDIR/findings"; : > "$OUTDIR/findings/findings.txt"
    ok "Output directory: $OUTDIR"
    {
        echo "# D3FAULT-DEATH v$VERSION — $(date)"
        echo "Target: ${DOMAIN:-$IP}  Mode: $MODE"
        echo "Author: $AUTHOR  GitHub: $GITHUB  LinkedIn: $LINKEDIN"
        echo "Root domain: ${DOMAIN_ROOT:-n/a}"
    } >> "$OUTDIR/report/summary.md"
}

#------------------------------------------------------------------------------
# Live dashboard in an external Terminator window
#   Opens a Terminator window with a tmux split: live scan log (left) and the
#   most CPU-active processes (right). Skipped when: not a TTY, headless (no
#   $DISPLAY), terminator is not installed, or LIVE_TERMINATOR=0.
#------------------------------------------------------------------------------
make_live_helper() {
    # Small launcher that Terminator executes; tmux gives us a split-pane
    # dashboard. The verbose-log path is embedded at generation time (no args
    # passed through terminator -e), and every step falls back to an
    # `exec tail --retry` so the window can never close on its own.
    local helper="$OUTDIR/logs/live-view.sh"
    command cat > "$helper" <<'HELPEOF'
#!/usr/bin/env bash
# D3fault-death live dashboard (auto-generated) — verbose log path embedded.
log="@VERBOSE_LOG_PATH@"
[ -n "$log" ] || log="/dev/null"
if command -v tmux >/dev/null 2>&1; then
    tmux kill-session -t ddeath 2>/dev/null
    tmux new-session -d -s ddeath "tail -n 0 -f \"$log\"" 2>/dev/null
    tmux split-window -h -p 35 "watch -n 2 \"ps -eo pcpu,comm,args --sort=-pcpu | head -25\"" 2>/dev/null
    tmux select-pane -L 2>/dev/null
    tmux attach 2>/dev/null || exec tail -n 0 -f "$log"
else
    exec tail -n 0 -f "$log"
fi
HELPEOF
    # embed the real verbose-log path (sed keeps the heredoc quoting intact)
    sed -i "s|@VERBOSE_LOG_PATH@|${VERBOSE_LOG:-/dev/null}|" "$helper"
    chmod +x "$helper"
    echo "$helper"
}

spawn_live_view() {
    [ "${LIVE_TERMINATOR:-1}" = "1" ] || return 0
    [ -t 0 ] || return 0
    [ -n "${DISPLAY:-}" ] || return 0
    tool_exists terminator || { warn "terminator not installed — live window skipped (sudo apt install terminator)"; return 0; }
    [ -n "$VERBOSE_LOG" ] || return 0
    local helper
    helper=$(make_live_helper)
    log "opening Terminator live view (verbose: $VERBOSE_LOG)"
    nohup terminator -T "D3fault-death live - ${DOMAIN:-$IP}" -e "bash $helper" >/dev/null 2>&1 &
    ok "Live view opening in a Terminator window (tail -f $VERBOSE_LOG)"
}

#------------------------------------------------------------------------------
# PHASE 1 — Passive OSINT
#------------------------------------------------------------------------------
phase_osint() {
    [ -z "$DOMAIN" ] && { warn "Phase 1 skipped (no domain)."; return; }
    banner_phase "PHASE 1: OSINT (whois / DNS records / zone transfer / theHarvester)"
    log "→ feeds PHASE 2 (DNS targets) and the final asset map"
    local O="$OUTDIR/osint"

    if tool_exists whois; then
        log "whois $DOMAIN"
        vlog "whois \"$DOMAIN\" -> $O/whois.txt"
        timeout 60 whois "$DOMAIN" > "$O/whois.txt" 2>/dev/null || warn "whois returned no/limited data"
    fi

    if tool_exists dig; then
        log "collecting DNS records (A AAAA MX NS TXT SOA CNAME)"
        for r in A AAAA MX NS TXT SOA CNAME; do
            vlog "dig +noall +answer $DOMAIN $r"
            dig +noall +answer "$DOMAIN" "$r" >> "$O/dns-records.txt" 2>/dev/null
        done
        # Zone-transfer attempts against discovered nameservers (fast, usually refused)
        mapfile -t ns_list < <(dig +short NS "$DOMAIN" 2>/dev/null | sed 's/\.$//')
        for ns in "${ns_list[@]:0:2}"; do
            log "attempting zone transfer on $ns"
            vlog "dig axfr @$ns $DOMAIN"
            timeout 25 dig axfr "@$ns" "$DOMAIN" > "$O/.axfr.tmp" 2>/dev/null || true
            grep -E 'IN\s+[A-Z]{2,5}\s+' "$O/.axfr.tmp" >> "$O/zone-transfer.txt" 2>/dev/null || true
        done
        rm -f "$O/.axfr.tmp"
    fi

    if tool_exists theHarvester && [ "$MODE" != "quick" ]; then
        log "theHarvester (passive; may take a few minutes)"
        vlog "theHarvester -d $DOMAIN -b $HARVESTER_SOURCES -f $O/theharvester.xml"
        timeout 600 theHarvester -d "$DOMAIN" -b "$HARVESTER_SOURCES" -f "$O/theharvester.xml" >/dev/null 2>&1 || true
    fi
    ok "OSINT done -> $O"
}

#------------------------------------------------------------------------------
# PHASE 2 — DNS Enumeration
#------------------------------------------------------------------------------
phase_dns() {
    [ -z "$DOMAIN" ] && { warn "Phase 2 skipped (no domain)."; return; }
    banner_phase "PHASE 2: DNS Enumeration (dnsrecon / dnsenum)"
    log "→ feeds PHASE 3 (subdomain wordlist results merge into scope)"
    local O="$OUTDIR/dns"

    if tool_exists dnsrecon; then
        log "dnsrecon standard + zone transfer"
        vlog "dnsrecon -d $DOMAIN --threads 30 -j $O/dnsrecon.json"
        timeout 600 dnsrecon -d "$DOMAIN" --threads 30 -j "$O/dnsrecon.json" >/dev/null 2>&1 || true
        if [ "$MODE" != "quick" ] && [ -r "$WLD_DNS" ]; then
            log "dnsrecon brute force (subdomain wordlist)"
            vlog "dnsrecon -d $DOMAIN -t brt -D $WLD_DNS --threads 30"
            timeout 900 dnsrecon -d "$DOMAIN" -t brt -D "$WLD_DNS" --threads 30 -j "$O/dnsrecon-bruteforce.json" >/dev/null 2>&1 || true
        fi
    fi
    if tool_exists dnsenum; then
        log "dnsenum --enum"
        local wl=""
        [ -r "$WLD_DNS" ] && [ "$MODE" != "quick" ] && wl="-f $WLD_DNS"
        vlog "dnsenum --enum --threads 20 $wl $DOMAIN"
        # shellcheck disable=SC2086
        timeout 600 dnsenum --enum --threads 20 $wl "$DOMAIN" > "$O/dnsenum.txt" 2>/dev/null || true
    fi
    ok "DNS enum done -> $O"
}

#------------------------------------------------------------------------------
# PHASE 3 — Subdomain Discovery
#------------------------------------------------------------------------------
phase_subdomains() {
    [ -z "$DOMAIN" ] && { warn "Phase 3 skipped (no domain)."; return; }
    banner_phase "PHASE 3: Subdomain Discovery (subfinder / amass / crt.sh / sublist3r / assetfinder)"
    log "→ feeds PHASE 4 (all sources merged and resolved)"
    local S="$OUTDIR/subdomains"
    local jobs=()

    if tool_exists subfinder; then
        log "subfinder -all"
        vlog "subfinder -d $DOMAIN -all -silent"
        ( timeout 600 subfinder -d "$DOMAIN" -all -silent > "$S/subfinder.txt" 2>/dev/null || true ) &
        jobs+=($!)
    else warn "subfinder not installed"; fi

    if tool_exists amass && [ "$MODE" != "quick" ]; then
        log "amass enum -passive (slow, best coverage)"
        vlog "amass enum -passive -d $DOMAIN"
        ( timeout 900 amass enum -passive -d "$DOMAIN" -o "$S/amass.txt" >/dev/null 2>&1 || true ) &
        jobs+=($!)
    fi

    if tool_exists sublist3r; then
        vlog "sublist3r -d $DOMAIN"
        ( timeout 600 sublist3r -d "$DOMAIN" -o "$S/sublist3r.txt" >/dev/null 2>&1 || true ) &
        jobs+=($!)
    fi

    if tool_exists assetfinder; then
        vlog "assetfinder --subs-only $DOMAIN"
        ( timeout 300 assetfinder --subs-only "$DOMAIN" > "$S/assetfinder.txt" 2>/dev/null || true ) &
        jobs+=($!)
    fi

    # crt.sh certificate transparency via curl (no tool needed)
    log "crt.sh certificate transparency"
    vlog "GET https://crt.sh/?q=%25.$DOMAIN (json)"
    ( timeout 120 curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
        | grep -oE '"name_value":"[^"]+"' | sed 's/"name_value":"//;s/"//' \
        | tr ',' '\n' | sed 's/^ *//;s/ *$//' \
        | grep -v '^\*' | grep -Ei "(^|\.)${DOMAIN//./\\.}$" | sort -u > "$S/crtsh.txt" || true ) &
    jobs+=($!)

    # CertSpotter certificate transparency (free, no key)
    log "certspotter certificate transparency"
    vlog "GET https://api.certspotter.com/v1/issuances?domain=$DOMAIN"
    ( timeout 120 curl -s "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" 2>/dev/null \
        | jq -r '.[].dns_names[]?' 2>/dev/null \
        | sed 's/^\*\.//' | grep -Ei "(^|\.)${DOMAIN//./\\.}$" | sort -u > "$S/certspotter.txt" || true ) &
    jobs+=($!)

    # HackerTarget hostsearch (free, no key)
    log "hackertarget hostsearch"
    vlog "GET https://api.hackertarget.com/hostsearch/?q=$DOMAIN"
    ( timeout 60 curl -s "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" 2>/dev/null \
        | cut -d, -f1 | sed 's/^ //' | grep -Ei "(^|\.)${DOMAIN//./\\.}$" | sort -u > "$S/hackertarget.txt" || true ) &
    jobs+=($!)

    # VirusTotal subdomains (needs VT_API_KEY)
    if [ -n "$VT_API_KEY" ]; then
        log "virustotal subdomains"
        vlog "GET https://www.virustotal.com/api/v3/domains/$DOMAIN/subdomains (VT_API_KEY)"
        ( timeout 60 curl -s "https://www.virustotal.com/api/v3/domains/${DOMAIN}/subdomains?limit=100" -H "x-apikey: ${VT_API_KEY}" 2>/dev/null \
            | jq -r '.data[]?.id' 2>/dev/null | grep -Ei "(^|\.)${DOMAIN//./\\.}$" | sort -u > "$S/virustotal.txt" || true ) &
        jobs+=($!)
    fi

    # SecurityTrails subdomains (needs ST_API_KEY)
    if [ -n "$ST_API_KEY" ]; then
        log "securitytrails subdomains"
        vlog "GET https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains (ST_API_KEY)"
        ( timeout 60 curl -s "https://api.securitytrails.com/v1/domain/${DOMAIN}/subdomains" -H "APIKEY: ${ST_API_KEY}" 2>/dev/null \
            | jq -r '.subdomains[]?' 2>/dev/null | sed "s/$/.${DOMAIN}/" \
            | grep -Ei "(^|\.)${DOMAIN//./\\.}$" | sort -u > "$S/securitytrails.txt" || true ) &
        jobs+=($!)
    fi

    for j in "${jobs[@]:-}"; do wait "$j" 2>/dev/null || true; done
    ok "passive subdomain sources finished"

    # Merge, dedupe, scope filter
    : > "$S/all-subdomains.txt"
    for f in "$S"/*.txt; do
        [ -e "$f" ] && [ "$f" != "$S/all-subdomains.txt" ] && command cat "$f" >> "$S/all-subdomains.txt"
    done
    { echo "$DOMAIN"; command cat "$S/all-subdomains.txt"; } \
        | tr '[:upper:]' '[:lower:]' | sed 's/^\.//' \
        | grep -Ei "(^|\.)${DOMAIN//./\\.}$" | sort -u > "$S/scope.txt"
    if [ -n "$SCOPE_FILE" ]; then
        local before
        before=$(count_lines "$S/scope.txt")
        filter_scope "$S/scope.txt" "$S/scope.txt.filtered"
        mv "$S/scope.txt.filtered" "$S/scope.txt"
        ok "Scope filter applied: kept $(count_lines "$S/scope.txt") of $before (from $SCOPE_FILE)"
    fi
    ok "Scope consolidated: $(count_lines "$S/scope.txt") unique hostnames"
}

#------------------------------------------------------------------------------
# PHASE 4 — Resolve (feeds ports + live probe)
#------------------------------------------------------------------------------
phase_resolve() {
    banner_phase "PHASE 4: Resolve hostnames -> IPs"
    log "→ feeds PHASE 5 (nmap targets) and PHASE 6 (live web probe list)"
    local S="$OUTDIR/subdomains"

    if [ -n "$IP" ]; then
        echo "$IP -> $IP" > "$S/resolved.txt"
        echo "$IP" > "$S/resolved-hosts.txt"
        ok "Using explicit IP target: $IP"
        return
    fi
    [ -z "$DOMAIN" ] && { warn "No domain to resolve."; return; }
    [ ! -f "$S/scope.txt" ] && { echo "$DOMAIN" > "$S/scope.txt"; }

    if [ "$(wc -l < "$S/scope.txt")" -gt "$MAX_RESOLVE" ]; then
        warn "Scope has $(wc -l < "$S/scope.txt") hostnames; resolving only the $MAX_RESOLVE shortest"
    fi
    log "resolving (xargs -P $RESOLVE_PARALLEL)"
    vlog "dig +short (A) each host, $RESOLVE_PARALLEL parallel"
    awk '{print length"\t"$0}' "$S/scope.txt" | sort -n | cut -f2- | head -n "$MAX_RESOLVE" \
        | xargs -P "$RESOLVE_PARALLEL" -I{} bash -c 'host="{}"; ip=$(dig +time=2 +tries=1 +short "$host" 2>/dev/null | grep -E "^[0-9]{1,3}(\.[0-9]{1,3}){3}$" | head -1); [ -n "$ip" ] && printf "%s -> %s\n" "$host" "$ip"' \
        | sort -u > "$S/resolved.txt" 2>/dev/null || true
    awk -F' -> ' '{print $1}' "$S/resolved.txt" > "$S/resolved-hosts.txt" 2>/dev/null
    ok "Resolved $(count_lines "$S/resolved.txt") hostnames -> $S/resolved.txt"
}

#------------------------------------------------------------------------------
# PHASE 5 — Port & Service Scanning (feeds CVE versions)
#------------------------------------------------------------------------------
phase_ports() {
    banner_phase "PHASE 5: Port & Service Scanning (nmap)"
    log "→ feeds PHASE 13 (service versions -> CVE matching)"
    local P="$OUTDIR/ports"
    local targets=()

    if [ -n "$IP" ]; then
        targets+=("$IP")
    elif [ -r "$OUTDIR/subdomains/resolved.txt" ]; then
        mapfile -t targets < <(awk -F' -> ' '{print $2}' "$OUTDIR/subdomains/resolved.txt" | sort -u)
    elif [ -n "$DOMAIN" ]; then
        local rip
        rip=$(dig +short "$DOMAIN" 2>/dev/null | grep -E '^[0-9]' | head -1 || true)
        [ -n "$rip" ] && targets+=("$rip")
    fi
    if [ ${#targets[@]} -eq 0 ]; then warn "No IP targets to scan."; return; fi
    if [ ${#targets[@]} -gt 25 ]; then
        warn "Limiting nmap to first 25 unique IPs (${#targets[@]} discovered)."
        targets=("${targets[@]:0:25}")
    fi

    # Shodan InternetDB (free, no key): known open ports per IP
    if [ "${USE_INTERNETDB:-1}" = "1" ]; then
        log "shodan internetdb (known ports/CVEs per IP)"
        vlog "GET https://internetdb.shodan.io/<ip> for ${#targets[@]} IP(s)"
        for t in "${targets[@]}"; do
            local safe; safe=$(sanitize_name "$t")
            ( timeout 20 curl -s "https://internetdb.shodan.io/${t}" > "$P/internetdb-${safe}.json" 2>/dev/null || true ) &
        done
        wait 2>/dev/null || true
        : > "$P/internetdb-ports.txt"
        for t in "${targets[@]}"; do
            local safe; safe=$(sanitize_name "$t")
            jq -r --arg ip "$t" '.ports[]? | "\($ip) \(.)"' "$P/internetdb-${safe}.json" 2>/dev/null >> "$P/internetdb-ports.txt"
        done
        [ -s "$P/internetdb-ports.txt" ] && ok "InternetDB: $(count_lines "$P/internetdb-ports.txt") known open ports -> $P/internetdb-ports.txt"
    fi

    for t in "${targets[@]}"; do
        local safe; safe=$(sanitize_name "$t")
        if [ "$MODE" = "quick" ]; then
            log "nmap -sV --top-ports 1000 $t"
            vlog "nmap -Pn -T4 -sV --top-ports 1000 -oA $P/nmap-$safe-top $t"
            timeout 900 nmap -Pn -T4 -sV --top-ports 1000 -oA "$P/nmap-${safe}-top" "$t" > "$P/nmap-${safe}-top.stdout" 2>&1 || true
        else
            log "nmap -sC -sV -O -p- $t  (slow: full port range)"
            vlog "nmap -Pn -T4 -sC -sV -O -p- -oA $P/nmap-$safe-full $t"
            timeout 3600 nmap -Pn -T4 -sC -sV -O -p- -oA "$P/nmap-${safe}-full" "$t" > "$P/nmap-${safe}-full.stdout" 2>&1 || true
        fi
    done
    local open
    open=$(grep -h 'open' "$P"/nmap-*.gnmap 2>/dev/null | grep -oE '[0-9]+/open' | sort -un | sed 's|/open||' | tr '\n' ' ')
    if [ -n "$open" ]; then ok "Open ports found: $open"; else warn "No open ports detected."; fi
}

#------------------------------------------------------------------------------
# PHASE 6 — Live web probe (feeds fingerprint + all web phases)
#------------------------------------------------------------------------------
phase_web_probe() {
    banner_phase "PHASE 6: Live Web Probe (httpx-toolkit)"
    log "→ feeds PHASES 7-12 (fingerprint, content, urls, params, vuln)"
    local W="$OUTDIR/web"
    local scope_file="$OUTDIR/subdomains/resolved-hosts.txt"
    [ -r "$scope_file" ] && [ -s "$scope_file" ] || scope_file="$OUTDIR/subdomains/scope.txt"
    if [ ! -r "$scope_file" ] || [ ! -s "$scope_file" ]; then
        # active/IP mode has no subdomain files — build a one-line probe list
        printf '%s\n' "${DOMAIN:-$IP}" > "$OUTDIR/web/.probe-list.txt"
        scope_file="$OUTDIR/web/.probe-list.txt"
    fi

    local hx
    hx=$(find_httpx || true)
    if [ -n "$hx" ]; then
        log "$hx probing $scope_file"
        vlog "$hx -silent -l $scope_file -title -status-code -tech-detect -follow-redirects"
        timeout 600 "$hx" -silent -l "$scope_file" -title -status-code -tech-detect \
            -follow-redirects -o "$W/http.txt" >/dev/null 2>&1 || true
    else
        warn "httpx not installed; using curl probe"
        vlog "curl -s -o /dev/null -w %{http_code} http(s)://<host>"
        while IFS= read -r h; do
            [ -z "$h" ] && continue
            for proto in http https; do
                code=$(timeout 6 wreq -o /dev/null -w '%{http_code}' "$proto://$h" 2>/dev/null || true)
                [ "$code" != "000" ] && echo "$proto://$h [$code]" >> "$W/http.txt"
            done
        done < "$scope_file"
    fi
    [ -f "$W/http.txt" ] && awk '{print $1}' "$W/http.txt" | sort -u > "$W/live-urls.txt"
    ok "Live web targets: $(count_lines "$W/live-urls.txt") -> $W/live-urls.txt"
}

#------------------------------------------------------------------------------
# PHASE 7 — Tech fingerprint (feeds CVE + WP detection)
#------------------------------------------------------------------------------
phase_fingerprint() {
    banner_phase "PHASE 7: Fingerprinting (whatweb / wafw00f)"
    log "→ feeds PHASE 12 (wpscan if WordPress) and PHASE 13 (versions -> CVE)"
    local W="$OUTDIR/web"
    [ ! -f "$W/live-urls.txt" ] && { warn "No live hosts to fingerprint."; return; }

    # Run whatweb and wafw00f in parallel across hosts using xargs
    local concurrency="${HOST_CONCURRENCY:-10}"

    if tool_exists whatweb; then
        log "whatweb -a 3 (parallel: $concurrency hosts)"
        xargs -P "$concurrency" -I{} bash -c '
            url="$1"; safe=$(printf "%s" "$url" | sed "s|https\?://||; s|[:/]|_|g");
            timeout 120 whatweb -a 3 "$url" > '"$W"'/whatweb-${safe}.txt 2>/dev/null || true
        ' _ {} < "$W/live-urls.txt"
    fi

    if tool_exists wafw00f; then
        log "wafw00f (parallel: $concurrency hosts)"
        xargs -P "$concurrency" -I{} bash -c '
            url="$1"; safe=$(printf "%s" "$url" | sed "s|https\?://||; s|[:/]|_|g");
            timeout 120 wafw00f "$url" > '"$W"'/waf-${safe}.txt 2>/dev/null || true
        ' _ {} < "$W/live-urls.txt"
    fi

    # Aggregate tech stack into one file (feeds CVE matcher)
    : > "$OUTDIR/tech/tech.txt"
    for f in "$W"/whatweb-*.txt; do
        [ -e "$f" ] && command cat "$f" >> "$OUTDIR/tech/tech.txt"
    done
    ok "Fingerprinting done -> $W (tech stack: $OUTDIR/tech/tech.txt)"
}

#------------------------------------------------------------------------------
# PHASE 7.5 — CVE Intelligence Engine (multi-source vulnerability correlation)
#------------------------------------------------------------------------------
phase_cve_intel() {
    banner_phase "PHASE 7.5: CVE Intelligence Engine (NVD + KEV + Exploit-DB + GitHub + Vendors)"
    log "→ feeds PHASE 8+ (prioritized findings) and PHASE 14 (CVE Intelligence report section)"

    local C="$OUTDIR/cve"
    mkdir -p "$C"
    local cache_dir="$CVE_DB_PATH"
    mkdir -p "$cache_dir"/{nvd,kev,exploitdb,github,vendor}

    # Source all CVE intelligence modules
    local lib_dir="$(dirname "${BASH_SOURCE[0]}")/lib"
    if [ -f "$lib_dir/cve_cache.sh" ]; then
        source "$lib_dir/cve_cache.sh"
    fi
    if [ -f "$lib_dir/cve_nvd.sh" ]; then
        source "$lib_dir/cve_nvd.sh"
    fi
    if [ -f "$lib_dir/cve_kev.sh" ]; then
        source "$lib_dir/cve_kev.sh"
    fi
    if [ -f "$lib_dir/cve_exploitdb.sh" ]; then
        source "$lib_dir/cve_exploitdb.sh"
    fi
    if [ -f "$lib_dir/cve_github.sh" ]; then
        source "$lib_dir/cve_github.sh"
    fi
    if [ -f "$lib_dir/cve_vendor.sh" ]; then
        source "$lib_dir/cve_vendor.sh"
    fi
    if [ -f "$lib_dir/cve_cpe.sh" ]; then
        source "$lib_dir/cve_cpe.sh"
    fi
    if [ -f "$lib_dir/cve_prioritize.sh" ]; then
        source "$lib_dir/cve_prioritize.sh"
    fi

    # Initialize cache
    cve_cache_init "$cache_dir"

    # Fetch KEV catalog once (shared across all lookups)
    cve_kev_fetch

    # Extract unique software:version pairs from fingerprinting results
    local products_file="$C/products.txt"
    : > "$products_file"

    # From nmap service banners
    if [ -d "$OUTDIR/ports" ]; then
        grep -hE '^[0-9]+/tcp\s+open' "$OUTDIR"/ports/nmap-*.nmap 2>/dev/null \
            | awk '{$1="";$2="";$3="";sub(/^  +/,"");print}' \
            | sort -u | while IFS= read -r line; do
                [ -z "$line" ] && continue
                local sw ver
                sw="$line"; ver=""
                if echo "$line" | grep -qE '[0-9]+\.[0-9]+'; then
                    ver=$(echo "$line" | grep -oE '[0-9]+(\.[0-9]+){1,3}[A-Za-z0-9]*' | head -1)
                    sw=$(echo "$line" | sed "s/ $ver .*/ /; s/ $ver$//")
                fi
                [ -n "$sw" ] && echo "$sw|$ver" >> "$products_file"
            done
    fi

    # From whatweb tech stack
    if [ -f "$OUTDIR/tech/tech.txt" ]; then
        # Strip ANSI color codes first
        local clean_tech
        clean_tech=$(sed 's/\x1b\[[0-9;]*m//g' "$OUTDIR/tech/tech.txt")

        # Extract product[version] patterns (whatweb format: Product[version] or Product[os][version])
        echo "$clean_tech" | grep -oE '[A-Za-z0-9._-]+\[[0-9][A-Za-z0-9._-]*\]' | while IFS= read -r t; do
            [ -z "$t" ] && continue
            # Product[version] format
            sw=$(echo "$t" | sed 's/\[.*//')
            ver=$(echo "$t" | grep -oE '\[[0-9][A-Za-z0-9._-]*\]' | head -1 | tr -d '[]')
            [ -n "$sw" ] && [ -n "$ver" ] && echo "$sw|$ver" >> "$products_file"
        done

        # Also extract Product[os][version] format (e.g., HTTPServer[Unix][Apache/2.4.49 (Unix)])
        echo "$clean_tech" | grep -oE '[A-Za-z0-9._-]+\[[A-Za-z0-9._-]*\]\[[A-Za-z0-9/._ ()-]*[0-9]+[A-Za-z0-9/._ ()-]*\]' | while IFS= read -r t; do
            [ -z "$t" ] && continue
            # Product[os][version] - extract the version from the last bracket, strip OS suffix
            sw=$(echo "$t" | sed 's/\[.*//')
            ver=$(echo "$t" | grep -oE '\[[^]]*[0-9]+[^]]*\]' | tail -1 | tr -d '[]' | sed 's/.*\///; s/ *(.*)//')
            [ -n "$sw" ] && [ -n "$ver" ] && echo "$sw|$ver" >> "$products_file"
        done

        # WordPress and PHP special cases
        echo "$clean_tech" | grep -oE 'WordPress\[[0-9][A-Za-z0-9._-]*\]' | while IFS= read -r t; do
            [ -z "$t" ] && continue
            ver=$(echo "$t" | grep -oE '\[[0-9][A-Za-z0-9._-]*\]' | head -1 | tr -d '[]')
            [ -n "$ver" ] && echo "WordPress|$ver" >> "$products_file"
        done
        echo "$clean_tech" | grep -oE 'PHP/[0-9][A-Za-z0-9._-]*' | while IFS= read -r t; do
            [ -z "$t" ] && continue
            ver="${t#PHP/}"
            [ -n "$ver" ] && echo "PHP|$ver" >> "$products_file"
        done
    fi

    # From httpx headers/tech
    if [ -f "$OUTDIR/web/http.txt" ]; then
        grep -hE 'Server:|X-Powered-By:' "$OUTDIR/web/http.txt" 2>/dev/null | \
            sed -E 's/.*(Server|X-Powered-By): *//; s/\/.*$//' | \
            grep -E '[0-9]+\.[0-9]+' | \
            awk -F'[ /]' '{print $1"|"$2}' | sort -u >> "$products_file"
    fi

    # Deduplicate products
    sort -u "$products_file" -o "$products_file"

    local product_count=$(count_lines "$products_file")
    [ "$product_count" -eq 0 ] && { warn "No products with versions found to query for CVEs."; return; }
    log "Querying CVE intelligence for $product_count unique product:version pairs (workers: $CVE_WORKERS)..."

    # Export for worker functions
    export OUTDIR CVE_WORKERS CVE_CACHE_TTL NVD_API_KEY cache_dir
    export -f cve_cache_init cve_cache_get cve_cache_set cve_cache_expire cve_cache_clear
    export -f cve_nvd_query cve_nvd_fetch_with_retry cve_nvd_normalize
    export -f cve_kev_fetch cve_kev_check cve_kev_is_kev
    export -f cve_exploitdb_query cve_exploitdb_check_cve
    export -f cve_github_query cve_github_query_rest
    export -f cve_vendor_query cve_vendor_fetch_fixed_version
    export -f cpe_build cpe_parse ver_cmp ver_normalize ver_satisfies
    export -f cve_prioritize_aggregate cve_prioritize_single cve_priority_score

    # Process products in parallel using xargs
    local intel_output="$C/cve-intel.json"
    local intel_summary="$C/cve-summary.txt"
    : > "$intel_output"
    : > "$intel_summary"

    # Write opening JSON array
    echo '[' > "$intel_output"

    # Worker function to process a single product
    cve_intel_worker() {
        local product_line="$1"
        local sw ver cpe cve_results

        sw=$(echo "$product_line" | cut -d'|' -f1)
        ver=$(echo "$product_line" | cut -d'|' -f2)

        [ -z "$sw" ] && return 0

        # Build CPE string
        cpe=$(cpe_build "$sw" "$ver")
        [ -z "$cpe" ] && cpe="$sw $ver"

        log "  CVE Intel: $sw $ver"

        # Query all sources
        local nvd_results kev_results exploitdb_results github_results vendor_results

        # NVD API
        nvd_results=$(cve_nvd_query "$cpe" "$sw" "$ver" 2>/dev/null || echo '[]')

        # CISA KEV (check against KEV catalog)
        kev_results=$(cve_kev_check "$nvd_results" 2>/dev/null || echo '[]')

        # Exploit-DB
        exploitdb_results=$(cve_exploitdb_query "$sw" "$ver" 2>/dev/null || echo '[]')

        # GitHub Security Advisories
        github_results=$(cve_github_query "$sw" "$ver" 2>/dev/null || echo '[]')

        # Vendor bulletins
        vendor_results=$(cve_vendor_query "$sw" "$ver" 2>/dev/null || echo '[]')

        # Aggregate and prioritize
        cve_results=$(cve_prioritize_aggregate "$sw" "$ver" "$cpe" \
            "$nvd_results" "$kev_results" "$exploitdb_results" "$github_results" "$vendor_results" 2>/dev/null)

        # Output JSON for this product
        if [ -n "$cve_results" ] && [ "$cve_results" != "[]" ]; then
            echo "$cve_results" | sed 's/^/  /' >> "$intel_output"
            echo "," >> "$intel_output"

            # Also write human-readable summary
            echo "$cve_results" | jq -r '.[] | "\(.id)|\(.priority)|\(.cvss)|\(.kev)//false|\(.exploit_available)//false|\(.vendor_fixed_version)//none|\(.description)"' 2>/dev/null \
                | while IFS='|' read -r id priority cvss kev exploit fixed desc; do
                    echo "$sw $ver | $id | $priority | CVSS:$cvss | KEV:$kev | Exploit:$exploit | Fixed:$fixed | $desc" >> "$intel_summary"

                    # Add to findings
                    local sev="High"
                    case "$priority" in
                        IMMEDIATE_ACTION) sev="Critical" ;;
                        URGENT) sev="High" ;;
                        SHOULD_PATCH) sev="Medium" ;;
                        *) sev="Info" ;;
                    esac
                    add_finding "$sev" "cve-intel" "$sw $ver" "$id" "$desc [Priority: $priority, CVSS: $cvss, KEV: $kev, Exploit: $exploit, Fixed: $fixed]" "https://nvd.nist.gov/vuln/detail/$id"
                done
        fi
    }
    export -f cve_intel_worker

    # Run workers in parallel
    cat "$products_file" | xargs -P "$CVE_WORKERS" -I{} bash -c 'cve_intel_worker "{}"'

    # Fix trailing comma and close JSON array
    sed -i '$ s/,$//' "$intel_output" 2>/dev/null || true
    echo ']' >> "$intel_output"

    # Show top findings in summary
    local critical_count urgent_count patch_count total_lines informational_count
    critical_count=$(grep -c 'IMMEDIATE_ACTION' "$intel_summary" 2>/dev/null); critical_count=${critical_count:-0}
    urgent_count=$(grep -c 'URGENT' "$intel_summary" 2>/dev/null); urgent_count=${urgent_count:-0}
    patch_count=$(grep -c 'SHOULD_PATCH' "$intel_summary" 2>/dev/null); patch_count=${patch_count:-0}
    total_lines=$(count_lines "$intel_summary" 2>/dev/null); total_lines=${total_lines:-0}
    # Force integer types (strip any stray whitespace/newlines)
    critical_count=$((critical_count + 0))
    urgent_count=$((urgent_count + 0))
    patch_count=$((patch_count + 0))
    total_lines=$((total_lines + 0))
    informational_count=$((total_lines - critical_count - urgent_count - patch_count))

    ok "CVE Intelligence complete -> $intel_output"
    log "  Summary: ${R}$critical_count Critical${NC} | ${Y}$urgent_count Urgent${NC} | ${C}$patch_count Should Patch${NC} | Informational: $informational_count"
    [ -s "$intel_summary" ] && head -20 "$intel_summary" | while IFS= read -r line; do
        log "  $line"
    done
}

#------------------------------------------------------------------------------
# PHASE 8 — Content discovery (feeds report)
#------------------------------------------------------------------------------
phase_content() {
    banner_phase "PHASE 8: Content Discovery (ffuf / gobuster / dirb)"
    local C="$OUTDIR/content"
    local wordlist="$WLD_WEB"
    [ -r "$WLD_WEB2" ] && wordlist="$WLD_WEB2"
    local live_file="$OUTDIR/web/live-urls.txt"
    [ ! -f "$live_file" ] && { warn "No live hosts to enumerate."; return; }

    local concurrency="${HOST_CONCURRENCY:-10}"

    if tool_exists ffuf; then
        log "ffuf dir (parallel: $concurrency hosts)"
        AUTH_STR="${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}"
        export AUTH_STR
        xargs -P "$concurrency" -I{} bash -c '
            url="$1"; safe=$(printf "%s" "$url" | sed "s|https\?://||; s|[:/]|_|g");
            timeout 600 ffuf -u "$url/FUZZ" -w '"$wordlist"' -mc 200,204,301,302,307,401,403 \
                -s $AUTH_STR -o '"$C"'/ffuf-${safe}.json >/dev/null 2>&1 || true
        ' _ {} < "$live_file"
    elif tool_exists gobuster; then
        log "gobuster dir (parallel: $concurrency hosts)"
        xargs -P "$concurrency" -I{} bash -c '
            url="$1"; safe=$(printf "%s" "$url" | sed "s|https\?://||; s|[:/]|_|g");
            timeout 600 gobuster dir -u "$url" -w '"$wordlist"' -q -o '"$C"'/gobuster-${safe}.txt >/dev/null 2>&1 || true
        ' _ {} < "$live_file"
    elif tool_exists dirb; then
        log "dirb (parallel: $concurrency hosts)"
        xargs -P "$concurrency" -I{} bash -c '
            url="$1"; safe=$(printf "%s" "$url" | sed "s|https\?://||; s|[:/]|_|g");
            timeout 600 dirb "$url" '"$wordlist"' -o '"$C"'/dirb-${safe}.txt >/dev/null 2>&1 || true
        ' _ {} < "$live_file"
    fi
    ok "Content discovery done -> $C"
}

#------------------------------------------------------------------------------
# PHASE 9 — Historical URLs (gau / waybackurls) — feeds JS + params + sqlmap
#------------------------------------------------------------------------------
phase_historical() {
    banner_phase "PHASE 9: Historical URLs (gau / waybackurls)"
    log "→ feeds PHASE 10 (JS endpoints) and PHASE 11 (parameters) and sqlmap"
    local U="$OUTDIR/urls"
    local scope_file="$OUTDIR/subdomains/scope.txt"
    [ -r "$scope_file" ] || scope_file="$DOMAIN"
    [ -z "$DOMAIN" ] && { warn "Historical URL phase needs a domain."; return; }

    if tool_exists gau; then
        log "gau (capped at $GAU_CAP URLs, timeout ${GAU_TIMEOUT}s)"
        vlog "gau --subs $DOMAIN"
        timeout "$GAU_TIMEOUT" gau --subs "$DOMAIN" > "$U/gau.txt" 2>/dev/null || true
    fi
    if tool_exists waybackurls; then
        vlog "waybackurls $DOMAIN"
        ( timeout "$WAYBACK_TIMEOUT" waybackurls "$DOMAIN" > "$U/wayback.txt" 2>/dev/null || true ) &
    fi
    if [ "${USE_COMMONCRAWL:-1}" = "1" ]; then
        log "commoncrawl index (latest crawl)"
        vlog "GET https://index.commoncrawl.org/CC-MAIN-<latest>-index?url=*.$DOMAIN"
        ( idx=$(timeout 30 curl -s "https://index.commoncrawl.org/collinfo.json" 2>/dev/null | jq -r '.[0].id' 2>/dev/null)
          [ -n "$idx" ] || exit 0
          timeout 90 curl -s "https://index.commoncrawl.org/${idx}-index?url=*.${DOMAIN}&output=json&filter=status:200&collapse=urlkey" 2>/dev/null \
              | jq -r '.url' 2>/dev/null | sort -u > "$U/commoncrawl.txt"
        ) &
    fi
    wait 2>/dev/null || true

    : > "$U/all-urls.txt"
    for f in "$U"/gau.txt "$U"/wayback.txt "$U"/commoncrawl.txt; do
        [ -f "$f" ] && command cat "$f" >> "$U/all-urls.txt"
    done
    sort -u "$U/all-urls.txt" -o "$U/all-urls.txt"
    head -n "$GAU_CAP" "$U/all-urls.txt" > "$U/historical.txt"
    # URLs with query parameters (for param discovery + sqlmap)
    grep -E '\?' "$U/historical.txt" | sort -u > "$U/param-urls.txt"
    ok "Historical URLs: $(count_lines "$U/historical.txt"); with params: $(count_lines "$U/param-urls.txt")"
}

#------------------------------------------------------------------------------
# PHASE 10 — JS / endpoint extraction (feeds params)
#------------------------------------------------------------------------------
phase_js() {
    banner_phase "PHASE 10: JS & Endpoint Extraction"
    log "→ feeds PHASE 11 (parameters from JS endpoints)"
    local U="$OUTDIR/urls"
    local live_file="$OUTDIR/web/live-urls.txt"
    local js_found=0

    if tool_exists katana; then
        log "katana crawl (JS + endpoints)"
        vlog "katana -list $live_file -js-crawl -jc -d 2 -silent"
        timeout 600 katana -list "$live_file" -js-crawl -jc -d 2 -silent > "$U/katana.txt" 2>/dev/null || true
    fi
    if tool_exists gospider; then
        vlog "gospider -S $live_file --js -d 2 --sitemap --robots"
        ( timeout 600 gospider -S "$live_file" --js -d 2 --sitemap --robots -q > "$U/gospider.txt" 2>/dev/null || true ) &
    fi

    # Lightweight JS extraction fallback (works without katana/gospider).
    # For each live host: pull the page, list its .js files, then fetch each
    # JS file and pull API-ish endpoint strings out of it.
    # CAP: limit to first 50 JS files total to avoid exponential blowup
    : > "$U/js-files.txt"; : > "$U/js-endpoints.txt"
    local max_js_files=50
    local js_count=0
    if [ -f "$live_file" ]; then
        # First pass: collect all JS file URLs
        local js_urls=()
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            local page
            page=$(timeout 10 wreq "$url" 2>/dev/null || true)
            for js in $(echo "$page" \
                         | grep -oE '<script[^>]+src=["'"'"'][^"'"'"']+["'"'"']' \
                         | grep -oE 'https?://[^"'"'"' ]+\.js[^"'"'"' ]*|//[^"'"'"' ]+\.js[^"'"'"' ]*|/[^"'"'"' ]+\.js[^"'"'"' ]*'); do
                # resolve the JS URL to an absolute URL (relative + protocol-relative)
                local full
                case "$js" in
                    http*) full="$js" ;;
                    //*)   full="https:$js" ;;
                    /*)    full="${url%/}$js" ;;
                    *)     full="${url%/}/$js" ;;
                esac
                js_urls+=("$full")
                ((js_count++))
                [ $js_count -ge $max_js_files ] && break 2
            done
        done < "$live_file"

        # Second pass: fetch and extract endpoints in parallel
        if [ ${#js_urls[@]} -gt 0 ]; then
            log "Extracting endpoints from ${#js_urls[@]} JS files (parallel: $HOST_CONCURRENCY)"
            JF_TMP="$U/js-files.tmp.$$"
            JE_TMP="$U/js-endpoints.tmp.$$"
            : > "$JF_TMP"; : > "$JE_TMP"
            export JF_TMP JE_TMP
            printf '%s\n' "${js_urls[@]}" | xargs -P "$HOST_CONCURRENCY" -I{} bash -c '
                full="$1";
                echo "$full" >> "$JF_TMP";
                timeout 8 wreq "$full" 2>/dev/null \
                    | grep -oE "/(api|v[0-9]|admin|user|login|graphql)[^\" ]{2,}" \
                    | sort -u >> "$JE_TMP"
            ' _ {}
            sort -u "$JF_TMP" >> "$U/js-files.txt" 2>/dev/null
            sort -u "$JE_TMP" >> "$U/js-endpoints.txt" 2>/dev/null
            rm -f "$JF_TMP" "$JE_TMP"
            sort -u "$U/js-files.txt" -o "$U/js-files.txt" 2>/dev/null
            sort -u "$U/js-endpoints.txt" -o "$U/js-endpoints.txt" 2>/dev/null
        fi
    fi
    wait 2>/dev/null || true
    # Merge katana/gospider endpoints
    for f in "$U/katana.txt" "$U/gospider.txt"; do
        [ -f "$f" ] && grep -iE 'api|admin|graphql|js' "$f" >> "$U/js-endpoints.txt"
    done
    sort -u "$U/js-endpoints.txt" -o "$U/js-endpoints.txt" 2>/dev/null
    ok "JS files: $(count_lines "$U/js-files.txt"); endpoints extracted: $(count_lines "$U/js-endpoints.txt")"
}

#------------------------------------------------------------------------------
# PHASE 11 — Parameter discovery (feeds sqlmap)
#------------------------------------------------------------------------------
phase_params() {
    banner_phase "PHASE 11: Parameter Discovery"
    log "→ feeds sqlmap (PHASE 12) with parameterized targets"
    local U="$OUTDIR/urls"

    if tool_exists arjun; then
        local concurrency="${HOST_CONCURRENCY:-10}"
        log "arjun parameter discovery (parallel: $concurrency hosts)"
        AJ_TMP="$U/arjun.tmp.$$"
        : > "$AJ_TMP"
        export AJ_TMP
        xargs -P "$concurrency" -I{} bash -c '
            url="$1";
            timeout 180 arjun -u "$url" -q 2>/dev/null | grep -E "^\?|param" >> "$AJ_TMP" || true
        ' _ {}
        sort -u "$AJ_TMP" >> "$U/arjun.txt" 2>/dev/null
        rm -f "$AJ_TMP"
    fi

    # Fallback: collect params from historical + live URLs
    : > "$U/params.txt"
    # Extract query strings from historical and param URLs using awk
    grep -h '?' "$U/historical.txt" "$U/param-urls.txt" 2>/dev/null \
        | awk -F'?' '{print $2}' \
        | tr '&' '\n' \
        | cut -d= -f1 \
        | sort -u >> "$U/params.txt"
    sort -u "$U/params.txt" -o "$U/params.txt"
    ok "Discovered parameters: $(count_lines "$U/params.txt") -> $U/params.txt"
}

#------------------------------------------------------------------------------
# PHASE 11.5 — JS secret hunting (AWS/GitHub/Slack keys, JWTs, private keys)
#------------------------------------------------------------------------------
scan_for_secrets() {
    # scan_for_secrets <host-label>
    # Streams text into the function; greps for high-signal secrets.
    # Each matched line is echoed to stdout (so phase_secrets can tee it to
    # urls/secrets.txt) AND recorded as a finding.
    local host="$1" line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        echo "$line" | grep -qE 'AKIA[0-9A-Z]{16}' \
            && add_finding "High" "secrets" "$host" "AWS Access Key ID" "$line" "https://nvd.nist.gov/vuln/detail/CVE-2019-11206" && echo "$line" && continue
        echo "$line" | grep -qE 'PRIVATE KEY' \
            && add_finding "Critical" "secrets" "$host" "Private key exposed" "$line" "https://owasp.org/www-community/vulnerabilities/Exposed_Secrets" && echo "$line" && continue
        echo "$line" | grep -qE 'ghp_[0-9A-Za-z]{36}' \
            && add_finding "High" "secrets" "$host" "GitHub personal access token" "$line" "https://github.com/search?q=ghp_&type=code" && echo "$line" && continue
        echo "$line" | grep -qE 'AIza[0-9A-Za-z_-]{35}' \
            && add_finding "Medium" "secrets" "$host" "Google/Firebase API key" "$line" "https://cloud.google.com/docs/authentication/api-keys" && echo "$line" && continue
        echo "$line" | grep -qE 'xox[baprs]-[0-9A-Za-z-]{10,}' \
            && add_finding "Medium" "secrets" "$host" "Slack token" "$line" "https://api.slack.com/docs/token-types" && echo "$line" && continue
        echo "$line" | grep -qE 'sk_live_[0-9A-Za-z]{24}' \
            && add_finding "High" "secrets" "$host" "Stripe live secret key" "$line" "https://stripe.com/docs/keys" && echo "$line" && continue
        echo "$line" | grep -qE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}' \
            && add_finding "Info" "secrets" "$host" "JWT token (inspect for auth bypass)" "$line" "https://jwt.io" && echo "$line" && continue
    done
}

phase_secrets() {
    banner_phase "PHASE 11.5: JS Secret Hunting (AWS / GitHub / Slack / keys)"
    log "→ feeds PHASE 12 (credential abuse checks) and the report"
    local U="$OUTDIR/urls"
    local live_file="$OUTDIR/web/live-urls.txt"

    : > "$U/secrets.txt"

    # 1) scan every collected JS file (full URL or path) - parallel
    if [ -f "$U/js-files.txt" ]; then
        log "Scanning JS files for secrets (parallel: $HOST_CONCURRENCY)"
        local js_secrets="$U/.js-secrets.tmp.$$"
        : > "$js_secrets"
        export js_secrets
        xargs -P "$HOST_CONCURRENCY" -I{} bash -c '
            js="$1";
            case "$js" in
                http*) full="$js" ;;
                *)     exit 0 ;;
            esac
            tmp=$(tmp_file sec)
            timeout 10 wreq "$full" 2>/dev/null | scan_for_secrets "$full" > "$tmp"
            [ -s "$tmp" ] && command cat "$tmp" >> "$js_secrets"
            rm -f "$tmp"
        ' _ {} < "$U/js-files.txt"
        command cat "$js_secrets" >> "$U/secrets.txt" 2>/dev/null
        rm -f "$js_secrets"
    fi

    # 2) scan homepages of live hosts - parallel
    if [ -f "$live_file" ]; then
        log "Scanning live hosts for secrets (parallel: $HOST_CONCURRENCY)"
        local live_secrets="$U/.live-secrets.tmp.$$"
        : > "$live_secrets"
        export live_secrets
        xargs -P "$HOST_CONCURRENCY" -I{} bash -c '
            url="$1";
            tmp=$(tmp_file sec)
            timeout 10 wreq "$url" 2>/dev/null | scan_for_secrets "$url" > "$tmp"
            [ -s "$tmp" ] && command cat "$tmp" >> "$live_secrets"
            rm -f "$tmp"
        ' _ {} < "$live_file"
        command cat "$live_secrets" >> "$U/secrets.txt" 2>/dev/null
        rm -f "$live_secrets"
    fi

    sort -u "$U/secrets.txt" -o "$U/secrets.txt" 2>/dev/null
    local n
    n=$(count_lines "$U/secrets.txt")
    ok "Secrets scan done: $n potential secret lines -> $U/secrets.txt"
}

#------------------------------------------------------------------------------
# PHASE 11.6 — Subdomain takeover + exposure candidates
#------------------------------------------------------------------------------
TAKEOVER_PROVIDERS="github.io|herokuapp.com|herokudns.com|s3.amazonaws.com|cloudfront.net|azurewebsites.net|azureedge.net|blob.core.windows.net|cname.vercel-dns.com|netlify.app|shopify.com|zendesk.com|wordpress.com|fastly.net|pantheon.io|surge.sh|bitbucket.io|wpengine.com|tumblr.com|acquia-sites.com|usergarden.com|readme.io|ghproxy.com|ngrok.io"

phase_takeover() {
    banner_phase "PHASE 11.6: Subdomain Takeover & Exposure Candidates"
    log "→ findings feed PHASE 14 (report); verification is manual (claim the CNAME)"
    local S="$OUTDIR/subdomains"
    local T="$OUTDIR/takeover"
    mkdir -p "$T"
    : > "$T/takeover-candidates.txt"

    [ -f "$S/scope.txt" ] || return

    # Subdomain takeover check - parallel
    local concurrency="${HOST_CONCURRENCY:-10}"
    local tk_cand="${T}/.candidates.tmp.$$"
    : > "$tk_cand"
    export tk_cand
    log "Checking subdomain takeovers (parallel: $concurrency)"
    local providers_regex
    providers_regex="($(echo "$TAKEOVER_PROVIDERS" | sed 's/|/|/g'))"
    xargs -P "$concurrency" -I{} bash -c '
        host="$1";
        providers_regex="$2";
        cname=$(timeout 8 dig +short CNAME "$host" 2>/dev/null | head -1 | sed "s/\.$//");
        [ -z "$cname" ] && exit 0;
        if echo "$cname" | grep -qE "$providers_regex"; then
            echo "$host -> CNAME $cname" >> "$tk_cand"
            probe=$(timeout 6 wreq -o /dev/null -w "%{http_code}" "http://$host/" 2>/dev/null )
            if [ "$probe" = "000" ] || [ "$probe" = "404" ] || [ "$probe" = "421" ]; then
                add_finding "High" "takeover" "$host" "Subdomain takeover candidate" "CNAME to unclaimed $cname (HTTP $probe)" "https://github.com/EdOverflow/can-i-take-over-xyz"
            else
                add_finding "Medium" "takeover" "$host" "Potential takeover (verify)" "CNAME to $cname, currently serving HTTP $probe" "https://github.com/EdOverflow/can-i-take-over-xyz"
            fi
        fi
    ' _ {} "$providers_regex" < "$S/scope.txt"
    sort -u "$tk_cand" > "$T/takeover-candidates.txt" 2>/dev/null
    rm -f "$tk_cand"

    # Exposure candidates on live hosts (cheap, high signal) - sequential (per-host temp files)
    if [ -f "$OUTDIR/web/live-urls.txt" ]; then
        log "Checking exposure candidates"
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            for path in "/.git/HEAD" "/.git/config" "/.env" "/.gitignore"; do
                local exp_f; exp_f=$(tmp_file exp)
                code=$(timeout 6 wreq -o "$exp_f" -w '%{http_code}' "$url$path" 2>/dev/null )
                if [ "$code" = "200" ] && grep -qiE 'ref:|\[core\]|APP_KEY=|DB_PASS|ls -la' "$exp_f" 2>/dev/null; then
                    add_finding "High" "exposure" "$url" "Sensitive file exposed: $path" "HTTP 200 with content signature" "https://github.com/digininja/DVWA"
                fi
                rm -f "$exp_f"
            done
        done < "$OUTDIR/web/live-urls.txt"
    fi
    ok "Takeover candidates: $(count_lines "$T/takeover-candidates.txt") -> $T (verify before reporting)"
}

#------------------------------------------------------------------------------
# PHASE 12.5 — STRATEGY ENGINE
#   Adaptive attack-vector hunting based on the professional "Ebb & Flow"
#   model: evaluate signals -> try the highest-value attack vector ->
#   if it hits, escalate / expand surface; if it misses, try the next vector.
#   Every attempt is logged so you can see exactly what was tried.
#------------------------------------------------------------------------------
STRAT_LOG=""
strat_note() { echo "[$(date +%H:%M:%S)] $*" >> "$STRAT_LOG"; log "  ${M}STRATEGY ▸${NC} $*"; }
strat_done() { echo "[$(date +%H:%M:%S)]   ↳ $*" >> "$STRAT_LOG"; }

_findings_before() { count_lines "$OUTDIR/findings/findings.txt"; }

strat_hit_report() {
    local before="$1" label="$2"
    local after; after=$(_findings_before)
    if [ "$after" -gt "$before" ]; then
        strat_done "$label: HIT — $((after-before)) new finding(s)"
        log "  ${G}✔ HIT${NC} $label: $((after-before)) new finding(s)"
        return 0
    fi
    strat_done "$label: miss (no new findings)"
    return 1
}

# ---- S1 low-hanging: exposed dev/admin endpoints (always) ----
strat_low_hanging() {
    strat_note "S1 Low-hanging fruit: probe dev/admin/API endpoints on live hosts"
    local live_file="$OUTDIR/web/live-urls.txt"
    [ -f "$live_file" ] || { strat_done "S1: no live hosts"; return 1; }
    local before; before=$(_findings_before)
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local h code body slh_f
        h=$(echo "$url" | sed 's|https\?://||g; s|/.*||g')
        for path in "/actuator" "/actuator/env" "/server-status" "/console" "/phpmyadmin" "/wp-config.php.bak" "/.well-known/security.txt"; do
            slh_f=$(tmp_file slh)
            code=$(timeout 6 wreq -o "$slh_f" -w '%{http_code}' "$url$path" 2>/dev/null )
            [ "$code" = "200" ] || { rm -f "$slh_f"; continue; }
            body=$(grep -oiE 'env|propertySources|Apache Server Status|This page can be displayed|define\s*\(|Tomcat|Jenkins|Grafana|Kibana|Spring Boot|console' "$slh_f" 2>/dev/null | head -1)
            case "$path" in
                /actuator*)  [ -n "$body" ] && add_finding "High" "exposure" "$url$path" "Spring Boot Actuator exposed" "HTTP 200 ($body)" "https://owasp.org/www-project-web-security-testing-guide/" ;;
                /server-status) [ -n "$body" ] && add_finding "High" "exposure" "$url$path" "Apache server-status exposed (info leak)" "HTTP 200 ($body)" "https://httpd.apache.org/docs/2.4/mod/mod_status.html" ;;
                /console)     [ -n "$body" ] && add_finding "Critical" "exposure" "$url$path" "Debug/management console exposed" "HTTP 200 ($body)" "https://owasp.org/www-project-web-security-testing-guide/" ;;
                *)            [ -n "$body" ] && add_finding "Info" "exposure" "$url$path" "Interesting endpoint found" "HTTP 200 ($body)" "-" ;;
            esac
            rm -f "$slh_f"
        done
    done < "$live_file"
    strat_hit_report "$before" "S1 low-hanging"
}

# ---- S2 param injection: open-redirect -> LFI -> SSTI on live params ----
strat_param_tests() {
    strat_note "S2 Parameter injection: open-redirect / LFI / SSTI on discovered params"
    local up="$OUTDIR/urls/param-urls.txt"
    local tech="$OUTDIR/tech/tech.txt"
    [ -f "$up" ] && [ -s "$up" ] || { strat_done "S2: no parameterized URLs found"; return 1; }
    local before; before=$(_findings_before)
    local count=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        count=$((count+1)); [ "$count" -gt "${PARAM_TEST_CAP:-20}" ] && { strat_done "S2: cap reached"; break; }
        local host; host=$(echo "$url" | sed 's|https\?://||g; s|/.*||g')

        # open redirect: append a redirect-ish param pointing to a benign external host
        local rl
        rl=$(timeout 6 wreq -o /dev/null -w '%{redirect_url}' -L --max-redirs 0 "$url&next=//example.com" 2>/dev/null || true)
        case "$rl" in *example.com*) add_finding "Medium" "redirect" "$host" "Open redirect via next= param" "$url&next=//example.com" "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards" ;; esac
        rl=$(timeout 6 wreq -o /dev/null -w '%{redirect_url}' -L --max-redirs 0 "$url&url=//example.com" 2>/dev/null || true)
        case "$rl" in *example.com*) add_finding "Medium" "redirect" "$host" "Open redirect via url= param" "$url&url=//example.com" "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards" ;; esac

        # LFI: inject traversal into file-ish params
        local param
        for param in file path page read dir download template lang include document; do
            local body
            body=$(timeout 6 wreq "$url&$param=../../../../etc/passwd" 2>/dev/null || true)
            if echo "$body" | grep -qE 'root:.*:0:0:'; then
                add_finding "High" "lfi" "$host" "Local File Inclusion via $param" "$url&$param=../../../../etc/passwd" "https://owasp.org/www-community/attacks/Path_Traversal"
                break
            fi
        done

        # SSTI if a template engine is present
        if [ -f "$tech" ] && grep -qiE 'jinja|twig|freemarker|velocity|smarty|handlebars|erb|thymeleaf' "$tech"; then
            local sstib sstib_base
            sstib_base=$(timeout 6 wreq "$url&name=test" 2>/dev/null || true)
            sstib=$(timeout 6 wreq "$url&name=%7B%7B7*7%7D%7D" 2>/dev/null || true)
            # 49 present in probe AND absent from the baseline = evaluated, not echoed
            if echo "$sstib" | grep -qE '\b49\b' && ! echo "$sstib_base" | grep -qE '\b49\b'; then
                add_finding "High" "ssti" "$host" "Server-Side Template Injection ({{7*7}} -> 49)" "$url&name={{7*7}}" "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Server_Side_Template_Injection"
            fi
        fi
    done < "$up"
    strat_hit_report "$before" "S2 param injection"
}

# ---- S3 API & GraphQL discovery ----
strat_api_discovery() {
    strat_note "S3 API discovery: /api /swagger /graphql introspection"
    local live_file="$OUTDIR/web/live-urls.txt"
    [ -f "$live_file" ] || { strat_done "S3: no live hosts"; return 1; }
    local before; before=$(_findings_before)
    : > "$OUTDIR/urls/api-endpoints.txt"
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local host; host=$(echo "$url" | sed 's|https\?://||g; s|/.*||g')
        local code body
        for path in "/graphql" "/swagger" "/swagger.json" "/swagger-ui" "/api-docs" "/openapi.json" "/v1" "/api"; do
            local api_f; api_f=$(tmp_file api)
            code=$(timeout 6 wreq -o "$api_f" -w '%{http_code}' "$url$path" 2>/dev/null )
            [ "$code" = "200" ] || { rm -f "$api_f"; continue; }
            body=$(grep -oiE 'graphql|swagger|openapi|"paths"|"swagger"' "$api_f" 2>/dev/null | head -1)
            case "$path" in
                /graphql) add_finding "High" "api" "$url$path" "GraphQL endpoint exposed" "HTTP 200 ($body)" "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/25-Testing_for_GraphQL" ;;
                /swagger*|/api-docs|/openapi.json) add_finding "Medium" "api" "$url$path" "API documentation exposed" "HTTP 200 ($body)" "https://owasp.org/www-project-api-security/" ;;
                /api|/v1)  add_finding "Info" "api" "$url$path" "API endpoint found" "HTTP 200" "-" ;;
            esac
            rm -f "$api_f"
        done
        # GraphQL introspection if the endpoint was alive
        local gi_f; gi_f=$(tmp_file gi)
        code=$(timeout 6 wreq -o "$gi_f" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
              -d '{"query":"{__schema{types{name}}}"}' "$url/graphql" 2>/dev/null )
        if [ "$code" = "200" ] && grep -qiE '__schema|queryType|types' "$gi_f" 2>/dev/null; then
            add_finding "High" "api" "$url/graphql" "GraphQL introspection enabled" "Schema exposed" "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/25-Testing_for_GraphQL"
            echo "$url/graphql" >> "$OUTDIR/urls/api-endpoints.txt"
        fi
        rm -f "$gi_f"
    done < "$live_file"
    sort -u "$OUTDIR/urls/api-endpoints.txt" -o "$OUTDIR/urls/api-endpoints.txt" 2>/dev/null
    strat_hit_report "$before" "S3 API discovery"
}

# ---- S4 CORS misconfiguration ----
strat_cors_check() {
    strat_note "S4 CORS: test for reflected arbitrary origins"
    local live_file="$OUTDIR/web/live-urls.txt"
    [ -f "$live_file" ] || { strat_done "S4: no live hosts"; return 1; }
    local before; before=$(_findings_before)
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local host; host=$(echo "$url" | sed 's|https\?://||g; s|/.*||g')
        local acao
        acao=$(timeout 6 wreq -H "Origin: https://evil.example.com" -o /dev/null -D - "$url" 2>/dev/null \
               | grep -i '^access-control-allow-origin:' | tr -d '\r' | awk '{print $2}')
        case "$acao" in
            "https://evil.example.com"|"*") add_finding "Medium" "cors" "$host" "CORS misconfiguration (reflects arbitrary origin)" "Access-Control-Allow-Origin: $acao" "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny" ;;
        esac
    done < "$live_file"
    strat_hit_report "$before" "S4 CORS"
}

# ---- S5 cloud storage candidates ----
strat_cloud() {
    strat_note "S5 Cloud storage: S3/GCS/Azure bucket candidates"
    local S="$OUTDIR/subdomains/scope.txt"
    [ -f "$S" ] || { strat_done "S5: no scope"; return 1; }
    local before; before=$(_findings_before)
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        case "$host" in
            *.s3.*.amazonaws.com|*.s3.amazonaws.com|*.blob.core.windows.net|*.storage.googleapis.com|*.azurewebsites.net)
                local code cb_f; cb_f=$(tmp_file cb)
                code=$(timeout 6 wreq -o "$cb_f" -w '%{http_code}' "http://$host/" 2>/dev/null )
                if [ "$code" = "200" ] && grep -qiE 'ListBucketResult|AccessDenied|PublicAccessBlock' "$cb_f" 2>/dev/null; then
                    add_finding "Medium" "cloud" "$host" "Exposed cloud storage bucket" "Listable ($code)" "https://owasp.org/www-project-api-security/"
                fi
                rm -f "$cb_f"
                ;;
        esac
    done < "$S"
    strat_hit_report "$before" "S5 cloud storage"
}

phase_strategies() {
    banner_phase "PHASE 12.5: STRATEGY ENGINE (Ebb & Flow attack-vector hunting)"
    log "→ adaptively tries attack vectors until something sticks; every attempt logged"
    STRAT_LOG="$OUTDIR/vuln/strategy.log"
    : > "$STRAT_LOG"

    # Run the strategy set in professional priority order.
    strat_low_hanging
    strat_param_tests
    strat_api_discovery
    strat_cors_check
    strat_cloud

    # Traceability: record the built-in automated strategies too.
    {
        echo ""
        echo "## Built-in strategy pass"
        echo "- nuclei:     $(count_lines "$OUTDIR/vuln/nuclei.txt" 2>/dev/null) raw results (CVE/XSS/misconfig templates)"
        echo "- nikto:      $(count_lines "$OUTDIR/vuln/nikto-"*.txt 2>/dev/null || echo 0) raw results"
        echo "- sqlmap:     $(count_lines "$OUTDIR/vuln/sqlmap-"*/*.txt 2>/dev/null || echo 0) raw results"
        echo "- wpscan:     $(count_lines "$OUTDIR/vuln/wpscan-"*.txt 2>/dev/null || echo 0) raw results"
        echo "- known-CVE:  version correlation against bundled CVE DB"
        echo "- takeover:   CNAME dead-check against known providers"
        echo "- secrets:    regex scan of JS + homepages"
    } >> "$STRAT_LOG"
    ok "Strategy engine finished -> $STRAT_LOG (see report for the full attack log)"
}

#------------------------------------------------------------------------------
# PHASE 12.5 — Candidate Engine (High-value manual-validation leads)
#   Generates CAND findings: 10-field format with reproduction curls
#   CAND|IMPACT_CLASS|HOST|TITLE|CONFIDENCE|EVIDENCE|REPRO_CURL|REF|CVSS31|TAG
#------------------------------------------------------------------------------
phase_candidates() {
    banner_phase "PHASE 12.5: CANDIDATE ENGINE (High-value manual-validation leads)"
    log "→ generates prioritized candidates with copy-paste reproduction commands"

    local live_file="$OUTDIR/web/live-urls.txt"
    local param_file="$OUTDIR/urls/param-urls.txt"
    local api_file="$OUTDIR/urls/api-endpoints.txt"
    local hist_file="$OUTDIR/urls/historical.txt"
    local secrets_file="$OUTDIR/urls/secrets.txt"
    local scope_file="$OUTDIR/subdomains/scope.txt"
    local cnames_file="$OUTDIR/subdomains/cnames.txt"
    local tech_file="$OUTDIR/tech/tech.txt"
    local cand_dir="$OUTDIR/findings"

    mkdir -p "$cand_dir"
    : > "$cand_dir/candidates.txt"
    : > "$cand_dir/.keys"

    # --- 1. IDOR/BOLA candidates (ported from HuntOps) ---
    _cand_idor() {
        log "  [1/11] IDOR/BOLA: scanning param URLs + API endpoints for object references"
        local count=0
        [ -f "$param_file" ] || return 0

        # HuntOps-style: grep for sequential/numeric identifiers in params (4+ digits)
        # Include the full URL in the match to extract host
        local pool="$param_file $api_file $hist_file"
        local tmp_matches; tmp_matches=$(tmp_file idor_matches)
        grep -haoE "https?://[^ ]*[?&][a-z_]*(id|user|account|subscriber|sub|order|file|doc|member|invoice|payment|ref)[a-z_]*=[0-9]{4,}" $pool 2>/dev/null \
            | sort -u | head -20 > "$tmp_matches"
        while IFS= read -r m; do
            [ -z "$m" ] && continue
            [ "$count" -ge "$PARAM_TEST_CAP" ] && break
            local host; host=$(echo "$m" | sed 's|https\?://||g; s|/.*||g')
            local param_part; param_part=$(echo "$m" | sed 's/.*[?&]\([a-z_]*=[0-9]\{4,\}\).*/\1/')
            local title="IDOR candidate: enumerable parameter $param_part"
            local ev="Sequential/numeric identifier found in a URL parameter — classic broken object-level authorization (OWASP A01)."
            local cvss=$(_class_cvss idor-bola)
            local confidence="LOW"
            local repro=""
            if [ -n "$TEST_ACCOUNT" ]; then
                confidence="HIGH"
                repro="# with your test account: replace ID with yours, then step ±1: curl -sk '$m' -w '%{http_code}'; compare bodies"
            else
                repro="# set --test-account <your@email> and only probe IDs you OWN: curl -sk '$m'"
            fi
            add_candidate "idor-bola" "$host" "$title" "$confidence" "$ev" "$repro" "https://owasp.org/API-Security/editions/2023/en/0xa1-Broken-Object-Level-Authorization/" "$cvss" "idor"
            count=$((count + 1))
        done < "$tmp_matches"
        rm -f "$tmp_matches"

        # BOLA: /api/.../<numeric> object references
        local tmp_bola; tmp_bola=$(tmp_file bola_matches)
        grep -haoE "https?://[^ ]*/api/[a-zA-Z0-9_./-]*/[0-9]{4,}" $pool 2>/dev/null | sort -u | head -10 > "$tmp_bola"
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            [ "$count" -ge "$PARAM_TEST_CAP" ] && break
            local host; host=$(echo "$p" | sed 's|https\?://||g; s|/.*||g')
            local cvss=$(_class_cvss idor-bola)
            local evidence="Numeric object reference in API path. Test object A with a second account's token."
            local repro="# curl -sk -H 'Authorization: Bearer <token-A>' '$p'; then access object owned by account B with token A"
            add_candidate "idor-bola" "$host" "BOLA candidate: $p" "LOW" "$evidence" "$repro" "https://owasp.org/API-Security/editions/2023/en/0xa1-Broken-Object-Level-Authorization/" "$cvss" "bola"
            count=$((count + 1))
        done < "$tmp_bola"
        rm -f "$tmp_bola"
        ok "  IDOR candidates: $count"
    }

    # --- 2. JWT weak algorithm / alg:none candidates (ported from HuntOps) ---
    _cand_jwt() {
        log "  [2/11] JWT: scanning for weak algorithm / alg:none candidates"
        local count=0
        [ -f "$secrets_file" ] || return 0

        # HuntOps: grep for JWTs in secrets file
        local toks
        toks=$(grep -aoE "eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}" "$secrets_file" 2>/dev/null | sort -u | head -5)
        [ -z "$toks" ] && { ok "  JWT candidates: 0"; return 0; }

        local tmp_toks; tmp_toks=$(tmp_file jwt_toks)
        echo "$toks" > "$tmp_toks"
        while IFS= read -r token; do
            [ -z "$token" ] && continue
            [ "$count" -ge 10 ] && break
            # URL-safe base64 decode the header
            local header; header=$(echo "$token" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null)
            [ -z "$header" ] && continue
            local alg; alg=$(echo "$header" | grep -oE '"alg"\s*:\s*"[^"]+"' | head -1)
            if echo "$header" | grep -qiE '"none"|HS256'; then
                local title="JWT with ${alg:-unknown} — test alg:none / weak-signing"
                local ev="JWT header allows alg tampering candidates. Decode: $header"
                local repro="# forge alg:none token: python3 -c \"import base64,json;print(base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()+'.'+base64.urlsafe_b64encode(json.dumps({'sub':'<victim>','admin':1}).encode()).rstrip(b'=').decode()+'.')\" then send as Authorization: Bearer <token>"
                add_candidate "jwt-weak" "$DOMAIN" "$title" "MEDIUM" "$ev" "$repro" "https://auth0.com/blog/critical-vulnerabilities-json-web-token-libraries/" "$(_class_cvss jwt-weak)" "jwt"
                count=$((count + 1))
            fi
        done < "$tmp_toks"
        rm -f "$tmp_toks"
        ok "  JWT candidates: $count"
    }

    # --- 3. GraphQL introspection candidates (ported from HuntOps) ---
    _cand_graphql() {
        log "  [3/11] GraphQL: checking for introspection enabled on API endpoints"
        local count=0
        [ -f "$live_file" ] || return 0

        # GraphQL paths (from HuntOps data/words/graphql-paths.txt)
        local graphql_paths="/graphql /graphql/ /api/graphql /api/graphql/ /api/v1/graphql /api/v2/graphql /gql /gql/ /v1/graphql /v2/graphql /query /query/ /graphiql /graphiql/ /playground /altair /admin/graphql /api/internal/graphql /graphql/console"

        # Test first 3 live hosts
        local hosts_tested=0
        local tmp_live; tmp_live=$(tmp_file graphql_live)
        cat "$live_file" > "$tmp_live"
        while IFS= read -r base; do
            [ -z "$base" ] && continue
            [ "$hosts_tested" -ge 3 ] && break
            hosts_tested=$((hosts_tested + 1))
            local host; host=$(echo "$base" | sed 's|https\?://||g; s|/.*||g')

            for p in $graphql_paths; do
                [ -z "$p" ] && continue
                [ "$count" -ge 5 ] && break
                local gi_f; gi_f=$(tmp_file gi)
                local body
                body=$(timeout "$STRATEGY_TIMEOUT" wreq -o "$gi_f" -X POST -H 'Content-Type: application/json' \
                      -d '{"query":"{__schema{types{name}}}"}' "$base$p" 2>/dev/null)
                if echo "$body" | grep -q '__schema' && echo "$body" | grep -qE '"types"'; then
                    add_candidate "graphql-introspection" "$host" "GraphQL introspection open at $p" "HIGH" \
                        "Introspection query returns schema — enumerate queries/mutations for deeper impact (IDOR/XXE/RCE)." \
                        "curl -sk -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name,fields{name,type{name,ofType}}}}}\"}' '$base$p'" \
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/25-Testing_for_GraphQL" \
                        "$(_class_cvss graphql-introspection)" "graphql"
                    count=$((count + 1))
                fi
                rm -f "$gi_f"
            done
        done < "$tmp_live"
        rm -f "$tmp_live"
        ok "  GraphQL candidates: $count"
    }

    # --- 4. SSRF-prone parameter candidates (ported from HuntOps) ---
    _cand_ssrf() {
        log "  [4/11] SSRF: scanning parameters for SSRF-prone names"
        local count=0
        [ -f "$param_file" ] || [ -f "$api_file" ] || return 0

        # HuntOps ssrf-params.txt wordlist
        local ssrf_params="url uri u link src href dest destination target target_url redirect redirect_url return return_url next next_url continue callback callback_url cb webhook webhook_url hook fetch fetch_url download download_url load load_url proxy proxy_url path file file_path image img image_url img_url pic avatar avatar_url thumbnail thumb_url logo logo_url media media_url source source_url origin origin_url domain host hostname feed feed_url rss rss_url api api_url endpoint service service_url remote remote_url"

        local pool="$param_file $api_file"
        local tmp_ssrf; tmp_ssrf=$(tmp_file ssrf_matches)
        grep -haoE "[?&]($ssrf_params)=[^&]*" $pool 2>/dev/null \
            | grep -vE "oembedResolve" | sort -u | head -15 > "$tmp_ssrf"
        while IFS= read -r m; do
            [ -z "$m" ] && continue
            [ "$count" -ge "$PARAM_TEST_CAP" ] && break
            local param_name=$(echo "$m" | sed 's/^[?&]//; s/=.*//')
            # Need to extract the full URL from param_file to get host
            local full_url=$(grep -m1 "$m" $pool 2>/dev/null | head -1)
            local host="$DOMAIN"
            if [ -n "$full_url" ]; then
                host=$(echo "$full_url" | sed 's|https\?://||g; s|/.*||g')
            fi
            add_candidate "ssrf" "$host" "SSRF-prone parameter: $m" "LOW" \
                "Parameter looks like a fetch/redirect target. Point it at a canary you control (interact.sh). /api/oembedResolve is OUT OF SCOPE for this program." \
                "curl -sk '$full_url' with value 'https://YOUR.canary.interact.sh/'; watch for callback" \
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery" \
                "$(_class_cvss ssrf)" "ssrf"
            count=$((count + 1))
        done < "$tmp_ssrf"
        rm -f "$tmp_ssrf"
        ok "  SSRF candidates: $count"
    }

    # --- 5. Open redirect candidates (ported from HuntOps) ---
    _cand_open_redirect() {
        log "  [5/11] Open Redirect: active probe on redirect parameters"
        local count=0
        [ -f "$live_file" ] || return 0

        # HuntOps redirect-params.txt wordlist
        local redirect_params="url redirect redirect_url next next_url return return_url returnTo return_to continue continue_url dest destination target go out forward callback cb ref refer r u to link uri path"

        # Test first 3 live hosts
        local hosts_tested=0
        local tmp_live; tmp_live=$(tmp_file or_live)
        cat "$live_file" > "$tmp_live"
        while IFS= read -r base; do
            [ -z "$base" ] && continue
            [ "$hosts_tested" -ge 3 ] && break
            hosts_tested=$((hosts_tested + 1))
            local host; host=$(echo "$base" | sed 's|https\?://||g; s|/.*||g')

            # Test common redirect endpoints
            for p in "/login" "/auth" "/signin" "/oauth/authorize" "/redirect" "/refer"; do
                local loc
                loc=$(timeout 12 wreq -o /dev/null -D - "$base$p?next=//evil.example.com" 2>/dev/null \
                    | grep -i '^location:' | tr -d '\r' | head -1)
                if echo "$loc" | grep -qiE "//evil\.example\.com"; then
                    add_candidate "open-redirect" "$host" "Open redirect via ?next on $p" "HIGH" \
                        "Server reflects attacker URL in Location header: $loc" \
                        "curl -skI '$base$p?next=//evil.example.com'" \
                        "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss open-redirect)" "open-redirect"
                    count=$((count + 1))
                fi
            done
        done < "$tmp_live"
        rm -f "$tmp_live"
        ok "  Open redirect candidates: $count"
    }

    # --- 6. Race condition candidates (ported from HuntOps) ---
    _cand_race() {
        log "  [6/11] Race: scanning for race-condition-prone endpoints"
        local count=0
        [ -f "$param_file" ] || [ -f "$hist_file" ] || return 0

        # HuntOps: check robots.txt for race seams
        local rob="$OUTDIR/urls/robots.txt"
        local seams=""
        [ -f "$rob" ] && seams=$(grep -aoE "^/(refer|invite|claim|redeem|coupon|checkout|payment|signup|upgrade|transfer)[a-zA-Z0-9_/-]*" "$rob" | sort -u)
        seams="${seams:-/refer/ /invite/ /claim/}"

        local tmp_seams; tmp_seams=$(tmp_file race_seams)
        echo "$seams" | sort -u | head -10 > "$tmp_seams"
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            # Extract host from the first live URL to build proper repro
            local host="$DOMAIN"
            if [ -f "$live_file" ]; then
                local first_live=$(head -1 "$live_file" 2>/dev/null)
                if [ -n "$first_live" ]; then
                    host=$(echo "$first_live" | sed 's|https\?://||g; s|/.*||g')
                fi
            fi
            add_candidate "logic-race" "$host" "Race condition candidate: $p" "LOW" \
                "State-changing endpoint (referral/claim/checkout). Race N parallel identical requests; >1 success = bug." \
                "for i in \$(seq 1 20); do curl -sk -X POST 'https://$host$p' --data 'code=TEST' & done; wait  (verify with Turbo Intruder/racelyzer)" \
                "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss race-condition)" "race"
            count=$((count + 1))
        done < "$tmp_seams"
        rm -f "$tmp_seams"
        ok "  Race candidates: $count"
    }

    # --- 7. Admin/debug path + host-header poisoning candidates (ported from HuntOps) ---
    _cand_admin_authz() {
        log "  [7/11] Admin/AuthZ: scanning for admin/debug paths + host header poisoning"
        local count=0
        [ -f "$live_file" ] || return 0

        # HuntOps admin-paths.txt wordlist
        local admin_paths="/admin /admin/ /admin/login /administrator /administrator/ /console /console/ /manager /manager/ /dashboard /dashboard/ /panel /panel/ /control /control/ /actuator /actuator/ /server-status /server-info /status /status/ /phpmyadmin /pma /wp-admin /wp-login.php /wp-config.php.bak /.git/config /.env /.env.backup /.gitignore /config.json /config.php.bak /swagger /swagger/ /swagger-ui.html /swagger/index.html /api-docs /v2/api-docs /v3/api-docs /openapi.json /openapi.yaml /.well-known/security.txt /robots.txt /sitemap.xml /crossdomain.xml"

        # Test first 3 live hosts
        local hosts_tested=0
        local tmp_live; tmp_live=$(tmp_file admin_live)
        cat "$live_file" > "$tmp_live"
        while IFS= read -r base; do
            [ -z "$base" ] && continue
            [ "$hosts_tested" -ge 3 ] && break
            hosts_tested=$((hosts_tested + 1))
            local host; host=$(echo "$base" | sed 's|https\?://||g; s|/.*||g')

            while IFS= read -r p; do
                [ -z "$p" ] && continue
                local code_f; code_f=$(tmp_file code)
                local code
                code=$(timeout 5 wreq -o "$code_f" -w '%{http_code}' "$base$p" 2>/dev/null)
                case "$code" in
                    200|401|403)
                        local confidence="LOW"
                        [ "$code" = "200" ] && confidence="MEDIUM"
                        [ -n "$TEST_ACCOUNT" ] && [ "$code" = "401" ] && confidence="HIGH"
                        local evidence="Endpoint from admin/actuator/environment list — check for unauthenticated exposure."
                        local repro="curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' '$base$p'   then inspect 200/403 and body"
                        add_candidate "admin-authz" "$host" "Admin/debug path to verify: $p" "$confidence" "$evidence" "$repro" "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" "$(_class_cvss admin-authz)" "admin"
                        count=$((count + 1))
                        ;;
                esac
                rm -f "$code_f"
            done <<< "$admin_paths"

            # Host header poisoning test (password reset / email change)
            local hh_loc
            hh_loc=$(timeout 5 wreq -o /dev/null -D - -H "Host: evil.example.com" "$base/api/forgot-password" 2>/dev/null \
                     | grep -i '^location:' | tr -d '\r' | head -1)
            if [ -n "$hh_loc" ] && echo "$hh_loc" | grep -q "evil.example.com"; then
                local evidence="If the app builds reset links from Host, poison it to steal tokens."
                local repro="curl -sk -X POST '$base/api/forgot-password' -H 'Host: evil.example.com' --data 'email=<your-test-account>'  then check the email link host"
                add_candidate "logic-flaw" "$host" "Host-header poisoning: test password-reset / email-change" "LOW" "$evidence" "$repro" "https://portswigger.net/web-security/host-header" "$(_class_cvss admin-authz)" "host-header"
                count=$((count + 1))
            fi
        done < "$tmp_live"
        rm -f "$tmp_live"
        ok "  Admin/AuthZ candidates: $count"
    }

    # --- 8. Secret exposure candidates ---
    _cand_secrets() {
        log "  [8/11] Secrets: scanning JS, historical URLs for exposed secrets"
        local count=0
        [ -f "$secrets_file" ] || return 0

        local tmp_secrets; tmp_secrets=$(tmp_file secrets_list)
        cat "$secrets_file" > "$tmp_secrets"
        while IFS= read -r secret; do
            [ -z "$secret" ] && continue
            [ "$count" -ge 30 ] && break

            local host="unknown"
            local impact="secret-exposure"
            local title="Secret exposure"
            local conf="HIGH"

            if echo "$secret" | grep -qE '^AKIA[0-9A-Z]{16}$'; then
                title="AWS Access Key ID exposed"
                impact="secret-exposure"
            elif echo "$secret" | grep -qE '^ghp_[A-Za-z0-9]{36}$'; then
                title="GitHub Personal Access Token exposed"
                impact="secret-exposure"
            elif echo "$secret" | grep -qE '^sk_live_[A-Za-z0-9]{24}$'; then
                title="Stripe Live Secret Key exposed"
                impact="secret-exposure"
            elif echo "$secret" | grep -qE '^xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}$'; then
                title="Slack Bot Token exposed"
                impact="secret-exposure"
            elif echo "$secret" | grep -qE '^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$'; then
                title="JWT token exposed"
                impact="jwt-weak"
                conf="MEDIUM"
            else
                title="Potential secret exposed"
                conf="MEDIUM"
            fi

            local evidence="Found in secrets.txt: ${secret:0:20}..."
            local repro="grep -r '${secret:0:10}' .  # Find source file"
            add_candidate "$impact" "$host" "$title" "$conf" "$evidence" "$repro" "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures" "$(_class_cvss $impact)" "secret"
            count=$((count + 1))
        done < "$tmp_secrets"
        rm -f "$tmp_secrets"
        ok "  Secret candidates: $count"
    }

    # --- 9. Cloud storage bucket candidates (ported from HuntOps) ---
    _cand_cloud() {
        log "  [9/11] Cloud: checking subdomains for cloud storage patterns"
        local count=0
        [ -f "$OUTDIR/subdomains/all-passive.txt" ] || return 0

        # HuntOps cloud-prefixes.txt
        local labels
        labels=$(awk -F. '{print $1}' "$OUTDIR/subdomains/all-passive.txt" 2>/dev/null | sort -u | head -15)
        [ -z "$labels" ] && labels="$DOMAIN"

        local tmp_labels; tmp_labels=$(tmp_file cloud_labels)
        echo "$labels" > "$tmp_labels"
        while IFS= read -r l; do
            [ -z "$l" ] && continue
            [ "$count" -ge 30 ] && break
            for u in "https://$l.s3.amazonaws.com" "https://storage.googleapis.com/$l" "https://$l.blob.core.windows.net"; do
                local code body; body=$(timeout 10 wreq -o /dev/null -D - "$u" 2>/dev/null); code=$(echo "$body" | head -1 | awk '{print $2}')
                if [ "$code" = "200" ] || [ "$code" = "403" ]; then
                    local evidence="HTTP $code on bucket URL. 200+ListBucket/listing XML or 403 (bucket exists) = test for public access."
                    local repro="curl -sk '$u' | head -50   # check for <ListBucketResult>"
                    add_candidate "cloud-storage" "$u" "Possible exposed cloud bucket ($code)" "LOW" "$evidence" "$repro" "https://owasp.org/www-project-web-security-testing-guide/" "$(_class_cvss cloud-storage)" "cloud"
                    count=$((count + 1))
                fi
            done
        done < "$tmp_labels"
        rm -f "$tmp_labels"
        ok "  Cloud candidates: $count"
    }

    # --- 10. Subdomain takeover candidates (ported from HuntOps) ---
    _cand_takeover() {
        log "  [10/11] Takeover: checking CNAME chains for dead providers"
        local count=0
        [ -f "$cnames_file" ] || return 0

        local tmp_cnames; tmp_cnames=$(tmp_file takeover_cnames)
        cat "$cnames_file" > "$tmp_cnames"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            [ "$count" -ge 30 ] && break
            local sub cname
            sub="${line%% -> *}"
            cname="${line##* -> }"
            case "$cname" in
                *.s3.amazonaws.com|s3.amazonaws.com|*.github.io|github.io|*.herokuapp.com|herokuapp.com|*.herokussl.com|herokussl.com|*.netlify.app|netlify.app|*.vercel.app|vercel.app|*.now.sh|now.sh|*.readme.io|readme.io|*.gitlab.io|gitlab.io|*.pantheonsite.io|pantheonsite.io|*.azurewebsites.net|azurewebsites.net|*.cloudapp.azure.com|cloudapp.azure.com|*.trafficmanager.net|trafficmanager.net|*.blob.core.windows.net|blob.core.windows.net|*.surge.sh|surge.sh|*.uservoice.com|uservoice.com|*.wordpress.com|wordpress.com|*.tumblr.com|tumblr.com|*.zendesk.com|zendesk.com|*.freshdesk.com|freshdesk.com|*.bitbucket.io|bitbucket.io|*.fastly.net|fastly.net|*.fastlylb.net|fastlylb.net|*.cargocollective.com|cargocollective.com|*.unbouncepages.com|unbouncepages.com|*.tilda.ws|tilda.ws)
                    add_candidate "takeover" "$sub" "Takeover candidate: CNAME → $cname" "MEDIUM" \
                        "Host points at a takeover-prone provider. Check the provider endpoint returns 'not found' → claimable." \
                        "dig +short $sub CNAME; curl -sk 'https://$sub/' | grep -i 'not found\|does not exist\|no such'" \
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover" \
                        "$(_class_cvss subdomain-takeover)" "takeover"
                    count=$((count + 1))
                    ;;
            esac
        done < "$tmp_cnames"
        rm -f "$tmp_cnames"
        ok "  Takeover candidates: $count"
    }

    # --- 11. CORS misconfiguration candidates ---
    _cand_cors() {
        log "  [11/11] CORS: testing for origin reflection + credentials"
        local count=0
        [ -f "$live_file" ] || return 0

        # Test first 10 live hosts
        local hosts_tested=0
        local test_origins="https://evil.example.com null https://sub.evil.example.com https://evil.example.com.evil.example.com"

        local tmp_live; tmp_live=$(tmp_file cors_live)
        cat "$live_file" > "$tmp_live"
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            [ "$hosts_tested" -ge 10 ] && break
            hosts_tested=$((hosts_tested + 1))
            local host; host=$(echo "$url" | sed 's|https\?://||g; s|/.*||g')

            for origin in $test_origins; do
                local acao acac
                acao=$(timeout 5 wreq -H "Origin: $origin" -o /dev/null -D - "$url" 2>/dev/null \
                       | grep -i '^access-control-allow-origin:' | tr -d '\r' | awk '{print $2}')
                acac=$(timeout 5 wreq -H "Origin: $origin" -o /dev/null -D - "$url" 2>/dev/null \
                       | grep -i '^access-control-allow-credentials:' | tr -d '\r' | awk '{print $2}')
                if [ "$acao" = "$origin" ] || [ "$acao" = "*" ]; then
                    local conf="MEDIUM"
                    [ "$acac" = "true" ] && conf="HIGH"
                    local evidence="Origin '$origin' reflected (ACAO: $acao)${acac:+, Credentials: $acac}"
                    local repro="curl -sk -H 'Origin: $origin' -D - '$url' | grep -i access-control"
                    add_candidate "cors-misconfig" "$host" "CORS misconfiguration: reflects $origin" "$conf" "$evidence" "$repro" "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny" "$(_class_cvss cors-misconfig)" "cors"
                    count=$((count + 1))
                    break
                fi
            done
        done < "$tmp_live"
        rm -f "$tmp_live"
        ok "  CORS candidates: $count"
    }

    # Execute all generators
    _cand_idor
    _cand_jwt
    _cand_graphql
    _cand_ssrf
    _cand_open_redirect
    _cand_race
    _cand_admin_authz
    _cand_secrets
    _cand_cloud
    _cand_takeover
    _cand_cors

    local total_cand
    total_cand=$(count_lines "$cand_dir/candidates.txt" 2>/dev/null || echo 0)
    ok "Candidate engine finished -> $cand_dir/candidates.txt ($total_cand candidates)"
}

#------------------------------------------------------------------------------
# PHASE 12 — Vulnerability scanning
#------------------------------------------------------------------------------
phase_vuln() {
    banner_phase "PHASE 12: Vulnerability Scanning (nuclei / nikto / sqlmap / wpscan / xss)"
    log "→ findings feed PHASE 14 (report)"
    local V="$OUTDIR/vuln"
    local live_file="$OUTDIR/web/live-urls.txt"

    # --- nuclei ---
    if tool_exists nuclei && [ -f "$live_file" ]; then
        if [ "$MODE" = "quick" ]; then
            log "nuclei (high+critical only)"
            vlog "nuclei -l $live_file -severity high,critical"
            timeout "$NUCLEI_TIMEOUT" nuclei -l "$live_file" -severity high,critical \
                ${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"} -o "$V/nuclei.txt" >/dev/null 2>&1 || true
        else
            # Single pass with combined tags (saves 2x scan time) - includes xss
            log "nuclei (default + CVE + exposures + misconfig + xss)"
            vlog "nuclei -l $live_file -tags cve,exposures,misconfig,network,vuln,xss"
            timeout "$NUCLEI_TIMEOUT" nuclei -l "$live_file" -tags cve,exposures,misconfig,network,vuln,xss \
                ${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"} -o "$V/nuclei.txt" >/dev/null 2>&1 || true
        fi
    fi

    # --- parse nuclei -> findings ---
    for f in "$V"/nuclei*.txt; do
        [ -e "$f" ] || continue
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local sev title host
            sev=$(echo "$line" | grep -oE '^\[[a-z]+\]' | tr -d '[]')
            [ -z "$sev" ] && sev="info"
            # nuclei line: [severity] [template-id] [host] [matched] — template id = group 2
            title=$(echo "$line" | grep -oE '^\[[a-z]+\] \[[a-zA-Z0-9._-]+\]' | grep -oE '\[[a-zA-Z0-9._-]+\]' | tail -1 | tr -d '[]')
            host=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
            case "$sev" in
                critical) sev="Critical" ;;
                high)     sev="High" ;;
                medium)   sev="Medium" ;;
                low)      sev="Low" ;;
                info)     sev="Info" ;;
                *)        sev="Info" ;;
            esac
            add_finding "$sev" "nuclei" "$host" "${title:-$host}" "$line" "https://github.com/projectdiscovery/nuclei"
        done < "$f"
    done
    ok "Nuclei findings: $(count_lines "$V"/nuclei*.txt 2>/dev/null || echo 0) raw findings"

    # --- nikto (full/bb) ---
    if tool_exists nikto && [ "$MODE" != "quick" ] && [ -f "$live_file" ]; then
        # Parallelize nikto with concurrency cap (respects HOST_CONCURRENCY env, default 2)
        local nikto_concurrency="${HOST_CONCURRENCY:-2}"
        log "nikto (parallel, concurrency=${nikto_concurrency})"
        export NIKTO_OUTDIR="$V"
        timeout 3600 xargs -P "$nikto_concurrency" -I{} bash -c '
            url="$1"
            [ -z "$url" ] && exit 0
            safe=$(echo "$url" | sed "s/[^A-Za-z0-9._:-]/_/g")
            timeout 900 nikto -h "$url" -Format txt -output "$NIKTO_OUTDIR/nikto-${safe}.txt" >/dev/null 2>&1 || true
        ' _ {} < "$live_file"
        grep -hE '^\s*\+ ' "$V"/nikto-*.txt 2>/dev/null | while IFS= read -r line; do
            add_finding "Medium" "nikto" "$line" "nikto finding" "$line" "https://cirt.net/Nikto2"
        done
        ok "Nikto findings: $(grep -chE '^\s*\+ ' "$V"/nikto-*.txt 2>/dev/null | awk '{s+=$1} END{print s+0}')"
    fi

    # --- WordPress scan ---
    if tool_exists wpscan && [ -f "$OUTDIR/tech/tech.txt" ] && grep -qi wordpress "$OUTDIR/tech/tech.txt"; then
        log "wpscan detected WordPress -> scanning"
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            local safe; safe=$(sanitize_name "$url")
            vlog "wpscan --url $url --disable-tls-checks"
            timeout 600 wpscan --url "$url" --no-banner --disable-tls-checks \
                -o "$V/wpscan-${safe}.txt" >/dev/null 2>&1 || true
        done < "$live_file"
        grep -hE '^\[!\]|Vulnerability' "$V"/wpscan-*.txt 2>/dev/null | while IFS= read -r line; do
            add_finding "High" "wpscan" "$line" "WordPress vulnerability" "$line" "https://wpscan.com/wordpresses/"
        done
    fi

    # --- sqlmap (bb mode only) ---
    if [ "$RUN_SQLMAP" = 1 ] && tool_exists sqlmap && [ -f "$OUTDIR/urls/param-urls.txt" ]; then
        local count=0
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            [ "$count" -ge "$SQLMAP_CAP" ] && { warn "sqlmap cap reached ($SQLMAP_CAP)."; break; }
            # only test URLs with at least one '='
            echo "$url" | grep -q '=' || continue
            count=$((count+1))
            log "sqlmap (batch, level1) $url"
            vlog "sqlmap -u $url --batch --level 1 --risk 1 --smart"
            timeout 600 sqlmap -u "$url" --batch --level 1 --risk 1 --smart \
                --flush-session --output-dir="$V/sqlmap-${count}" >/dev/null 2>&1 || true
            local found
            found=$(find "$V/sqlmap-${count}" -name '*.txt' 2>/dev/null | head -1)
            [ -n "$found" ] && {
                grep -iE 'parameter.*type|is vulnerable' "$found" | while IFS= read -r line; do
                    add_finding "Critical" "sqlmap" "$url" "SQL Injection" "$line" "https://github.com/sqlmapproject/sqlmap"
                done
            }
        done < "$OUTDIR/urls/param-urls.txt"
    fi

    ok "Vulnerability scanning done -> $V"
}

#------------------------------------------------------------------------------
# PHASE 12.7 — INTEL ENGINE
#   Signal-driven decision engine (OWASP Top 10:2025 + CWE Top 25).
#   For every live host it:
#     1) collects signals (security headers, cookies, server, params, URL shape)
#     2) decides WHICH vulnerability classes are worth testing and WHY
#     3) runs the matching detection modules (confidence-gated)
#     4) logs every decision so the reasoning is auditable
#   Findings are tagged TOOL=intel.
#------------------------------------------------------------------------------
_intel_note() { echo "[$(date +%H:%M:%S)] $*" >> "${INTEL_LOG:-/dev/null}"; }

_i_ib=""   # current intel body temp file (set by _i)
_i_ih=""   # current intel headers temp file (set by _i)
_i() {  # _i <url> -> HTTP code; body in $_i_ib, headers in $_i_ih
    _i_ib=$(tmp_file ib)
    _i_ih=$(tmp_file ih)
    wreq -o "$_i_ib" -D "$_i_ih" -w '%{http_code}' "$1" 2>/dev/null
}

intel_hdrs() { grep -i "^$1:" "$_i_ih" 2>/dev/null | head -1; }

# ---- M1 security posture: clickjacking / missing security headers ----
m_security_posture() {
    local host="$1" url="$2" xf csp hsts xcto rp setcookie secure_cookie http_cookie
    _i "$url" >/dev/null
    xf=$(intel_hdrs "x-frame-options")
    csp=$(intel_hdrs "content-security-policy")
    hsts=$(intel_hdrs "strict-transport-security")
    xcto=$(intel_hdrs "x-content-type-options")
    rp=$(intel_hdrs "referrer-policy")
    if [ -z "$xf" ] && ! echo "$csp" | grep -qi "frame-ancestors"; then
        add_finding "Medium" "intel" "$host" "Clickjacking (no frame protection)" "No X-Frame-Options or CSP frame-ancestors" "https://owasp.org/www-community/attacks/Clickjacking"
    fi
    case "$url" in https://*)
        [ -z "$hsts" ] && add_finding "Low" "intel" "$host" "HSTS missing" "No Strict-Transport-Security on HTTPS" "https://owasp.org/www-project-secure-headers/"
    ;; esac
    [ -z "$xcto" ] && add_finding "Low" "intel" "$host" "MIME-sniffing allowed (X-Content-Type-Options missing)" "Could enable content-type confusion" "https://owasp.org/www-project-secure-headers/"
    [ -z "$rp" ] && add_finding "Info" "intel" "$host" "Referrer-Policy missing" "Referrer leakage risk" "https://owasp.org/www-project-secure-headers/"
    # cookie flags
    grep -i '^set-cookie:' "$_i_ih" 2>/dev/null | while IFS= read -r sc; do
        local name; name=$(echo "$sc" | sed -E 's/^[Ss]et-[Cc]ookie: *//; s/=.*//')
        [ -z "$name" ] && continue
        case "$url" in https://*)
            echo "$sc" | grep -qiE ';\s*secure' || add_finding "Medium" "intel" "$host" "Cookie '${name}' without Secure flag" "$(echo "$sc"|tr -d '\r')" "https://owasp.org/www-project-top-ten/"
        ;; esac
        echo "$sc" | grep -qiE ';\s*httponly' || add_finding "Medium" "intel" "$host" "Cookie '${name}' without HttpOnly" "$(echo "$sc"|tr -d '\r')" "https://owasp.org/www-project-top-ten/"
        echo "$sc" | grep -qiE ';\s*samesite' || add_finding "Low" "intel" "$host" "Cookie '${name}' without SameSite" "$(echo "$sc"|tr -d '\r')" "https://owasp.org/www-project-top-ten/"
    done
}

# ---- M2 HTTP methods / TRACE / verb tampering ----
m_method_tampering() {
    local host="$1" url="$2" allow trace
    allow=$(wreq -X OPTIONS -o /dev/null -D - "$url" 2>/dev/null | grep -i '^allow:' | tr -d '\r')
    if echo "$allow" | grep -qiE 'PUT|DELETE|TRACE|PATCH'; then
        add_finding "Medium" "intel" "$host" "Verbose HTTP methods allowed (OPTIONS Allow: $allow)" "PUT/DELETE/TRACE enabled" "https://owasp.org/www-project-web-security-testing-guide/"
    fi
    trace=$(wreq -X TRACE -D - "$url" 2>/dev/null | head -5)
    if echo "$trace" | grep -qE '^HTTP/|^Host:|^X-' && [ -n "$(echo "$trace" | grep -iE 'TRACE|Max-Forwards')" ]; then
        add_finding "High" "intel" "$host" "TRACE method enabled (XST / cross-site tracing)" "Request echoed back" "https://owasp.org/www-community/attacks/Cross_Site_Tracing"
    fi
}

# ---- M3 directory listing / autoindex ----
m_directory_listing() {
    local host="$1" url="$2" body
    body=$(wreq "$url/" 2>/dev/null | grep -oiE 'Index of /|Parent Directory|<title>.*Index of' | head -1)
    [ -n "$body" ] && add_finding "Medium" "intel" "$host" "Directory listing enabled (autoindex)" "$body" "https://owasp.org/www-project-web-security-testing-guide/"
}

# ---- M4 verbose error / information disclosure ----
m_verbose_errors() {
    local host="$1" url="$2" body
    body=$(wreq "$url/?x='\"" 2>/dev/null \
        | grep -oiE 'Stack trace|Fatal error|Uncaught|SQLSTATE|Traceback|Undefined variable' | sort -u | head -3 | tr '\n' ' ')
    [ -n "$body" ] && add_finding "Medium" "intel" "$host" "Verbose error messages leak internals" "$body" "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"
}

# ---- M5 debug parameters ----
m_debug_params() {
    local host="$1" url="$2" p body
    for p in debug=1 test=1 _debug=1 __debug=1 phpinfo=1; do
        body=$(wreq "$url?$p" 2>/dev/null)
        if echo "$body" | grep -qiE 'phpinfo\(\)|DEBUG MODE|debug_enabled|Xdebug|Laravel.*debug|symfony.*debug'; then
            add_finding "High" "intel" "$host" "Debug mode enabled via ?$p" "Debug output detected" "https://owasp.org/www-project-web-security-testing-guide/"
            return 0
        fi
    done
    return 1
}

# ---- M6 CRLF / response splitting ----
m_crlf() {
    local host="$1" url="$2" hdr
    local test_url="${url}?x=%0d%0aX-Intel-Test:%20injected"
    hdr=$(wreq -o /dev/null -D - "$test_url" 2>/dev/null | grep -i '^x-intel-test:' | tr -d '\r')
    [ -n "$hdr" ] && add_finding "High" "intel" "$host" "CRLF injection / response splitting" "Header injection via ?x= param got: $hdr" "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"
}

# ---- M7 command injection (param-based) ----
m_command_injection() {
    # Command injection probe — only meaningful on URLs that actually have a query string
    local host="$1" url="$2" param body sep payload
    # Skip base URLs without query strings (avoids SPA 200-all false positives)
    echo "$url" | grep -q '?' || return 1
    # Determine separator: '&' if query string already present, else '?'
    echo "$url" | grep -q '?' && sep='&' || sep='?'
    for param in host ip url cmd exec ping traceroute whois; do
        # Properly URL-encode payloads: ';' -> %3B, '|' -> %7C
        local test1="${url}${sep}${param}=%3Bid"
        body=$(wreq "$test1" 2>/dev/null)
        if echo "$body" | grep -qE 'uid=[0-9]+\([a-z]+\)'; then
            local uid=$(echo "$body" | grep -oE 'uid=[^<]+' | head -1)
            local msg1="Command injection via ${param} [semicolon]"
            local det1="RCE confirmed: ${uid}"
            add_finding "Critical" "intel" "$host" "$msg1" "$det1" "https://owasp.org/www-community/attacks/Command_Injection"
            return 0
        fi
        local test2="${url}${sep}${param}=%7Cid"
        body=$(wreq "$test2" 2>/dev/null)
        if echo "$body" | grep -qE 'uid=[0-9]+\([a-z]+\)'; then
            local msg2="Command injection via ${param} [pipe]"
            add_finding "Critical" "intel" "$host" "$msg2" "RCE confirmed" "https://owasp.org/www-community/attacks/Command_Injection"
            return 0
        fi
    done
    return 1
}

# ---- M8 XXE probe (only if XML-looking endpoint) ----
m_xxe() {
    local host="$1" url="$2" ct body
    ct=$(intel_hdrs "content-type")
    echo "$ct" | grep -qiE 'xml|soap' || return 1
    body=$(wreq -H 'Content-Type: application/xml' \
        -d '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>' "$url" 2>/dev/null)
    echo "$body" | grep -qE 'root:.*:0:0:' \
        && add_finding "High" "intel" "$host" "XXE external entity file read [etc/passwd]" "XML endpoint expands file entity" "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_Processing" \
        && return 0
    return 1
}

# ---- M9 IDOR / BOLA candidates (flag + probe) ----
m_idor_candidates() {
    local host="$1" url="$2" hit
    # flag numeric/UUID ids in live param URLs
    hit=$(grep -hoE '/api/[^?]*/[0-9]{3,}|[?&][a-z_]*=[0-9]{3,}' \
              "$OUTDIR/urls/param-urls.txt" "$OUTDIR/urls/api-endpoints.txt" 2>/dev/null | head -3 | tr '\n' ' ')
    [ -n "$hit" ] && add_finding "Info" "intel" "$host" "IDOR BOLA candidates" "$hit" "https://owasp.org/Top10/A01_2021-Broken_Access_Control"
    # probe a likely object endpoint without auth
    local cand
    cand=$(echo "$url" | grep -oE 'https?://[^?]*/api/[^/]+/[0-9]{3,}' | head -1)
    [ -z "$cand" ] && return 1
    local code body
    code=$(_i "$cand"); body=$(grep -oiE '"(email|ssn|credit_card|password|id_card|bank_account)"' "$_i_ib" | head -1)
    if [ "$code" = "200" ] && [ -n "$body" ]; then
        add_finding "High" "intel" "$host" "Sensitive data exposed on unauthenticated API object" "$cand returned $code with $body" "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    fi
}

# ---- M10 default/management panel discovery ----
m_default_panels() {
    local host="$1" url="$2" p code body sig
    local home ip_f
    home=$(wreq "$url" 2>/dev/null)   # homepage body — skips all-paths-200 SPAs
    ip_f=$(tmp_file ip)
    for p in "/admin" "/manager/html" "/jenkins" "/phpmyadmin" "/adminer.php" "/grafana" "/kibana" "/admin/login"; do
        sig=""
        code=$(wreq -o "$ip_f" -w '%{http_code}' "$url$p" 2>/dev/null)
        body=$(< "$ip_f" 2>/dev/null)
        [ -n "$body" ] && [ "$body" = "$home" ] && continue   # same page as homepage
        case "$p" in
            /phpmyadmin)  echo "$body" | grep -qi 'phpMyAdmin' && sig="phpMyAdmin" ;;
            /grafana)     echo "$body" | grep -qi 'Grafana' && sig="Grafana" ;;
            /kibana)      echo "$body" | grep -qi 'Kibana' && sig="Kibana" ;;
            /jenkins)     echo "$body" | grep -qiE 'Jenkins' && sig="Jenkins" ;;
            /adminer.php) echo "$body" | grep -qiE 'Adminer' && sig="Adminer" ;;
            /manager/html) echo "$body" | grep -qiE 'Tomcat' && sig="Apache Tomcat" ;;
            *)            echo "$body" | grep -qiE '<form[^>]*>.*type="password"' && sig="login form" ;;
        esac
        case "$code" in
            200|302)
                [ -n "$sig" ] && add_finding "Medium" "intel" "$host" "Management/admin panel exposed: $p" "HTTP $code [$sig] [try default credentials]" "https://owasp.org/www-project-web-security-testing-guide/"
                ;;
            401|403) add_finding "Info" "intel" "$host" "Admin panel found auth protected: $p" "HTTP $code" "-" ;;
        esac
    done
    rm -f "$ip_f"
}

# ---- M11 JWT decode & alg:none ----
m_jwt() {
    local host="$1" url="$2" tok seg alg
    # Only flag JWTs actually found in the secret scan (avoids false positives)
    tok=$(grep -hoE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}' \
              "$OUTDIR/urls/secrets.txt" 2>/dev/null | head -1)
    [ -z "$tok" ] && return 1
    local hdr64; hdr64="${tok%%.*}"
    # base64url -> base64 with padding so decode always works
    case $(( ${#hdr64} % 4 )) in 2) hdr64="${hdr64}==" ;; 3) hdr64="${hdr64}=" ;; esac
    alg=$(echo "$hdr64" | tr '_-' '/+' | base64 -d 2>/dev/null | grep -oE '"alg":"[^"]+"')
    if echo "$alg" | grep -qiE 'none'; then
        add_finding "High" "intel" "$host" "JWT signed with alg:none [auth bypass]" "$alg" "https://owasp.org/www-project-web-security-testing-guide/"
    fi
    add_finding "Info" "intel" "$host" "JWT token found — decode & test" "$tok" "https://jwt.io"
}

# ---- M12 Host header injection / password-reset poisoning ----
m_host_header() {
    local host="$1" url="$2" reflected reset
    reflected=$(wreq -H 'Host: evil.example.com' "$url" 2>/dev/null | grep -o 'evil.example.com' | head -1)
    [ -n "$reflected" ] && add_finding "Medium" "intel" "$host" "Host header reflected in response" "Injection point for cache poisoning / password-reset poisoning" "https://owasp.org/www-project-web-security-testing-guide/"
    for rp in "/forgot-password" "/forgot" "/reset-password" "/password/reset"; do
        reset=$(wreq -H 'Host: evil.example.com' -o /dev/null -w '%{http_code}' "$url$rp" 2>/dev/null )
        [ "$reset" = "200" ] && add_finding "Info" "intel" "$host" "Password-reset endpoint exists: $rp [test Host-header poisoning]" "HTTP 200" "https://owasp.org/www-project-web-security-testing-guide/"
    done
}

# ---- M13 race-condition / state-changing endpoints (flag for manual) ----
m_logic_candidates() {
    local host="$1" url="$2" hit
    hit=$(grep -hoE '(https?://[^ ?]+)(/[a-zA-Z]*(login|register|signup|otp|verify|transfer|payment|checkout|coupon|redeem|claim)[a-zA-Z]*)' \
              "$OUTDIR/urls/historical.txt" 2>/dev/null | head -3 | tr '\n' ' ')
    [ -n "$hit" ] && add_finding "Info" "intel" "$host" "State-changing endpoints [test race conditions logic flaws]" "$hit" "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
}

# ---- M14 rate-limit absence (login) ----
m_rate_limit() {
    local host="$1" url="$2" c1 c2 c3 form
    # only test a host that actually has a login form (avoids all-paths-200 noise)
    form=$(timeout 6 wreq "$url/login" 2>/dev/null | grep -qiE '<form[^>]*login|name="(user|email)"[^>]*|type="password"' && echo yes)
    [ "$form" = "yes" ] || return 1
    c1=$(_i "$url/login")
    c2=$(_i "$url/login")
    c3=$(_i "$url/login")
    # flag only a stable 2xx with zero 429 anywhere (429 = rate limit IS present)
    if [ "$c1" = "$c2" ] && [ "$c2" = "$c3" ] && [ "$c1" != "000" ] \
       && [ "$c1" != "429" ] && [ "$c1" != "404" ]; then
        add_finding "Info" "intel" "$host" "No obvious rate limiting on login [3x HTTP $c1]" "Manually verify with POST /login brute-force" "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    fi
}

# ---- M15 weak TLS (HTTPS hosts) ----
m_weak_tls() {
    local host="$1" port=443 tls
    # honor an explicit port; only probe common HTTPS ports
    case "$host" in
        *:[0-9]*) port="${host##*:}"; host="${host%:*}" ;;
    esac
    [ "$port" != "443" ] && [ "$port" != "8443" ] && return 1
    # -brief prints "Protocol version: TLSv1" on a successful TLS1.0 handshake;
    # grep matches the TLSv1 (not TLSv1.2/1.3) line specifically.
    tls=$(timeout 6 openssl s_client -connect "${host}:${port}" -tls1 -brief 2>&1 < /dev/null)
    echo "$tls" | grep -qE 'Protocol version: *TLSv1$|Ciphersuite:' \
        && add_finding "High" "intel" "$host" "TLSv1.0/1.1 enabled [legacy crypto]" "Deprecated protocol downgrade possible" "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
}

# ---- Intel engine orchestration ----
phase_intel() {
    banner_phase "PHASE 12.7: INTEL ENGINE [OWASP Top 10 2025 signal-driven decision layer]"
    local INTEL_LOG="$OUTDIR/vuln/intel-decisions.txt"
    log "→ 15+ detection modules; every decision is logged in $INTEL_LOG"
    : > "$INTEL_LOG"
    local live_file="$OUTDIR/web/live-urls.txt"
    [ -f "$live_file" ] || { warn "No live hosts for intel analysis."; return; }

    # CAP: limit intel engine to first 20 live hosts to avoid O(N) explosion
    local max_intel_hosts=20
    local count=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        count=$((count+1))
        [ "$count" -gt "$max_intel_hosts" ] && { warn "Intel engine cap reached"; break; }
        local host; host=$(echo "$url" | sed 's|https\?://||g; s|/.*||g')
        _intel_note "== $host [collecting signals] =="

        m_security_posture "$host" "$url"
        _intel_note "  post: security posture evaluated [headers cookies]"
        m_method_tampering "$host" "$url"
        m_directory_listing "$host" "$url"
        m_verbose_errors "$host" "$url"
        m_debug_params "$host" "$url"
        m_crlf "$host" "$url"
        m_xxe "$host" "$url"
        m_idor_candidates "$host" "$url"
        m_default_panels "$host" "$url"
        m_jwt "$host" "$url"
        m_host_header "$host" "$url"
        m_logic_candidates "$host" "$url"
        m_rate_limit "$host" "$url"
        m_weak_tls "$host" "$url"
        _intel_note "  done: 14 modules dispatched for $host"
    done < "$live_file"

    # parameter-only modules need a parameterized target
    if [ -f "$OUTDIR/urls/param-urls.txt" ]; then
        local pcount=0
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            pcount=$((pcount+1)); [ "$pcount" -gt "${PARAM_TEST_CAP:-20}" ] && break
            local ph; ph=$(echo "$p" | sed 's|https\?://||g; s|/.*||g')
            _intel_note "== $ph — parameter injection tests =="
            m_command_injection "$ph" "$p"
            _intel_note "  done: command-injection + [redirect/LFI/SSTI already in S2]"
        done < "$OUTDIR/urls/param-urls.txt"
    fi
    ok "Intel engine finished -> $INTEL_LOG"
}

#------------------------------------------------------------------------------
# PHASE 13 — CVE correlation
#------------------------------------------------------------------------------
write_cve_db() {
    # Bundled mini CVE database. Format per line:
    #   software|oplist;...|verlist;...|CVE|severity|score|description|reference
    # ops: ge gt le lt eq ne   (multiple ops ANDed with ';')
    # Expanded to 100 entries covering CISA KEV, widely exploited CVEs, and bug bounty high-value targets
    local DB="$OUTDIR/cve/cve-db.txt"
    command cat > "$DB" <<'EOF'
apache|ge;lt|2.4.49;2.4.50|CVE-2021-41773|Critical|9.8|Apache HTTP Server path traversal + arbitrary file read / RCE (fixed in 2.4.50)|https://nvd.nist.gov/vuln/detail/CVE-2021-41773
apache|ge;lt|2.4.50;2.4.51|CVE-2021-42013|Critical|9.8|Apache HTTP Server path traversal bypass of CVE-2021-41773 (fixed in 2.4.51)|https://nvd.nist.gov/vuln/detail/CVE-2021-42013
apache|lt|2.4.34|CVE-2018-11759|High|7.5|Apache mod_jk status worker path traversal|https://nvd.nist.gov/vuln/detail/CVE-2018-11759
apache|lt|2.4.18|CVE-2016-5387|High|7.5|Apache HTTPoxy CGI proxy redirect|https://nvd.nist.gov/vuln/detail/CVE-2016-5387
nginx|lt|1.20.1|CVE-2021-23017|High|7.7|nginx resolver off-by-one stack write (fixed in 1.21.0 / 1.20.1)|https://nvd.nist.gov/vuln/detail/CVE-2021-23017
nginx|lt|1.18.0|CVE-2019-20372|High|7.5|nginx HTTP/2 request smuggling|https://nvd.nist.gov/vuln/detail/CVE-2019-20372
nginx|lt|1.17.7|CVE-2019-9511|High|7.5|nginx HTTP/2 DoS (flood)|https://nvd.nist.gov/vuln/detail/CVE-2019-9511
nginx|lt|1.16.1|CVE-2019-11043|Critical|9.8|nginx PHP-FPM RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-11043
openssh|lt|9.3|CVE-2023-38408|High|9.8|OpenSSH agent forwarding RCE when system has PKCS#11 provider (fixed in 9.3p2)|https://nvd.nist.gov/vuln/detail/CVE-2023-38408
openssh|le|7.7|CVE-2018-15473|Medium|5.3|OpenSSH user enumeration via timing side-channel|https://nvd.nist.gov/vuln/detail/CVE-2018-15473
openssh|lt|7.9|CVE-2020-14145|Medium|6.5|OpenSSH man-in-the-middle|https://nvd.nist.gov/vuln/detail/CVE-2020-14145
openssh|lt|8.2|CVE-2021-28041|Medium|6.0|OpenSSH agent forwarding double-free|https://nvd.nist.gov/vuln/detail/CVE-2021-28041
vsftpd|eq|2.3.4|CVE-2011-2523|Critical|10.0|vsftpd 2.3.4 backdoor (smiley-face) remote root|https://nvd.nist.gov/vuln/detail/CVE-2011-2523
openssl|ge;lt|1.0.1;1.0.2|CVE-2014-0160|Critical|7.5|Heartbleed — OpenSSL heartbeat memory disclosure|https://nvd.nist.gov/vuln/detail/CVE-2014-0160
openssl|lt|1.1.1k|CVE-2021-3450|High|7.4|OpenSSL SM2 decryption buffer overflow|https://nvd.nist.gov/vuln/detail/CVE-2021-3450
openssl|ge;lt|3.0.0;3.0.7|CVE-2022-3786|High|7.5|OpenSSL X.509 email address buffer overflow|https://nvd.nist.gov/vuln/detail/CVE-2022-3786
openssl|lt|3.0.7|CVE-2022-3602|High|7.5|OpenSSL X.509 email buffer overflow|https://nvd.nist.gov/vuln/detail/CVE-2022-3602
log4j|ge;lt|2.0.0;2.15.0|CVE-2021-44228|Critical|10.0|Log4Shell — JNDI injection RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-44228
log4j|ge;lt|2.15.0;2.16.0|CVE-2021-45046|Critical|9.0|Log4Shell DoS bypass|https://nvd.nist.gov/vuln/detail/CVE-2021-45046
log4j|ge;lt|2.16.0;2.17.0|CVE-2021-45105|Critical|9.0|Log4Shell DoS|https://nvd.nist.gov/vuln/detail/CVE-2021-45105
log4j|lt|2.17.1|CVE-2021-44832|High|6.6|Log4j RCE (JDBC)|https://nvd.nist.gov/vuln/detail/CVE-2021-44832
bash|lt|4.3|CVE-2014-6271|Critical|9.8|Shellshock — env variable function definition RCE|https://nvd.nist.gov/vuln/detail/CVE-2014-6271
bash|lt|4.4|CVE-2014-7169|Critical|9.8|Shellshock incomplete fix|https://nvd.nist.gov/vuln/detail/CVE-2014-7169
php|lt|7.1.33|CVE-2019-11043|Critical|9.8|PHP-FPM env_path_info underflow RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-11043
php|ge;lt|7.2;7.2.24|CVE-2019-11043|Critical|9.8|PHP-FPM env_path_info underflow RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-11043
php|ge;lt|7.3;7.3.11|CVE-2019-11043|Critical|9.8|PHP-FPM env_path_info underflow RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-11043
php|lt|7.4.0|CVE-2019-11042|High|7.8|PHP info leak|https://nvd.nist.gov/vuln/detail/CVE-2019-11042
php|lt|8.1.0|CVE-2021-21703|Critical|9.8|PHP-FPM RCE (8.x)|https://nvd.nist.gov/vuln/detail/CVE-2021-21703
php|lt|8.0.12|CVE-2021-21708|High|8.8|PHP OPcache RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-21708
drupal|lt|8.5.1|CVE-2018-7600|Critical|9.8|Drupalgeddon2 — form API RCE|https://nvd.nist.gov/vuln/detail/CVE-2018-7600
drupal|lt|9.2.0|CVE-2022-25277|Critical|9.8|Drupal core RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-25277
drupal|lt|10.0.0|CVE-2023-25584|High|8.8|Drupal access bypass|https://nvd.nist.gov/vuln/detail/CVE-2023-25584
wordpress|lt|6.1|CVE-2022-21661|High|8.1|WordPress WP_Query SQL injection|https://nvd.nist.gov/vuln/detail/CVE-2022-21661
wordpress|lt|5.8.2|CVE-2021-44223|Critical|9.8|WordPress Super Cache RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-44223
wordpress|lt|5.7|CVE-2021-29447|High|8.8|WordPress media library XXE|https://nvd.nist.gov/vuln/detail/CVE-2021-29447
wordpress|lt|4.9.8|CVE-2018-6389|Medium|5.3|WordPress DoS (load-scripts.php)|https://nvd.nist.gov/vuln/detail/CVE-2018-6389
wordpress|lt|5.2|CVE-2019-9787|Medium|6.1|WordPress stored XSS via comments|https://nvd.nist.gov/vuln/detail/CVE-2019-9787
jenkins|lt|2.150.1|CVE-2018-1000861|Critical|9.8|Jenkins RCE via dynamic routing / CLI|https://nvd.nist.gov/vuln/detail/CVE-2018-1000861
jenkins|lt|2.426.1|CVE-2022-26488|Critical|9.8|Jenkins deserialization RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-26488
jenkins|lt|2.401|CVE-2022-41126|High|8.8|Jenkins sandbox bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-41126
tomcat|ge;lt|9.0.0;9.0.31|CVE-2020-1938|Critical|9.8|Ghostcat — Apache Tomcat AJP file read / RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-1938
tomcat|ge;lt|8.5.0;8.5.51|CVE-2020-1938|Critical|9.8|Ghostcat — Apache Tomcat AJP file read / RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-1938
tomcat|lt|9.0.65|CVE-2022-29885|High|8.8|Tomcat filter bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-29885
tomcat|lt|10.0.0|CVE-2020-9484|Critical|9.8|Tomcat deserialization RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-9484
exim|lt|4.92|CVE-2019-10149|Critical|9.8|Exim RCE via crafted delivery request|https://nvd.nist.gov/vuln/detail/CVE-2019-10149
exim|lt|4.94.2|CVE-2020-28007|High|8.8|Exim heap buffer overflow|https://nvd.nist.gov/vuln/detail/CVE-2020-28007
exim|lt|4.95|CVE-2021-27216|High|8.8|Exim link attack|https://nvd.nist.gov/vuln/detail/CVE-2021-27216
elasticsearch|lt|1.3.5|CVE-2015-1427|Critical|10.0|Elasticsearch Groovy RCE (fixed 1.3.5)|https://nvd.nist.gov/vuln/detail/CVE-2015-1427
elasticsearch|lt|7.13.0|CVE-2021-22147|High|8.8|Elasticsearch RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-22147
elasticsearch|lt|7.17.0|CVE-2022-23634|High|8.8|Elasticsearch auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-23634
mongodb|lt|2.4.5|CVE-2013-3969|High|7.5|MongoDB DoS via crafted request|https://nvd.nist.gov/vuln/detail/CVE-2013-3969
mongodb|lt|3.6.0|CVE-2018-20330|Medium|6.5|MongoDB injection|https://nvd.nist.gov/vuln/detail/CVE-2018-20330
mongodb|lt|4.4.0|CVE-2021-20330|High|7.5|MongoDB RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-20330
phpmyadmin|lt|4.9.3|CVE-2019-12616|High|7.5|phpMyAdmin SQL injection in designer feature|https://nvd.nist.gov/vuln/detail/CVE-2019-12616
phpmyadmin|lt|5.0.4|CVE-2020-5504|High|8.8|phpMyAdmin XSRF/RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-5504
phpmyadmin|lt|5.2.0|CVE-2022-43854|High|8.8|phpMyAdmin auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-43854
gitlab|lt|12.9.1|CVE-2020-10977|High|8.8|GitLab arbitrary file read via CI (fixed 12.9.1)|https://nvd.nist.gov/vuln/detail/CVE-2020-10977
gitlab|lt|14.0.0|CVE-2021-22205|Critical|10.0|GitLab RCE (exiftool)|https://nvd.nist.gov/vuln/detail/CVE-2021-22205
gitlab|lt|15.0.0|CVE-2022-2185|Critical|9.8|GitLab RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-2185
grafana|lt|8.3.1|CVE-2021-43798|Medium|5.3|Grafana arbitrary file read via plugins path traversal|https://nvd.nist.gov/vuln/detail/CVE-2021-43798
grafana|lt|9.0.0|CVE-2022-23529|High|8.8|Grafana SQLi|https://nvd.nist.gov/vuln/detail/CVE-2022-23529
grafana|lt|10.0.0|CVE-2023-3128|High|8.8|Grafana auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2023-3128
redis|lt|6.0.5|CVE-2020-14147|High|7.2|Redis Lua scripting sandbox escape|https://nvd.nist.gov/vuln/detail/CVE-2020-14147
redis|lt|7.0.0|CVE-2022-0543|Critical|10.0|Redis Lua sandbox escape|https://nvd.nist.gov/vuln/detail/CVE-2022-0543
redis|lt|7.0.5|CVE-2022-24834|High|8.8|Redis ACL bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-24834
mysql|lt|5.6.0|CVE-2012-2122|High|7.0|MySQL auth bypass (cryptographic collision)|https://nvd.nist.gov/vuln/detail/CVE-2012-2122
mysql|lt|5.7.0|CVE-2016-6662|High|7.5|MySQL root escalation|https://nvd.nist.gov/vuln/detail/CVE-2016-6662
mysql|lt|8.0.12|CVE-2018-3058|Medium|6.5|MySQL client RCE|https://nvd.nist.gov/vuln/detail/CVE-2018-3058
postgresql|lt|9.0.0|CVE-2010-3482|Medium|5.0|PostgreSQL fsync race condition|https://nvd.nist.gov/vuln/detail/CVE-2010-3482
postgresql|lt|10.0|CVE-2017-7547|High|7.5|PostgreSQL RCE|https://nvd.nist.gov/vuln/detail/CVE-2017-7547
postgresql|lt|13.0|CVE-2021-3393|High|8.8|PostgreSQL SQLi|https://nvd.nist.gov/vuln/detail/CVE-2021-3393
spring|lt|5.3.0|CVE-2022-22965|Critical|9.8|Spring4Shell RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-22965
spring|lt|5.2.0|CVE-2022-22963|Critical|9.8|Spring Cloud Function RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-22963
spring|lt|5.1.0|CVE-2020-5405|High|7.5|Spring Data RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-5405
confluence|lt|7.4.0|CVE-2021-26084|Critical|9.8|Confluence OGNL RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-26084
confluence|lt|7.13.0|CVE-2022-26134|Critical|9.8|Confluence OGNL RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-26134
confluence|lt|8.0.0|CVE-2023-22515|Critical|9.8|Confluence auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2023-22515
exchange|lt|2013|CVE-2021-26855|Critical|9.8|ProxyLogon SSRF|https://nvd.nist.gov/vuln/detail/CVE-2021-26855
exchange|lt|2016|CVE-2021-26857|Critical|9.8|ProxyLogon RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-26857
exchange|lt|2019|CVE-2021-34473|Critical|9.8|ProxyShell RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-34473
jira|lt|8.4.0|CVE-2020-14181|High|7.5|Jira template injection|https://nvd.nist.gov/vuln/detail/CVE-2020-14181
jira|lt|8.13.0|CVE-2021-26086|Critical|9.8|Jira RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-26086
jira|lt|8.20.0|CVE-2022-0540|Critical|9.8|Jira template injection|https://nvd.nist.gov/vuln/detail/CVE-2022-0540
zookeeper|lt|3.5.0|CVE-2021-26087|High|8.8|ZooKeeper RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-26087
solr|lt|8.8.0|CVE-2021-27905|Critical|9.8|Solr RCE (Velocity)|https://nvd.nist.gov/vuln/detail/CVE-2021-27905
solr|lt|8.11.0|CVE-2021-44228|Critical|10.0|Log4Shell in Solr|https://nvd.nist.gov/vuln/detail/CVE-2021-44228
weblogic|lt|12.2.1|CVE-2020-14882|Critical|9.8|WebLogic RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-14882
weblogic|lt|12.2.1|CVE-2020-14883|High|7.5|WebLogic auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2020-14883
weblogic|lt|14.1.1|CVE-2021-2109|Critical|9.8|WebLogic RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-2109
shibboleth|lt|4.3.0|CVE-2021-21345|High|7.5|Shibboleth IDP RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-21345
citrix|lt|12.1|CVE-2019-19781|Critical|9.8|Citrix ADC RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-19781
citrix|lt|13.0|CVE-2020-8193|High|7.5|Citrix ADC info leak|https://nvd.nist.gov/vuln/detail/CVE-2020-8193
pulse|lt|9.1|CVE-2019-11510|Critical|10.0|Pulse Secure RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-11510
pulse|lt|9.1|CVE-2020-8243|High|7.5|Pulse Secure RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-8243
fortinet|lt|6.0.0|CVE-2018-13379|Critical|9.8|FortiGate path traversal|https://nvd.nist.gov/vuln/detail/CVE-2018-13379
fortinet|lt|7.0.0|CVE-2022-40684|Critical|9.8|FortiOS auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-40684
vmware|lt|7.0|CVE-2021-21972|Critical|9.8|vCenter RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-21972
vmware|lt|8.0|CVE-2022-22954|Critical|9.8|VMware Workspace RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-22954
apache_struts|lt|2.5.0|CVE-2017-5638|Critical|10.0|Struts2 RCE (Equifax)|https://nvd.nist.gov/vuln/detail/CVE-2017-5638
apache_struts|lt|2.5.0|CVE-2018-11776|Critical|9.8|Struts2 RCE|https://nvd.nist.gov/vuln/detail/CVE-2018-11776
apache_struts|lt|2.5.0|CVE-2019-0230|High|8.8|Struts2 RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-0230
jboss|lt|7.0|CVE-2017-12149|Critical|9.8|JBoss deserialization|https://nvd.nist.gov/vuln/detail/CVE-2017-12149
jboss|lt|7.0|CVE-2020-14645|High|8.8|JBoss RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-14645
glassfish|lt|5.0|CVE-2020-9499|Critical|9.8|GlassFish RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-9499
axis2|lt|1.8.0|CVE-2019-0227|High|7.5|Axis2 RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-0227
freemarker|lt|2.3.30|CVE-2020-13942|High|8.8|FreeMarker RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-13942
velocity|lt|2.3.0|CVE-2020-13956|High|8.8|Velocity RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-13956
proftpd|ge;lt|1.3.3;1.3.3d|CVE-2010-4221|Critical|10.0|ProFTPD 1.3.3c backdoor RCE|https://nvd.nist.gov/vuln/detail/CVE-2010-4221
EOF
    echo "$DB"
}

# ---- Product name normalization (D3fault-death) -----------------------------------
_normalize_product_dd() {
  local product="$1"
  product=$(echo "$product" | tr '[:upper:]' '[:lower:]')

  case "$product" in
    *httpd*|*apache*http*|*apache*/*|*apache*) echo "apache" ;;
    *nginx*) echo "nginx" ;;
    *openssh*|*ssh*|*sshd*) echo "openssh" ;;
    *vsftpd*|*ftp*vsftpd*) echo "vsftpd" ;;
    *proftpd*) echo "proftpd" ;;
    *openssl*|*libssl*|*ssl*) echo "openssl" ;;
    *log4j*|*apache*log4j*) echo "log4j" ;;
    *bash*|*gnu*bash*) echo "bash" ;;
    *php*fpm*|*php-fpm*) echo "php" ;;
    *php*) echo "php" ;;
    *drupal*) echo "drupal" ;;
    *wordpress*|*wp-*) echo "wordpress" ;;
    *jenkins*) echo "jenkins" ;;
    *tomcat*|*apache*tomcat*) echo "tomcat" ;;
    *exim*) echo "exim" ;;
    *elasticsearch*|*elastic*search*) echo "elasticsearch" ;;
    *mongodb*|*mongo*db*) echo "mongodb" ;;
    *phpmyadmin*|*pma*) echo "phpmyadmin" ;;
    *gitlab*) echo "gitlab" ;;
    *grafana*) echo "grafana" ;;
    *redis*) echo "redis" ;;
    *mysql*|*mariadb*) echo "mysql" ;;
    *postgresql*|*postgres*|*psql*) echo "postgresql" ;;
    *spring*boot*|*spring*framework*|*spring*) echo "spring" ;;
    *confluence*|*atlassian*confluence*) echo "confluence" ;;
    *exchange*|*microsoft*exchange*) echo "exchange" ;;
    *jira*|*atlassian*jira*) echo "jira" ;;
    *zookeeper*|*apache*zookeeper*) echo "zookeeper" ;;
    *solr*|*apache*solr*) echo "solr" ;;
    *weblogic*|*oracle*weblogic*) echo "weblogic" ;;
    *shibboleth*) echo "shibboleth" ;;
    *citrix*adc*|*netscaler*|*citrix*) echo "citrix" ;;
    *pulse*secure*|*pulse*vpn*) echo "pulse" ;;
    *fortinet*|*fortigate*|*fortios*) echo "fortinet" ;;
    *vmware*|*vcenter*|*esxi*) echo "vmware" ;;
    *struts*|*apache*struts*) echo "apache_struts" ;;
    *jboss*|*wildfly*|*eap*) echo "jboss" ;;
    *glassfish*) echo "glassfish" ;;
    *axis2*|*apache*axis*) echo "axis2" ;;
    *freemarker*) echo "freemarker" ;;
    *velocity*|*apache*velocity*) echo "velocity" ;;
    *) echo "$product" ;;
  esac
}

# ---- Extract version from various formats (D3fault-death) -------------------------
_extract_version_dd() {
  local str="$1"
  # Match semver (1.2.3), date-based (2021.01.01), build (1.2.3.4), etc.
  echo "$str" | grep -oE '[0-9]+(\.[0-9]+)+([.-][0-9a-zA-Z]+)*' | head -1
}

# ---- Enhanced CVE matching with confidence scoring & deduplication ---------------
cve_match_version() {
    # cve_match_version "software-string" "version" -> writes findings
    local sw="$1" ver="$2" db="$3" normalized
    normalized=$(_normalize_product_dd "$sw")
    [ -z "$normalized" ] && return 0

    local db_sw oplist vlist cve sev score desc ref
    local -A seen_cves=()

    while IFS='|' read -r db_sw oplist vlist cve sev score desc ref; do
        [ -z "$db_sw" ] && continue
        db_sw=$(echo "$db_sw" | tr '[:upper:]' '[:lower:]')

        # Exact match on normalized product name
        [ "$db_sw" = "$normalized" ] || continue

        [ -z "$ver" ] && continue
        # evaluate ANDed version conditions
        local pass=1 i ops vts
        IFS=';' read -r -a ops <<< "$oplist"
        IFS=';' read -r -a vts <<< "$vlist"
        for i in "${!ops[@]}"; do
            ver_cmp "$ver" "${ops[$i]}" "${vts[$i]}" || { pass=0; break; }
        done
        [ "$pass" = 1 ] || continue

        # Deduplicate by CVE ID
        [ -n "${seen_cves[$cve]:-}" ] && continue
        seen_cves[$cve]=1

        add_finding "$sev" "cve" "$sw $ver" "$cve" "$desc [detected: $sw $ver]" "$ref"
        log "    MATCH: $sw $ver -> $cve [$sev]"
    done < "$db"
}

phase_cve() {
    banner_phase "PHASE 13: CVE Correlation [version matching + searchsploit]"
    log "-> feeds PHASE 14 [CVE table in report]"
    local C="$OUTDIR/cve"
    local db
    db=$(write_cve_db)
    : > "$C/cve-findings.txt"

    # --- extract software:version pairs from nmap ---
    # nmap -oA .nmap lines: "80/tcp open http Apache httpd 2.4.49"
    local sw ver
    grep -hE '^[0-9]+/tcp\s+open' "$OUTDIR"/ports/nmap-*.nmap 2>/dev/null \
        | awk '{$1="";$2="";$3="";sub(/^  +/,"");print}' \
        | sort -u | while IFS= read -r line; do
            sw="$line"; ver=""
            # first dotted-version token in the service line (avoids grabbing a
            # trailing distro version like "0.6" from "OpenSSH 8.9p1 Ubuntu3...")
            if echo "$line" | grep -qE '[0-9]+\.[0-9]+'; then
                ver=$(echo "$line" | grep -oE '[0-9]+(\.[0-9]+){1,3}[A-Za-z0-9]*' | head -1)
                sw=$(echo "$line" | sed "s/ $ver .*/ /; s/ $ver$//")
            fi
            [ -n "$sw" ] && cve_match_version "$sw" "$ver" "$db"
        done

    # --- extract software:version pairs from whatweb tech stack ---
    # whatweb output contains "[Apache/2.4.49]", "[nginx/1.18.0]", "WordPress[6.0]"
    local techs
    techs=$(grep -hoE '\[[A-Za-z0-9._-]+/[0-9][A-Za-z0-9._-]*\]|WordPress\[[0-9][A-Za-z0-9._-]*\]|PHP/[0-9][A-Za-z0-9._-]*' \
                "$OUTDIR"/tech/tech.txt 2>/dev/null || true)
    while IFS= read -r t; do
        [ -z "$t" ] && continue
        case "$t" in
            WordPress\[*) ver=$(echo "$t" | grep -oE '[0-9][A-Za-z0-9._-]*' | head -1); sw="WordPress" ;;
            PHP/*)        ver="${t#PHP/}"; sw="PHP" ;;
            *)            sw=$(echo "$t" | tr -d '[]'); ver=$(echo "$sw" | grep -oE '[0-9][A-Za-z0-9._-]*' | head -1); sw="${sw%%/*}" ;;
        esac
        [ -n "$sw" ] && [ -n "$ver" ] && cve_match_version "$sw" "$ver" "$db"
    done <<< "$techs"

    # --- searchsploit lookups (Exploit-DB) ---
    if tool_exists searchsploit; then
        grep -hoE 'Apache|nginx|OpenSSH|WordPress|Drupal|Jenkins|Tomcat|PHP|Exim|Redis|MySQL|PostgreSQL|vsftpd|ProFTPD' \
            "$OUTDIR"/ports/nmap-*.nmap "$OUTDIR"/tech/tech.txt 2>/dev/null \
            | sort -u | while IFS= read -r sw; do
            [ -z "$sw" ] && continue
            log "searchsploit $sw"
            local out
            out=$(timeout 120 searchsploit --color off "$sw" 2>/dev/null | grep -E '^\s*[0-9]' || true)
            if [ -n "$out" ]; then
                {
                    echo "## $sw exploits [Exploit-DB]"
                    echo "$out"
                    echo
                } >> "$C/exploits.txt"
                # add notable entries to findings as Info
                echo "$out" | head -5 | while IFS= read -r e; do
                    add_finding "Info" "searchsploit" "$sw" "Exploit-DB match" "$e" "https://www.exploit-db.com/"
                done
            fi
        done
    fi

    # CVEs known to Shodan InternetDB (free, no key)
    for f in "$OUTDIR"/ports/internetdb-*.json; do
        [ -e "$f" ] || continue
        local ip; ip=$(basename "$f" | sed 's/internetdb-//; s/\.json$//')
        jq -r '.vulnerabilities[]?' "$f" 2>/dev/null | sort -u | while IFS= read -r cve; do
            [ -z "$cve" ] && continue
            sev=$(grep -F "|${cve}|" "$OUTDIR/cve/cve-db.txt" 2>/dev/null | head -1 | cut -d'|' -f5)
            [ -z "$sev" ] && sev="High"
            add_finding "$sev" "cve" "$ip" "$cve" "Exposed service with known CVE [Shodan InternetDB]" "https://nvd.nist.gov/vuln/detail/${cve}"
        done
    done

    ok "CVE correlation done -> $C (see findings for matches)"
}

#------------------------------------------------------------------------------
# PHASE 13.5 — Target ranking (which host to attack first)
#------------------------------------------------------------------------------
phase_rank() {
    banner_phase "PHASE 13.5: Target Ranking (prioritize what to test today)"
    log "→ feeds PHASE 14 (🔥 Priority Targets section)"
    local live_file="$OUTDIR/web/live-urls.txt"
    local tech_file="$OUTDIR/tech/tech.txt"
    local rank_file="$OUTDIR/web/ranking.txt"
    [ -f "$live_file" ] || { warn "No live hosts to rank."; return; }
    : > "$rank_file"

    local score line host tags
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        host=$(echo "$url" | sed 's|https\?://||g; s|/.*||g')
        score=5; tags=""

        # status code
        local st
        st=$(grep -F "$host" "$OUTDIR/web/http.txt" 2>/dev/null | grep -oE '\[[0-9]{3}\]' | head -1 | tr -d '[]')
        case "$st" in
            200) score=$((score+5)); tags+="200," ;;
            301|302) score=$((score+2)); tags+="redirect," ;;
        esac

        # CDN / WAF penalty
        if grep -qiE 'cloudflare|akamai|fastly|incapsula|sucuri|imperva' "$OUTDIR"/web/waf-*.txt "$tech_file" 2>/dev/null; then
            score=$((score-8)); tags+="CDN/WAF,"
        fi

        # unique tech bonus
        if grep -qiE 'wordpress|laravel|django|flask|ruby on rails|spring|jenkins|phpmyadmin|graphql|react|angular|next|nuxt|express|golang|node' "$tech_file" 2>/dev/null; then
            score=$((score+6)); tags+="unique-tech,"
        fi

        # hostname signal
        if echo "$host" | grep -qiE 'admin|dev|staging|test|internal|api|portal|dashboard|login|cms|backup|uat|beta|jenkins|gitlab|grafana|kibana'; then
            score=$((score+7)); tags+="interesting-host,"
        fi

        # interaction signals
        if grep -qF "$host" "$OUTDIR/urls/param-urls.txt" 2>/dev/null; then score=$((score+3)); tags+="params,"; fi
        if grep -qF "$host" "$OUTDIR/urls/js-endpoints.txt" 2>/dev/null; then score=$((score+3)); tags+="js-endpoints,"; fi

        echo "$score|$url|${tags%,}" >> "$rank_file"
    done < "$live_file"

    sort -t'|' -k1,1nr "$rank_file" -o "$rank_file"
    ok "Ranked $(count_lines "$rank_file") live hosts -> $rank_file"
    echo -e "  ${G}🔥 Top targets today:${NC}"
    head -n "$RANK_CAP" "$rank_file" | while IFS='|' read -r s u t; do
        [ -n "$s" ] && echo -e "    [$s] ${C}$u${NC} (${t:-none})"
    done
}

#------------------------------------------------------------------------------
# PHASE 13.6 — Screenshots (gowitness)
#------------------------------------------------------------------------------
phase_shots() {
    banner_phase "PHASE 13.6: Screenshots (gowitness)"
    log "→ feeds PHASE 14 (🖼 Screenshot gallery)"
    local live_file="$OUTDIR/web/live-urls.txt"
    local shots="$OUTDIR/report/screenshots"
    [ -f "$live_file" ] || { warn "No live hosts to screenshot."; return; }
    [ "$MODE" = "quick" ] && { warn "Screenshots skipped in quick mode."; return; }

    if ! tool_exists gowitness; then
        warn "gowitness not installed — install with 'go install github.com/sensepost/gowitness@latest'"
        return
    fi
    mkdir -p "$shots"
    log "gowitness scanning $(count_lines "$live_file") URLs"
    vlog "gowitness scan file -f $live_file --screenshot-path $shots"
    # gowitness CLI variants differ; try the common form then fall back.
    if timeout "$SHOT_TIMEOUT" gowitness scan file -f "$live_file" --screenshot-path "$shots" --write-db=false >/dev/null 2>&1 \
       || timeout "$SHOT_TIMEOUT" gowitness scan file --file "$live_file" --screenshot-path "$shots" --write-db=false >/dev/null 2>&1; then
        ok "Screenshots saved -> $shots"
    else
        warn "gowitness produced no screenshots (browser may be missing)."
    fi
}

#------------------------------------------------------------------------------
# PHASE 14 — Report
#------------------------------------------------------------------------------
report_sev_color() {
    case "$1" in
        Critical) echo "#ff3b30" ;; High) echo "#ff9500" ;;
        Medium)  echo "#ffcc00" ;; Low) echo "#34c759" ;;
        *)       echo "#8e8e93" ;;
    esac
}

report_sev_badge() {
    local s="$1"; local color; color=$(report_sev_color "$s")
    echo "<span class=\"badge\" style=\"background:$color\">$s</span>"
}

generate_report() {
    banner_phase "PHASE 14: Report Generation"
    local R="$OUTDIR/report"
    local summary="$R/summary.md"

    # summary.md asset counts
    {
        echo ""
        echo "## Results Summary"
        echo "- Subdomains discovered: $(count_lines "$OUTDIR/subdomains/scope.txt")"
        echo "- Hosts resolved: $(count_lines "$OUTDIR/subdomains/resolved.txt")"
        echo "- Live web hosts: $(count_lines "$OUTDIR/web/live-urls.txt")"
        local open_ports
        open_ports=$(grep -h 'open' "$OUTDIR"/ports/nmap-*.gnmap 2>/dev/null | grep -oE '[0-9]+/open' | sort -un | sed 's|/open||' | tr '\n' ' ')
        echo "- Open ports seen: ${open_ports:-none}"
    } >> "$summary"

    # ---- Build HTML ----
    local html="$R/D3fault-death-report.html"
    local findings_file="$OUTDIR/findings/findings.txt"

    # counts for summary cards
    local c_crit=0 c_high=0 c_med=0 c_low=0 c_info=0 total_f=0
    local cand_count=0 cand_high=0 cand_med=0 cand_low=0 cand_info=0
    if [ -f "$findings_file" ]; then
        c_crit=$(grep -c '^Critical|' "$findings_file" || true)
        c_high=$(grep -c '^High|'      "$findings_file" || true)
        c_med=$(grep -c '^Medium|'     "$findings_file" || true)
        c_low=$(grep -c '^Low|'        "$findings_file" || true)
        c_info=$(grep -c '^Info|'      "$findings_file" || true)
        total_f=$(count_lines "$findings_file")
    fi
    local cand_file="$OUTDIR/findings/candidates.txt"
    if [ -f "$cand_file" ]; then
        cand_count=$(count_lines "$cand_file")
        cand_high=$(grep -c '|HIGH|' "$cand_file" || true)
        cand_med=$(grep -c '|MEDIUM|' "$cand_file" || true)
        cand_low=$(grep -c '|LOW|' "$cand_file" || true)
        cand_info=$(grep -c '|INFO|' "$cand_file" || true)
    fi

    # findings table rows
    local rows=""
    if [ -f "$findings_file" ]; then
        while IFS='|' read -r sev tool host title detail ref; do
            [ -z "$sev" ] && continue
            rows+="<tr><td>$(report_sev_badge "$sev")</td><td>$(echo "$tool"|html_esc)</td><td>$(echo "$host"|html_esc)</td><td>$(echo "$title"|html_esc)</td><td>$(echo "$detail"|html_esc)</td><td>"
            if [ -n "$ref" ] && [ "$ref" != "-" ]; then
                rows+="<a href=\"$ref\" target=\"_blank\">link</a>"
            fi
            rows+="</td></tr>"
        done < "$findings_file"
    fi
    [ -z "$rows" ] && rows="<tr><td colspan=6 class=\"empty\">No vulnerabilities detected. Asset inventory below.</td></tr>"

    # CVE table rows (from findings where tool == cve)
    local cve_rows=""
    if [ -f "$findings_file" ]; then
        while IFS='|' read -r sev tool host title detail ref; do
            [ "$tool" = "cve" ] || continue
            cve_rows+="<tr><td>$(report_sev_badge "$sev")</td><td><code>$(echo "$title"|html_esc)</code></td><td>$(echo "$host"|html_esc)</td><td>$(echo "$detail"|html_esc)</td><td><a href=\"$ref\" target=\"_blank\">NVD</a></td></tr>"
        done < "$findings_file"
    fi
    [ -z "$cve_rows" ] && cve_rows="<tr><td colspan=5 class=\"empty\">No version-based CVE matches (add entries to cve-db.txt to extend).</td></tr>"

    # CANDIDATE table rows (from candidates.txt)
    local cand_rows=""
    if [ -f "$cand_file" ]; then
        cand_rows="<table><tr><th>Impact</th><th>Conf</th><th>Host</th><th>Title</th><th>Evidence</th><th>Repro Curl</th><th>Ref</th><th>CVSS3.1</th><th>Tag</th></tr>"
        while IFS='|' read -r prefix impact_class host title confidence evidence repro_curl ref cvss31 tag; do
            [ "$prefix" = "CAND" ] || continue
            local badge_color
            case "$confidence" in
                HIGH) badge_color="#ff3b30" ;;
                MEDIUM) badge_color="#ff9500" ;;
                LOW) badge_color="#ffcc00" ;;
                INFO) badge_color="#34c759" ;;
                *) badge_color="#8e8e93" ;;
            esac
            local badge="<span class=\"badge\" style=\"background:$badge_color\">$confidence</span>"
            local repro_display="$repro_curl"
            [ -n "$repro_curl" ] && [ "$repro_curl" != "-" ] && repro_display="<code style=\"font-size:.75em;background:#0d1117;padding:2px 4px\">$repro_curl</code>"
            [ -z "$repro_curl" ] || [ "$repro_curl" = "-" ] && repro_display="-"
            cand_rows+="<tr><td>$(echo "$impact_class"|html_esc)</td><td>$badge</td><td>$(echo "$host"|html_esc)</td><td>$(echo "$title"|html_esc)</td><td>$(echo "$evidence"|html_esc)</td><td>$repro_display</td><td>"
            [ -n "$ref" ] && [ "$ref" != "-" ] && cand_rows+="<a href=\"$ref\" target=\"_blank\">link</a>"
            cand_rows+="</td><td>$(echo "$cvss31"|html_esc)</td><td>$(echo "$tag"|html_esc)</td></tr>"
        done < "$cand_file"
        cand_rows+="</table>"
    fi
    [ -z "$cand_rows" ] && cand_rows="<p class=\"empty\">No candidate leads generated (run in active/full/bb mode).</p>"

    # asset inventory
    local sub_count res_count live_count open_ports_s
    sub_count=$(count_lines "$OUTDIR/subdomains/scope.txt")
    res_count=$(count_lines "$OUTDIR/subdomains/resolved.txt")
    live_count=$(count_lines "$OUTDIR/web/live-urls.txt")
    open_ports_s=$(grep -h 'open' "$OUTDIR"/ports/nmap-*.gnmap 2>/dev/null | grep -oE '[0-9]+/open' | sort -un | sed 's|/open||' | tr '\n' ' ')

    # live host list
    local live_html=""
    if [ -f "$OUTDIR/web/live-urls.txt" ]; then
        while IFS= read -r u; do
            [ -z "$u" ] && continue
            live_html+="<li><a href=\"$(echo "$u"|html_esc)\" target=\"_blank\">$(echo "$u"|html_esc)</a></li>"
        done < "$OUTDIR/web/live-urls.txt"
    fi
    [ -z "$live_html" ] && live_html="<li>none found</li>"

    # open services list
    local services_html=""
    services_html=$(grep -hE '^[0-9]+/tcp\s+open' "$OUTDIR"/ports/nmap-*.nmap 2>/dev/null | head -25 \
        | sed 's/^/    <li>/;s/$/<\/li>/')

    # phase file inventory
    local files_html=""
    find "$OUTDIR" -type f -not -path '*/logs/*' -not -path '*/findings/*' 2>/dev/null \
        | sort | while IFS= read -r f; do
            echo "    <li><code>${f#$OUTDIR/}</code></li>"
        done >> "$R/.files.tmp"
    files_html=$(command cat "$R/.files.tmp" 2>/dev/null); rm -f "$R/.files.tmp"

    # 🔥 priority targets (ranking)
    local priority_html=""
    if [ -f "$OUTDIR/web/ranking.txt" ]; then
        priority_html="<table><tr><th>Score</th><th>Target</th><th>Why</th></tr>"
        head -n "$RANK_CAP" "$OUTDIR/web/ranking.txt" | while IFS='|' read -r s u t; do
            [ -z "$s" ] && continue
            echo "    <tr><td><b>$s</b></td><td><a href=\"$(echo "$u"|html_esc)\" target=\"_blank\">$(echo "$u"|html_esc)</a></td><td>$(echo "$t"|html_esc)</td></tr>"
        done >> "$R/.rank.tmp"
        priority_html+=$(command cat "$R/.rank.tmp" 2>/dev/null); rm -f "$R/.rank.tmp"
        priority_html+="</table>"
    fi

    # 🧠 strategy log (+ intel decisions)
    local strategy_html=""
    strategy_html="<pre style=\"white-space:pre-wrap;background:#0d1117;padding:10px;border-radius:6px\">$( { [ -f "$OUTDIR/vuln/strategy.log" ] && command cat "$OUTDIR/vuln/strategy.log"; echo; [ -f "$OUTDIR/vuln/intel-decisions.txt" ] && echo "## Intel Engine decisions" && command cat "$OUTDIR/vuln/intel-decisions.txt"; } | html_esc )</pre>"

    # 🖼 screenshots
    local shots_html=""
    local shot
    if [ -d "$OUTDIR/report/screenshots" ]; then
        for shot in "$OUTDIR"/report/screenshots/*.png; do
            [ -e "$shot" ] || continue
            shots_html+="<img src=\"screenshots/$(basename "$shot")\" style=\"max-width:220px;border-radius:6px;margin:4px;border:1px solid #30363d\">"
        done
    fi

    # 🔄 watch-mode changes (compare against WATCH_DIR)
    local watch_html=""
    if [ -n "$WATCH_DIR" ] && [ -d "$WATCH_DIR" ]; then
        local new_sub new_host new_find
        new_sub=$(comm -13 <(sort "$WATCH_DIR/subdomains/scope.txt" 2>/dev/null) <(sort "$OUTDIR/subdomains/scope.txt" 2>/dev/null) | head -20)
        new_host=$(comm -13 <(sort "$WATCH_DIR/web/live-urls.txt" 2>/dev/null) <(sort "$OUTDIR/web/live-urls.txt" 2>/dev/null) | head -20)
        new_find=$(comm -13 <(sort "$WATCH_DIR/findings/findings.txt" 2>/dev/null) <(sort "$OUTDIR/findings/findings.txt" 2>/dev/null) | head -20)
        watch_html="<p style=\"color:#7ee787\">New subdomains: $(echo "$new_sub"|grep -c . 2>/dev/null || echo 0) &nbsp;•&nbsp; New live hosts: $(echo "$new_host"|grep -c . 2>/dev/null || echo 0) &nbsp;•&nbsp; New findings: $(echo "$new_find"|grep -c . 2>/dev/null || echo 0)</p>"
        [ -n "$new_sub" ] && watch_html+="<h3>New subdomains since last scan</h3><ul>" && for h in $new_sub; do watch_html+="<li>$(echo "$h"|html_esc)</li>"; done && watch_html+="</ul>"
        [ -n "$new_host" ] && watch_html+="<h3>New live hosts</h3><ul>" && for h in $new_host; do watch_html+="<li>$(echo "$h"|html_esc)</li>"; done && watch_html+="</ul>"
        [ -n "$new_find" ] && watch_html+="<h3>New findings</h3><ul>" && while IFS= read -r h; do [ -n "$h" ] && watch_html+="<li>$(echo "$h"|html_esc)</li>"; done <<< "$new_find" && watch_html+="</ul>"
    fi

    local target_name="${DOMAIN:-$IP}"
    local duration=$(( ($(date +%s) - START_TIME) / 60 ))

    {
    echo "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    echo "<title>D3FAULT-DEATH Report — $target_name</title>"
    echo "<style>
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1,h2,h3{color:#f0f6fc}
a{color:#58a6ff;text-decoration:none}
code{background:#161b22;padding:2px 5px;border-radius:4px;font-size:.9em}
.badge{display:inline-block;color:#fff;padding:2px 10px;border-radius:12px;font-size:.75em;font-weight:700}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}
.card .n{font-size:2em;font-weight:800;display:block}
.card .l{color:#8b949e;font-size:.8em}
table{width:100%;border-collapse:collapse;margin:10px 0;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #30363d;font-size:.9em;word-break:break-word}
th{background:#21262d;color:#f0f6fc}
tr:hover{background:#1c2128}
.empty{color:#8b949e;text-align:center}
.section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:18px 0}
.footer{color:#8b949e;font-size:.85em;text-align:center;margin:30px 0}
.tag{display:inline-block;background:#1f6feb;color:#fff;padding:1px 8px;border-radius:10px;font-size:.7em;margin:2px}
</style></head><body><div class=\"wrap\">"
    echo "<h1>☠ D3FAULT-DEATH — Bug Bounty Scan Report</h1>"
    echo "<p><span class=\"tag\">Target: $target_name</span> <span class=\"tag\">Mode: $MODE</span> <span class=\"tag\">$(date)</span></p>"
    echo "<p><span class=\"tag\">Duration: ${duration}m</span> <span class=\"tag\">v$VERSION</span></p>"
    echo "<div class=\"cards\">"
    echo "<div class=\"card\"><span class=\"n\">$total_f</span><span class=\"l\">Total Findings</span></div>"
    echo "<div class=\"card\"><span class=\"n\" style=\"color:#ff3b30\">$c_crit</span><span class=\"l\">Critical</span></div>"
    echo "<div class=\"card\"><span class=\"n\" style=\"color:#ff9500\">$c_high</span><span class=\"l\">High</span></div>"
    echo "<div class=\"card\"><span class=\"n\" style=\"color:#ffcc00\">$c_med</span><span class=\"l\">Medium</span></div>"
    echo "<div class=\"card\"><span class=\"n\">$sub_count</span><span class=\"l\">Subdomains</span></div>"
    echo "<div class=\"card\"><span class=\"n\">$res_count</span><span class=\"l\">Resolved Hosts</span></div>"
    echo "<div class=\"card\"><span class=\"n\">$live_count</span><span class=\"l\">Live Web Hosts</span></div>"
    echo "<div class=\"card\"><span class=\"n\">$open_ports_s</span><span class=\"l\">Open Ports</span></div>"
    [ "$cand_count" -gt 0 ] && echo "<div class=\"card\"><span class=\"n\" style=\"color:#ff3b30\">$cand_high</span><span class=\"l\">Cand High</span></div>" || echo "<div class=\"card\"><span class=\"n\">0</span><span class=\"l\">Candidates</span></div>"
    [ "$cand_count" -gt 0 ] && echo "<div class=\"card\"><span class=\"n\" style=\"color:#ff9500\">$cand_med</span><span class=\"l\">Cand Med</span></div>" || true
    [ "$cand_count" -gt 0 ] && echo "<div class=\"card\"><span class=\"n\" style=\"color:#ffcc00\">$cand_low</span><span class=\"l\">Cand Low</span></div>" || true
    echo "</div>"
    echo "<div class=\"section\"><h2>🔎 Vulnerabilities</h2><table><tr><th>Severity</th><th>Source</th><th>Host</th><th>Title</th><th>Detail</th><th>Ref</th></tr>$rows</table></div>"
    echo "<div class=\"section\"><h2>🛡️ CVE Correlation</h2><table><tr><th>Severity</th><th>CVE</th><th>Detected On</th><th>Detail</th><th>Reference</th></tr>$cve_rows</table></div>"
    [ "$cand_count" -gt 0 ] && echo "<div class=\"section\"><h2>💰 Candidate Leads (Manual Validation)</h2>$cand_rows</div>"
    [ -n "$priority_html" ] && echo "<div class=\"section\"><h2>🔥 Priority Targets</h2>$priority_html</div>"
    [ -n "$strategy_html" ] && echo "<div class=\"section\"><h2>🧠 Strategy Log (what was tried)</h2>$strategy_html</div>"
    [ -n "$watch_html" ] && echo "<div class=\"section\"><h2>🔄 Changes Since Last Scan</h2>$watch_html</div>"
    [ -n "$shots_html" ] && echo "<div class=\"section\"><h2>🖼 Screenshots</h2>$shots_html</div>"
    echo "<div class=\"section\"><h2>🌐 Asset Inventory</h2><p><b>Open ports:</b> ${open_ports_s:-none}</p><h3>Live hosts</h3><ul>$live_html</ul><h3>Open services (nmap)</h3><ul>$services_html</ul></div>"
    echo "<div class=\"section\"><h2>📁 Raw Output Files</h2><ul>$files_html</ul></div>"
    echo "<div class=\"footer\">Generated by <b>D3FAULT-DEATH v$VERSION</b> — Author <b>$AUTHOR</b><br>"
    echo "<a href=\"$GITHUB\" target=\"_blank\">GitHub: github.com/Mazen7771</a> &nbsp;•&nbsp; <a href=\"https://$LINKEDIN\" target=\"_blank\">LinkedIn: $LINKEDIN</a><br>"
    echo "<span style=\"color:#484f58\">Authorized-use only. This report reflects passive + active scanning of a target you own or were authorized to test.</span></div>"
    echo "</div></body></html>"
    } > "$html"

    # Console summary
    echo -e "\n${G}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${G}  ☠ SCAN COMPLETE${NC}"
    echo -e "  Output: ${C}$OUTDIR${NC}"
    echo -e "  HTML report: ${C}$html${NC}"
    local dur=$(( ($(date +%s) - START_TIME) ))
    printf '  Duration: %dm %ds\n' $((dur/60)) $((dur%60))
    echo -e "  Findings: $total_f (Critical:$c_crit High:$c_high Medium:$c_med Low:$c_low Info:$c_info)"
    echo -e "${G}════════════════════════════════════════════════════════════════${NC}"
}

#------------------------------------------------------------------------------
# Parse long options (--skip-*, --cve-*, --no-cve) before getopts
#------------------------------------------------------------------------------
parse_long_opts() {
    local args=("$@")
    local i=0
    while [[ $i -lt ${#args[@]} ]]; do
        case "${args[i]}" in
            --skip-content)     SKIP_CONTENT=1 ;;
            --skip-params)      SKIP_PARAMS=1 ;;
            --skip-intel)       SKIP_INTEL=1 ;;
            --skip-hist)        SKIP_HIST=1 ;;
            --skip-js)          SKIP_JS=1 ;;
            --skip-secrets)     SKIP_SECRETS=1 ;;
            --skip-takeover)    SKIP_TAKEOVER=1 ;;
            --skip-sqlmap)      SKIP_SQLMAP=1 ;;
            --skip-candidates)  SKIP_CANDIDATES=1 ;;
            --cve-db)           ((i++)); CVE_DB_PATH="${args[i]}" ;;
            --cve-workers)      ((i++)); CVE_WORKERS="${args[i]}" ;;
            --cve-cache-ttl)    ((i++)); CVE_CACHE_TTL="${args[i]}" ;;
            --nvd-api-key)      ((i++)); NVD_API_KEY="${args[i]}" ;;
            --no-cve)           RUN_CVE_INTEL=0 ;;
            --) shift; break ;;  # end of options
            -*) ;; # ignore short options (handled by getopts)
        esac
        ((i++))
    done
}
parse_long_opts "$@"

# Rebuild $@ with every --skip-* and --cve-* token removed so the getopts loop
# below only ever sees short options (its optstring has no '-', so a leftover
# --skip-* would abort with "illegal option -- -"). Once we hit a literal '--'
# end-of-options marker, everything after it passes through verbatim (standard
# getopt semantics).
_args=()
_end=0
for _a in "$@"; do
    if [[ $_end -eq 1 ]]; then
        _args+=("$_a"); continue
    fi
    case "$_a" in
        --skip-*) ;;                                    # consumed: drop it
        --cve-*) ;;                                     # consumed: drop it
        --no-cve) ;;                                    # consumed: drop it
        --)       _end=1; _args+=("$_a") ;;           # end-of-options marker
        *)        _args+=("$_a") ;;
    esac
done
set -- "${_args[@]}"
unset _args _a _end

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
while getopts "d:t:o:m:s:w:H:ihva:" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        t) IP="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        s) SCOPE_FILE="$OPTARG" ;;
        w) WATCH_DIR="$OPTARG" ;;
        H) AUTH_ARGS+=("-H" "$OPTARG") ;;
        i) DO_INSTALL=1 ;;
        h) usage ;;
        v) VERBOSE=1 ;;
        a) TEST_ACCOUNT="$OPTARG" ;;
        *) usage ;;
    esac
done

# Apply skip flags after mode
apply_skip_flags() {
    [ "$SKIP_CONTENT" = 1 ] && RUN_CONTENT=0
    [ "$SKIP_PARAMS" = 1 ] && RUN_PARAM=0
    [ "$SKIP_INTEL" = 1 ] && RUN_INTEL=0
    [ "$SKIP_HIST" = 1 ] && RUN_HIST=0
    [ "$SKIP_JS" = 1 ] && RUN_JS=0
    [ "$SKIP_SECRETS" = 1 ] && RUN_SECRETS=0
    [ "$SKIP_TAKEOVER" = 1 ] && RUN_TAKEOVER=0
    [ "$SKIP_SQLMAP" = 1 ] && RUN_SQLMAP=0
    [ "$SKIP_CANDIDATES" = 1 ] && RUN_CANDIDATES=0
}
apply_mode
apply_skip_flags

print_banner
echo -e "${Y}  Authorized-use only. Actively scans targets; run only against systems\n  you own or have written permission to test.${NC}"

# ---- Easy interactive start: no -d/-t given? just ask for the URL ----
if [ -z "$DOMAIN" ] && [ -z "$IP" ]; then
    if [ -t 0 ]; then
        prompt_target
        prompt_mode
        apply_mode
    else
        # piped input (echo example.com | ./D3fault-death.sh)
        read -r piped_target || true
        if [ -n "${piped_target:-}" ]; then
            piped_target=$(echo "$piped_target" | sed -E 's|^[a-zA-Z][a-zA-Z0-9+.-]*://||; s|/.*$||; s|/+$||')
            if is_ip "$piped_target"; then IP="$piped_target"; else DOMAIN="$piped_target"; fi
        else
            err "No target given. Run with -d <domain>, -t <ip>, or interactively."
            exit 1
        fi
    fi
fi

setup_target
log "D3FAULT-DEATH v$VERSION started (mode: $MODE) by $AUTHOR"
if [ -n "$SCOPE_FILE" ]; then ok "Scope enforcement active: $SCOPE_FILE"; fi
if [ -n "$WATCH_DIR" ]; then ok "Watch mode active: comparing against $WATCH_DIR"; fi
check_deps

# Open the external Terminator live view once the log path exists
spawn_live_view

# ---- Chronological pipeline (each phase feeds the next) ----
# Runs as a background subshell so the parent's foreground `wait` is what the
# terminal interrupts on Ctrl+C. `wait` (a builtin) runs the INT trap promptly,
# unlike a bare foreground tool (whose death by SIGINT can leave bash waiting
# without running the trap). The subshell disables the trap so only the parent
# does the Ctrl+C cleanup.
run_pipeline() {
    trap - INT TERM
    [ "$RUN_OSINT"     = 1 ] && phase_osint
    [ "$RUN_DNS"       = 1 ] && phase_dns
    [ "$RUN_SUB"       = 1 ] && phase_subdomains
    [ "$RUN_SUB"       = 1 ] && phase_resolve
    [ "$RUN_PORTS"     = 1 ] && phase_ports
    [ "$RUN_WEB"       = 1 ] && phase_web_probe
    [ "$RUN_WEB"       = 1 ] && phase_fingerprint
    [ "$RUN_CVE_INTEL" = 1 ] && phase_cve_intel
    [ "$RUN_CONTENT"   = 1 ] && phase_content
    [ "$RUN_HIST"      = 1 ] && phase_historical
    [ "$RUN_JS"        = 1 ] && phase_js
    [ "$RUN_SECRETS"   = 1 ] && phase_secrets
    [ "$RUN_PARAM"     = 1 ] && phase_params
    [ "$RUN_TAKEOVER"  = 1 ] && phase_takeover
    [ "$RUN_VULN"      = 1 ] && phase_vuln
    [ "$RUN_VULN"      = 1 ] && phase_strategies
    [ "$RUN_CANDIDATES" = 1 ] && phase_candidates
    [ "$RUN_INTEL"     = 1 ] && phase_intel
    [ "$RUN_CVE"       = 1 ] && phase_cve
    [ "$RUN_RANK"      = 1 ] && phase_rank
    [ "$RUN_SHOT"      = 1 ] && phase_shots
    [ "$RUN_REPORT"    = 1 ] && generate_report
}
run_pipeline &
wait $!
exit 0
