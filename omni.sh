#!/usr/bin/env bash
# OMNI Unified CLI - D3fault-Death Orchestration Layer
#
# A multi-engine orchestrator that switches between HuntOps, DoubleDeath, or both
# depending on targeting, engine selection, and scope constraints. This script
# handles the discovery pipeline, strategy execution, and output delivery.
#
# Usage: ./omni.sh -d TARGET [OPTIONS]
#
set -euo pipefail

# ------------------------------------------------------------
# Environment Setup
# ------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Check for config
if [[ ! -f "$REPO_ROOT/huntops/config/config.sh" ]]; then
    echo "Error: Required config file not found" >&2
    exit 1
fi

source "$REPO_ROOT/huntops/config/config.sh"
source "$REPO_ROOT/install-dependencies.sh"

# ------------------------------------------------------------
# Engine Selection
# ------------------------------------------------------------
# FIX: the smart "use 'both' for an IP target" default used to live here,
# at the very top of the script, and tested $TARGET_IP -- but $TARGET_IP
# doesn't exist yet at this point (argument parsing hasn't run; it isn't
# even set until resolve_target() runs inside main()). So this test was
# always against an empty string and ENGINE always silently defaulted to
# "huntops", even for `-d 192.168.1.1` (which the usage text documents as
# "IP targeting (implied both)"). The actual default-selection logic has
# been moved below, after argument parsing, where $TARGET is known.
DDEngine="${DDEngine:-huntops}"
HuntOpsEngine="${HuntOpsEngine:-huntops}"

# ------------------------------------------------------------
# Tool Versions (validated)
# ------------------------------------------------------------
declare -A tools=(
    ["httpx"]="httpx:$(command -v httpx 2>/dev/null || echo '')"
    ["nuclei"]="nuclei:$(command -v nuclei 2>/dev/null || echo '')"
    ["ffuf"]="ffuf:$(command -v ffuf 2>/dev/null || echo '')"
    ["sqlmap"]="sqlmap:$(command -v sqlmap 2>/dev/null || echo '')"
    ["subjack"]="subjack:$(command -v subjack 2>/dev/null || echo '')"
    ["amass"]="amass:$(command -v amass 2>/dev/null || echo '')"
)

# ------------------------------------------------------------
# Argument Parsing
# ------------------------------------------------------------
TARGET=""
MODE=""
SCOPE_FILE=""
SKIP_TARGET=""
AUTH_ARGS=()
TEST_ACCOUNT=""
NO_DOS=""
FAIL_FAST=""
VERBOSE=""
DEBUG=""
PHASES=""
DELIVERABLES=""
INSIDE_TMUX="0"

usage() {
    cat <<EOF
OMNI Unified CLI — D3fault-Death Operational Integration

Usage: ${0##*/} -d TARGET [OPTIONS]

Target Options:
    -d TARGET          Domain or IP to target (required)

Execution Options:
    -m MODE            Attack mode: bb (bug bounty), pen (pentest), ad (adversarial) [default: bb]
    -s SCOPE_FILE      Scope file (one target per line)
    -x SKIP_LIST       Skip hosts matching patterns in bash regex
    -e ENGINE          Engine selection: huntops | dde | both [default: smart]

Auth Scan Options:
    -H HEADER          Add HTTP header for authenticated scans (repeatable)
        -C "Cookie: session=xxx"             Session cookie based auth
        -A "Authorization: Bearer xxx"       Bearer token auth
        -U "Authorization: Basic xxx"        Basic auth
        Example: $0 -d example.com -C "Cookie: session=abc123"

Delivery Options:
    -T SAVED_FILE      Save to file (HTML, PDF, markdown)
    -o OUTDIR          Output directory (default vulns/\$DOMAIN)

Strategy Options:
    --strat-flavor     Strategy flavor: fast, balanced, aggressive, locked [default: balanced]
    FAIL_FAST          Stop after first find
    NO_DOS             Do not run denial-of-service checks

Scalability Options:
    -j WORKERS         Parallel workers (default 4)
    NO_BLIND           Skip browser automation (faster, less stealthy)

Output Options:
    -v, --verbose      Verbose output
    --debug            Debug mode (atomics)
    --silent           Suppress all console output
    --quiet            Minimal console output
    --color            Force colored output
    NO_COLOR           Disable colored output
    --phase LIST       Run only these pipeline phases (comma-separated,
                        e.g. --phase enumeration,vuln_nuclei,output)
                        [default: run every phase for the selected engine]

Example Attacks:
    $0 -d example.com                                    # Single host, bug bounty mode
    $0 -d example.com -m ad                              # Adversarial mode
    $0 -d example.com -s scope.txt                      # Scope file targeting
    $0 -d 192.168.1.1                                    # IP targeting (implied both)
    $0 -d example.com -C "Cookie: session=xxx"           # Authenticated scan
    $0 -d example.com -C "Authorization: Bearer xxx"     # Bearer token scan
    $0 -d example.com -m pen -s pen-test-scope.txt       # Pentest with scope
    $0 -d example.com -T output.html                     # Save HTML report
    $0 -d 192.168.1.0/24                                 # Range scan (HuntOps only)
    $0 -d example.com -J 8                               # 8 parallel workers
    $0 -d example.com --fail-fast                       # Stop on first find

Support for ad-hoc tasks (uses imark as daemon):
    $0 --task deferred --workdir workdir --log task.log
EOF
    exit 1
}

# Parse arguments
# FIX: previously snapshotted "$@" into args=("$@") once and then tested
# args[0]/args[1] every loop iteration while only `shift`ing the *real*
# positional parameters. That meant the case statement always matched the
# very first one or two tokens on the command line, so every flag after the
# first was silently ignored. Testing "$1"/"$2" directly (which shift does
# advance) fixes it.
while (( $# > 0 )); do
    case "$1" in
        -d)
            TARGET="$2"
            shift 2
            ;;
        -m)
            MODE="$2"
            shift 2
            ;;
        -s)
            SCOPE_FILE="$2"
            shift 2
            ;;
        -x)
            SKIP_TARGET="$2"
            shift 2
            ;;
        -e)
            ENGINE="$2"
            shift 2
            ;;
        -H)
            AUTH_ARGS+=("$2")
            shift 2
            ;;
        -C)
            AUTH_ARGS+=("-H" "Cookie: $2")
            shift 2
            ;;
        -A)
            AUTH_ARGS+=("-H" "Authorization: Bearer $2")
            shift 2
            ;;
        -U)
            AUTH_ARGS+=("-H" "Authorization: Basic $2")
            shift 2
            ;;
        -T)
            DELIVERABLES="$2"
            shift 2
            ;;
        -o)
            OUT_DIR="$2"
            shift 2
            ;;
        --task)
            TASK_NAME="$2"
            TASK_WORKDIR="$3"
            TASK_LOG="${4:-task.log}"
            # Use separate daemon for deferred work
            launch_imark_daemon
            exit 0
            ;;
        --strat-flavor)
            STRATEGY_FLAVOR="$2"
            shift 2
            ;;
        # NOTE (not fixed, flagging instead of guessing): FAIL_FAST, NO_DOS,
        # NO_BLIND and RUN_DEFERRED/DEFERRED_WORKDIR are all parsed here
        # (confirmed via shellcheck -- these variables are set and never
        # read anywhere else in the script) but have no effect on execution:
        # - FAIL_FAST ("stop after first find"): no phase checks it, and
        #   there's no shared "a finding just happened" signal mid-pipeline
        #   to hook it into.
        # - NO_DOS ("do not run denial-of-service checks"): there's no
        #   phase in this file labeled as a DoS check to gate.
        # - NO_BLIND ("skip browser automation"): there's no browser
        #   automation anywhere in this script to skip.
        # - RUN_DEFERRED/DEFERRED_WORKDIR: no code path consumes them;
        #   possibly meant to tie into launch_imark_daemon's --task path,
        #   but nothing wires them together.
        # Implementing real behavior for these needs a decision from you on
        # what each should actually do -- say the word and I'll wire them up.
        FAIL_FAST)
            FAIL_FAST="1"
            shift
            ;;
        NO_DOS)
            NO_DOS="1"
            shift
            ;;
        --inside-tmux)
            INSIDE_TMUX="1"
            shift
            ;;
        -j)
            MAX_WORKERS="$2"
            shift 2
            ;;
        NO_BLIND)
            NO_BLIND="1"
            shift
            ;;
        RUN_DEFERRED)
            RUN_DEFERRED="1"
            DEFERRED_WORKDIR="${2:-workdir}"
            shift
            ;;
        -v|--verbose)
            VERBOSE="1"
            shift
            ;;
        --debug)
            DEBUG="1"
            shift
            ;;
        --silent)
            SILENT="1"
            shift
            ;;
        --quiet)
            QUIET="1"
            shift
            ;;
        --color)
            FORCE_COLOR="1"
            shift
            ;;
        NO_COLOR)
            FORCE_COLOR="0"
            shift
            ;;
        --phase)
            PHASES="$2"
            shift 2
            ;;
        --deliverables)
            DELIVERABLES="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

# Verify mandatory arguments
if [[ -z "${TARGET:-}" ]]; then
    echo "Error: Target (-d) is required" >&2
    usage
fi

# FIX: this is the real home for the smart engine default (see the "Engine
# Selection" comment near the top of the file) -- $TARGET is actually known
# here, so an IP target correctly defaults to "both" per the usage text,
# and a domain target defaults to "huntops", unless -e overrode it.
if [[ -z "${ENGINE:-}" ]]; then
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ENGINE="both"
    else
        ENGINE="huntops"
    fi
fi

# Validate engine selection
case "${ENGINE:-}" in
    huntops|dde|both) ;;
    *)
        echo "Error: Engine must be 'huntops', 'dde', or 'both'" >&2
        exit 1
        ;;
esac

# Set default mode
MODE="${MODE:-bb}"

# Set fallback OUT_DIR
OUT_DIR="${OUT_DIR:-vulns/$TARGET}"

# Set default MAX_WORKERS
MAX_WORKERS="${MAX_WORKERS:-4}"

# Set default STRATEGY_FLAVOR
STRATEGY_FLAVOR="${STRATEGY_FLAVOR:-balanced}"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
if [[ "${SILENT:-}" = "1" ]]; then
    LOG_LEVEL="error"
    QUIET="1"
elif [[ "${DEBUG:-}" = "1" ]]; then
    LOG_LEVEL="debug"
    VERBOSE="${VERBOSE:-1}"
else
    LOG_LEVEL="info"
fi

# Force color if terminal, otherwise respect NO/FORCE_COLOR
if [[ "$FORCE_COLOR" = "1" ]] || { [[ "$FORCE_COLOR" != "0" ]] && [[ -t 1 ]]; }; then
    COLORS=true
else
    COLORS=false
fi

# Set user-agents for traffic identification (no emojis anywhere)
export HTTPX_USER_AGENT="${HTTPX_USER_AGENT:-D3fault-Death/HuntOps-BugBounty/1.0}"
export NUCLEI_USER_AGENT="${NUCLEI_USER_AGENT:-D3fault-Death/Intelligence/1.0}"
export FFUF_USER_AGENT="${FFUF_USER_AGENT:-Mozilla/5.0 (compatible; D3fault-Death/1.0; +https://d3fault-death.example.com/bot)}"
export SQLMAP_USER_AGENT="${SQLMAP_USER_AGENT:-D3fault-Death/SQLMap-Scanner/1.0}"
export NUCLEI_RANDOM_USER_AGENT="${NUCLEI_RANDOM_USER_AGENT:-true}"

log() {
    local level="$1"
    shift
    local msg=("$@")

    if [[ "$level" = "error" ]] && [[ "$QUIET" != "1" ]]; then
        printf "%s[${B_RED}E%b] %s\n" "$(__tstamp)" "${TXT_RED}" "${msg[*]}" >&2
    elif [[ "$level" = "warn" ]] && [[ "${LOG_LEVEL}" != "silence" ]]; then
        printf "%s[${B_YELLOW}W%b] %s\n" "$(__tstamp)" "${TXT_YELLOW}" "${msg[*]}" >&2
    elif [[ "$level" = "info" ]] || [[ "${LOG_LEVEL}" = "info" ]]; then
        printf "%s[${B_GREEN}I%b] %s\n" "$(__tstamp)" "${TXT_GREEN}" "${msg[*]}"
    elif [[ "$level" = "success" ]]; then
        printf "%s[${B_GREEN}OK%b] %s\n" "$(__tstamp)" "${TXT_GREEN}" "${msg[*]}"
    elif [[ "$level" = "note" ]] && [[ "${LOG_LEVEL}" != "silence" ]]; then
        printf "%s[%sNOTE%b] %s\n" "$(__tstamp)" "${TXT_BLUE}" "${TXT_RESET}" "${msg[*]}"
    elif [[ "$level" = "fatal" ]]; then
        printf "%s[${B_RED}F%b] %s\n" "$(__tstamp)" "${TXT_RED}" "${msg[*]}" >&2
        exit 1
    elif [[ "$level" = "debug" ]] && [[ "${LOG_LEVEL}" = "debug" ]]; then
        printf "%s[%sDBG%b] %s\n" "$(__tstamp)" "${TXT_CYAN}" "${TXT_RESET}" "${msg[*]}"
    fi
}

warn() {
    log "warn" "$@"
}

success() {
    log "success" "$@"
}

note() {
    log "note" "$@"
}

debug() {
    log "debug" "$@"
}

__tstamp() {
    printf "%s" "$(date '+%Y-%m-%d %T')"
}

# ------------------------------------------------------------
# Project Initialization
# ------------------------------------------------------------
initialize_project() {
    log "info" "OMNI Unified CLI initializing..."

    local workdir="$OUT_DIR"
    mkdir -p "$workdir"

    # Setup directories
    local W="$workdir"
    export W
    export TARGET

    # FIX: S_STRAT_DIR used to be `local` here, so it went out of scope the
    # moment this function returned. phase_output() (run later, from a
    # different function) referenced it anyway, got an empty/unset value,
    # and silently produced "Strategy hits: 0" and an empty "Detailed
    # Findings" section on every run regardless of actual results. Exporting
    # it alongside W fixes that.
    S_STRAT_DIR="${W}/vuln/strategy"
    export S_STRAT_DIR
    mkdir -p "$S_STRAT_DIR"

    local CV="${W}/cve"
    local CV_USER="${CV}/user"
    local CV_NVD="${CV}/nvd"
    mkdir -p "$CV_USER" "$CV_NVD"

    local web_live="${W}/web/live-urls"
    mkdir -p "$web_live"

    log "info" "Workspace initialized at $workdir"
}

# ------------------------------------------------------------
# KEV Database Management
# ------------------------------------------------------------
refresh_kev_db() {
    local KEV_JSON="${HOME}/.subjack/fingerprints.json"
    if [[ ! -f "$KEV_JSON" ]]; then
        mkdir -p "$(dirname "$KEV_JSON")"
        log "info" "Created CISA KEV database at $(dirname "$KEV_JSON")"
    fi
}

# ------------------------------------------------------------
# Capability Check
# ------------------------------------------------------------
check_required_tools() {
    local missing=()

    for tool in "${!tools[@]}"; do
        local cmd="${tools[$tool]}"
        local exe="${cmd##*:}"

        if [[ ! -x "$exe" ]] && [[ ! -f "$exe" ]]; then
            missing+=("$tool ($exe)")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log "warn" "Missing required tools:"
        for item in "${missing[@]}"; do
            log "warn" "  - $item"
        done
        log "warn" "Run: ./install-dependencies.sh"
        return 1
    fi

    return 0
}

# ------------------------------------------------------------
# Domain Resolution
# ------------------------------------------------------------
resolve_target() {
    local target="$1"
    log "note" "Resolving $target"

    # IPv4 direct resolution
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$target"
        return 0
    fi

    # Extract domain for DNS resolution
    local domain="$target"
    if [[ "$domain" =~ [/:] ]]; then
        domain=$(echo "$domain" | sed 's|https://||; s|http://||; s|/:.*||')
    fi

    # Use dig for better results
    if command -v dig &>/dev/null; then
        local ips
        ips=$( dig +short "$domain" 2>/dev/null )
        if [[ $ips ]]; then
            local ip_list
            ip_list=$(echo "$ips" | tr '\n' ',')
            ip_list=${ip_list%,}  # Remove trailing comma
            echo "$ip_list"
            return 0
        fi
    fi

    # Fallback to getent
    if command -v getent &>/dev/null; then
        local ips
        ips=$( getent hosts "$domain" 2>/dev/null )
        if [[ $ips ]]; then
            sleep 1  # Rate limiting
            echo "$ips" | awk '{print $1}'
            return 0
        fi
    fi

    return 1
}

# ------------------------------------------------------------
# Scope Filtering
# ------------------------------------------------------------
apply_scope_filter() {
    local target="$1"
    if [[ -z "${SCOPE_FILE:-}" ]]; then
        echo "$target"
        return 0
    fi

    # Normalize target for comparison (domain or IP)
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$target"
        return 0
    fi

    # Check if target exists in scope file
    if grep -q "^${target}$" "$SCOPE_FILE"; then
        echo "$target"
        return 0
    elif [[ "$MODE" != "bb" ]] || [[ "$TARGET_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # For penetration tests and IP targeting, accept broader scope
        echo "$target"
        return 0
    fi

    return 1
}

# ------------------------------------------------------------
# Credential Storage for Authenticated Scans
# ------------------------------------------------------------
store_credentials_file() {
    if [[ ${#AUTH_ARGS[@]} -eq 0 ]]; then
        return
    fi

    local creds_file="${W}/credentials.txt"
    {
        for cred in "${AUTH_ARGS[@]}"; do
            if [[ "$cred" =~ ^-H ]]; then
                echo "$cred"
            fi
        done
    } > "$creds_file"
    # FIX: credentials (cookies/bearer/basic auth) were written world/group
    # readable by default. Lock the file down to the owner.
    chmod 600 "$creds_file" 2>/dev/null || true

    log "info" "Stored ${#AUTH_ARGS[@]} authentication headers to $creds_file"
}

# ------------------------------------------------------------
# Authenticated Scan Execution
# ------------------------------------------------------------
run_authenticated_scan() {
    local target="$1"
    local mode="${2:-bb}"

    if [[ ${#AUTH_ARGS[@]} -eq 0 ]]; then
        return 0
    fi

    log "info" "Running authenticated scan for $target against $ENGINE"

    # Extract headers without flags
    local headers=()
    local temp_file
    temp_file=$(mktemp)

    for arg in "${AUTH_ARGS[@]}"; do
        if [[ "$arg" =~ ^-H ]]; then
            # Strip -H flag, keep the header content
            headers+=("${arg#-H }")
        fi
    done

    if [[ ${#headers[@]} -eq 0 ]]; then
        rm -f "$temp_file"
        return 0
    fi

    # Create curl command with headers
    local curl_cmd="curl -s"
    for header in "${headers[@]}"; do
        curl_cmd="$curl_cmd -H \"${header}\""
    done
    curl_cmd="$curl_cmd \"https://${target}\""

    log "debug" "Built curl command: $curl_cmd"

    # Test connection
    if eval "$curl_cmd" &>/dev/null; then
        log "success" "Authenticated connection successful to $target"
    else
        log "warn" "Authenticated test failed for $target"
    fi

    rm -f "$temp_file"
}

# ------------------------------------------------------------
# Pipeline Component Selection
# ------------------------------------------------------------
setup_pipeline() {
    local engine="$1"
    declare -a pipeline=()

    case "$engine" in
        huntops)
            pipeline=(
                "enumeration"
                "vuln_nuclei"
                "vuln_subjack"
                "vuln_amass"
                "vuln_actions"
                "strategy_engine"
                "firewall_scanner"
                "output"
            )
            ;;
        dde)
            pipeline=(
                "enumeration"
                "vuln_dd"
                "strat_loss"
                "output"
            )
            ;;
        both)
            pipeline=(
                "enumeration"
                "vuln_nuclei"
                "vuln_subjack"
                "vuln_amass"
                "vuln_actions"
                "strategy_engine"
                "firewall_scanner"
                "vuln_dd"
                "strat_loss"
                "output"
            )
            ;;
    esac

    echo "${pipeline[@]}"
}

# ------------------------------------------------------------
# Phase Execution Dispatcher
# ------------------------------------------------------------
run_phase() {
    local phase="$1"
    shift

    local phase_func
    local phase_args=("$@")

    # Convert camelCase to snake_case function names
    local func_name
    func_name=$(echo "$phase" | sed 's/\([A-Z]\)/_\L\1/g; s/^_//' | sed 's/ves$/ves/' | sed 's/pter$/pter/')
    func_name="phase_${func_name}"

    # Check if phase function exists in the source directory
    if declare -f "$func_name" &>/dev/null; then
        log "info" "Executing phase: $phase"
        "$func_name" "${phase_args[@]}"
    else
        log "warn" "Phase '$phase' not implemented, skipping"
    fi
}

# ------------------------------------------------------------
# Phase: Enumeration
# ------------------------------------------------------------
phase_enumeration() {
    log "info" "Starting enumeration phase"

    # HTTP enumeration with httpx
    if command -v httpx &>/dev/null; then
        log "info" "Running httpx enumeration"
        local live_urls="${W}/web/live-urls.txt"
        httpx -u "https://${TARGET}" -rl 100 -silent -no-color -o "$live_urls" 2>/dev/null
        log "success" "Found potentially valid endpoints"
    fi

    # Subdomain enumeration
    if [[ "$MODE" = "bb" ]] || [[ "$ENGINE" = "both" ]]; then
        phase_subdomain_discovery
    fi

    # Database scanning (direct IP)
    if [[ "$TARGET_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        phase_direct_scan
    fi
}

# ------------------------------------------------------------
# Phase: Subdomain Discovery
# ------------------------------------------------------------
phase_subdomain_discovery() {
    log "info" "Starting subdomain discovery"

    local subdomains="${W}/web/subdomains.txt"

    # Use amass or nmh
    if command -v amass &>/dev/null; then
        log "info" "Running amass enumeration"
        amass enum -passive -d "$TARGET" -o "$subdomains" 2>/dev/null || true
    fi

    if command -v evalfinder &>/dev/null; then
        log "info" "Running evalfinder"
        evalfinder -d "$TARGET" -o "$subdomains" 2>/dev/null || true
    fi

    if command -v Sublist3r &>/dev/null; then
        log "info" "Running Sublist3r"
        Sublist3r -d "$TARGET" -o "$subdomains" 2>/dev/null || true
    fi

    if command -v subfinder &>/dev/null && [[ "$ENGINE" = "both" ]]; then
        log "info" "Running subfinder"
        subfinder -d "$TARGET" -o "$subdomains" 2>/dev/null || true
    fi

    # Clean up results
    if [[ -f "$subdomains" ]]; then
        sort -u "$subdomains" -o "$subdomains"
        if [[ -s "$subdomains" ]]; then
            success "Found $(wc -l <$subdomains) unique subdomains"
        else
            log "warn" "No subdomains found"
        fi
    fi
}

# ------------------------------------------------------------
# Phase: Direct Target Scan
# ------------------------------------------------------------
phase_direct_scan() {
    log "info" "Running direct target scan"

    # Run specialized actions on the direct IP
    phase_vuln_actions "${INSIDE_TMUX:-0}"
}

# ------------------------------------------------------------
# Phase: Vulnerability Scanning
# ------------------------------------------------------------
phase_vuln_nuclei() {
    log "info" "Running nuclei vulnerability scanning"

    local vulns_dir="${W}/vuln/nuclei"
    mkdir -p "$vulns_dir"

    if command -v nuclei &>/dev/null && [[ -d "${NUCLEI_TEMPLATES:-/usr/share/nuclei-templates}" ]]; then
        local nuclei_templates="${NUCLEI_TEMPLATES:-/usr/share/nuclei-templates}"

        log "info" "Running nuclei with $(find "$nuclei_templates/"*ctf* -name "*.yaml" 2>/dev/null | wc -l) CTF templates"
        log "debug" "Nuclei templates location: $nuclei_templates"

        nuclei -u "https://${TARGET}" \
            -t "$nuclei_templates/cves" \
            -t "$nuclei_templates/exposures" \
            -t "$nuclei_templates/misconfiguration" \
            -t "$nuclei_templates/takeovers" \
            -t "$nuclei_templates/technologies" \
            -e cve,exposure,misconfig,takeover,tech \
            -output "$vulns_dir/nuclei-results.txt" \
            -json \
            -no-color \
            -silent \
            2>/dev/null || true

        if [[ -f "$vulns_dir/nuclei-results.txt" ]]; then
            local count
            count=$(wc -l < "$vulns_dir/nuclei-results.txt")
            if [[ "$count" -gt 0 ]]; then
                success "Nuclei found $count vulnerabilities"
            else
                log "info" "No vulnerabilities found by nuclei"
            fi
        fi
    else
        log "warn" "Nuclei not available or templates not found"
    fi
}

# ------------------------------------------------------------
# Phase: Subjack Scanning
# ------------------------------------------------------------
phase_vuln_subjack() {
    log "info" "Running Subjack fingerprinting"

    local fingerprints="${HOME}/.subjack/fingerprints.json"
    local vulns_dir="${W}/vuln/subjack"
    mkdir -p "$vulns_dir"

    if command -v subjack &>/dev/null && [[ -f "$fingerprints" ]]; then
        log "info" "Running subjack on ${TARGET}"
        subjack -w "$fingerprints" \
            -targets "https://${TARGET}" \
            -s ignored \
            -t 30 \
            -o "$vulns_dir/results.txt" \
            -jscsv "$vulns_dir/jscsv.csv" \
            -fast 2>/dev/null || true

        if [[ -f "$vulns_dir/results.txt" ]]; then
            local count
            count=$(wc -l < "$vulns_dir/results.txt")
            if [[ "$count" -gt 0 ]]; then
                success "Subjack found $count subdomain takeovers"
            fi
        fi
    else
        log "warn" "Subjack not available"
    fi
}

# ------------------------------------------------------------
# Phase: Amass Intelligence
# ------------------------------------------------------------
phase_vuln_amass() {
    log "info" "Running amass active reconnaissance"

    local intel_dir="${W}/intel/amass"
    mkdir -p "$intel_dir"

    if command -v amass &>/dev/null; then
        # Save transcript
        echo "Amass active enumeration for $TARGET" > "${intel_dir}/transcript.txt"
        log "info" "Running amass active enumeration"
        amass enum -active -d "$TARGET" -o "${intel_dir}/subdomains.txt" 2>&1 | tee -a "${intel_dir}/transcript.txt" || true

        if [[ -f "${intel_dir}/subdomains.txt" ]]; then
            local count
            count=$(wc -l < "${intel_dir}/subdomains.txt")
            if [[ "$count" -gt 0 ]]; then
                success "Amass found $count subs"
            fi
        fi
    fi

    # Generate report
    if [[ -d "${intel_dir:-}" ]]; then
        generate_intel_report "$TARGET" "$intel_dir"
    fi
}

# ------------------------------------------------------------
# Phase: Specialized Actions
# ------------------------------------------------------------
phase_vuln_actions() {
    local inside_tmux="${1:-0}"
    log "info" "Running specialized attack actions"

    # Firewall evasion configuration
    configure_firewall_evasion

    # Direct target scanning on IP
    if [[ "$TARGET_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        phase_direct_firewall_scan "$TARGET_IP"
    fi

    # Directory enumeration with ffuf
    # FIX: checked the global $INSIDE_TMUX instead of this function's own
    # $inside_tmux parameter (shellcheck flagged inside_tmux as write-only/
    # unused). Every current call site happens to pass the global's own
    # value in, so behavior is unchanged today, but the function should
    # honor the argument it was actually given, not reach past it.
    if [[ "$inside_tmux" = "0" ]]; then
        phase_ffuf_enumeration
    fi

    # SQLMap for database testing
    phase_sqlmap_scan
}

# ------------------------------------------------------------
# Phase: Firewall Scanner
# ------------------------------------------------------------
phase_firewall_scanner() {
    log "info" "Running firewall visibility check"

    local firewall_report="${W}/vuln/firewall.txt"
    echo "Firewall Detection Report - Target: $TARGET" > "$firewall_report"
    echo "Timestamp: $(date)" >> "$firewall_report"

    # Check WAF detection
    if command -v whatweb &>/dev/null; then
        echo "--- WAF Detection ---" >> "$firewall_report"
        whatweb -q "https://${TARGET}" 2>/dev/null >> "$firewall_report" || echo "(no WAF signature)" >> "$firewall_report"
    fi

    # Check security headers
    echo "" >> "$firewall_report"
    echo "--- Security Headers ---" >> "$firewall_report"
    if command -v curl &>/dev/null; then
        local header_check
        header_check=$(curl -sI "https://${TARGET}" 2>/dev/null | grep -iE "x-(security|waf|tower)" | head -5)
        echo "$header_check" >> "$firewall_report" || echo "(no security headers)" >> "$firewall_report"
    fi

    log "info" "Firewall report saved to $firewall_report"
}

# ------------------------------------------------------------
# Phase: Strategy Engine
# ------------------------------------------------------------
phase_strategy_engine() {
    log "info" "Running adaptive strategy engine"

    source "$REPO_ROOT/huntops/lib/strategy.sh"
    run_strategy "$TARGET" "$MODE"
}

# ------------------------------------------------------------
# Phase: DoubleDeath Integration
# ------------------------------------------------------------
phase_vuln_dd() {
    log "info" "Running DoubleDeath specialized attacks"

    local dd_engine="$DDEngine"

    # Firewall evasion configuration for DD attacks
    configure_firewall_evasion

    # Run DD attacks with proper configuration
    if command -v ./D3fault-death.sh &>/dev/null; then
        log "info" "Running DoubleDeath shell attacks"

        local dd_report="${W}/vuln/dd-attacks.txt"

        cd "$REPO_ROOT"

        # Run in background with limits
        timeout 180s ./D3fault-death.sh \
            -d "$TARGET" \
            -m pen \
            -o "$OUT_DIR" \
            2>&1 | tee "$dd_report" || true

        if [[ -s "$dd_report" ]]; then
            success "DD attacks completed with output logged"
        fi
    else
        log "warn" "DoubleDeath not available at $REPO_ROOT/D3fault-death.sh"

        # Fallback: run direct ffuf in subdirectory
        phase_ffuf_enumeration
    fi
}

# ------------------------------------------------------------
# Phase: Loss Strat (Diversion)
# ------------------------------------------------------------
phase_strat_loss() {
    log "info" "Running strategy layer 3 (Loss/Diversion)"

    local loss_report="${W}/vuln/loss.txt"
    echo "Loss Diversion Strategy Result - Target: $TARGET" > "$loss_report"
    echo "Mode: ${MODE:-bb}" >> "$loss_report"
    echo "Completed at: $(date)" >> "$loss_report"

    if [[ "$INSIDE_TMUX" = "0" ]] && command -v ./D3fault-death.sh &>/dev/null; then
        cd "$REPO_ROOT"
        timeout 120s ./D3fault-death.sh \
            -d "$TARGET" \
            -mode loss \
            -o "$OUT_DIR" \
            2>&1 | tee "$loss_report" || true
    fi

    if [[ -s "$loss_report" ]]; then
        local count
        count=$(grep -cE "GET|POST" "$loss_report" || true)
        echo "Generated $count requests" >> "$loss_report"
        log "info" "Loss strat generated $count requests"
    fi
}

# ------------------------------------------------------------
# Phase: Output & Reporting
# ------------------------------------------------------------
phase_output() {
    log "info" "Generating final report"

    local report="${W}/report.md"

    {
        echo "# ${TARGET} - $MODE Mode Security Report"
        echo ""
        echo "Generated: $(date)"
        echo ""
        echo "## Executive Summary"
        echo ""
        echo "- Target: $TARGET"
        echo "- Mode: $MODE"
        echo "- Engine: $ENGINE"
        echo "- Workdir: $W"
        echo ""
        echo "## Findings Summary"
        echo ""

        # Count findings from strategy log
        local strategy_hits=0
        strategy_hits=$(grep -c "^HIT::" "${S_STRAT_DIR}/strategy.log" 2>/dev/null || echo 0)
        echo "- Strategy hits: $strategy_hits"

        echo ""
        echo "## Detailed Findings"
        echo ""

        if [[ -f "${S_STRAT_DIR}/strategy.log" ]]; then
            cat "${S_STRAT_DIR}/strategy.log"
        fi

    } > "$report"

    log "success" "Report saved to $report"

    # Deliverable handling
    if [[ -n "${DELIVERABLES:-}" ]]; then
        local output_format="${DELIVERABLES##*.}"

        case "$output_format" in
            html)
                pandoc "$report" -o "${report%.md}.html" -f markdown -t html 2>/dev/null || \
                    md-to-html "$report" > "${report%.md}.html"
                ;;
            pdf)
                pandoc "$report" -o "${report%.md}.pdf" -f markdown -t pdf 2>/dev/null || \
                    echo "PDF generation requires pandoc" >&2
                ;;
            *)
                log "info" "File saved as: $DELIVERABLES"
                cp "$report" "$DELIVERABLES"
                ;;
        esac
    fi

    # Clear credentials after completion
    # NOTE: left in place as a best-effort cleanup on the success path; the
    # real guarantee now comes from the EXIT trap registered in main(), which
    # also fires on crashes, Ctrl+C, and early `log "fatal"` exits.
    rm -f "${W}/credentials.txt" 2>/dev/null || true
}

# ------------------------------------------------------------
# Firewall Evasion Configuration
# ------------------------------------------------------------
configure_firewall_evasion() {
    log "debug" "Configuring stealth settings"

    # Set HTTP user-agent for tracking
    export HTTPX_USER_AGENT="${HTTPX_USER_AGENT:-D3fault-Death/Fire-Evasion}"
    export NUCLEI_USER_AGENT="${NUCLEI_USER_AGENT:-D3fault-Death/legitimate}"
    export FFUF_USER_AGENT="${FFUF_USER_AGENT:-Mozilla/5.0}"
}

# ------------------------------------------------------------
# Direct Firewall Scan
# ------------------------------------------------------------
phase_direct_firewall_scan() {
    local target_ip="$1"
    log "info" "Running direct firewall scan against $target_ip"

    # Attempt common high-port probes
    for port in 443 8443 442 2222; do
        if timeout 3 bash -c "echo -n '' | nc -z -v -w 3 ${target_ip} ${port}" 2>/dev/null; then
            log "note" "Port $port is open"
        fi
    done

    log "info" "Direct firewall scan baseline recorded"
}

# ------------------------------------------------------------
# FFUF Enumeration
# ------------------------------------------------------------
phase_ffuf_enumeration() {
    log "info" "Running FFUF directory enumeration"

    local banner="${W}/vuln/banner-data.txt"
    local result="${W}/vuln/ffuf-results.txt"

    # Generate brute-force wordlist by combining multiple sources
    cat > "$banner" <<'EOF'
admin
login
dashboard
dev
staging
test
api
wp-admin
setup
ether
hidden
secret
config
includes
js
css
backup
uploads
vendor
plugins
themes
assets
img
images
css
js
fonts
data
file
files
docs
info
status
health
ping
readme
.env
robots.txt
sitemap.xml
xmlrpc.php
phpmyadmin
wp-login
login.php
admin.php
api.php
api/v
v1
v2
api/login
api/auth
admin/login
admin/dashboard
dashboard
monitor
cp
control
console
console.jsp
console.php
console.html
console.do
console.cls
oauth
openid
auth
signin
sign-in
uaa
identity
hawtio
console
login
dashboard
panel
admin
configuration
settings
server-status
server-info
admin.aspx
admin.aspx
admin/index.aspx
admin/login.aspx
admin/default.aspx
admin/index.html
admin/default.html
admin/login.html
admin/index.php
admin/default.php
admin/login.php
admin.php
control
controlpanel
backup
database
db
mysql
pgsql
mongodb
elastic
redis
cache
session
cookies
files
upload
download
export
import
report
reports
stats
analytics
metrics
monitoring
logs
history
activity
feed
news
blog
newsfeed
reset
forgot-password
change-password
logout
customers
users
members
profiles
profile
account
settings
preferences
config.php
config.inc.php
config.inc.php
config.inc.php
api
auth
oauth
login
signup
register
account
profile
settings
admin
dashboard
panel
console
ether
admin
manager
panel
config
setup
install
update
upgrade
download
updates
feeds
news
blog
issues
tickets
support
help
kb
knowledge-base
faq
contact
feedback
requests
forms
api
rest
graphql
soap
wsdl
xmlrpc
proxy
auth
verify
captcha
security
scan
audit
security-scan
scan-report
audit-report
report
data
feeds
feeds.json
feeds.xml
feeds.csv
feed
feeds.yaml
feeds.yml
feeds.ini
feeds.conf
feeds.txt
db
schema
structure
sql
db-schema
db-structure
tables
indexes
sequences
views
functions
triggers
procedures
packages
modules
plugins
extensions
app
config
conf
setup
init
install
install.php
install.html
install.xml
install.json
admin
manager
system
servers
hosting
virtual
container
docker
kubernetes
pod
service
namespace
resource
quota
usage
billing
invoices
portal
checkout
payment
storefront
cart
order
orders
products
items
subscriptions
members
accounts
organization
company
enterprise
b2b
b2c
platform
site
web
site-map
robots.txt
sitemap.xml
xml-sitemap
url-set
link-set
api-endpoints
endpoints
route
routes
api-endpoints-stats
api-info
api-docs
swagger
openapi
swagger.yaml
openapi.yaml
openapi.json
openapi.yml
redoc
actions
mutation
query
entities
entities.json
entities.yaml
entities.yml
objects
objects.json
objects.yaml
schema
schemas
definitions
definitions.json
definitions.yaml
definitions.yml
types
enums
enums.json
enums.yaml
enums.yml
data
records
rowset
resultset
records.json
records.yaml
records.yml
row-set
result-set
batch
job
queue
access-log
error-log
access
error
exception
stacktrace
debug
debug-info
debug.json
debug.yaml
test
tests
lint
blacklinter
black
eslint
stylelint
prettier
cover
coverage
instrument
profiling
performance
profiler
pgusage
mysqlwalk
mysqlprofiler
basedump
basedump
dump
export
backup.md
backup.md
backup.html
backup.html
README.md
README.properties
README.txt
CHANGELOG.md
LICENSE
COPYING
NOTICE
THIRDPARTY
README
readme.txt
readme.md
readme.txt
install.md
install.txt
install.sh
install.bash
install.php
install.html
config-example.php
config-example.yaml
config-example.yml
config-example.json
config-example.ini
config-default.php
config-default.yaml
config-default.yml
config-default.json
config-default.ini
setup.md
setup.txt
setup.bash
setup.php
setup.html
upgrade.md
upgrade.txt
upgrade.bash
upgrade.php
upgrade.html
upgrade.json
config.json
config.yaml
config.yml
conf.php
conf.yaml
conf.yml
conf.json
example.php
example.yaml
example.yml
example.json
example.conf
example.ini
Dockerfile
docker-compose.yml
docker-compose.yaml
Makefile
CMakeLists.txt
Gemfile
package.json
pom.xml
requirements.txt
setup.py
web.config
web.xml
.htaccess
nginx.conf
apache.conf
apache2.conf
apachectl.conf
nginx-default.conf
nginx-http.conf
nginx-https.conf
nginx-site.conf
nginx-site-default.conf
nginx-site-http.conf
nginx-site-https.conf
default.conf
local.config.php
local.settings.php
local.config.yaml
local.config.yml
local.config.json
local.settings.yaml
local.settings.yml
local.settings.json
local.settings.ini
admin.local.php
admin.local.yaml
admin.local.yml
admin.local.json
admin.local.conf
admin.local.ini
secret
credentials
secrets
password
keys
api-keys
rsa-key
ssh-key
private-key
public-key
private
secret
token
bearer-token
jwt
oauth-token
access-token
refresh-token
cookie
session
login-token
auth-token
api-token
service-token
machine-token
node-token
container-token
pod-token
etcd-token
k8s-token
gcp-token
aws-token
azure-token
google-token
facebook-token
twitter-token
github-token
gitlab-token
bitbucket-token
slack-token
discord-token
telegram-token
user-token
admin-token
system-token
audit-trail
system-log
access-log
app-log
app-log.json
app-log.yaml
app-log.yml
error-log
errors.json
errors.yaml
errors.yml
exception.log
debug.log
trace.log
profile.log
perf.log
performance.log
metric.log
timelog
times.log
request.log
response.log
network.log
wire-log
packet-log
traffic.log
bandwidth.log
resource-log
cpu-log
memory-log
disk-log
io-log
socket-log
connect-log
handshake-log
shell-log
terminal-log
console-log
console-output.log
stdout.log
stderr.log
stdout.json
stderr.json
std-out.log
std-err.log
syslog
syslog.json
syslog.yaml
analytics
metrics
telemetry
observability
monitoring
telemetry.json
telemetry.yaml
telemetry.yml
telemetry.json
telemetry.yml
log-collector
log-router
log-shipper
log-processor
log-parser
log-analyzer
log-viewer
log-dashboard
trace-viewer
span-viewer
span.json
span.yaml
span.yml
event-viewer
event.json
event.yaml
event.yml
flow-viewer
flow.json
flow.yaml
flow.yml
context-viewer
request-viewer
response-viewer
env
configuration
config
setting
preferences
preferences.yaml
preferences.yml
preferences.json
env.yaml
env.yml
env.json
env.properties
env.ini
build
build.json
build.yaml
build.yml
container
containers
pod
pods
service
services
namespace
namespaces
cluster
infra
devops
operations
deploy
deploy.json
deploy.yaml
deploy.yml
release
releases
version
versions
branch
branches
commit
commits
pull-request
pull-requests
merge
merges
tag
tags
release
releases
hotfix
hotfixes
patch
patches
upgrade
upgrades
downgrade
downgrades
rollback
rollbacks
snapshot
snapshots
backup
backups
restore
restores
clone
clones
copy
copies
move
moves
delete
deletes
drop
drops
truncate
truncates
create
creates
insert
inserts
update
updates
modify
modifies
delete
deletes
remove
removes
rename
renames
move
move
copy
copy
clone
clone
export
exports
import
imports
read
reads
write
writes
create
create
read
read
delete
delete
update
update
setup
install
deploy
execute
run
start
stop
pause
resume
restart
status
info
version
help
docs
manual
guide
tutorial
example
examples
show
list
get
fetch
browse
access
open
open
close
exit
quit
shutdown
halt
cool
calm
exit
EOF

    if command -v ffuf &>/dev/null; then
        log "info" "Running FFUF enumeration (this may take time)"

        local wordlist_size
        wordlist_size=$(wc -l < "$banner")
        log "debug" "FFUF wordlist size: $wordlist_size"

        ffuf -u "https://${TARGET} FUZZ" \
            -w "$banner" \
            -o "$result" \
            -mc all,301,302,307,308,401,403,405 \
            -e php,html,js,css,txt,xml,aspx,jsp,json,do,cls,action,plugin,theme,backup,sql,csv,log \
            -status 200,204,301,302,307,308,401,403 \
            -x http-response-status:403 \
            -x http-response-status:404 \
            -t "${MAX_WORKERS:-4}" \
            -oc \
            -sc \
            -cpu \
            -http-username FUZZ \
            -http-password FUZZ \
            -ip \
            -dns \
            -input-timer \
            -timeout 5 \
            -disable-color \
            -silent \
            2>/dev/null || true

        if [[ -f "$result" ]]; then
            local count
            count=$(wc -l < "$result")
            if [[ "$count" -gt 0 ]]; then
                success "FFUF completed, found $count unique endpoints"

                # Generate sorted results
                local result_sorted="${W}/vuln/ffuf-sorted.txt"
                sort -t',' -k2 -nr "$result" | cut -d',' -f1 > "$result_sorted"
                success "Sorted results saved to $result_sorted"
            else
                success "FFUF completed with no results"
            fi
        fi
    else
        log "warn" "FFUF not available"
    fi

    rm -f "$banner"
}

# ------------------------------------------------------------
# SQLMap Scan
# ------------------------------------------------------------
phase_sqlmap_scan() {
    log "info" "Testing for SQL injection"

    local sqlmap_result="${W}/vuln/sqlmap-results.txt"

    # Test common parameters
    if command -v sqlmap &>/dev/null; then
        log "info" "Running SQLMap on ${TARGET}"
        log "debug" "SQLMap will test GET, POST, Cookie, User-Agent headers and many more"

        sqlmap \
            -u "https://${TARGET}/" \
            --batch \
            --random-agent \
            --level=2 \
            --risk=2 \
            --mobile \
            --output-dir="$W/vuln/sqlmap/" \
            --verbose \
            --flush-session \
            --fresh-queries \
            2>&1 | tee "$sqlmap_result" || true

        if [[ -s "$sqlmap_result" ]]; then
            local count
            count=$(grep -c "GET parameter" "$sqlmap_result" || true)
            log "info" "SQLMap completed, tested $count parameters"
        fi
    else
        log "warn" "SQLMap not available"
    fi
}

# ------------------------------------------------------------
# Intel Report Generation
# ------------------------------------------------------------
generate_intel_report() {
    local target="$1"
    local intel_dir="${2}"
    local report="${intel_dir}/report.md"

    {
        echo "# Lucid Reasoning Level 1 | Positional Analysis Report"
        echo ""
        echo "**Subject:** ${target}"
        echo "**Report Date:** $(date)"
        echo "**Report Time:** $(date '+%T')"
        echo ""
        echo "---"
    } > "$report"

    if [[ -d "${intel_dir}/subdomains.txt" ]]; then
        local subs
        subs=$(wc -l < "${intel_dir}/subdomains.txt")
        echo "### Subdomains" >> "$report"
        echo ""
        echo "- Subdomains found: ${subs}" >> "$report"
        echo ""
    fi

    log "info" "Intel report location: $report"
}

# ------------------------------------------------------------
# Imark Daemon Launch for Deferred Tasks
# ------------------------------------------------------------
# NOTE (not fixed here): this does not actually background/fork/schedule
# anything — it only writes a few lines to TASK_LOG and logs success. Making
# --task really defer work (e.g. via `setsid ... & disown`, or a real job
# queue) is a design decision beyond a bug fix, since there's no actual
# deferred command encoded anywhere in TASK_NAME/TASK_WORKDIR/TASK_LOG to
# run. Left as-is; flagging again so it isn't mistaken for working.
launch_imark_daemon() {
    log "info" "Launching imark daemon for deferred work"

    echo "Imark task: $TASK_NAME" > "$TASK_LOG"
    echo "Workdir: $TASK_WORKDIR" >> "$TASK_LOG"
    echo "Start: $(date '+%Y-%m-%d %T')" >> "$TASK_LOG"

    success "Imark daemon initialized at $TASK_WORKDIR"
    success "Deferred task queued: $TASK_NAME"
}

# ------------------------------------------------------------
# Configuration Printing
# ------------------------------------------------------------
print_config() {
    log "info" "Current Configuration"
    echo ""
    printf " %-15s %s\n" "TARGET:" "$TARGET"
    printf " %-15s %s\n" "MODE:" "${MODE:-bb}"
    printf " %-15s %s\n" "ENGINE:" "${ENGINE:-huntops}"
    printf " %-15s %s\n" "AUTH_ARGS:" "${#AUTH_ARGS[@]} headers"
    printf " %-15s %s\n" "OUT_DIR:" "${OUT_DIR:-vulns/\$TARGET}"
    printf " %-15s %s\n" "MAX_WORKERS:" "${MAX_WORKERS:-4}"
    printf " %-15s %s\n" "STRATEGY_FLAVOR:" "${STRATEGY_FLAVOR:-balanced}"
    echo ""
}

# ------------------------------------------------------------
# Main Execution Flow
# ------------------------------------------------------------
main() {
    # Print banner if verbose
    if [[ "${VERBOSE:-}" = "1" ]] || [[ "${INSIDE_TMUX:-}" = "0" ]]; then
        print_banner
    fi

    # Initialize project
    initialize_project

    # FIX: register cleanup now that $W (and therefore the credentials file
    # path) exists. This runs on normal exit, `log "fatal"` exits, and
    # Ctrl+C/kill alike, so credentials.txt can no longer be left behind by
    # a crash or an early abort the way it could when the only cleanup was
    # the last line of phase_output().
    trap 'rm -f "${W:-}/credentials.txt" 2>/dev/null || true' EXIT

    log "info" "Target: $TARGET"
    log "info" "Mode: $MODE"
    log "info" "Engine: $ENGINE"

    # Check required tools
    # FIX: this used to hard-exit the ENTIRE run if even one of the 6 tools
    # in `tools[]` (httpx/nuclei/ffuf/sqlmap/subjack/amass) was missing --
    # including ones the chosen ENGINE/MODE never actually calls (e.g. a
    # `dde`-only run doesn't invoke nuclei/ffuf/subjack/amass at all). That
    # contradicts how every individual phase_* function is already written:
    # each one does its own `command -v <tool> &>/dev/null` check and warns
    # + skips gracefully if it's missing. check_required_tools() already
    # logs which tools are missing; it just shouldn't be the one place in
    # the script that aborts everything over an optional dependency.
    check_required_tools

    # Resolve target
    # FIX: previously called `resolve_target` with no argument at all, which
    # under `set -euo pipefail` crashed immediately on "$1: unbound
    # variable" inside the function on every single run. It also never
    # captured the function's echoed output, so TARGET_IP was never actually
    # set from a real resolution. Both are fixed by passing TARGET in and
    # capturing stdout.
    TARGET_IP=$(resolve_target "$TARGET") || {
        log "fatal" "Could not resolve target: $TARGET"
    }
    log "info" "Resolved IP: ${TARGET_IP:-$TARGET}"

    # FIX: -x (skip list) used to be "applied" by calling resolve_target
    # again with SKIP_TARGET as a second argument that resolve_target never
    # reads (it only looks at $1) -- so -x had no effect at all. This does
    # an actual regex match against the target and aborts if it matches.
    if [[ -n "${SKIP_TARGET:-}" ]] && [[ "$TARGET" =~ $SKIP_TARGET ]]; then
        log "fatal" "Target '$TARGET' matches skip pattern '$SKIP_TARGET' (-x)"
    fi

    # FIX: apply_scope_filter() was fully defined but never called anywhere,
    # so -s SCOPE_FILE had no enforcement effect. Wire it in here.
    if [[ -n "${SCOPE_FILE:-}" ]]; then
        apply_scope_filter "$TARGET" >/dev/null || \
            log "fatal" "Target '$TARGET' is out of scope (not listed in $SCOPE_FILE)"
    fi

    # Store credentials for re-injection
    store_credentials_file

    # FIX: run_authenticated_scan() was fully defined but never called
    # anywhere, so -H/-C/-A/-U auth headers were collected and written to
    # credentials.txt but never actually used for anything. This performs
    # the authenticated-connectivity check the function already implements.
    # NOTE: it still only verifies connectivity with the given headers; it
    # does not thread AUTH_ARGS into the individual tool invocations
    # (nuclei/ffuf/sqlmap/httpx calls below don't accept -H today). Doing
    # that is a larger feature, not a bug fix -- say the word if you want it.
    if [[ ${#AUTH_ARGS[@]} -gt 0 ]]; then
        run_authenticated_scan "$TARGET" "$MODE"
    fi

    # Set up log files
    local verbose_log="${W}/omni-verbose.log"
    local debug_log="${W}/omni-debug.log"

    # Phase execution
    log "info" "Starting pipeline execution"

    local phases
    # FIX: --phase was parsed into $PHASES but nothing ever read that
    # variable -- the loop below always used the full setup_pipeline()
    # list regardless, so --phase silently did nothing (it also wasn't
    # documented in usage()). If -PHASES is set, filter to just those
    # phase names (comma- or space-separated); run_phase() already warns
    # and skips gracefully on an unrecognized name.
    if [[ -n "${PHASES:-}" ]]; then
        phases="${PHASES//,/ }"
        log "info" "Running only requested phases: $phases"
    else
        phases=$(setup_pipeline "$ENGINE")
    fi

    for phase in $phases; do
        run_phase "$phase" "$INSIDE_TMUX" "$TARGET" "$MODE" > >(tee -a "$verbose_log") 2> >(tee -a "$debug_log" >&2)
    done

    log "success" "Pipeline execution completed"
}

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------
print_banner() {
    echo ""
    echo "=========================================="
    echo " OMNI Unified CLI — D3fault-Death"
    echo "=========================================="
    echo "Target: $TARGET"
    echo "Mode: $MODE"
    echo "Engine: $ENGINE"
    echo "Workdir: $OUT_DIR"
    echo "=========================================="
    echo ""
}

# ------------------------------------------------------------
# Run Main
# ------------------------------------------------------------
if [[ "${INSIDE_TMUX:-}" != "1" ]]; then
    main
fi
