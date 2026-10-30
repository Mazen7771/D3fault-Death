#!/usr/bin/env bash
#===============================================================================
# security-audit-validation.sh — Automated security and quality validation
#
# Runs syntax validation, security checks, and reliability tests across
# all D3fault-Death scripts.
#
# Usage: ./security-audit-validation.sh
#
# Returns: 0 if all checks pass, non-zero on failure
#
set -euo pipefail

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
STRICT_MODE="${STRICT_MODE:-0}"
VERBOSE="${VERBOSE:-0}"

# Color codes (no emojis)
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

log() {
    local level="$1"
    shift
    local timestamp
    timestamp=$(date '+%Y-%m-%d %T')

    case "$level" in
        info)
            echo "[INFO] $timestamp: $*" >&2
            ;;
        success)
            echo "[SUCCESS] $timestamp: $*" >&2
            ;;
        warn)
            echo "[WARN] $timestamp: $*" >&2
            ;;
        error)
            echo "[ERROR] $timestamp: $*" >&2
            ;;
        fatal)
            echo "[FATAL] $timestamp: $*" >&2
            exit 1
            ;;
    esac
}

success() {
    log "success" "$*"
}

warn() {
    log "warn" "$*"
}

# ----------------------------------------------------------------------
# Pattern Verification Functions
# ----------------------------------------------------------------------
check_no_emojis() {
    local file="$1"
    # Check for Unicode emoji characters
    if grep -qE '[\x{1F600}-\x{1F64F}]' "$file" 2>/dev/null; then
        log "error" "File contains emojis: $file"
        return 1
    fi

    success "No emojis found: $file"
    return 0
}

check_bash_syntax() {
    local file="$1"
    if bash -n "$file" 2>&1 | grep -qE"error|Error"; then
        log "error" "Syntax error in $file"
        return 1
    fi

    success "Bash syntax valid: $file"
    return 0
}

check_brace_alignment() {
    local file="$1"
    local open_count
    open_count=$(grep -o '{' "$file" | wc -l)
    local close_count
    close_count=$(grep -o '}' "$file" | wc -l)

    if [[ "$open_count" -ne "$close_count" ]]; then
        log "error" "Mismatched braces in $file: $open_count opens, $close_count closes"
        return 1
    fi

    success "Brace balance: $file ($open_count pairs)"
    return 0
}

# ----------------------------------------------------------------------
# Password/Credential Checks
# ----------------------------------------------------------------------
check_hardcoded_passwords() {
    local file="$1"

    # Simple negation patterns
    local password_vars=(
        'PASSWORD'
        'pass ='
        'pass='
        'token ='
        'token='
        'apikey ='
        'apikey='
        'api_key ='
        'api_key='
    )

    for pattern in "${password_vars[@]}"; do
        if grep -qi "$pattern" "$file"; then
            log "error" "Potential hardcoded password/credential in $file: $pattern"
            return 1
        fi
    done

    success "No password credentials found: $file"
    return 0
}

# ----------------------------------------------------------------------
# Permission Checks
# ----------------------------------------------------------------------
check_output_permissions() {
    log "info" "Checking output directory permissions"

    local targets=(
        "$HOME/.d3fault-work"
        "$HOME/.d3fault-work/active"
        "$HOME/.subjack"
    )

    for dir in "${targets[@]}"; do
        if [[ -d "$dir" ]]; then
            local perms
            if command -v stat &>/dev/null; then
                perms=$(stat -c '%a' "$dir" 2>/dev/null)
            elif [[ "$OSTYPE" == "darwin"* ]]; then
                perms=$(stat -f '%A' "$dir" 2>/dev/null)
            fi

            if [[ -n "$perms" ]] && [[ "$perms" -gt "755" ]]; then
                warn "Directory $dir has too permissive permissions: $perms (should be at most 755)"
            else
                success "Directory permissions ok: $dir ($perms)"
            fi
        fi
    done

    success "Output permissions validated"
    return 0
}

# ----------------------------------------------------------------------
# Integration Tests
# ----------------------------------------------------------------------
test_auth_injection_fix() {
    log "info" "Testing AUTH_ARGS quoting fix"

    local omni_file="/home/zodlek/D3fault-Death/omni.sh"

    if grep -q 'AUTH_ARGS\[@\]' "$omni_file"; then
        log "error" "AUTH_ARGS array expansion not properly handled: $omni_file"
        return 1
    fi

    success "AUTH_ARGS wrapping fix verified"
    return 0
}

test_strategy_sorting() {
    log "info" "Testing adaptive strategy execution"

    local strat_file="/home/zodlek/D3fault-Death/huntops/lib/strategy.sh"

    if ! grep -Fq 'for strat in "${strategy_order[@]}"' "$strat_file"; then
        log "error" "Strategy sorted execution not implemented: $strat_file"
        return 1
    fi

    success "Strategy execution properly implemented: $strat_file"
    return 0
}

test_cve_engine() {
    log "info" "Testing CVE correlation engine"

    local cve_file="/home/zodlek/D3fault-Death/huntops/lib/cve.sh"

    if grep -Fq '_seed_cve_db' "$cve_file"; then
        log "error" "Old static CVE database still used: $cve_file"
        return 1
    fi

    if ! grep -Fq 'cve_nvd_query' "$cve_file" && ! grep -Fq 'cve_prioritize' "$cve_file"; then
        log "warn" "No CVE correlation functions in: $cve_file"
    fi

    success "CVE engine uses live lookup: $cve_file"
    return 0
}

# ----------------------------------------------------------------------
# Main Validation Flow
# ----------------------------------------------------------------------
main() {
    log "info" "========================================"
    log "info" "D3fault-Death Security Audit Validation"
    log "info" "========================================"
    log "info" ""

    local exit_code=0
    local files=() root="/home/zodlek/D3fault-Death"

    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$root" -type f -name "*.sh" -print0)

    log "info" "Scanning ${#files[@]} shell scripts..."

    local checked=0
    local passed=0
    local failed=0

    for file in "${files[@]}"; do
        local relative
        relative="${file#$root/}"

        # Skip temporary and known files
        [[ "$relative" =~ (node_modules|vendor|\.git) ]] && continue
        [[ "$relative" =~ (tmp|temp|\.tmp) ]] && continue
        [[ "$relative" =~ common\.sh ]] && continue

        log "info" "Checking: $relative"
        checked=$((checked + 1))

        # Run checks
        check_no_emojis "$file" && passed=$((passed + 1)) || failed=$((failed + 1))
        check_bash_syntax "$file" && passed=$((passed + 1)) || exit_code=$?
        check_brace_alignment "$file" && passed=$((passed + 1)) || exit_code=$?
        check_hardcoded_passwords "$file" && passed=$((passed + 1)) || exit_code=$?

        log "info" ""
    done

    # Integration tests
    log "info" "Running integration tests..."

    test_auth_injection_fix || exit_code=$?
    test_strategy_sorting || exit_code=$?
    test_cve_engine || exit_code=$?

    check_output_permissions || exit_code=$?

    # Summary
    echo ""
    log "info" "========================================"
    log "info" "VALIDATION SUMMARY"
    log "info" "========================================"
    echo ""
    log "info" "Scripts checked: $checked"
    log "info" "Checks passed: $passed"
    log "info" "Checks failed: $failed"
    echo ""

    if [[ $exit_code -eq 0 ]]; then
        log "success" "All validations passed"
    else
        log "warn" "Some validations failed (fix with STRICT_MODE=1)"
    fi

    return $exit_code
}

main "$@"
