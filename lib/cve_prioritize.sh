#!/usr/bin/env bash
#===============================================================================
# lib/cve_prioritize.sh — CVE Prioritization Engine
#
# Aggregates CVE data from all sources and applies prioritization logic:
# - KEV + Exploit + High CVSS → IMMEDIATE_ACTION
# - KEV or Exploit → URGENT
# - High CVSS (≥7.0) → SHOULD_PATCH
# - Others → INFORMATIONAL
#===============================================================================

# cve_prioritize_aggregate <product> <version> <cpe> <nvd_json> <kev_json> <exploitdb_json> <github_json> <vendor_json>
# Aggregate all sources and apply prioritization
cve_prioritize_aggregate() {
    local product="$1" version="$2" cpe="$3"
    local nvd_json="$4" kev_json="$5" exploitdb_json="$6" github_json="$7" vendor_json="$8"

    # Ensure all inputs are valid JSON arrays (empty string -> [])
    nvd_json="${nvd_json:-[]}"
    kev_json="${kev_json:-[]}"
    exploitdb_json="${exploitdb_json:-[]}"
    github_json="${github_json:-[]}"
    vendor_json="${vendor_json:-[]}"

    # Validate JSON
    echo "$nvd_json" | jq -e '.' >/dev/null 2>&1 || nvd_json='[]'
    echo "$kev_json" | jq -e '.' >/dev/null 2>&1 || kev_json='[]'
    echo "$exploitdb_json" | jq -e '.' >/dev/null 2>&1 || exploitdb_json='[]'
    echo "$github_json" | jq -e '.' >/dev/null 2>&1 || github_json='[]'
    echo "$vendor_json" | jq -e '.' >/dev/null 2>&1 || vendor_json='[]'

    # Combine all sources into a single array of CVEs
    local combined
    combined=$(jq -n \
        --argjson nvd "$nvd_json" \
        --argjson kev "$kev_json" \
        --argjson exploitdb "$exploitdb_json" \
        --argjson github "$github_json" \
        --argjson vendor "$vendor_json" \
        '$nvd + $kev + $exploitdb + $github + $vendor')

    # Deduplicate by CVE ID, merge fields
    # Vendor entries don't have CVE IDs, so filter those out first
    local deduped
    deduped=$(echo "$combined" | jq -s '
        flatten |
        map(select(.id != null and .id != "")) |
        group_by(.id) |
        map(
            reduce .[] as $item ({}; . * $item)
        )
    ')

    # Apply prioritization to each CVE
    echo "$deduped" | jq -r --arg prod "$product" --arg ver "$version" --arg cpe "$cpe" '
        map(
            . + {
                product: $prod,
                version: $ver,
                cpe: $cpe,
                priority: (
                    if (.kev == true and .exploit_available == true and (.cvss | tonumber) >= 7.0) then "IMMEDIATE_ACTION"
                    elif (.kev == true or .exploit_available == true) then "URGENT"
                    elif (.cvss | tonumber) >= 7.0 then "SHOULD_PATCH"
                    else "INFORMATIONAL"
                    end
                ),
                vendor_fixed_version: (
                    .vendor_fixed_version // .fixed_version // .patched_versions[0] // "none"
                )
            }
        )
    '
}

# cve_prioritize_single <cve_json>
# Get priority tier for a single CVE object
cve_prioritize_single() {
    local cve_json="$1"
    echo "$cve_json" | jq -r '
        if (.kev == true and .exploit_available == true and (.cvss | tonumber) >= 7.0) then "IMMEDIATE_ACTION"
        elif (.kev == true or .exploit_available == true) then "URGENT"
        elif (.cvss | tonumber) >= 7.0 then "SHOULD_PATCH"
        else "INFORMATIONAL"
        end
    '
}

# cve_priority_score <priority>
# Convert priority to numeric score for sorting
cve_priority_score() {
    local priority="$1"
    case "$priority" in
        IMMEDIATE_ACTION) echo 100 ;;
        URGENT) echo 75 ;;
        SHOULD_PATCH) echo 50 ;;
        INFORMATIONAL) echo 10 ;;
        *) echo 0 ;;
    esac
}