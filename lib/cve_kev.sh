#!/usr/bin/env bash
#===============================================================================
# lib/cve_kev.sh — CISA Known Exploited Vulnerabilities (KEV) catalog client
#
# Fetches and caches the CISA KEV catalog for fast lookup of actively
# exploited vulnerabilities.
#===============================================================================

KEV_CATALOG_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL=3600  # 1 hour

# cve_kev_fetch
# Fetch KEV catalog and cache it
cve_kev_fetch() {
    local cache_key="kev_catalog"
    local cached

    # Check cache by reading file directly (avoid var mangling)
    local cache_file="$cache_dir/kev/$cache_key.json"
    if [ -s "$cache_file" ]; then
        # Check TTL
        local now age
        now=$(date +%s)
        age=$((now - $(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null || echo "$now")))
        if [ "$age" -le "$KEV_CACHE_TTL" ]; then
            [ "$VERBOSE" = "1" ] && echo "    KEV cache hit" >&2
            /bin/cat "$cache_file"
            return 0
        fi
    fi

    [ "$VERBOSE" = "1" ] && echo "    Fetching CISA KEV catalog..." >&2

    # Use temp file to preserve Unicode chars (bash var assignment mangles them)
    local tmpfile
    tmpfile=$(mktemp /tmp/kev_raw.XXXXXX)
    curl -sS --max-time 30 "$KEV_CATALOG_URL" 2>/dev/null > "$tmpfile"

    if [ ! -s "$tmpfile" ] || ! /usr/bin/jq -e '.vulnerabilities' "$tmpfile" >/dev/null 2>&1; then
        echo "    KEV fetch failed, using empty catalog" >&2
        rm -f "$tmpfile"
        echo '{"cves":[]}'
        return 1
    fi

    # Transform directly using jq reading from file (avoids bash string mangling)
    local normalized_file
    normalized_file=$(mktemp /tmp/kev_norm.XXXXXX)
    /usr/bin/jq -c '
        {
            cves: [.vulnerabilities[]? | {
                cve_id: .cveID,
                vendor_project: .vendorProject,
                product: .product,
                vulnerability_name: .vulnerabilityName,
                date_added: .dateAdded,
                short_description: .shortDescription,
                required_action: .requiredAction,
                due_date: .dueDate,
                known_ransomware: .knownRansomwareCampaignUse
            }]
        }
    ' "$tmpfile" > "$normalized_file"
    rm -f "$tmpfile"

    if [ ! -s "$normalized_file" ] || ! /usr/bin/jq -e '.cves' "$normalized_file" >/dev/null 2>&1; then
        echo "    KEV transform failed" >&2
        rm -f "$normalized_file"
        echo '{"cves":[]}'
        return 1
    fi

    # Cache the normalized file directly (avoid bash var mangling)
    mv "$normalized_file" "$cache_file"
    chmod 600 "$cache_file" 2>/dev/null || true

    # Output by reading the cached file (ensure stdout - use /bin/cat to avoid bat alias)
    /bin/cat "$cache_file"
}

# cve_kev_check <nvd_results_json>
# Check NVD results against KEV catalog, returns KEV-enriched results
cve_kev_check() {
    local nvd_results="$1"
    local kev_catalog_file

    # Write KEV catalog to temp file (too large for --argjson)
    kev_catalog_file=$(mktemp /tmp/kev_cat.XXXXXX)
    cve_kev_fetch > "$kev_catalog_file"

    # Enrich NVD results with KEV data using --slurpfile
    echo "$nvd_results" | /usr/bin/jq --slurpfile kev "$kev_catalog_file" '
        map(
            . + {
                kev: (
                    .id as $cve_id |
                    $kev[0].cves[]? | select(.cve_id == $cve_id) | true
                ) // false,
                kev_details: (
                    .id as $cve_id |
                    $kev[0].cves[]? | select(.cve_id == $cve_id)
                ) // {}
            }
        )
    '
    rm -f "$kev_catalog_file"
}

# cve_kev_is_kev <cve_id>
# Quick check if a CVE ID is in KEV catalog
cve_kev_is_kev() {
    local cve_id="$1"
    local kev_catalog_file

    kev_catalog_file=$(mktemp /tmp/kev_cat.XXXXXX)
    cve_kev_fetch > "$kev_catalog_file"
    /usr/bin/jq -e --arg id "$cve_id" '.cves[]? | select(.cve_id == $id)' "$kev_catalog_file" >/dev/null 2>&1
    rm -f "$kev_catalog_file"
}