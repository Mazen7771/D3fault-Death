#!/usr/bin/env bash
#===============================================================================
# lib/cve_nvd.sh — NVD API v2 client for CVE Intelligence Engine
#
# Queries NVD REST API v2 for CVE data by CPE name or keyword.
# Implements rate limiting, exponential backoff, and pagination.
#===============================================================================

# NVD API configuration
NVD_API_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY="${NVD_RATE_LIMIT_DELAY:-0.2}"  # 5 req/s default
NVD_MAX_RETRIES=3
NVD_TIMEOUT=30

# cve_nvd_query <cpe> <product> <version>
# Query NVD for CVEs matching the given CPE/product/version
# Returns JSON array of normalized CVE objects
cve_nvd_query() {
    local cpe="$1" product="$2" version="$3"
    local cache_key cache_ttl cached results

    cache_key="nvd_${cpe}"
    cache_ttl="${CVE_CACHE_TTL:-86400}"

    # Try cache first
    cached=$(cve_cache_get "$cache_dir" "nvd" "$cache_key" "$cache_ttl" 2>/dev/null)
    if [ -n "$cached" ]; then
        vlog "    NVD cache hit: $cpe"
        echo "$cached"
        return 0
    fi

    vlog "    NVD API query: $cpe"

    # URL-encode CPE (contains : / * that break curl if unencoded)
    local enc_cpe enc_kw
    enc_cpe=$(printf '%s' "$cpe" | sed 's/:/%3A/g; s/\//%2F/g; s/\*/%2A/g')
    enc_kw=$(printf '%s' "${product} ${version}" | sed 's/ /%20/g; s/:/%3A/g; s/\//%2F/g')

    # Build query parameters
    # Use cpeName for exact matching, or keywordSearch for fuzzy
    local query_url="${NVD_API_BASE}?cpeName=${enc_cpe}&resultsPerPage=2000"
    # Also try keyword search as fallback
    local keyword_url="${NVD_API_BASE}?keywordSearch=${enc_kw}&resultsPerPage=2000"

    local response
    response=$(cve_nvd_fetch_with_retry "$query_url")

    # If no results, try keyword search
    if echo "$response" | jq -e '.totalResults == 0' >/dev/null 2>&1; then
        vlog "    NVD: no results for CPE, trying keyword search..."
        response=$(cve_nvd_fetch_with_retry "$keyword_url")
    fi

    # Normalize response to our internal format
    results=$(echo "$response" | cve_nvd_normalize "$product" "$version")

    # Cache the results
    cve_cache_set "$cache_dir" "nvd" "$cache_key" "$results"

    echo "$results"
}

# cve_nvd_fetch_with_retry <url>
# Fetch URL with exponential backoff and rate limiting
cve_nvd_fetch_with_retry() {
    local url="$1" attempt=0 delay response http_code

    while [ "$attempt" -lt "$NVD_MAX_RETRIES" ]; do
        # Rate limiting: sleep between requests
        sleep "$NVD_RATE_LIMIT_DELAY"

        # Build curl command
        local curl_cmd=(curl -sS --max-time "$NVD_TIMEOUT" -H "Accept: application/json")

        # Add API key if available
        if [ -n "${NVD_API_KEY:-}" ]; then
            curl_cmd+=(-H "apiKey: ${NVD_API_KEY}")
            # With API key, we can go faster
            NVD_RATE_LIMIT_DELAY=0.02  # 50 req/s
        fi

        response=$("${curl_cmd[@]}" "$url" 2>/dev/null)
        http_code=$?

        if [ "$http_code" -eq 0 ] && echo "$response" | jq -e '.vulnerabilities' >/dev/null 2>&1; then
            echo "$response"
            return 0
        fi

        # Check for rate limit (429) or server error (5xx)
        if echo "$response" | grep -q '"message".*rate limit' 2>/dev/null; then
            warn "    NVD API rate limited, backing off..."
            sleep $((2 ** attempt * 5))
        elif [ "$http_code" -ne 0 ]; then
            warn "    NVD API request failed (curl exit: $http_code), retry $((attempt+1))/$NVD_MAX_RETRIES"
            sleep $((2 ** attempt * 2))
        else
            warn "    NVD API returned invalid response, retry $((attempt+1))/$NVD_MAX_RETRIES"
            sleep $((2 ** attempt * 2))
        fi

        attempt=$((attempt + 1))
    done

    # Return empty array on failure
    echo '{"vulnerabilities":[],"totalResults":0}'
}

# cve_nvd_normalize <product> <version>
# Normalize NVD API response to internal CVE object format
# Reads JSON from stdin, outputs JSON array
cve_nvd_normalize() {
    local product="$1" version="$2"
    jq -r --arg prod "$product" --arg ver "$version" '
        .vulnerabilities[]? |
        {
            id: .cve.id,
            cvss: (
                .cve.metrics.cvssMetricV31[0].cvssData.baseScore //
                .cve.metrics.cvssMetricV30[0].cvssData.baseScore //
                .cve.metrics.cvssMetricV2[0].cvssData.baseScore //
                0
            ),
            severity: (
                .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity //
                .cve.metrics.cvssMetricV30[0].cvssData.baseSeverity //
                .cve.metrics.cvssMetricV2[0].baseSeverity //
                "UNKNOWN"
            ),
            description: (.cve.descriptions[]? | select(.lang=="en") | .value // ""),
            references: [.cve.references[]?.url // empty],
            cpe_match: [.cve.configurations[]?.nodes[]?.cpeMatch[]? | select(.vulnerable==true) | .criteria // empty],
            source: "nvd"
        }
    ' | jq -s '.'
}