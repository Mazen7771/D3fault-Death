#!/usr/bin/env bash
#===============================================================================
# lib/cve_github.sh — GitHub Security Advisories client
#
# Queries GitHub Security Advisories API (GraphQL) for vendor advisories
# and patched versions. Uses unauthenticated API (60 req/hr) or authenticated
# with token (5000 req/hr).
#===============================================================================

GITHUB_API_URL="https://api.github.com/graphql"
GITHUB_ADVISORIES_REST="https://api.github.com/advisories"
GITHUB_CACHE_TTL=86400  # 24 hours
GITHUB_RATE_LIMIT_DELAY=1.0  # conservative for unauthenticated

# cve_github_query <product> <version>
# Query GitHub Security Advisories for the product
cve_github_query() {
    local product="$1" version="$2"
    local cache_key="github_${product}_${version}"
    local cached

    cached=$(cve_cache_get "$cache_dir" "github" "$cache_key" "$GITHUB_CACHE_TTL" 2>/dev/null)
    if [ -n "$cached" ]; then
        vlog "    GitHub Advisories cache hit: $product $version"
        echo "$cached"
        return 0
    fi

    vlog "    Querying GitHub Security Advisories: $product $version"

    local results

    # Try REST API first (simpler, no auth needed for public advisories)
    results=$(cve_github_query_rest "$product" "$version")

    # If we have a GitHub token, we could use GraphQL for more data
    # but REST is sufficient for our needs

    cve_cache_set "$cache_dir" "github" "$cache_key" "$results"
    echo "$results"
}

# cve_github_query_rest <product> <version>
# Query GitHub Security Advisories via REST API
cve_github_query_rest() {
    local product="$1" version="$2"
    local url="${GITHUB_ADVISORIES_REST}?per_page=100"

    # Add ecosystem/package query if we can map product to package
    local ecosystem package
    case "$(echo "$product" | tr '[:upper:]' '[:lower:]')" in
        *npm*|*node*|*javascript*|*typescript*) ecosystem="npm" ;;
        *python*|*pypi*|*django*|*flask*) ecosystem="pypi" ;;
        *maven*|*java*|*spring*) ecosystem="maven" ;;
        *go*|*golang*) ecosystem="go" ;;
        *ruby*|*gem*|*rails*) ecosystem="gem" ;;
        *rust*|*cargo*) ecosystem="cargo" ;;
        *nuget*|*.net*|*csharp*) ecosystem="nuget" ;;
        *) ecosystem="" ;;
    esac

    # Try package search - GitHub advisories are indexed by package name
    local query="${product} ${version}"
    local encoded_query
    encoded_query=$(printf '%s' "$query" | jq -sRr @uri)
    url="${GITHUB_ADVISORIES_REST}?query=${encoded_query}&per_page=50"

    local response
    response=$(curl -sS --max-time 20 -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "${GITHUB_TOKEN:+-H \"Authorization: Bearer ${GITHUB_TOKEN}\"}" \
        "$url" 2>/dev/null || true)

    if [ -z "$response" ] || ! echo "$response" | jq -e 'length > 0' >/dev/null 2>&1; then
        echo '[]'
        return 0
    fi

    # Normalize to our format
    echo "$response" | jq -r '
        map(
            select(.ghsa_id != null) |
            {
                id: (.cve_id // .ghsa_id),
                cvss: (.cvss.score // 0),
                severity: (.severity // "UNKNOWN" | ascii_upcase),
                description: (.description // .summary // ""),
                references: [.references[]?.url // empty],
                patched_versions: [.vulnerabilities[]?.patched_versions[]? // empty],
                vulnerable_versions: [.vulnerabilities[]?.vulnerable_version_range // empty],
                source: "github"
            }
        )
    '
}