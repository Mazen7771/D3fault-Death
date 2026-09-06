#!/usr/bin/env bash
#===============================================================================
# lib/cve_vendor.sh — Vendor security bulletins client
#
# Fetches fixed version information from vendor security pages for major
# products. Provides exact remediation guidance.
#===============================================================================

VENDOR_CACHE_TTL=604800  # 7 days (vendor pages change infrequently)

# Vendor security URLs and parsing patterns
declare -A VENDOR_URLS=(
    [apache]="https://httpd.apache.org/security/vulnerabilities_24.html"
    [nginx]="https://nginx.org/en/security_advisories.html"
    [openssh]="https://www.openssh.com/security.html"
    [openssl]="https://www.openssl.org/news/vulnerabilities.html"
    [linux]="https://www.kernel.org/category/security.html"
    [redis]="https://redis.io/security/"
    [postgresql]="https://www.postgresql.org/support/security/"
    [mysql]="https://www.mysql.com/security/"
    [mongodb]="https://www.mongodb.com/security"
    [jenkins]="https://www.jenkins.io/security/advisories/"
    [tomcat]="https://tomcat.apache.org/security.html"
    [docker]="https://docs.docker.com/engine/security/"
    [kubernetes]="https://kubernetes.io/docs/reference/issues-security/"
)

# cve_vendor_query <product> <version>
# Query vendor bulletins for fixed versions
cve_vendor_query() {
    local product="$1" version="$2"
    local lc_product cache_key cached

    lc_product=$(echo "$product" | tr '[:upper:]' '[:lower:]')
    cache_key="vendor_${lc_product}_${version}"
    cached=$(cve_cache_get "$cache_dir" "vendor" "$cache_key" "$VENDOR_CACHE_TTL" 2>/dev/null)

    if [ -n "$cached" ]; then
        vlog "    Vendor cache hit: $product $version"
        echo "$cached"
        return 0
    fi

    vlog "    Checking vendor bulletins: $product $version"

    local results='[]'
    local vendor_url=""
    local fixed_version=""

    # Find matching vendor
    for vendor in "${!VENDOR_URLS[@]}"; do
        if [[ "$lc_product" == *"$vendor"* ]] || [[ "$vendor" == *"$lc_product"* ]]; then
            vendor_url="${VENDOR_URLS[$vendor]}"
            fixed_version=$(cve_vendor_fetch_fixed_version "$vendor" "$vendor_url" "$version")
            break
        fi
    done

    # Also check common aliases
    case "$lc_product" in
        *httpd*|*apache*) vendor_url="${VENDOR_URLS[apache]}"; fixed_version=$(cve_vendor_fetch_fixed_version "apache" "$vendor_url" "$version") ;;
        *nginx*) vendor_url="${VENDOR_URLS[nginx]}"; fixed_version=$(cve_vendor_fetch_fixed_version "nginx" "$vendor_url" "$version") ;;
        *openssh*|*ssh*) vendor_url="${VENDOR_URLS[openssh]}"; fixed_version=$(cve_vendor_fetch_fixed_version "openssh" "$vendor_url" "$version") ;;
        *openssl*|*ssl*) vendor_url="${VENDOR_URLS[openssl]}"; fixed_version=$(cve_vendor_fetch_fixed_version "openssl" "$vendor_url" "$version") ;;
        *redis*) vendor_url="${VENDOR_URLS[redis]}"; fixed_version=$(cve_vendor_fetch_fixed_version "redis" "$vendor_url" "$version") ;;
        *postgres*|*postgresql*) vendor_url="${VENDOR_URLS[postgresql]}"; fixed_version=$(cve_vendor_fetch_fixed_version "postgresql" "$vendor_url" "$version") ;;
        *mysql*|*mariadb*) vendor_url="${VENDOR_URLS[mysql]}"; fixed_version=$(cve_vendor_fetch_fixed_version "mysql" "$vendor_url" "$version") ;;
        *mongo*|*mongodb*) vendor_url="${VENDOR_URLS[mongodb]}"; fixed_version=$(cve_vendor_fetch_fixed_version "mongodb" "$vendor_url" "$version") ;;
        *jenkins*) vendor_url="${VENDOR_URLS[jenkins]}"; fixed_version=$(cve_vendor_fetch_fixed_version "jenkins" "$vendor_url" "$version") ;;
        *tomcat*) vendor_url="${VENDOR_URLS[tomcat]}"; fixed_version=$(cve_vendor_fetch_fixed_version "tomcat" "$vendor_url" "$version") ;;
        *docker*) vendor_url="${VENDOR_URLS[docker]}"; fixed_version=$(cve_vendor_fetch_fixed_version "docker" "$vendor_url" "$version") ;;
        *kubernetes*|*k8s*) vendor_url="${VENDOR_URLS[kubernetes]}"; fixed_version=$(cve_vendor_fetch_fixed_version "kubernetes" "$vendor_url" "$version") ;;
    esac

    if [ -n "$fixed_version" ]; then
        results=$(jq -n --arg vendor "$vendor_url" --arg fixed "$fixed_version" '[{
            vendor_url: $vendor,
            fixed_version: $fixed,
            source: "vendor"
        }]')
    fi

    cve_cache_set "$cache_dir" "vendor" "$cache_key" "$results"
    echo "$results"
}

# cve_vendor_fetch_fixed_version <vendor> <url> <version>
# Fetch vendor page and extract fixed version for given version
cve_vendor_fetch_fixed_version() {
    local vendor="$1" url="$2" version="$3"
    local response fixed=""

    response=$(curl -sS --max-time 20 "$url" 2>/dev/null || true)
    [ -z "$response" ] && return 1

    # Vendor-specific parsing
    case "$vendor" in
        apache)
            # Apache HTTPD security page - look for version in table
            fixed=$(echo "$response" | grep -iE "CVE-[0-9]{4}-[0-9]+" | \
                sed -n "s/.*${version//\//\\/}.*fixed in \([0-9.]*\).*/\1/p" | head -1)
            ;;
        nginx)
            fixed=$(echo "$response" | grep -iE "fixed in|patched in" | \
                sed -n "s/.*${version}.*fixed in \([0-9.]*\).*/\1/p" | head -1)
            ;;
        openssh)
            fixed=$(echo "$response" | grep -iE "fixed in|openssh [0-9.]" | \
                sed -n "s/.*openssh \([0-9.]*[a-z]*\).*/\1/p" | head -1)
            ;;
        openssl)
            fixed=$(echo "$response" | grep -iE "fixed in|openssl [0-9.]" | \
                sed -n "s/.*openssl \([0-9.]*[a-z]*\).*/\1/p" | head -1)
            ;;
        *)
            # Generic: look for version patterns near "fixed" or "patched"
            fixed=$(echo "$response" | grep -iE "fixed|patched" | \
                grep -oE '[0-9]+(\.[0-9]+){1,3}[a-z]*' | \
                sort -V | tail -1)
            ;;
    esac

    # If no specific match, return latest known version from page
    if [ -z "$fixed" ]; then
        fixed=$(echo "$response" | grep -oE '[0-9]+(\.[0-9]+){1,3}[a-z]*' | sort -V | tail -1)
    fi

    echo "$fixed"
}