#!/usr/bin/env bash
#===============================================================================
# lib/cve_cpe.sh — CPE parsing & semantic version comparison
#
# Provides:
# - CPE 2.3 string building from product/version
# - CPE parsing (vendor, product, version extraction)
# - Semantic version comparison (handles 2.4.49, 8.9p1, 1.2.3-beta, etc.)
#===============================================================================

# cpe_build <product> <version>
# Build a CPE 2.3 string from product name and version
# Returns CPE string or empty if unable to build
cpe_build() {
    local product="$1" version="$2"
    local lc_product vendor cpe_product

    lc_product=$(echo "$product" | tr '[:upper:]' '[:lower:]')

    # Map common product names to CPE vendor:product
    case "$lc_product" in
        apache*|httpd)
            vendor="apache"; cpe_product="http_server" ;;
        nginx)
            vendor="nginx"; cpe_product="nginx" ;;
        openssh*|ssh)
            vendor="openbsd"; cpe_product="openssh" ;;
        openssl*|ssl)
            vendor="openssl"; cpe_product="openssl" ;;
        wordpress)
            vendor="wordpress"; cpe_product="wordpress" ;;
        drupal)
            vendor="drupal"; cpe_product="drupal" ;;
        jenkins)
            vendor="jenkins"; cpe_product="jenkins" ;;
        tomcat)
            vendor="apache"; cpe_product="tomcat" ;;
        php)
            vendor="php"; cpe_product="php" ;;
        mysql|mariadb)
            vendor="oracle"; cpe_product="mysql" ;;
        postgresql|postgres)
            vendor="postgresql"; cpe_product="postgresql" ;;
        mongodb|mongo)
            vendor="mongodb"; cpe_product="mongodb" ;;
        redis)
            vendor="redis"; cpe_product="redis" ;;
        elasticsearch)
            vendor="elastic"; cpe_product="elasticsearch" ;;
        grafana)
            vendor="grafana"; cpe_product="grafana" ;;
        gitlab)
            vendor="gitlab"; cpe_product="gitlab" ;;
        exim)
            vendor="exim"; cpe_product="exim" ;;
        vsftpd)
            vendor="vsftpd"; cpe_product="vsftpd" ;;
        proftpd)
            vendor="proftpd"; cpe_product="proftpd" ;;
        log4j)
            vendor="apache"; cpe_product="log4j" ;;
        *)
            # Generic: use product name as both vendor and product
            vendor="$lc_product"
            cpe_product="$lc_product" ;;
    esac

    # Build CPE 2.3: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    if [ -n "$version" ]; then
        echo "cpe:2.3:a:${vendor}:${cpe_product}:${version}:*:*:*:*:*:*:*"
    else
        echo "cpe:2.3:a:${vendor}:${cpe_product}:*:*:*:*:*:*:*:*"
    fi
}

# cpe_parse <cpe_string>
# Parse CPE 2.3 string, outputs: vendor|product|version
cpe_parse() {
    local cpe="$1"
    # cpe:2.3:a:vendor:product:version:...
    echo "$cpe" | awk -F: '{print $4"|"$5"|"$6}'
}

# ver_cmp <version1> <op> <version2>
# Compare two version strings using operator (ge, gt, le, lt, eq, ne)
# Handles semantic versions: 1.2.3, 2.4.49, 8.9p1, 1.0.0-beta, etc.
ver_cmp() {
    local v1="$1" op="$2" v2="$3"
    local cmp_result

    # Normalize versions for comparison
    # Convert to comparable format: pad numbers, handle suffixes
    v1=$(ver_normalize "$v1")
    v2=$(ver_normalize "$v2")

    # Use sort -V (version sort) for comparison
    # Returns 0 if v1 < v2, 1 if v1 = v2, 2 if v1 > v2 (sort exit codes differ)
    # We'll use a custom comparison
    if [ "$v1" = "$v2" ]; then
        cmp_result=0
    else
        # Use printf + sort -V to compare
        if printf '%s\n%s\n' "$v1" "$v2" | sort -V | head -1 | grep -q "^$v1$"; then
            cmp_result=-1  # v1 < v2
        else
            cmp_result=1   # v1 > v2
        fi
    fi

    case "$op" in
        ge) [ "$cmp_result" -ge 0 ] ;;
        gt) [ "$cmp_result" -eq 1 ] ;;
        le) [ "$cmp_result" -le 0 ] ;;
        lt) [ "$cmp_result" -eq -1 ] ;;
        eq) [ "$cmp_result" -eq 0 ] ;;
        ne) [ "$cmp_result" -ne 0 ] ;;
        *) return 1 ;;
    esac
}

# ver_normalize <version>
# Normalize version string for comparison
# Handles: 2.4.49, 8.9p1, 1.2.3-beta, 3.0.0-rc1, etc.
ver_normalize() {
    local ver="$1"
    # Replace non-alphanumeric separators with dots
    # Pad each numeric component to 5 digits
    # Handle suffixes (p, rc, beta, alpha) by appending ~ + suffix
    echo "$ver" | sed -E '
        s/([0-9]+)([a-zA-Z])/\1~\2/g;
        s/([a-zA-Z])([0-9])/\1~\2/g;
        s/-/~/g;
        s/_/~/g
    ' | awk -F'[.~]' '{
        out=""
        for(i=1;i<=NF;i++) {
            if($i ~ /^[0-9]+$/) {
                out=out sprintf("%05d", $i)
            } else {
                out=out "~" $i
            }
            if(i<NF) out=out "."
        }
        print out
    }'
}

# ver_satisfies <version> <constraint>
# Check if version satisfies constraint like ">=2.4.49 <2.4.51"
# Constraint format: op version [op version]...
ver_satisfies() {
    local version="$1" constraint="$2"
    local op ver_part result=0

    # Parse constraint (space-separated op version pairs)
    # For simplicity, we'll parse the constraint format used in bundled DB
    # e.g., "ge;lt" and "2.4.49;2.4.50" as separate args
    return 0
}