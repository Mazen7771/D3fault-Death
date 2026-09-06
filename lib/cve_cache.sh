#!/usr/bin/env bash
#===============================================================================
# lib/cve_cache.sh — Local cache management for CVE Intelligence Engine
#
# Uses JSON files in a directory structure:
#   ~/.cache/d3fault-death/cve/
#   ├── nvd/          # NVD API responses (keyed by CPE or product)
#   ├── kev/          # CISA KEV catalog (single file)
#   ├── exploitdb/    # SearchSploit results per product
#   ├── github/       # GitHub Security Advisories per product
#   └── vendor/       # Vendor bulletins per product
#
# Cache entries have TTL (time-to-live) in seconds.
#===============================================================================

# cve_cache_init <cache_dir>
# Initialize cache directory structure
cve_cache_init() {
    local cache_dir="$1"
    mkdir -p "$cache_dir"/{nvd,kev,exploitdb,github,vendor}
    chmod 700 "$cache_dir" 2>/dev/null || true
    chmod 700 "$cache_dir"/* 2>/dev/null || true
}

# cve_cache_get <cache_dir> <subdir> <key> <ttl_seconds>
# Get cached value if not expired. Returns JSON or empty string.
# key will be sanitized for filesystem safety.
cve_cache_get() {
    local cache_dir="$1" subdir="$2" key="$3" ttl="$4"
    local safe_key cache_file age now

    # Sanitize key for filesystem (replace / : @ etc with _)
    safe_key=$(printf '%s' "$key" | sed 's/[\/:@]/_/g; s/[^A-Za-z0-9._-]/_/g')
    cache_file="$cache_dir/$subdir/$safe_key.json"

    [ -f "$cache_file" ] || return 1

    # Check TTL
    now=$(date +%s)
    age=$((now - $(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null || echo "$now")))
    [ "$age" -gt "$ttl" ] && return 1

    command cat "$cache_file"
    return 0
}

# cve_cache_set <cache_dir> <subdir> <key> <json_value>
# Store JSON value in cache atomically
cve_cache_set() {
    local cache_dir="$1" subdir="$2" key="$3" value="$4"
    local safe_key cache_file tmp_file

    safe_key=$(printf '%s' "$key" | sed 's/[\/:@]/_/g; s/[^A-Za-z0-9._-]/_/g')
    cache_file="$cache_dir/$subdir/$safe_key.json"
    tmp_file=$(mktemp "${cache_file}.tmp.XXXXXX")

    printf '%s' "$value" > "$tmp_file"
    mv "$tmp_file" "$cache_file"
    chmod 600 "$cache_file" 2>/dev/null || true
}

# cve_cache_expire <cache_dir> <subdir> <key> <ttl_seconds>
# Check if cache entry is expired (returns 0 if expired, 1 if valid)
cve_cache_expire() {
    local cache_dir="$1" subdir="$2" key="$3" ttl="$4"
    local safe_key cache_file age now

    safe_key=$(printf '%s' "$key" | sed 's/[\/:@]/_/g; s/[^A-Za-z0-9._-]/_/g')
    cache_file="$cache_dir/$subdir/$safe_key.json"

    [ -f "$cache_file" ] && return 0  # not expired if doesn't exist (caller handles)

    now=$(date +%s)
    age=$((now - $(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null || echo "$now")))
    [ "$age" -gt "$ttl" ]
}

# cve_cache_clear <cache_dir> [subdir]
# Clear cache (all or specific subdir)
cve_cache_clear() {
    local cache_dir="$1" subdir="${2:-}"
    if [ -n "$subdir" ]; then
        rm -rf "$cache_dir/$subdir" 2>/dev/null
        mkdir -p "$cache_dir/$subdir"
    else
        rm -rf "$cache_dir" 2>/dev/null
        cve_cache_init "$cache_dir"
    fi
}