#!/usr/bin/env bash
# HuntOps — Kiterunner Adapter
# API endpoint discovery via OpenAPI/Swagger specs
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/kiterunner"
  return 0
}

adapter_name() {
  echo "kiterunner"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon api graphql openapi endpoints"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "kr"; then
    adapter_warn "kiterunner (kr) not found in PATH"
    return 1
  fi
  return 0
}

adapter_health_check() {
  kr version 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")
  threads=$(parse_opt "$opts_json" "threads" "10")

  # Get live URLs from web probe phase
  local live_urls_file="$outdir/../web/live-urls.txt"
  if [ ! -f "$live_urls_file" ] || [ ! -s "$live_urls_file" ]; then
    adapter_warn "No live URLs found for API discovery"
    return 0
  fi

  local output_file="$outdir/kiterunner.txt"
  local count=0

  # Check for OpenAPI/Swagger specs at common paths
  local spec_paths=(
    "/swagger.json"
    "/swagger.yaml"
    "/swagger.yml"
    "/openapi.json"
    "/openapi.yaml"
    "/openapi.yml"
    "/api/swagger.json"
    "/api/openapi.json"
    "/v1/swagger.json"
    "/v2/swagger.json"
    "/api-docs"
    "/api-docs.json"
  )

  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)

    for spec_path in "${spec_paths[@]}"; do
      local spec_url="${url%/}$spec_path"
      local response=$(timeout -k 10 30 curl -skI "$spec_url" 2>/dev/null | head -1)

      if echo "$response" | grep -q "200 OK"; then
        adapter_log "Found OpenAPI spec: $spec_url"

        # Download and scan with kiterunner
        local spec_file="$outdir/${host//./_}_spec.json"
        timeout -k 10 30 curl -sk "$spec_url" -o "$spec_file" 2>/dev/null

        if [ -s "$spec_file" ]; then
          # Run kiterunner to enumerate endpoints
          kr scan "$spec_file" -o "$output_file" --output-format json --concurrency $threads 2>/dev/null

          if [ -f "$output_file" ] && [ -s "$output_file" ]; then
            local endpoints
            endpoints=$(jq -r '.[]? | "\(.method)|\(.path)|\(.description // "")"' "$output_file" 2>/dev/null)
            if [ -n "$endpoints" ]; then
              while IFS= read -r ep; do
                [ -z "$ep" ] && continue
                local method=$(echo "$ep" | cut -d'|' -f1)
                local path=$(echo "$ep" | cut -d'|' -f2)
                local desc=$(echo "$ep" | cut -d'|' -f3)

                emit_finding "info" "$host" "API endpoint: $method $path" "confirmed" \
                  "Discovered via OpenAPI spec: $desc" \
                  "curl -X $method \"${url%/}$path\"" \
                  "kiterunner:api:$method:$path" "" "api,openapi,endpoint"
                count=$((count + 1))
              done <<< "$endpoints"
            fi
          fi
        fi
      fi
    done
  done < <(head -20 "$live_urls_file")

  # Also scan for GraphQL endpoints
  local gql_paths=("/graphql" "/graphql/" "/api/graphql" "/v1/graphql" "/gql")
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)

    for gql_path in "${gql_paths[@]}"; do
      local gql_url="${url%/}$gql_path"
      # Test GraphQL introspection
      local introspection='{"query":"{__schema{types{name}}}"}'
      local resp=$(timeout -k 10 30 curl -sk -X POST -H "Content-Type: application/json" -d "$introspection" "$gql_url" 2>/dev/null)

      if echo "$resp" | grep -q "__schema"; then
        emit_finding "medium" "$host" "GraphQL introspection enabled" "confirmed" \
          "GraphQL endpoint at $gql_url allows introspection" \
          "curl -X POST -H 'Content-Type: application/json' -d '$introspection' \"$gql_url\"" \
          "kiterunner:graphql:introspection" "6.5" "graphql,api,introspection"
        count=$((count + 1))
      fi
    done
  done < <(head -20 "$live_urls_file")

  adapter_log "Kiterunner found $count API endpoints"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan