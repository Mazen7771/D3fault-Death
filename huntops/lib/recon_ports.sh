#!/usr/bin/env bash
# HuntOps — port scanning: naabu (fast, all hosts) + nmap -sV (services).
set -u

P="$W/ports"
mkdir -p "$P"

run_recon_ports() {
  [ -f "$W/subdomains/final-resolved.txt" ] || { warn "no resolved hosts — run subdomains first"; return 0; }

  local hosts="$W/subdomains/final-resolved.txt"
  [ "$(count_lines "$hosts")" -eq 0 ] && { warn "no hosts to port-scan"; return 0; }

  # ---- naabu fast pass (all hosts, top-ports) --------------------------------
  local ports_arg=""
  if [ "$MODE_DEEP" = 1 ] && [ "$NO_DOS" = 1 ]; then ports_arg="-p -"; else ports_arg="-top-ports 1000"; fi

  if tool_exists naabu; then
    local nb_rate="${NAABU_RATE:-1000}"
    [ "${NO_DOS:-0}" = 1 ] && nb_rate="${NAABU_RATE_NO_DOS:-5000}"
    log "naabu port scan ($ports_arg, rate $nb_rate)"
    timeout -k 30 1200 naabu -list "$hosts" $ports_arg -rate "$nb_rate" -c 20 -silent \
      -o "$P/naabu.txt" 2>/dev/null || warn "naabu failed"
  elif tool_exists masscan; then
    warn "naabu missing — masscan fallback on first 50 hosts"
    head -50 "$hosts" > "$P/.scan50"
    timeout -k 30 900 masscan -iL "$P/.scan50" -p1-10000 --rate "$MASS_RATE" 2>/dev/null \
      -oJ "$P/masscan.json" || warn "masscan failed"
  else
    warn "no fast port scanner (naabu/masscan) — nmap only"
  fi

  # ---- nmap -sV on open hosts (service versions → CVE layer) ------------------
  if tool_exists nmap; then
    local nmap_targets="$P/.nmap-targets"
    : > "$nmap_targets"
    if [ -f "$P/naabu.txt" ]; then
      awk -F: '{print $1}' "$P/naabu.txt" | sort -u | head -50 > "$nmap_targets"
    else
      head -50 "$hosts" > "$nmap_targets"
    fi
    [ "$(count_lines "$nmap_targets")" -gt 0 ] || return 0
    # nmap's built-in resolver is unreliable in this environment (observed
    # "Failed to resolve ... / 0 hosts up"). Pre-resolve hostnames -> IPs with
    # dig so nmap only ever sees IPs; unresolvable hosts are dropped with a note.
    local nmap_ips="$P/.nmap-ips"
    : > "$nmap_ips"
    local h ip
    while read -r h; do
      [ -z "$h" ] && continue
      ip=$(dig +short "$h" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
      [ -n "$ip" ] && echo "$ip" >> "$nmap_ips"
    done < "$nmap_targets"
    local nres; nres=$(count_lines "$nmap_ips")
    if [ "$nres" -eq 0 ]; then
      warn "nmap: none of $(count_lines "$nmap_targets") hosts resolved to an IP — skipping service scan"
      return 0
    fi
    log "nmap -sV on $nres resolved IPs (of $(count_lines "$nmap_targets") hosts)"
    timeout -k 30 1800 command nmap -sV -sC -Pn --top-ports 100 -iL "$nmap_ips" \
      -oN "$P/nmap.txt" -oG "$P/nmap.gnmap" 2>/dev/null || warn "nmap failed"
    # Guard against garbage/foreign output (e.g. a shadowed binary writing bat
    # usage into the -oN file): only trust the file if it is a real nmap report.
    if ! grep -qE "Nmap scan report|Nmap done" "$P/nmap.txt" 2>/dev/null; then
      warn "nmap output looks invalid — retrying without -sC"
      timeout -k 30 1800 command nmap -sV -Pn --top-ports 100 -iL "$nmap_ips" \
        -oN "$P/nmap.txt" -oG "$P/nmap.gnmap" 2>/dev/null || warn "nmap retry failed"
    fi
    if grep -aqE "0 IP addresses \(0 hosts up\)" "$P/nmap.txt"; then
      warn "nmap scanned 0 hosts — service/version layer will be empty (see $P/nmap.txt)"
    fi
    grep -E "open" "$P/nmap.txt" | head -40 > "$P/services.txt" 2>/dev/null || true
  fi
  ok "port scan done -> $P"
}
