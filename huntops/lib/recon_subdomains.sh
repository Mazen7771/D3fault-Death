#!/usr/bin/env bash
# HuntOps — subdomain enumeration: multi-source passive + permutation + brute,
# DNS validation with wildcard filtering, and a LOW-YIELD WARNING.
# This is the fix for the old "silently collapses to 1 hostname" failure.
set -u

SD="$W/subdomains"
RAW="$SD/raw"
mkdir -p "$RAW"

# A source's output is normalized via extract_hostnames() into the master set.
_collect_source() { # name, command...
  local name="$1"; shift
  [ -f "$RAW/$name.txt" ] && return  # already collected (resume)
  ( timeout "${SRC_TIMEOUT:-120}" "$@" > "$RAW/$name.txt" 2>"$RAW/$name.log" ) &
}

# amass on this box is a /usr/bin/amass wrapper that runs
#   sudo libpostal_data download all /var/lib/libpostal
# whenever /usr/share/libpostal/transliteration is missing — that prompts for a
# password on any tty (tmux windows!) and otherwise hangs. Only run amass when
# the libpostal data it needs is already present; warn once otherwise.
_amass_ready() {
  [ -e /usr/share/libpostal/transliteration ] || [ -d /var/lib/libpostal ]
}

run_recon_subdomains() {
  log "multi-source passive subdomain enumeration"
  SRC_TIMEOUT=${SRC_TIMEOUT:-150}

  # ---- Stage A: passive sources (parallel) ----------------------------------
  _collect_source subfinder   bash -c "subfinder -d '$DOMAIN' -all -silent 2>/dev/null"
  if _amass_ready; then
    _collect_source amass     bash -c "amass enum -passive -d '$DOMAIN' -o /dev/stdout 2>/dev/null"
  else
    warn "amass skipped (libpostal data missing — run './huntops.sh -i' once to provision)"
  fi
  tool_exists assetfinder && _collect_source assetfinder bash -c "assetfinder --subs-only '$DOMAIN' 2>/dev/null"
  _collect_source crtsh       bash -c "curl -sk --max-time 120 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' 2>/dev/null | tr ' ' '\n'"
  _collect_source certspotter bash -c "curl -sk --max-time 60 'https://api.certspotter.com/v1/issuances?domain=$DOMAIN&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]' 2>/dev/null"
  _collect_source hackertarget bash -c "curl -sk --max-time 60 'https://api.hackertarget.com/hostsearch/?q=$DOMAIN' | cut -d, -f1 2>/dev/null"
  _collect_source rapiddns    bash -c "curl -sk --max-time 60 'https://rapiddns.io/subdomain/$DOMAIN?full=1' | grep -oE '[a-z0-9._-]+\.$DOMAIN' 2>/dev/null"
  _collect_source bufferover  bash -c "curl -sk --max-time 60 'https://dns.bufferover.run/dns?q=.$DOMAIN' | jq -r '.FDNS_A[], .RDNS[]' 2>/dev/null | grep -oE '[a-z0-9._-]+\.$DOMAIN'"
  _collect_source otx         bash -c "curl -sk --max-time 60 'https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns' | jq -r '.passive_dns[].hostname' 2>/dev/null"
  _collect_source anubis      bash -c "curl -sk --max-time 60 'https://jldc.me/anubis/subdomains/$DOMAIN' | jq -r '.[]' 2>/dev/null"
  _collect_source urlscan     bash -c "curl -sk --max-time 90 'https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=100' | jq -r '.results[].page.url' 2>/dev/null"
  _collect_source wayback     bash -c "curl -sk --max-time 90 'http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=json&fl=original&collapse=urlkey&limit=50000' | jq -r '.[1:][][]' 2>/dev/null"
  _collect_source grepapp     bash -c "curl -sk --max-time 60 'https://grep.app/api/search?q=$DOMAIN' | jq -r '.hits.hits[].repo.raw, .hits.hits[].path.raw' 2>/dev/null"
  # keyed (only if keys present)
  [ -n "${VIRUSTOTAL_KEY:-}" ] && _collect_source virustotal bash -c "curl -sk --max-time 60 'https://www.virustotal.com/api/v3/domains/$DOMAIN/subdomains?limit=40' -H 'x-apikey: $VIRUSTOTAL_KEY' | jq -r '.data[].id' 2>/dev/null"
  [ -n "${CHAOS_KEY:-}" ] && _collect_source chaos bash -c "chaos -d '$DOMAIN' -key '$CHAOS_KEY' -o - 2>/dev/null"
  wait

  # ---- merge + normalize ------------------------------------------------------
  : > "$SD/all-passive.txt"
  for f in "$RAW"/*.txt; do
    [ -f "$f" ] || continue
    extract_hostnames < "$f" >> "$SD/all-passive.txt"
  done
  sort -u -o "$SD/all-passive.txt" "$SD/all-passive.txt"

  # yield-per-source table (diagnosis for the low-yield warning)
  : > "$SD/source-yield.tsv"
  for f in "$RAW"/*.txt; do
    [ -f "$f" ] || continue
    n=$(extract_hostnames < "$f" | sort -u | wc -l | tr -d ' ')
    printf '%s\t%s\n' "$(basename "$f" .txt)" "$n" >> "$SD/source-yield.tsv"
  done
  ok "passive sources merged: $(count_lines "$SD/all-passive.txt") unique hostnames"
  column -t "$SD/source-yield.tsv" >/dev/null 2>&1

  # ---- Stage B: permutation ---------------------------------------------------
  cp "$SD/all-passive.txt" "$SD/candidates.txt"
  log "generating permutations"
  _permute | head -n "$PERM_CAP" >> "$SD/candidates.txt"
  # Dedupe PRESERVING ORDER: passive hosts first, then permuted. (sort -u would
  # alphabetically bury the real names among the permuted garbage, so dnsx's
  # timeout expires before it ever reaches them — coda's www.* was never hit.)
  awk '!seen[$0]++' "$SD/candidates.txt" > "$SD/candidates.dedup" && mv "$SD/candidates.dedup" "$SD/candidates.txt"
  ok "after permutation: $(count_lines "$SD/candidates.txt") candidates"

  # ---- Stage B2: DNS brute force (deep mode or --no-dos) ----------------------
  if [ "$MODE_DEEP" = 1 ] || [ "$NO_DOS" = 1 ]; then
    if tool_exists shuffledns && tool_exists massdns && [ -f "$WLD_DNS" ]; then
      log "shuffledns brute-force (Jhaddix $(( $(wc -l < "$WLD_DNS")/1000 ))k lines)"
      timeout -k 30 1800 shuffledns -mode bruteforce -d "$DOMAIN" -w "$WLD_DNS" -r "$RESOLVERS" -t "$SHUFFLED_THREADS" \
        -o "$RAW/shuffledns.txt" 2>/dev/null || warn "shuffledns brute failed"
      [ -s "$RAW/shuffledns.txt" ] && extract_hostnames < "$RAW/shuffledns.txt" >> "$SD/candidates.txt"
    elif [ -f "$WLD_DNS" ]; then
      # massdns absent (shuffledns is a massdns wrapper): fall back to dnsx on the
      # most frequent wordlist prefix — the Jhaddix list is frequency-ordered, so
      # the head is where real subdomains live. Keeps DNS brute working sans root.
      local sample="${DNSX_BRUTE_SAMPLE:-100000}"
      log "massdns missing — dnsx brute fallback (top ${sample}k of wordlist)"
      head -n "$sample" "$WLD_DNS" \
        | awk -v d="$DOMAIN" '{print $1"."d}' \
        | timeout -k 30 1800 dnsx -silent -r "$RESOLVERS" -t 2000 2>/dev/null > "$RAW/dnsx-brute.txt" \
        || warn "dnsx brute fallback failed"
      [ -s "$RAW/dnsx-brute.txt" ] && extract_hostnames < "$RAW/dnsx-brute.txt" >> "$SD/candidates.txt"
    else
      warn "Jhaddix wordlist missing — skipping brute (install.sh)"
    fi
    # Order-preserving dedup — NEVER sort here: sorting would alphabetically
    # re-bury the passive hosts among the permuted garbage and dnsx would time
    # out before reaching them.
    awk '!seen[$0]++' "$SD/candidates.txt" > "$SD/candidates.dedup" && mv "$SD/candidates.dedup" "$SD/candidates.txt"
    ok "after brute force: $(count_lines "$SD/candidates.txt") candidates"
  fi

  # ---- Stage C: DNS validation + wildcard filter ------------------------------
  _validate_dns

  # ---- Stage D: low-yield warning ---------------------------------------------
  local total; total=$(count_lines "$SD/final-resolved.txt")
  if [ "$total" -lt "$LOW_YIELD_THRESHOLD" ]; then
    warn "LOW YIELD: only $total validated hosts for $DOMAIN (threshold $LOW_YIELD_THRESHOLD)"
    warn "per-source counts (find the silent failure):"
    while read -r s n; do [ -n "$s" ] && printf '  %-16s %s\n' "$s" "$n"; done < "$SD/source-yield.tsv"
    for expect in app mail api dashboard dev admin; do
      grep -q "^$expect\.$DOMAIN\$" "$SD/final-resolved.txt" || warn "  expected host MISSING: $expect.$DOMAIN"
    done
    warn "If a source returned 0, check $RAW/<source>.log for rate-limit/block. Continuing with a ${total}-host scope."
  else
    ok "validated hosts: $total  (low-yield threshold $LOW_YIELD_THRESHOLD met)"
  fi
}

# ---- permutation engine -------------------------------------------------------
_permute() {
  local base labels w h
  labels=$(awk -F. '{print $1}' "$SD/all-passive.txt" | sort -u)
  # root-level: <word>.<DOMAIN>
  while read -r w; do [ -n "$w" ] && echo "$w.$DOMAIN"; done < "$PERM_WORDS"
  # label-word combos: <w>-<l> and <l>-<w> and <w>.<l>
  while read -r l; do
    [ -z "$l" ] && continue
    while read -r w; do
      [ -z "$w" ] && continue
      echo "$w-$l.$DOMAIN"
      echo "$l-$w.$DOMAIN"
      echo "$w.$l.$DOMAIN"
    done < "$PERM_WORDS"
  done <<< "$labels"
  # keyword swaps
  sed -e 's/^api/api2/' -e 's/^app/app2/' -e 's/^mail/email/' -e 's/^www/www2/' \
      -e 's/^dev/dev2/' -e 's/^test/test2/' -e 's/^admin/admin2/' \
      "$SD/all-passive.txt"
}

# ---- DNS validation with wildcard filtering -----------------------------------
_validate_dns() {
  log "DNS validation (dnsx) + wildcard filtering"
  local wc="" rc=0
  if command -v dig >/dev/null 2>&1; then
    wc=$(dig +short "wildcard-probe-$(date +%s).$DOMAIN" A 2>/dev/null | tr '\n' ' ')
    [ -n "$wc" ] && { echo "$DOMAIN is WILDCARDED (A: $wc)" > "$SD/wildcard-flag.txt"; warn "DNS wildcard detected: $wc"; }
  fi

  if tool_exists dnsx; then
    timeout -k 30 900 dnsx -l "$SD/candidates.txt" -a -aaaa -cname -resp -json -silent -retry 1 \
      -r "$RESOLVERS" -o "$SD/dnsx.jsonl" 2>/dev/null
    rc=$?
    if [ "$rc" -ne 0 ]; then
      if [ -s "$SD/dnsx.jsonl" ]; then
        # Timeout with partial results (passive hosts at the head of the list are
        # already resolved): keep them rather than burning another 900s re-scan.
        warn "dnsx partial ($(count_lines "$SD/dnsx.jsonl") hosts, exit $rc) — continuing with partial coverage"
      else
        warn "dnsx failed (exit $rc) — retrying once"
        timeout -k 30 900 dnsx -l "$SD/candidates.txt" -a -aaaa -cname -resp -json -silent -retry 1 \
          -r "$RESOLVERS" -o "$SD/dnsx.jsonl" 2>/dev/null || warn "dnsx retry failed"
      fi
    fi
    _parse_dnsx "$wc"
  else
    warn "dnsx missing — falling back to dig resolution (slow)"
    _resolve_dig "$wc"
  fi

  # seed the apex + target so scope is never empty
  echo "$DOMAIN" >> "$SD/final-resolved.txt"
  grep -qx "$TARGET" "$SD/final-resolved.txt" || echo "$TARGET" >> "$SD/final-resolved.txt"
  sort -u -o "$SD/final-resolved.txt" "$SD/final-resolved.txt"
  : > "$SD/final-hosts.txt"
  # CNAMEs feed the takeover checks
  [ -f "$SD/cnames.txt" ] && cp "$SD/cnames.txt" "$W/takeover-candidates.txt" 2>/dev/null || true
  ok "final resolved hosts: $(count_lines "$SD/final-resolved.txt")"
}

_parse_dnsx() { # wildcard_a_set (space-separated)
  python3 - "$SD/dnsx.jsonl" "$SD/final-resolved.txt" "$SD/cnames.txt" "$1" <<'PYEOF'
import json, sys
inp, out_hosts, out_cnames, wc = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].split()
wc_set = set(wc)
hosts, cnames = set(), {}
for line in open(inp, encoding='utf-8', errors='ignore'):
    line = line.strip()
    if not line: continue
    try: j = json.loads(line)
    except Exception: continue
    h = (j.get('host') or '').strip().rstrip('.')
    if not h: continue
    a = j.get('a') or []
    if isinstance(a, str): a = [a]
    # wildcard filter: drop host whose A-set is a non-empty subset of the wildcard set
    if wc_set and a and set(a).issubset(wc_set) and set(a):
        continue
    if a: hosts.add(h)
    cn = j.get('cname')
    if cn:
        for c in (cn if isinstance(cn, list) else [cn]):
            c = str(c).strip().rstrip('.')
            if c and c != h: cnames[h] = c
open(out_hosts, 'w').write('\n'.join(sorted(hosts)) + '\n')
open(out_cnames, 'w').write('\n'.join(f'{k} -> {v}' for k, v in sorted(cnames.items())) + '\n')
PYEOF
}

_resolve_dig() { # fallback (no dnsx): parallel dig A lookups
  local wc_set="$1"
  command cat "$SD/candidates.txt" | xargs -P "$XARGS_PARALLEL" -I{} sh -c '
    ips=$(dig +short A "{}" 2>/dev/null | grep -E "^[0-9.]+$" | tr "\n" " ")
    [ -n "$ips" ] && echo "{} $ips"
  ' > "$SD/resolve-raw.txt" 2>/dev/null
  python3 - "$SD/resolve-raw.txt" "$SD/final-resolved.txt" "$wc_set" <<'PYEOF'
import sys
inp, out, wc = sys.argv[1], sys.argv[2], set(sys.argv[3].split())
hosts=set()
for line in open(inp, encoding='utf-8', errors='ignore'):
    p=line.split(); h=p[0]; ips=p[1:]
    if not ips: continue
    if wc and set(ips).issubset(wc): continue
    hosts.add(h)
open(out,'w').write('\n'.join(sorted(hosts))+'\n')
PYEOF
}
