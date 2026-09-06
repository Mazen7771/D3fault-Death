#!/usr/bin/env bash
# HuntOps — idempotent tool installer.  do_install()  prints a coverage matrix.
# Go binaries land in $HOME/go/bin (added to PATH here); pip in --user.

GO_TOOLS=(
  # ProjectDiscovery suite (core recon)
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest:dnsx"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest:naabu"
  "github.com/projectdiscovery/katana/cmd/katana@latest:katana"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest:shuffledns"
  "github.com/projectdiscovery/chaos-client/cmd/chaos@latest:chaos"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest:httpx"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest:nuclei"
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest:subfinder"
  "github.com/projectdiscovery/alterx/cmd/alterx@latest:alterx"
  "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest:mapcidr"
  "github.com/projectdiscovery/notify/cmd/notify@latest:notify"
  "github.com/projectdiscovery/kiterunner/cmd/kr@latest:kr"
  # Tomnomnom tools
  "github.com/tomnomnom/assetfinder@latest:assetfinder"
  "github.com/tomnomnom/waybackurls@latest:waybackurls"
  "github.com/tomnomnom/gf@latest:gf"
  "github.com/tomnomnom/anew@latest:anew"
  "github.com/tomnomnom/gron@latest:gron"
  "github.com/tomnomnom/unew@latest:unew"
  # Fuzzing / Content Discovery
  "github.com/ffuf/ffuf/v2@latest:ffuf"
  "github.com/OJ/gobuster/v3@latest:gobuster"
  "github.com/epi052/feroxbuster@latest:feroxbuster"
  # Secrets / Sensitive Data
  "github.com/trufflesecurity/trufflehog/v3@latest:trufflehog"
  "github.com/zricethezav/gitleaks/v8@latest:gitleaks"
  # Screenshots / Visual
  "github.com/sensepost/gowitness@latest:gowitness"
  # Parameter Discovery
  "github.com/hahwul/dalfox/v2@latest:dalfox"
  # DNS brute force helpers
  "github.com/blechschmidt/massdns@latest:massdns"
  # Subdomain Takeover
  "github.com/haccer/subjack@latest:subjack"
  "github.com/LukaSikic/subzy@latest:subzy"
  # Supply Chain / SBOM
  "github.com/anchore/grype/cmd/grype@latest:grype"
  "github.com/anchore/syft/cmd/syft@latest:syft"
  # WebSocket Recon
  "github.com/nccgroup/wsrecon@latest:wsrecon"
)

PIP_TOOLS=(
  # Parameter discovery
  arjun paramspider
  # Recon / OSINT
  dnsgen sublist3r theharvester
  # Vulnerability scanning
  ghauri tplmap shodan dalfox
  # URL/JS analysis
  linkfinder js-beautifier jsluice mantra
  # AuthZ / IDOR
  authmatrix autorize
  # CMS
  droopescan cmsmap
  # Cloud
  cloud_enum prowler
  # JWT
  jwt_tool
)

do_install() {
  log "HuntOps installer"
  export PATH="$HOME/go/bin:$PATH"

  # --- apt core ---------------------------------------------------------------
  if ! tool_exists jq; then
    warn "installing jq via apt"
    sudo apt-get install -y jq 2>/dev/null || true
  fi
  # massdns: shuffledns (in GO_TOOLS) is only a wrapper around it — without it the
  # DNS brute-force stage no-ops. Debian/Kali package it; needs sudo once.
  if ! tool_exists massdns; then
    warn "installing massdns via apt (needed by shuffledns brute-force)"
    sudo apt-get install -y massdns 2>/dev/null \
      && ok "massdns installed" || warn "massdns install failed — dnsx brute fallback will be used"
  fi

  # --- go tools ---------------------------------------------------------------
  if tool_exists go; then
    for entry in "${GO_TOOLS[@]}"; do
      mod="${entry%%:*}"; bin="${entry##*:}"
      if tool_exists "$bin"; then ok "go: $bin already installed"; continue; fi
      warn "go install $mod"
      timeout -k 30 600 go install "$mod" || err "go install failed: $mod"
    done
  else
    err "go not found — cannot install go tools"
  fi

  # --- pip tools --------------------------------------------------------------
  if tool_exists pip3; then
    for p in "${PIP_TOOLS[@]}"; do
      if python3 -c "import ${p%%-*}" >/dev/null 2>&1; then ok "pip: $p present"; continue; fi
      warn "pip3 install $p"
      timeout -k 30 300 pip3 install --break-system-packages --user -q "$p" 2>/dev/null \
        || warn "pip install $p failed (py-version issue, degraded path available)"
    done
  fi

  # --- nuclei templates (MANDATORY — this is the CVE engine) -------------------
  if tool_exists nuclei; then
    tc=$(find ~/.local/share/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l)
    if [ "${tc:-0}" -lt 100 ]; then
      warn "downloading full nuclei template library (~670MB) — this is the CVE breadth"
      timeout -k 30 3000 nuclei -update-templates -ud ~/.local/share/nuclei-templates >/dev/null 2>&1 \
        || err "nuclei template download failed (check internet/disk)"
    else
      ok "nuclei templates present: $tc"
    fi
  fi

  # --- libpostal data (amass wrapper needs it; else it sudo-prompts every scan) -
  # The /usr/bin/amass wrapper runs `sudo libpostal_data download all /var/lib/libpostal`
  # whenever /usr/share/libpostal/transliteration is missing. Provision it once so
  # scans never hit an interactive sudo prompt. May prompt for sudo here once.
  if [ -x /usr/bin/amass ] && { [ ! -e /usr/share/libpostal/transliteration ] || [ ! -d /var/lib/libpostal ]; }; then
    warn "provisioning libpostal data for amass (may ask for sudo once)"
    mkdir -p /var/lib/libpostal 2>/dev/null || true
    if timeout -k 30 300 sudo -n true 2>/dev/null; then
      timeout -k 30 600 sudo libpostal_data download all /var/lib/libpostal 2>/dev/null \
        && { mkdir -p /usr/share/libpostal; ln -sf /var/lib/libpostal/transliteration /usr/share/libpostal/transliteration 2>/dev/null || true; \
             ok "libpostal provisioned"; } \
        || warn "libpostal download failed — amass will be skipped at scan time"
    else
      warn "sudo not available non-interactively — amass will be skipped at scan time (run install interactively to provision)"
    fi
  fi

  # --- resolvers ---------------------------------------------------------------
  if [ ! -s "$RESOLVERS" ]; then
    warn "downloading trickest resolvers"
    mkdir -p "$(dirname "$RESOLVERS")"
    timeout -k 30 120 curl -skL -o "$RESOLVERS" https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
      && ok "resolvers: $(wc -l < "$RESOLVERS") lines" || warn "resolver download failed"
  fi

  # --- wordlists ---------------------------------------------------------------
  for w in "$WLD_DNS" "$WLD_WEB" "$WLD_DNS_TOP"; do
    [ -f "$w" ] || warn "wordlist missing: $w (install seclists: sudo apt install seclists)"
  done

  coverage_matrix
  ok "install done. Re-run: ./huntops.sh -d target.com"
}

coverage_matrix() {
  printf '\n%-18s %s\n' "TOOL" "STATUS"
  printf '%-18s %s\n' "----" "------"
  local tools=(subfinder amass assetfinder dnsx naabu nmap masscan httpx httpx-toolkit katana \
               nuclei nikto sqlmap ghauri ffuf gobuster gau waybackurls arjun dnsgen shuffledns \
               whatweb wafw00f gowitness trufflehog gitleaks gf theHarvester searchsploit wpscan dnsrecon dnsenum jq curl dig \
               # NEW: Visual Recon
               feroxbuster \
               # NEW: Takeover
               subjack subzy \
               # NEW: API/GraphQL
               kr \
               # NEW: Supply Chain
               grype syft \
               # NEW: WebSocket
               wsrecon \
               # NEW: Parameter discovery
               paramspider dalfox \
               # NEW: JS Analysis
               jsluice mantra)
  for t in "${tools[@]}"; do
    if tool_exists "$t"; then printf '%-18s %s\n' "$t" "$C_GRN OK$C_RST"; else printf '%-18s %s\n' "$t" "$C_YLW MISSING$C_RST"; fi
  done
  local tc; tc=$(find ~/.local/share/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l)
  printf '%-18s %s\n' "nuclei-templates" "$([ "${tc:-0}" -gt 100 ] && echo "$C_GRN $tc yaml$C_RST" || echo "$C_YLW $tc (run -i)$C_RST")"
}
