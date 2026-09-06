# ⚙️ Installation Guide — D3FAULT-DEATH + HuntOps + OMNI

This guide covers everything needed to install and run the D3Fault-Death suite.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Install (Recommended)](#quick-install-recommended)
- [Manual Install — APT Packages](#manual-install--apt-packages)
- [Manual Install — Go Modules](#manual-install--go-modules)
- [Manual Install — Python Packages](#manual-install--python-packages)
- [Manual / Special Installs](#manual--special-installs)
- [API Keys (Optional)](#api-keys-optional)
- [Verification Checklist](#verification-checklist)
- [Kali-Specific Notes](#kali-specific-notes)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before installing, ensure you have:

| Requirement | Version | Check |
|-------------|---------|-------|
| **Operating System** | Kali Linux (recommended) / Debian / Ubuntu | `cat /etc/os-release` |
| **Bash** | 4.3+ | `bash --version` |
| **Go** | 1.21+ | `go version` |
| **Python** | 3.9+ | `python3 --version` |
| **Git** | any recent | `git --version` |
| **jq** | any recent | `jq --version` |
| **Internet** | yes | — |

> **Note:** This tool is designed primarily for **Kali Linux**. Most dependencies
> are available in Kali's repos. On other Debian-based systems, some tools may
> need manual compilation.

---

## Quick Install (Recommended)

### Option 1: Install everything with OMNI

```bash
git clone https://github.com/Mazen7771/D3fault-Death.git
cd D3fault-Death
./omni.sh -i
```

This installs the full toolchain for **both** engines (D3fault-death + HuntOps),
including:

- All APT packages
- All Go modules
- All Python packages
- Nuclei templates
- Wordlists (SecLists)
- DNS resolvers
- testssl.sh

### Option 2: Install D3fault-death only

```bash
./D3fault-death.sh -i
```

### Option 3: Install HuntOps only

```bash
./huntops/huntops.sh -i
```

All three installers detect what's already installed and only fetch what's
missing, so they're safe to run repeatedly.

---

## Manual Install — APT Packages

If you prefer to install manually, run:

```bash
sudo apt-get update
sudo apt-get install -y \
  jq curl dig nmap masscan whatweb wafw00f nikto gobuster dirb \
  exploitdb sqlmap wpscan terminator \
  massdns dnsrecon dnsenum \
  seclists \
  whois host
```

**Optional but recommended:**

```bash
# testssl.sh is NOT in Kali repos — install manually (see below)
# gowitness — prefer go install (see Go modules)
```

---

## Manual Install — Go Modules

Requires Go 1.21+ and `~/go/bin` in your PATH:

```bash
export PATH="$HOME/go/bin:$PATH"
```

### ProjectDiscovery suite (core recon)

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/projectdiscovery/notify/cmd/notify@latest
```

### Tomnomnom tools

```bash
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gron@latest
go install github.com/tomnomnom/unew@latest
```

### Fuzzing / content discovery

```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/epi052/feroxbuster@latest
```

### Secrets / sensitive data

```bash
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/zricethezav/gitleaks/v8@latest
```

### Screenshots / visual

```bash
go install github.com/sensepost/gowitness@latest
go install github.com/michenriksen/aquatone@latest
```

### Parameter discovery

```bash
go install github.com/hahwul/dalfox/v2@latest
```

### DNS brute force

```bash
go install github.com/blechschmidt/massdns@latest
```

### Subdomain takeover

```bash
go install github.com/haccer/subjack@latest
go install github.com/LukaSikic/subzy@latest
```

### API / GraphQL / supply chain / misc

```bash
go install github.com/projectdiscovery/kiterunner/cmd/kr@latest
go install github.com/anchore/grype/cmd/grype@latest
go install github.com/anchore/syft/cmd/syft@latest
go install github.com/nccgroup/wsrecon@latest
```

---

## Manual Install — Python Packages

```bash
pip3 install --break-system-packages --user \
  arjun paramspider \
  dnsgen sublist3r theharvester \
  ghauri tplmap shodan \
  linkfinder js-beautifier \
  jsluice mantra \
  droopescan cmsmap \
  cloud_enum prowler
```

### JWT tool (special install)

```bash
git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool
pip3 install -r /opt/jwt_tool/requirements.txt
alias jwt_tool='python3 /opt/jwt_tool/jwt_tool.py'
```

### graphw00f (GraphQL fingerprinting)

```bash
pip3 install git+https://github.com/dolevf/graphw00f.git
```

---

## Manual / Special Installs

### nuclei templates (MANDATORY for CVE scanning)

```bash
nuclei -update-templates -ud ~/.local/share/nuclei-templates
```

- Size: ~670MB
- Downloads 10,000+ templates
- The installers (`./omni.sh -i`, `./huntops/huntops.sh -i`) do this for you

### libpostal data (required for amass)

The Debian/Kali `amass` wrapper needs libpostal data or it sudo-prompts every scan.

```bash
sudo mkdir -p /var/lib/libpostal
sudo libpostal_data download all /var/lib/libpostal
sudo mkdir -p /usr/share/libpostal
sudo ln -sf /var/lib/libpostal/transliteration /usr/share/libpostal/transliteration
```

### DNS resolvers (for massdns/dnsx/shuffledns)

The HuntOps installer auto-downloads to `config/resolvers.txt`:

```bash
curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt > config/resolvers.txt
```

### testssl.sh (TLS/SSL scanner)

```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /home/mazin/tools/testssl_tool
```

Or set `OMNI_TESTSSL_BIN` to your install path.

### SecLists wordlists (if not via apt)

```bash
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

### subjack fingerprints

```bash
mkdir -p ~/.subjack
wget -O ~/.subjack/fingerprints.json https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json
```

---

## API Keys (Optional)

All scanners work **without** keys (graceful degradation). Keys only expand
subdomain/VULN coverage. Add them to your shell profile (`~/.bashrc`, `~/.zshrc`):

```bash
export VT_API_KEY="your_virustotal_key"        # https://virustotal.com
export ST_API_KEY="your_securitytrails_key"    # https://securitytrails.com
export CERTSPOTTER_API_KEY="your_key"          # https://certspotter.com
export SHODAN_API_KEY="your_key"               # https://shodan.io
export CHAOS_API_KEY="your_key"                # https://chaos.projectdiscovery.io
export GITHUB_TOKEN="your_github_token"        # for GitHub code search
```

> **Security:** Never commit keys to the repo. They stay in your shell profile
> or `config/keys.conf` (which is gitignored). See `config/keys.conf` for the
> full template.

---

## Verification Checklist

After installing, verify everything is in place:

```bash
# Core
which jq curl dig nmap masscan

# Go tools (should be in $HOME/go/bin)
which dnsx naabu httpx nuclei subfinder assetfinder waybackurls gau \
      ffuf gobuster gowitness trufflehog gitleaks katana shuffledns chaos dalfox

# Python tools
python3 -c "import arjun dnsgen sublist3r ghauri tplmap shodan"

# Nuclei templates
ls ~/.local/share/nuclei-templates/*.yaml | wc -l  # should be > 1000

# testssl.sh
ls /home/mazin/tools/testssl_tool/testssl.sh

# Wordlists
ls /usr/share/seclists/Discovery/DNS/
ls /usr/share/seclists/Discovery/Web-Content/

# Resolvers
wc -l config/resolvers.txt  # should be > 1000

# libpostal (for amass)
ls /usr/share/libpostal/transliteration
```

### Run the smoke tests

```bash
# HuntOps offline regression suite (25 checks)
./huntops/tests/smoke.sh

# Cross-engine integration suite
./tests/integration_smoke.sh -v
```

Both should pass cleanly after a complete install.

---

## Kali-Specific Notes

On Kali Linux, some tools have different names or quirks:

| Tool | Kali Name / Issue | Note |
|------|-------------------|------|
| `httpx` | `httpx-toolkit` | Package: `golang-github-projectdiscovery-httpx`. Both scanners auto-detect it. |
| `gau` | git alias! | Real binary at `~/go/bin/gau` — install via `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `amass` | Debian wrapper | sudo-prompts for libpostal data — provision libpostal (see above) |
| `bat` | Bacula conflict | `/sbin/bat` is Bacula's GUI. Use `command cat` or the Read tool. |
| `timeout` | — | All `timeout` calls use `timeout -k 30` — ffuf/gowitness ignore SIGTERM |

---

## Troubleshooting

### "command not found" for Go tools
```bash
export PATH="$HOME/go/bin:$PATH"
# add to ~/.bashrc to persist
```

### jq missing
```bash
sudo apt-get install -y jq
```

### pip3 "externally-managed-environment" error (Ubuntu 23+)
```bash
pip3 install --break-system-packages --user <package>
```

### amass still prompts for sudo
Ensure libpostal is provisioned:
```bash
ls /usr/share/libpostal/transliteration  # must exist
```

### nuclei templates not found
```bash
nuclei -update-templates -ud ~/.local/share/nuclei-templates
```

### Low disk space
The full install (especially nuclei templates + SecLists) can take several GB.
Ensure `df -h` shows adequate free space before running `./omni.sh -i`.

---

## Summary

| Method | Command | Installs |
|--------|---------|----------|
| **Quick (recommended)** | `./omni.sh -i` | Everything for both engines |
| D3fault-death only | `./D3fault-death.sh -i` | D3fault-death toolchain |
| HuntOps only | `./huntops/huntops.sh -i` | HuntOps toolchain |
| Manual | follow sections above | — |

---

**Author:** ZOLDEK · **GitHub:** https://github.com/Mazen7771 · **License:** MIT
