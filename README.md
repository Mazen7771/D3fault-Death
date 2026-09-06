# ☠ D3FAULT-DEATH — Bug Bounty Reconnaissance & Vulnerability Scanner

[![CI](https://github.com/Mazen7771/D3fault-Death/actions/workflows/ci.yml/badge.svg)](https://github.com/Mazen7771/D3fault-Death/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-blue.svg)](https://www.gnu.org/software/bash/)
[![GitHub release](https://img.shields.io/github/v/release/Mazen7771/D3fault-Death)](https://github.com/Mazen7771/D3fault-Death/releases)
[![Last commit](https://img.shields.io/github/last-commit/Mazen7771/D3fault-Death)](https://github.com/Mazen7771/D3fault-Death/commits/main)

**Bug Bounty Reconnaissance & Vulnerability Scanner** — a chronological, self-feeding pipeline that chains the best open-source tools on Kali Linux into a single command, then **adaptively hunts attack vectors** the way professional bounty hunters do (Ebb & Flow).

This repository bundles three tools:

| Tool | What it is |
|------|------------|
| **`D3fault-death.sh`** | The flagship monolithic pipeline (~2350 lines, v2.0.0) — 20+ phases, Strategy Engine, Intel Engine |
| **`huntops/`** | A modular rewrite: thin CLI driver + `lib/*.sh` phases, tmux live windows, HackerOne-style candidate classification |
| **`omni.sh`** | A single CLI entry point that runs either engine — or both in a merged pipeline |

**Author:** ZOLDEK
**GitHub:** https://github.com/Mazen7771
**LinkedIn:** https://linkedin.com/in/mazen-basher
**License:** MIT

> ⚠️ **Authorized use only.** This tool actively scans and probes targets.
> Run it only against systems you own or have written permission to test, and
> always respect your bug-bounty program's scope rules.

---

## Table of Contents

- [Quick Start](#the-easiest-way-to-start-no-flags)
- [Features](#features)
- [Documentation](#documentation)
- [D3fault-death.sh (Monolith)](#the-pipeline-each-phase-feeds-the-next)
- [HuntOps (Modular)](#huntops-deliverables-explained)
- [OMNI (Unified CLI)](#omni--unified-cli-for-both-scanners)
- [Architecture](#architecture)
- [Legal](#legal)

---

## Features

| Feature | D3fault-death | HuntOps | OMNI |
|---------|:---:|:---:|:---:|
| Chronological 20+ phase pipeline | ✅ | ✅ | ✅ |
| Subdomain enumeration (10+ tools) | ✅ | ✅ | ✅ |
| Port scanning (nmap + InternetDB) | ✅ | ✅ | ✅ |
| Live web probing + fingerprinting | ✅ | ✅ | ✅ |
| Content discovery (ffuf/gobuster) | ✅ | ✅ | ✅ |
| Historical URL mining | ✅ | — | ✅ |
| JS/endpoint extraction + secrets | ✅ | ✅ | ✅ |
| Parameter discovery | ✅ | ✅ | ✅ |
| Subdomain takeover checks | ✅ | ✅ | ✅ |
| Vulnerability scanning (nuclei/nikto/sqlmap) | ✅ | ✅ | ✅ |
| TLS testing (testssl.sh) | — | ✅ | ✅ |
| **Strategy Engine** (Ebb & Flow) | ✅ | ✅ | ✅ |
| **Intel Engine** (OWASP Top 10) | ✅ | ✅ | ✅ |
| CVE correlation (bundled DB) | ✅ | ✅ | ✅ |
| **Candidate classification** (10-field + repro curl) | — | ✅ | ✅ |
| Screenshots (gowitness) | ✅ | — | ✅ |
| HTML report | ✅ | ✅ | ✅ |
| tmux live windows | — | ✅ | ✅ |
| Watch-mode diff | ✅ | — | ✅ |
| Rate limiting / no-DoS rails | ✅ | ✅ | ✅ |
| Scope file enforcement | ✅ | ✅ | ✅ |
| Authenticated scanning | ✅ | ✅ | ✅ |
| Offline smoke-test suite | — | ✅ | ✅ |

## Documentation

| Guide | Contents |
|-------|----------|
| [**README.md**](README.md) | Overview, quick start, architecture |
| [**USAGE.md**](USAGE.md) | Full usage for all three tools, tunables, troubleshooting |
| [**INSTALLATION.md**](INSTALLATION.md) | Step-by-step install for every dependency |
| [**CONTRIBUTING.md**](CONTRIBUTING.md) | How to contribute |
| [**requirements.txt**](requirements.txt) | Complete dependency manifest |
| [**LICENSE**](LICENSE) | MIT License |

---

## The easiest way to start (no flags)

```bash
./D3fault-death.sh
```

It asks you for the URL, then shows an **arrow-key menu** to pick the mode:

```
? Select scan mode:  (↑/↓ arrows · Enter to pick · q for default bb)
  ▶ bb       Full pipeline + sqlmap, secrets, takeover, ranking, screenshots
    full     Everything except sqlmap
    quick    Fast first pass (~minutes)
    passive  Recon only — no active scanning
    active   Ports, web, content, params + intel testing
```

↑/↓ to move, **Enter** to confirm, a **number key (1-5)** to jump straight to an
option, or **q** to fall back to the default (`bb`). That's it.

You can also paste a full URL (`https://example.com/anything`) — it normalizes it for you. Piped input works too: `echo example.com | ./D3fault-death.sh`.

## Quick reference

```bash
./D3fault-death.sh                                # interactive (asks for URL + mode)
./D3fault-death.sh -d example.com                 # bug-bounty scan (default: bb)
./D3fault-death.sh -t 1.2.3.4 -m active           # IP target, active mode
./D3fault-death.sh -d example.com -m quick        # fast first pass (~minutes)
./D3fault-death.sh -d example.com -m passive      # no active scanning
./D3fault-death.sh -d example.com -m full         # everything except sqlmap
./D3fault-death.sh -d example.com -s scope.txt    # enforce program scope
./D3fault-death.sh -d example.com -w last_scan    # watch: diff vs previous run
./D3fault-death.sh -d example.com -o /tmp/scan    # custom output dir
./D3fault-death.sh -d example.com -m bb -H 'Cookie: session=abc123' -H 'Authorization: Bearer <token>'   # AUTHENTICATED scan
./D3fault-death.sh -i                             # install missing tools
```

| Flag | Meaning |
|------|---------|
| `-d` | target domain |
| `-t` | target IP |
| `-m` | quick \| passive \| active \| full \| bb (default bb) |
| `-s` | **scope file** — auto-skips anything out of scope |
| `-w` | **watch mode** — compare this scan to a previous output dir; report what changed |
| `-H` | **authenticated mode** — repeatable HTTP header sent on every probe (`Cookie:`/`Authorization:`). Unlocks IDOR, authz, and post-login testing |
| `-o` | output directory |
| `-i` | install missing tools (apt/go/pip) and exit |

### Scope file format (one per line)
```
example.com          # allow whole domain
*.example.com        # allow subdomains
!admin.example.com   # deny (overrides allows)
10.0.0.0/8           # allow CIDR
api.mysite.com       # allow exact host + subdomains
```

## The pipeline (each phase feeds the next)

```
OSINT → DNS → Subdomains → Resolve → Ports → Live Web → Fingerprint
   → Content → Historical URLs → JS Endpoints → Secrets → Parameters
   → Takeover → Vuln Scan → STRATEGY ENGINE → CVE → Ranking → Screenshots
   → HTML Report
```

| Phase | Tools |
|-------|-------|
| 1. OSINT | whois, dig, theHarvester |
| 2. DNS enum | dnsrecon, dnsenum |
| 3. Subdomains | subfinder, amass, sublist3r, assetfinder, crt.sh |
| 4. Resolve | dig (parallel, scope-filtered) |
| 5. Ports | nmap (-sC -sV -O) |
| 6. Live probe | httpx-toolkit |
| 7. Fingerprint | whatweb, wafw00f |
| 8. Content | ffuf, gobuster, dirb |
| 9. Historical URLs | gau, waybackurls |
| 10. JS endpoints | katana/gospider + curl fallback |
| 11. **Secrets** | regex hunt in JS + pages (AWS, GitHub, Slack, keys, JWTs) |
| 12. Parameters | arjun + fallback |
| 13. **Takeover** | CNAME dead-check (12+ providers) + exposed-file checks |
| 14. Vuln scan | nuclei (+CVE/+XSS sets), nikto, sqlmap (batch), wpscan |
| 15. **Strategy Engine** | adaptive attack-vector hunting (below) |
| 15.5 **Intel Engine** | OWASP Top10:2025 / CWE Top25 signal-driven decision layer — clickjacking, cookie flags, security headers, TRACE/XST, method tampering, directory listing, verbose errors, debug params, CRLF, command injection, XXE, IDOR candidates, default panels, JWT, host-header poisoning, race-condition endpoints, rate-limit, weak TLS |
| 16. CVE match | bundled CVE DB + searchsploit |
| 17. **Ranking** | scores every live host → "🔥 what to test today" |
| 18. **Screenshots** | gowitness gallery |
| 19. Report | HTML + Markdown |

## 🧠 Strategy Engine (the "try different ways until it finds something" part)

Based on the professional **Ebb & Flow** model (jhaddix, HuntBook, etc.): instead of a fixed scan, the engine reads what recon revealed and attacks the highest-value vector first, escalating when it hits and switching when it misses. Every attempt is logged.

| Strategy | What it does | Trigger |
|----------|-------------|---------|
| S1 Low-hanging | probes `/actuator`, `/server-status`, `/console`, `/wp-config.php.bak`, phpMyAdmin | live hosts exist |
| S2 Param injection | open-redirect → LFI (`../../etc/passwd`) → SSTI (`{{7*7}}`) on every live parameter | params found |
| S3 API discovery | probes `/graphql`, `/swagger`, `/openapi.json`, runs **GraphQL introspection** | live hosts exist |
| S4 CORS | checks for reflected arbitrary origins | live hosts exist |
| S5 Cloud | finds exposed S3/GCS/Azure buckets | cloud-named hosts |
| Built-in pass | nuclei, nikto, sqlmap, wpscan, known-CVE, takeover, secrets | — |

The full attack log lands in the report under **🧠 Strategy Log** so you can see exactly what was tried and what hit.

## CVE correlation

Detects service + version from **nmap** and **whatweb**, then matches a **bundled CVE database** (`cve/cve-db.txt`, 30 entries, range-aware — edit to extend):

```
apache httpd|ge;lt|2.4.49;2.4.50|CVE-2021-41773|Critical|9.8|Apache path traversal RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-41773
```

Plus `searchsploit` per technology. Verified: Apache2.4.49→CVE-2021-41773, vsftpd2.3.4 backdoor, Heartbleed, Log4Shell, Shellshock, Drupalgeddon2, Ghostcat, and more — patched versions correctly excluded.

## Output

```
death_<target>_<timestamp>/
├── report/
│   ├── D3fault-death-report.html     ← open in a browser
│   ├── screenshots/                  ← gowitness gallery (full/bb modes)
│   └── summary.md
├── findings/findings.txt             ← SEVERITY|tool|host|title|detail|ref
├── vuln/strategy.log                 ← every strategy attempt + outcome
├── web/ranking.txt                   ← 🔥 priority list
├── takeover/  osint/  dns/  subdomains/  ports/
├── web/  content/  urls/  vuln/  cve/  tech/  logs/
```

The HTML report includes: summary cards, **severity-coded findings**, CVE table with NVD links, **🔥 Priority Targets**, **🧠 Strategy Log**, **🔄 Changes since last scan** (watch mode), **🖼 Screenshots**, and raw files.

## Tunables (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `MAX_RESOLVE` | 15000 | cap on hostnames resolved |
| `RESOLVE_PARALLEL` | 50 | concurrent DNS resolutions |
| `SQLMAP_CAP` | 5 | max sqlmap targets in bb mode |
| `GAU_CAP` | 5000 | max historical URLs kept |
| `GAU_TIMEOUT` | 180 | seconds before gau is killed |
| `WAYBACK_TIMEOUT` | 120 | seconds before waybackurls is killed |
| `NUCLEI_TIMEOUT` | 1800 | seconds before nuclei is killed |
| `PARAM_TEST_CAP` | 20 | max URLs the param-injection strategy tests |
| `RANK_CAP` | 25 | how many top targets appear in the report |
| `SHOT_TIMEOUT` | 300 | gowitness max seconds |
| `VT_API_KEY` | — | **optional** — enables VirusTotal subdomain discovery (phase 3) |
| `ST_API_KEY` | — | **optional** — enables SecurityTrails subdomain discovery (phase 3) |
| `USE_INTERNETDB` | 1 | set to `0` to disable Shodan InternetDB (ports/CVEs, phase 5) |
| `USE_COMMONCRAWL` | 1 | set to `0` to disable Common Crawl historical URLs (phase 9) |
| `LIVE_TERMINATOR` | 1 | set to `0` to disable the external Terminator live window |

## Live Terminator window

When you start a scan from a terminal (with a graphical session), the script
opens an **external Terminator window** with a **verbose** live view — your
main terminal keeps showing just the steps, and the Terminator shows what's
happening underneath:

```
┌────────────────────────────────┬──────────────────────┐
│  tail -f logs/death.verbose.log │  watch top-CPU proc  │
│  14:02:11 subfinder -all        │  0.0 tail -f ...log  │
│  14:02:12 subfinder -d example.com -all -silent   │  0.0 watch -n 2 ...   │
│  14:02:13 crt.sh cert...        │  (running recon      │
│  14:02:13 GET https://crt.sh/.. │   tools)             │
└────────────────────────────────┴──────────────────────┘
```

The **verbose stream** (`$OUTDIR/logs/death.verbose.log`) contains every step
plus the exact command for each tool (magenta detail lines). The main terminal
shows only the steps unless you pass **`-v`** — then the same detail also prints
inline. The right pane refreshes every 2s showing the most CPU-active processes.
The window auto-skips when stdin isn't a TTY, there's no `$DISPLAY`, or
Terminator isn't installed (`sudo apt install terminator`). Set
`LIVE_TERMINATOR=0` to turn it off.

## External data sources

On top of the local toolchain, the scanner queries these web data sources —
each is additive and fails gracefully (timeout + skip) if unreachable:

| Source | Phase | Key needed? |
|--------|-------|-------------|
| [CertSpotter](https://certspotter.com) CT | 3 subdomains | no |
| [HackerTarget](https://hackertarget.com) hostsearch | 3 subdomains | no |
| [VirusTotal](https://virustotal.com) subdomains | 3 subdomains | `VT_API_KEY` |
| [SecurityTrails](https://securitytrails.com) subdomains | 3 subdomains | `ST_API_KEY` |
| [Shodan InternetDB](https://internetdb.shodan.io) | 5 ports + CVE | no |
| [Common Crawl](https://commoncrawl.org) CDX index | 9 historical URLs | no |

Set the optional keys as environment variables so they stay out of the script:
```bash
export VT_API_KEY=your_token      # https://virustotal.com -> API key
export ST_API_KEY=your_token      # https://securitytrails.com -> API key
```
`jq` is now a required dependency (used to parse the JSON APIs) — it ships with
Kali and is installed by `./D3fault-death.sh -i` if missing.

> GitHub code-search (needs a `GITHUB_TOKEN`) is a planned future add — grep.app
> was evaluated but is bot-gated and returns no usable JSON.

## Legal

D3FAULT-DEATH is a security tool. Using it on systems without authorization may
violate the law and your bug-bounty program's terms. You are responsible for
how you use it. Only scan targets you own or are explicitly authorized to test.

---

# OMNI — Unified CLI for Both Scanners

**omni.sh** is a single entry point that runs either scanner — or both in a merged pipeline — with a shared workdir, unified findings format, and HuntOps-style deliverables.

```bash
./omni.sh -d example.com --engine=dd        # D3fault-death pipeline
./omni.sh -d example.com --engine=huntops   # HuntOps pipeline
./omni.sh -d example.com --engine=both      # merged: dd recon → huntops vuln/intel/candidates/outputs
```

| Flag | Meaning |
|------|---------|
| `-d` | target domain (required) |
| `--engine` | `dd` \| `huntops` \| `both` (default: both) |
| `-m` | `quick` \| `deep` (default: quick) |
| `-o` | output root (default: `output/<domain>_<ts>`) |
| `--no-terminal` | disable tmux live windows |
| `--test-account` | email for authenticated IDOR/authz probes |
| `--no-dos` | lift rate limits (explicit opt-out of safety rails) |
| `-H` | repeatable header for authenticated scans |
| `-i` | install missing tools (both engines) |

## Quick Start

```bash
# Fast merged scan (recon from dd, vuln/intel/candidates from huntops)
./omni.sh -d example.com --engine=both -m quick

# HuntOps only, deep mode with authenticated account for high-confidence IDOR
./omni.sh -d example.com --engine=huntops -m deep --test-account you@example.com

# D3fault-death only, bug-bounty mode (full pipeline)
./omni.sh -d example.com --engine=dd -m bb
```

## What each engine gives you

| Engine | Recon | Vuln Scanning | Attack Surface Classification | Deliverables |
|--------|-------|---------------|------------------------------|--------------|
| `dd` | 20 phases (OSINT→Screenshots) | nuclei, nikto, sqlmap, wpscan | Strategy Engine (Ebb & Flow) + Intel Engine (OWASP Top 10) | `death_*/report/D3fault-death-report.html`, `findings/findings.txt`, `web/ranking.txt` |
| `huntops` | modular phases (recon_*) | nuclei, testssl.sh, nikto, sqlmap | **Candidates stream** (IDOR, JWT, GraphQL, SSRF, race, admin/authz, secrets, cloud, takeover, CORS) — each with copy-paste `curl` repro | `<domain>.txt` (findings sheet), `info-<domain>.txt` (recon dossier + attack angles), `report/huntops-report.html` |
| `both` | dd phases 1-13 (OSINT→takeover) | huntops nuclei, testssl.sh, nikto, sqlmap | huntops candidates + intel + cve | **both sets of deliverables** in same workdir |

## Merged pipeline (`--engine=both`)

The merged pipeline runs **D3fault-death recon phases 1-13** (they produce superior subdomain/port/web/content data), then switches to **HuntOps vuln/intel/candidates/outputs** (they produce superior classification and deliverables).

```
omni.sh --engine=both
 ├─ dd: recon_osint, recon_dns, recon_subdomains, recon_resolve, recon_ports
 ├─ dd: recon_web, recon_fingerprint, recon_content, recon_historical
 ├─ dd: recon_js, recon_secrets, recon_params, recon_takeover
 ├─ huntops: vuln_nuclei, vuln_tls (testssl.sh), vuln_nikto, vuln_sqlmap
 ├─ huntops: candidates (IDOR/JWT/GraphQL/SSRF/race/admin/secrets/cloud/takeover/CORS)
 ├─ huntops: intel (OWASP signal checks)
 ├─ huntops: cve (correlation)
 ├─ huntops: outputs (domain.txt + info-domain.txt)
 └─ huntops: report (HTML)
```

**Why this wins:** dd's subdomain/port/web pipeline is battle-tested and broader; huntops's candidate classification, testssl.sh TLS, and per-domain deliverables are purpose-built for bounty reporting. The merged mode gets you both without duplicate work.

## Tunables (environment variables — merged config)

| Variable | Default | Applies to |
|----------|---------|------------|
| `OMNI_MAX_RESOLVE` | 15000 | dd recon |
| `OMNI_RESOLVE_PARALLEL` | 50 | dd recon |
| `OMNI_NUCLEI_RATE` | 150 | both (nuclei rps) |
| `OMNI_NUCLEI_CONCURRENCY` | 25 | both |
| `OMNI_NUCLEI_TIMEOUT` | 1800 | both |
| `OMNI_TESTSSL_BIN` | `/home/mazin/tools/testssl_tool/testssl.sh` | huntops TLS |
| `OMNI_TLS_HOST_CAP` | 10 | huntops TLS |
| `OMNI_SQLMAP_CAP` | 5 | both |
| `OMNI_GAU_CAP` | 5000 | dd historical |
| `OMNI_GAU_TIMEOUT` | 180 | dd historical |
| `OMNI_WAYBACK_TIMEOUT` | 120 | dd historical |
| `OMNI_USE_INTERNETDB` | 1 | dd ports |
| `OMNI_USE_COMMONCRAWL` | 1 | dd historical |
| `OMNI_RANK_CAP` | 25 | dd ranking |
| `OMNI_SHOT_TIMEOUT` | 300 | dd shots |
| `OMNI_HOST_CONCURRENCY` | 10 | dd content/js/secrets/params |
| `OMNI_VT_API_KEY` | — | dd subdomains |
| `OMNI_ST_API_KEY` | — | dd subdomains |

Backward-compat aliases: `MAX_RESOLVE`, `RESOLVE_PARALLEL`, `NUCLEI_TIMEOUT`, `SQLMAP_CAP`, `GAU_CAP`, `GAU_TIMEOUT`, `WAYBACK_TIMEOUT`, `USE_INTERNETDB`, `USE_COMMONCRAWL`, `RANK_CAP`, `SHOT_TIMEOUT`, `VT_API_KEY`, `ST_API_KEY` all work.

## Output layout (merged)

```
output/example.com_20260819-123456/
├── death_example.com_123456/         ← D3fault-death artifacts
│   ├── report/D3fault-death-report.html
│   ├── findings/findings.txt
│   ├── web/ranking.txt
│   └── ...
├── example.com.txt                    ← HuntOps findings sheet
├── info-example.com.txt               ← HuntOps recon dossier + attack angles
├── report/huntops-report.html         ← HuntOps HTML report
├── findings/findings.txt              ← unified CONFIRMED (6-field pipe)
├── findings/candidates.txt            ← unified CANDIDATES (10-field pipe)
├── findings/info.txt                  ← unified INFO (6-field pipe)
├── subdomains/, ports/, web/, urls/, js/, vuln/, cve/, osint/, takeover/, content/
└── logs/omni.log                      ← unified phase ledger
```

## HuntOps deliverables explained

### `<domain>.txt` — findings sheet (open this first)
```
============================================================
 HuntOps findings — example.com
 Scan: 2026-08-19 12:34  mode: quick  tool: v0.9.0
 Confirmed: 3   Candidates: 12   Info/excluded: 5
============================================================

## CONFIRMED FINDINGS (report these)
CRITICAL | nuclei | example.com | CVE-2021-41773 | Path traversal in Apache 2.4.49 | https://nvd.nist.gov/...

## TOP CANDIDATES (verify before reporting, sorted by CVSS)
[9.8] ssrf        example.com   SSRF via url parameter — http://example.com/fetch?url=http://interact.sh
      repro: curl -s "http://example.com/fetch?url=http://YOUR_CANARY"
[7.5] idor-manual example.com   IDOR numeric ID in /api/user/123
      repro: curl -H "Cookie: session=YOURS" "http://example.com/api/user/124"

## INFO / PROGRAM-EXCLUDED
  (excluded by data/program-exclusions.txt)

## ASSET SUMMARY
  subdomains=42  live_web=18  historical_urls=2847  param_urls=312

Full details: output/.../report/huntops-report.html
Recon dossier: output/.../info-example.com.txt
```

### `info-<domain>.txt` — recon dossier (your manual testing playbook)
```
============================================================
 HuntOps recon dossier — example.com
 Scan: 2026-08-19 12:34  mode: quick  tool: v0.9.0
 Use this to drive manual testing — every angle below is a lead.
============================================================

## 1. ASSET INVENTORY (42 validated subdomains)
  api.example.com cdn.example.com staging.example.com ...

## 2. LIVE WEB HOSTS (18) — status | title | server | tech | WAF
  200 | Example Domain | nginx/1.18.0 | PHP,nginx | Cloudflare

## 3. PORTS / SERVICES
  80  open  http    nginx 1.18.0
  443 open  https   nginx 1.18.0

## 4. HISTORICAL ATTACK SURFACE
  historical_urls=2847  api_endpoints=23  param_urls=312  js_endpoints=187
  --- interesting historical endpoints ---
  /api/v1/admin/users
  /actuator/env
  /graphql

## 5. SUBDOMAIN TAKEOVER CANDIDATES (CNAMEs)
  cdn.example.com → dead-cdn.provider.com

## 6. SUGGESTED ATTACK ANGLES (auto-derived)
  - IDOR: 4 enumerable-numeric params — retest with --test-account you@example.com and only IDs you OWN
  - SSRF: 2 fetch/redirect params — point each at an interact.sh canary
  - AuthZ: 1 admin/debug paths on live hosts — check for unauthenticated exposure
  - Takeover: 1 dangling CNAME — register the external host and verify
  - TLS: run testssl.sh against each live host IP:443 (already done by this tool)
  - Params: 312 param-carrying URLs — feed into your fuzzer with auth
  - Historical: review the 2847 URLs for leaked endpoints/credentials
```

## Common workflows

```bash
# 1. First pass — fast merged, no auth
./omni.sh -d target.com --engine=both -m quick --no-terminal

# 2. Review findings in target.com.txt + info-target.com.txt
#    Follow the "SUGGESTED ATTACK ANGLES" in the dossier

# 3. Deep authenticated run (IDOR/authz become high-confidence)
./omni.sh -d target.com --engine=both -m deep \
  --test-account you@yourdomain.com \
  -H 'Cookie: session=YOUR_SESSION' \
  -H 'Authorization: Bearer YOUR_TOKEN'

# 4. HuntOps-only deep for maximum candidate coverage
./omni.sh -d target.com --engine=huntops -m deep --no-dos --test-account you@x

# 5. Watch mode — diff against previous run (dd engine)
./omni.sh -d target.com --engine=dd -m bb -w output/target.com_20260818-...
```

## Install

```bash
./omni.sh -i  # installs both engines' toolchains
```

---

## Architecture

### Directory layout

```
Bug-stealer/
├── D3fault-death.sh          # Monolithic scanner (chronological pipeline)
├── huntops/                  # Modular scanner
│   ├── huntops.sh            # CLI driver
│   ├── config/               # Rates, caps, wordlists (env-overridable)
│   ├── lib/                  # Phase modules: run_<phase>().sh
│   ├── data/                 # Wordlists, impact classes, program exclusions
│   ├── docs/                 # PROFESSIONAL-REVIEW.md
│   └── tests/                # smoke.sh (offline regression suite)
├── omni.sh                   # Unified CLI (runs dd | huntops | both)
├── config/
│   └── omni.conf             # Unified config: rates, caps, wordlists, API keys
├── lib/
│   ├── common.sh             # Shared utilities (find_tool, esc_rec, add_finding…)
│   ├── dd_adapter.sh         # D3fault-death phases as HuntOps modules
│   └── huntops_adapter.sh    # HuntOps phases callable from D3fault-death
├── tests/
│   └── integration_smoke.sh  # Cross-engine regression suite
├── d3fault-death/            # Go prototype (experimental, early-stage)
├── README.md                 # This file
├── LICENSE                   # MIT
├── CONTRIBUTING.md           # Contribution guidelines
├── .gitignore                # Excludes outputs, binaries, secrets
└── .github/workflows/ci.yml  # CI: shellcheck + smoke tests
```

### How the pieces connect

- **`omni.sh`** sources `config/omni.conf` (unified tunables) and `lib/common.sh` (shared
  utilities), then builds a pipeline from either `D3fault-death.sh`'s phases (via
  `lib/dd_adapter.sh`) or `huntops/lib/*.sh` modules (via `lib/huntops_adapter.sh`), or a
  **merged** pipeline that takes the best of both.
- **`huntops/`** is self-contained: `huntops.sh` sources `config/config.sh`, then loops over
  `PIPELINE_*` arrays, sourcing each `lib/<phase>.sh` and calling `run_<phase>()`.
- **Findings** flow through three streams with content-hash dedupe:
  `findings/findings.txt` (CONFIRMED), `candidates.txt` (CANDIDATE w/ repro curl),
  `info.txt` (INFO/excluded noise).

### Safety rails

Both scanners are **no-DoS by default**: global request throttle + per-tool rate caps.
`--no-dos` lifts them but is opt-in. `--test-account` gates IDOR/authz probes to accounts
you own. PII encountered during a scan should be purged per program rules.

---

## Legal

D3FAULT-DEATH and HuntOps are security tools. Using them on systems without authorization may
violate the law and your bug-bounty program's terms. You are responsible for
how you use them. Only scan targets you own or are explicitly authorized to test.

---

**Author:** ZOLDEK · **GitHub:** https://github.com/Mazen7771 · **LinkedIn:** https://linkedin.com/in/mazen-basher · **License:** MIT
