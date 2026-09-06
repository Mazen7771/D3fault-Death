# 📖 Usage Guide — D3FAULT-DEATH + HuntOps + OMNI

This guide covers how to use all three tools in the D3Fault-Death suite:

| Tool | What it is |
|------|------------|
| **`D3fault-death.sh`** | Monolithic pipeline scanner (20+ phases) |
| **`huntops/`** | Modular rewrite with tmux live windows + candidate classification |
| **`omni.sh`** | Unified CLI that runs either engine — or both in a merged pipeline |

> ⚠️ **Authorized use only.** These tools actively scan and probe targets. Run them
> only against systems you own or have written permission to test, and always
> respect your bug-bounty program's scope rules.

---

## Table of Contents

- [Quick Start](#quick-start)
- [D3fault-death.sh](#d3fault-deathsh)
- [HuntOps](#huntops)
- [OMNI (Unified CLI)](#omni--unified-cli)
- [Authenticated Scanning](#authenticated-scanning)
- [Scope Files](#scope-files)
- [Tunables (Environment Variables)](#tunables-environment-variables)
- [Output Layout](#output-layout)
- [Troubleshooting](#troubleshooting)
- [Legal](#legal)

---

## Quick Start

```bash
# Clone & install everything (one command)
git clone https://github.com/Mazen7771/D3fault-Death.git
cd D3fault-Death
./omni.sh -i          # installs both engines' toolchains

# Fast merged scan
./omni.sh -d example.com --engine=both -m quick

# D3fault-death only, full bug-bounty mode
./omni.sh -d example.com --engine=dd -m bb

# HuntOps only, deep mode
./omni.sh -d example.com --engine=huntops -m deep
```

---

## D3fault-death.sh

The flagship monolithic scanner. It runs a chronological, self-feeding pipeline
(OSINT → DNS → Subdomains → Ports → Live Web → Content → Params → Vuln → Strategy
→ CVE → Rank → Report).

### Interactive mode (no flags)

```bash
./D3fault-death.sh
```

It asks for the target URL, then shows an arrow-key menu to pick the mode:

```
? Select scan mode:  (↑/↓ arrows · Enter to pick · q for default bb)
  ▶ bb       Full pipeline + sqlmap, secrets, takeover, ranking, screenshots
    full     Everything except sqlmap
    quick    Fast first pass (~minutes)
    passive  Recon only — no active scanning
    active   Ports, web, content, params + intel testing
```

Press **Enter** to confirm, a **number key (1-5)** to jump to an option, or **q**
to use the default (`bb`). You can also paste a full URL (`https://example.com/...`)
— it normalizes it — or pipe input: `echo example.com | ./D3fault-death.sh`.

### CLI reference

```bash
./D3fault-death.sh -d example.com                 # bug-bounty scan (default: bb)
./D3fault-death.sh -t 1.2.3.4 -m active           # IP target, active mode
./D3fault-death.sh -d example.com -m quick        # fast first pass
./D3fault-death.sh -d example.com -m passive      # no active scanning
./D3fault-death.sh -d example.com -m full         # everything except sqlmap
./D3fault-death.sh -d example.com -s scope.txt    # enforce program scope
./D3fault-death.sh -d example.com -w last_scan    # watch: diff vs previous run
./D3fault-death.sh -d example.com -o /tmp/scan    # custom output dir
./D3fault-death.sh -d example.com -i              # install missing tools
```

### Flags

| Flag | Meaning |
|------|---------|
| `-d` | target domain |
| `-t` | target IP |
| `-m` | `quick` \| `passive` \| `active` \| `full` \| `bb` (default `bb`) |
| `-s` | **scope file** — auto-skips anything out of scope |
| `-w` | **watch mode** — compare this scan to a previous output dir; report what changed |
| `-H` | **authenticated mode** — repeatable HTTP header on every probe (`Cookie:`/`Authorization:`) |
| `-o` | output directory |
| `-i` | install missing tools (apt/go/pip) and exit |

### Modes explained

| Mode | Description |
|------|-------------|
| `bb` | Full pipeline: sqlmap, secrets, takeover, ranking, screenshots |
| `full` | Everything except sqlmap |
| `quick` | Fast first pass (~minutes) |
| `passive` | Recon only — no active scanning |
| `active` | Ports, web, content, params + intel testing |

---

## HuntOps

The modular rewrite. It uses a thin CLI driver that loops over a pipeline of
`lib/<phase>.sh` modules.

```bash
./huntops/huntops.sh -i                            # install tools + nuclei templates
./huntops/huntops.sh -d target.com                 # auto-mode scan, depth bb
./huntops/huntops.sh -d target.com -m deep --no-dos # exhaustive
./huntops/huntops.sh -d target.com --test-account you@x # IDOR/authz high-confidence
./huntops/huntops.sh -d target.com --no-terminal   # disable tmux live windows
./huntops/tests/smoke.sh                           # offline regression suite (25 checks)
./huntops/tests/smoke.sh -w output/<target>/<date> # validate a real run's artifacts
```

### Modes

| Mode | Depth |
|------|-------|
| `quick` | Fast first pass |
| `bb` | Bug bounty (default) |
| `deep` | Exhaustive — needs `--no-dos` for heavy scans |

### tmux live windows

HuntOps auto-launches a tmux session `huntops-<target>` with three windows:
`main`, `verbose`, `behind-scenes`. Disabled with `--no-terminal`, non-tty, or
when already inside tmux.

> **Note:** tmux session names containing dots (e.g. `huntops-coda.com`) need a
> trailing colon: `huntops-coda.com:`

### The three finding streams

HuntOps classifies everything into three streams (all in `findings/`):

| Stream | File | Fields | Purpose |
|--------|------|--------|---------|
| **CONFIRMED** | `findings.txt` | `SEVERITY\|TOOL\|HOST\|TITLE\|DETAIL\|REF` (6) | Verified, reportable |
| **CANDIDATE** | `candidates.txt` | `CAND\|CLASS\|HOST\|TITLE\|CONF\|EVIDENCE\|REPRO\|REF\|CVSS\|TAG` (10) | Manual validation, each with copy-paste `curl` repro |
| **INFO** | `info.txt` | 6 fields | Recon data / auto-demoted noise |

---

## OMNI — Unified CLI

`omni.sh` is a single entry point that runs either scanner — or both in a merged
pipeline — with a shared workdir, unified findings format, and HuntOps-style
deliverables.

```bash
./omni.sh -d example.com --engine=dd        # D3fault-death pipeline
./omni.sh -d example.com --engine=huntops   # HuntOps pipeline
./omni.sh -d example.com --engine=both      # merged: best of both
```

### Flags

| Flag | Meaning |
|------|---------|
| `-d` | target domain (required) |
| `-t` | target IP |
| `--engine` | `dd` \| `huntops` \| `both` (default: `both`) |
| `-m` | `quick` \| `bb` \| `deep` (default: `bb`) |
| `-o` | output root |
| `-s` | scope file |
| `-H` | auth header (repeatable) |
| `--test-account` | email for authenticated IDOR/authz probes |
| `--no-terminal` | disable tmux live windows |
| `--no-dos` | lift rate limits (explicit opt-out of safety rails) |
| `--ssl` / `--no-ssl` | force / disable testssl.sh TLS phase |
| `--debug` | behind-the-scenes raw view of every tool call |
| `--fail-fast` | abort pipeline on first phase failure |
| `--phase=LIST` | comma-separated phase subset (e.g. `recon_subdomains,vuln_nuclei`) |
| `-i` | install missing tools (both engines) |

### Common workflows

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

### Merged pipeline (`--engine=both`)

Runs **D3fault-death recon phases 1-13** (battle-tested subdomain/port/web
pipeline), then switches to **HuntOps vuln/intel/candidates/outputs** (superior
classification and deliverables).

```
omni.sh --engine=both
 ├─ dd: recon_osint, recon_dns, recon_subdomains, recon_resolve, recon_ports
 ├─ dd: recon_web, recon_fingerprint, recon_content, recon_historical
 ├─ dd: recon_js, recon_secrets, recon_params, recon_takeover
 ├─ huntops: vuln_nuclei, vuln_tls, vuln_nikto, vuln_sqlmap
 ├─ huntops: candidates (IDOR/JWT/GraphQL/SSRF/race/admin/secrets/cloud/takeover/CORS)
 ├─ huntops: intel (OWASP signal checks)
 ├─ huntops: cve (correlation)
 ├─ huntops: outputs (domain.txt + info-domain.txt)
 └─ huntops: report (HTML)
```

---

## Authenticated Scanning

Pass HTTP headers to test authenticated/authorized functionality:

```bash
# D3fault-death
./D3fault-death.sh -d example.com -H 'Cookie: session=abc123' -H 'Authorization: Bearer <token>'

# OMNI
./omni.sh -d example.com -H 'Cookie: session=abc123' -H 'Authorization: Bearer <token>'

# With a test account for high-confidence IDOR/authz
./omni.sh -d example.com --test-account you@yourdomain.com
```

The `--test-account` flag gates IDOR/authz probes so they only fire against
accounts you own — never against other users' data.

---

## Scope Files

Scope files enforce program rules. Anything out of scope is auto-skipped.

```bash
./D3fault-death.sh -d example.com -s scope.txt
```

**Format (one entry per line):**

```
example.com          # allow whole domain
*.example.com        # allow subdomains
!admin.example.com   # deny (overrides allows)
10.0.0.0/8           # allow CIDR
api.mysite.com       # allow exact host + subdomains
```

- `!` prefix = **deny** (overrides allows)
- CIDR ranges supported
- Matches subdomains automatically

---

## Tunables (Environment Variables)

All tools are configurable via environment variables. Set them before running
(no code changes needed).

### D3fault-death / OMNI

| Variable | Default | Meaning |
|----------|---------|---------|
| `MAX_RESOLVE` | 15000 | cap on hostnames resolved |
| `RESOLVE_PARALLEL` | 50 | concurrent DNS resolutions |
| `SQLMAP_CAP` | 5 | max sqlmap targets |
| `GAU_CAP` | 5000 | max historical URLs kept |
| `GAU_TIMEOUT` | 180 | seconds before gau is killed |
| `WAYBACK_TIMEOUT` | 120 | seconds before waybackurls is killed |
| `NUCLEI_TIMEOUT` | 1800 | seconds before nuclei is killed |
| `PARAM_TEST_CAP` | 20 | max URLs the param-injection strategy tests |
| `RANK_CAP` | 25 | top targets in the report |
| `SHOT_TIMEOUT` | 300 | gowitness max seconds |
| `VT_API_KEY` | — | **optional** — VirusTotal subdomain discovery |
| `ST_API_KEY` | — | **optional** — SecurityTrails subdomain discovery |
| `USE_INTERNETDB` | 1 | set `0` to disable Shodan InternetDB |
| `USE_COMMONCRAWL` | 1 | set `0` to disable Common Crawl historical URLs |
| `LIVE_TERMINATOR` | 1 | set `0` to disable the Terminator live window |

### HuntOps

| Variable | Default | Meaning |
|----------|---------|---------|
| `RATE_GLOBAL` | 10 | global request throttle (req/s) |
| `CONCURRENCY` | 3 | parallel tool chains |
| `HOST_BUDGET` | 25 | max concurrent hosts per tool |
| `NUCLEI_RATE` | 15 | nuclei requests/sec |
| `NUCLEI_CONCURRENCY` | 10 | nuclei concurrency |
| `FUF_RATE` | 50 | ffuf rate |
| `NAABU_RATE` | 1000 | naabu rate |
| `STRATEGY_LIVE_CAP` | 50 | max live hosts to probe |
| `STRATEGY_PARAM_CAP` | 30 | max param URLs to test |

### OMNI merged config

| Variable | Default | Applies to |
|----------|---------|------------|
| `OMNI_NUCLEI_RATE` | 150 | both (nuclei rps) |
| `OMNI_NUCLEI_CONCURRENCY` | 25 | both |
| `OMNI_NUCLEI_TIMEOUT` | 1800 | both |
| `OMNI_TESTSSL_BIN` | `/home/mazin/tools/testssl_tool/testssl.sh` | huntops TLS |
| `OMNI_TLS_HOST_CAP` | 10 | huntops TLS |
| `OMNI_SQLMAP_CAP` | 5 | both |
| `OMNI_HOST_CONCURRENCY` | 10 | dd content/js/secrets/params |

**Backward-compat aliases** work for OMNI: `MAX_RESOLVE`, `RESOLVE_PARALLEL`,
`NUCLEI_TIMEOUT`, `SQLMAP_CAP`, `GAU_CAP`, `GAU_TIMEOUT`, `WAYBACK_TIMEOUT`,
`USE_INTERNETDB`, `USE_COMMONCRAWL`, `RANK_CAP`, `SHOT_TIMEOUT`, `VT_API_KEY`,
`ST_API_KEY`.

### Example

```bash
export VT_API_KEY=your_token
export ST_API_KEY=your_token
export RANK_CAP=50
./omni.sh -d example.com --engine=both -m deep
```

---

## Output Layout

### D3fault-death

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

The HTML report includes: summary cards, severity-coded findings, CVE table
with NVD links, 🔥 Priority Targets, 🧠 Strategy Log, 🔄 Changes since last scan
(watch mode), 🖼 Screenshots, and raw files.

### HuntOps

```
output/<target>_<timestamp>/
├── findings/
│   ├── findings.txt          ← CONFIRMED (6-field pipe)
│   ├── candidates.txt        ← CANDIDATES (10-field pipe, with repro curl)
│   └── info.txt              ← INFO (6-field pipe)
├── report/huntops-report.html
├── <target>.txt              ← findings sheet (open this first)
├── info-<target>.txt         ← recon dossier + suggested attack angles
├── subdomains/  ports/  web/  urls/  js/  vuln/  cve/  osint/  takeover/
└── logs/                     ← scan logs + phase ledger
```

### OMNI (merged)

```
output/<target>_<timestamp>/
├── death_<target>_<timestamp>/      ← D3fault-death artifacts
│   └── report/D3fault-death-report.html
├── <target>.txt                     ← HuntOps findings sheet
├── info-<target>.txt                ← HuntOps recon dossier
├── report/huntops-report.html       ← HuntOps HTML report
├── findings/{findings,candidates,info}.txt
├── subdomains/  ports/  web/  urls/  js/  vuln/  cve/  osint/  takeover/
└── logs/omni.log                    ← unified phase ledger
```

---

## Troubleshooting

### `cat` prints garbage / Bareos usage
On this box `cat` is aliased to Bacula's `bat`. Use the Read tool, `sed`, or
`command cat` instead. The tools handle this automatically.

### `gau: command not found`
`gau` is a git alias (`git add --update`) on Kali. Install the real tool:
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
# add ~/go/bin to PATH
export PATH="$HOME/go/bin:$PATH"
```

### `httpx: command not found`
On Kali, ProjectDiscovery's httpx is named `httpx-toolkit`. Both scanners
auto-detect it. If missing, install via go:
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### `amass` asks for sudo / libpostal
The Debian `amass` wrapper needs libpostal data. Provision it once:
```bash
sudo mkdir -p /var/lib/libpostal
sudo libpostal_data download all /var/lib/libpostal
sudo mkdir -p /usr/share/libpostal
sudo ln -sf /var/lib/libpostal/transliteration /usr/share/libpostal/transliteration
```

### Wayback CDX unreachable
Wayback CDX can be unreachable from some networks. Common Crawl
(`index.commoncrawl.org`) works as a fallback — historical-URL phases stay thin
but don't break.

### `testssl.sh not found`
The TLS phase needs testssl.sh. Install:
```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /home/mazin/tools/testssl_tool
```
Or point to your install with `OMNI_TESTSSL_BIN=/path/to/testssl.sh`.

### ffuf/gowitness leave zombie processes
The tools ignore SIGTERM. All `timeout` calls use `timeout -k 30` to force-kill
them.

### Low nuclei template count
Nuclei templates are needed for CVE scanning:
```bash
nuclei -update-templates -ud ~/.local/share/nuclei-templates
```
Run `./omni.sh -i` to install the full library automatically.

---

## Legal

D3FAULT-DEATH and HuntOps are security tools. Using them on systems without
authorization may violate the law and your bug-bounty program's terms. You are
responsible for how you use them. Only scan targets you own or are explicitly
authorized to test.

---

**Author:** ZOLDEK · **GitHub:** https://github.com/Mazen7771 · **License:** MIT
