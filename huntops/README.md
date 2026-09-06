# HuntOps — general-purpose auto-mode bug-bounty scanner

A modular, target-agnostic recon + vulnerability scanner that runs the whole
professional pipeline **unattended**. Point it at any domain you're authorized
to test; it re-enumerates the real attack surface (subdomains, ports, JS, params,
historical URLs), runs nuclei/nikto/sqlmap at controlled rates, and — the point —
generates **manually-validatable candidates** in the bug classes that actually
pay on HackerOne (IDOR/BOLA, auth, SSRF, GraphQL, races, secrets, takeover),
each with a copy-paste repro curl command.

> ⚠️ Authorized use only. Only run against systems you own or have written
> permission to test, and respect your program's scope + rules (no DoS, test
> accounts only, purge any user data you encounter).

## Quick start

```bash
./huntops.sh -i                 # install tools + nuclei templates (once)
./huntops.sh -d target.com      # auto mode, bb depth
./huntops.sh -d target.com -m deep --no-dos   # exhaustive (DNS brute, full ports)
./huntops.sh -d target.com --test-account you@test.com   # IDOR/authz = high confidence
./huntops.sh -d target.com -H 'Cookie: session=abc'      # authenticated scan
./huntops.sh -d target.com -s scope.txt                  # enforce program scope
./huntops.sh -t 1.2.3.4                                   # IP target
```

Output: `output/<target>/<date>/report/huntops-report.html` (+ `summary.md`).

## Live terminal view

Every scan auto-launches a **tmux session** (`huntops-<target>`) with three windows:
`main` (the scan), `verbose` (live step feed), `behind-scenes` (raw tool output).
Detach with `Ctrl-b d`; the scan keeps running. Disable with `--no-terminal`
(for scripts/CI), or add `--debug` to also capture raw phase output to
`output/<target>/<date>/logs/debug.log`. Run `./huntops.sh` with no args (or
`--menu`) for an interactive setup prompt.

## Per-domain deliverables

Two grep-friendly files are written into every scan directory, ready to paste
into a report:

- **`output/<target>/<date>/<target>.txt`** — findings sheet: confirmed findings,
  top candidates sorted by CVSS, and info/excluded, with counts.
- **`output/<target>/<date>/info-<target>.txt`** — recon dossier: asset
  inventory, live hosts with tech + WAF, ports/services, historical URLs,
  JS endpoints, CNAME takeover leads, and **suggested attack angles**.

Both are embedded in the HTML report too.

## How findings are classified (HackerOne-clean)

| Stream | File | Meaning |
|---|---|---|
| CONFIRMED | `findings/findings.txt` | Critical/High with real matcher evidence |
| CANDIDATE | `findings/candidates.txt` | **Needs manual validation** — each has a repro curl, impact class, confidence, suggested CVSS3.1 |
| INFO | `findings/info.txt` | Program-excluded noise (auto-demoted) |

Scanner noise (missing headers, cookie flags, clickjacking, info leaks) is
demoted automatically via `data/program-exclusions.txt` so the report stays
focused on what might actually be paid.

## Pipeline

```
recon_subdomains → recon_ports → recon_web → vuln_tls → recon_content → recon_js
→ recon_params → vuln_nuclei → vuln_nikto → vuln_sqlmap → candidates
→ intel → cve → report → outputs
```

Modes: `quick` · `bb` (default) · `deep` (adds DNS brute-force, heavy wordlists).
`vuln_tls` runs testssl.sh against each live host's resolved IP:443 (CRITICAL/HIGH →
confirmed, MEDIUM/LOW → candidate, excluded → info). `outputs` writes the
per-domain deliverables.

## Modules

- **recon_subdomains** — 14+ passive sources (crt.sh, certspotter, hackertarget,
  rapiddns, bufferover, OTX, anubis, urlscan, wayback, grep.app, subfinder,
  amass, assetfinder) + permutation + shuffledns brute (dnsx fallback when
  massdns is absent) + dnsx validation with wildcard filtering. Amass is gated
  on its libpostal data (else it sudo-prompts on a tty) — provision via `-i`.
  **Warns loudly on low yield** instead of silently collapsing to a 1-host scope.
- **vuln_tls** — testssl.sh against every live host's resolved IP:443; parses the
  pretty JSON (`vulnerabilities` array on 3.3dev, `findings` on older builds) and
  routes CRITICAL/HIGH → confirmed, MEDIUM/LOW → candidate, INFO → info, and
  drops "OK / not vulnerable" rows as noise. Falls back to logfile scraping when
  a CDN edge kills the connection mid-scan.
- **candidates** — the money engine (IDOR/BOLA, JWT, GraphQL introspection,
  SSRF, open redirect, race conditions, admin/authz, secrets, cloud buckets,
  subdomain takeover, CORS).
- **vuln_nuclei** — full template library, per-tag runs (cve, kev, xss, sqli,
  ssrf, lfi, exposure, takeover, api/graphql, jwt) at controlled rate.
- **intel / cve** — free OSINT lookups + searchsploit + seeded CVE DB.

## Config

- `config/config.sh` — rates, caps, wordlists, `TESTSSL_BIN`, `DNSX_BRUTE_SAMPLE`
  (all env-overridable).
- `config/keys.conf` — optional keys (Shodan, Censys, VirusTotal, SecurityTrails,
  GitHub, Chaos). Everything works without them.
- `data/program-exclusions.txt` — edit for the program you're testing.
- `data/impact-classes.conf` — impact class → suggested CVSS3.1.

## Testing

`tests/smoke.sh` runs a fast offline regression suite (syntax, record-format
integrity, amass gate, brute fallback, colour hygiene, TLS parser, CLI exit
codes). `tests/smoke.sh -w output/<target>/<date>` also validates a real run's
artifacts (ledger, logs, deliverables, candidate field counts).

- `config/config.sh` — rates, caps, wordlists (env-overridable).
- `config/keys.conf` — optional keys (Shodan, Censys, VirusTotal, SecurityTrails,
  GitHub, Chaos). Everything works without them.
- `data/program-exclusions.txt` — edit for the program you're testing.
- `data/impact-classes.conf` — impact class → suggested CVSS3.1.

## Ethics & safety rails

- Global request throttle + per-tool rate caps (nuclei `-rl`, ffuf `-rate`,
  naabu `-rate`, xargs `-P`). Full `-p-` scans and deep sqlmap need `--no-dos`.
- `--test-account` gates IDOR/authz candidates to accounts you own.
- PII purge: if a probe surfaces real-user data, stop and purge per program rules.
