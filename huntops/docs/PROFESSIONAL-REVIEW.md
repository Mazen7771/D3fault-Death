# HuntOps — Professional Code Review

Review performed after the M7 validation run (3 real targets, ~8h unattended) plus a
line-by-line pass over every module. Findings are severity-tagged and marked
`FIXED` (this redesign) or `KNOWN` (accepted, documented).

**Review bar:** "would I ship this on a live engagement unattended?" — every item
below either corrupts the report, silently loses data, or surprises an operator.

---

## Critical

| # | Finding | Impact | Status |
|---|---------|--------|--------|
| C1 | **Pipe-delimited records corrupted by literal `\|` in evidence/repro.** `_cand_cloud` embeds `curl ... \| head -50`, `_cand_cors` embeds `\| grep`, so 22 records in the real run split into 11 fields. `IFS='\|'` readers mis-render every downstream table. | Report integrity | **FIXED** — central `esc_rec()` in `core.sh` (replaces `\|`→`│`, `\n`→space) applied in all three `add_*` sinks. |
| C2 | **Newline inside a repro splits one record across ~20 physical lines.** `_cand_race` used `$(seq 1 20)` inside double quotes — command-substitution output embedded raw newlines. | Report integrity + line-count stats | **FIXED** — escaped `\$(seq …)` so the repro stores the literal command; `esc_rec()` also neutralises stray newlines. |
| C3 | **Phase ledger silently empty.** `setup_target` pre-creates `phase-status.tsv` empty, so the `[ -f ]` header guard never fires AND rows were lost; `report.sh` columns showed nothing. | Audit trail absent | **FIXED** — header guard now `-s` (non-empty), rows appended reliably. |
| C4 | **nmap hostname resolution fails silently** (observed: every host `Failed to resolve`, `0 IP addresses (0 hosts up)`) → the entire service/version layer feeds the CVE phase with nothing, no warning. | Silent data loss | **FIXED** — `recon_ports.sh` pre-resolves hosts→IPs with `dig` before `nmap -iL`, warns when nothing resolves, and warns on `0 hosts up`. |
| C5 | **sqlmap "confirmed" Critical on log noise.** `_parse_sqlmap` treated any `sqlmap identified` match as a Critical confirmed finding — that phrase appears in logs for clean targets. | False confirmed findings | **FIXED** — only explicit `is vulnerable` / `parameter … injectable` confirm; bare matches demote to a low candidate. |
| C6 | **`--no-dos` silently ignored for most tools.** `config.sh` is sourced before `--no-dos` parses; only nuclei rate was runtime-adjusted. ffuf/naabu/masscan caps stayed polite, so `--no-dos` claimed heavy scans but didn't deliver them. | Contract violation | **FIXED** — `FUF_RATE_NO_DOS` / `NAABU_RATE_NO_DOS` applied at runtime in their modules (same pattern as nuclei). |

## High

| # | Finding | Impact | Status |
|---|---------|--------|--------|
| H1 | **No verbosity / debug view at all.** No `-v`, no `--debug`, no file sink — every tool's stderr is `2>/dev/null` (22× in subdomains alone). When a phase silently no-ops you can't see why. | Operability | **FIXED** — `--verbose`/`--debug` + tmux live windows; all `log/ok/warn/err` teed to `$W/logs/verbose.log`; raw phase output teed to `debug.log` under `--debug`; `dbg()` stream. |
| H2 | **No per-domain deliverables.** Findings only lived inside a 76KB markdown / 107KB HTML; nothing grep-friendly to paste into a report, nothing for the hunter when confirmed=0. | Usability | **FIXED** — `$W/<domain>.txt` (findings sheet) and `$W/info-<domain>.txt` (recon dossier) always written (`lib/outputs.sh`). |
| H3 | **Nuclei candidates had blank CVSS/ref/tag** (vuln_nuclei emitted only 7 of 10 fields). HTML table showed empty CVSS for every nuclei row. | Report quality | **FIXED** — severity→CVSS mapping added, ref/tag filled. |
| H4 | **nuclei ignores SIGTERM** — `timeout` caps are theatre; a "90-min" cve pass ran 3h. | Unbounded phases | **KNOWN** — bounded per-tag `timeout 300` used for fast sets in the run; document that `timeout` can't pre-empt nuclei mid-scan. |
| H5 | **No TLS layer** despite testssl.sh installed. | Coverage gap | **FIXED** — `lib/vuln_tls.sh` runs testssl per live host IP:443, parses JSON, routes CRITICAL/HIGH→confirmed, MED/LOW→candidate, excluded→info. |

## Medium

| # | Finding | Impact | Status |
|---|---------|--------|--------|
| M1 | Dead `-w WATCH_DIR` flag parsed but never consumed; `usage` exits 0 even on errors. | CLI hygiene | **FIXED** — flag removed, `usage` exits 2 on unknown arg/missing target/bad mode. |
| M2 | `report.sh` dead `cls="info"` line (result of `tr` was always overwritten). | Clarity | **FIXED**. |
| M3 | Duplicated exclusion engines: `is_excluded` (bash) vs `excluded()` (python) can drift. | Maintainability | **KNOWN** — both work; noted for consolidation. |
| M4 | Aggregations silently 0-byte: `content/ffuf.txt`, `urls/params.txt`, `web/whatweb.txt` failed at runtime though raw data exists (jq/grep repro succeeds manually). | Data loss | **KNOWN** — raw per-host JSON (`ffuf-*.json`), `katana.txt`, `live.txt` are the authoritative sources and outputs.sh reads them. |
| M5 | Cross-module global leakage (`recon_params` reads `$JS`/`$CT` leaked by other modules; `urls/secrets.txt` overwritten by two phases). | Fragility | **KNOWN** — pipeline-order-dependent by design; documented. |
| M6 | `logs/phase-status.tsv` not populated (see C3). | — | **FIXED** with C3. |

## Low

| # | Finding | Status |
|---|---------|--------|
| L1 | Silent caps: nmap top-50, robots top-5, JS downloads top-50, arjun top-3. | **KNOWN** — intended resource bounds; noted in help. |
| L2 | `cve.sh` hardcodes `medium` confidence + `$DOMAIN` host regardless of DB severity. | **KNOWN**. |
| L3 | `intel.sh` comment references VIRUSTOTAL/CENSYS keys that are never used. | **KNOWN**. |
| L4 | `whatweb.txt` truncates before failure → 0-byte file on tool error. | **KNOWN**. |

---

## Verification-phase fixes (found by testing, not review)

| Fix | What broke | Status |
|-----|-----------|--------|
| V1 | **tmux dot-in-name quirk** — session `huntops-coda.com` parsed as window `.com`/pane by every `-t` target, so `verbose`/`behind-scenes` windows silently failed to create. | **FIXED** — trailing `:` on every tmux `-t` reference forces whole-session resolution. |
| V2 | **`ok()`/`warn()`/`err()` hardcoded `\e[0m`** — `--no-color` stripped the colour codes but left a literal reset byte. | **FIXED** — reset now `$C_RST` (empty under no-color); verified 0 ESC bytes. |
| V3 | **TLS skipped on scheme-bearing URLs** — `web/live-urls.txt` holds `http://host`, so `dig +short "http://host"` failed and every host was dropped as "no A record". | **FIXED** — `vuln_tls.sh` strips `https?://` + trailing `/` before resolving. |
| V4 | **`wc -l` inflates counts on empty-line files** — `takeover-candidates.txt` was a lone `\n`, counted as 1; `grep -c`'s "0 + exit1" also doubled under `\|\| echo 0`. | **FIXED** — `grep -c .` with default-after-capture in `outputs.sh`. |
| V5 | Bacula's `/sbin/bat` (a Qt GUI) shadows on this box — it previously corrupted `nmap.txt`; surfaces again as stray stderr on tty runs. | **KNOWN** — external environment issue, pre-existing; note for the operator. |

## Post-redesign hardening pass (found by live tmux runs + the smoke suite)

| # | Finding | Impact | Status |
|---|---------|--------|--------|
| H6 | **`amass enum -passive` prompts for sudo.** `/usr/bin/amass` is a Debian wrapper that runs `sudo libpostal_data download all /var/lib/libpostal` whenever `/usr/share/libpostal/transliteration` is missing. On any tty (tmux windows!) that's a hung password prompt mid-scan; amass also returns nothing until the data exists. | Scan UX + silent source | **FIXED** — `_amass_ready()` gates amass (skip + warn when data missing); install.sh provisions libpostal once. |
| H7 | **Bacula's `/sbin/bat` shadows the syntax-highlighter `bat` and some shells alias `cat`→`bat`** — output corruption (nmap.txt in M7). | Data corruption | **FIXED** — all 7 bare `cat` call sites now `command cat`; preflight warns when PATH `bat` resolves under `/usr/sbin:/sbin`. |
| H8 | **`esc_rec` pipe-replacement was emitting garbage.** `tr '|' '│'` maps one byte to one byte, so the multi-byte `│` became a single `\342` byte in every record field. Functional (pipes gone) but every rendered field held a broken byte. | Report quality | **FIXED** — sed (UTF-8-safe) for pipes + tr for newlines. Caught by the new smoke suite. |
| H9 | **DNS brute-force silently no-oped** — shuffledns is a massdns wrapper and massdns isn't installed. | Coverage gap | **FIXED** — install.sh adds `apt install massdns`; runtime falls back to a dnsx brute on the top-100k frequency-ordered wordlist prefix. |
| H10 | No repeatable regression guard. | Maintainability | **FIXED** — `tests/smoke.sh` (18 checks): syntax, esc_rec, record field-count integrity (C1/C2 regression), amass gate, brute fallback, colour hygiene, ledger, TLS parser, CLI exit codes, real-run artifact validation. |
| H11 | **ffuf timeout silently discarded all content-discovery results.** `ffuf ... || continue` skipped the jq extraction whenever ffuf exited non-zero — and a rate-limited scan on a big wordlist times out constantly, so this dropped every host's results (23 json files held 263 URLs, `ffuf.txt` stayed 0 bytes). | Findings loss | **FIXED** — extraction runs whenever the partial json exists, regardless of ffuf's exit code; smoke test added. |
| H12 | **Content discovery was sequential** (23 hosts × ~3 min ≈ 70-min phase). | Wall-clock | **FIXED** — parallelized via `xargs -P $CONCURRENCY`; the SAME run that showed the 0-URL bug went from 2-hr content phase to a few minutes once parallelized. |
| H13 | **`timeout N cmd` can't kill SIGTERM-ignoring tools** (ffuf, gowitness, sqlmap) — a 4-hour zombie ffuf was still running from a prior session. | Resource leak | **FIXED** — all 27 `timeout` command calls now use `timeout -k 30` (SIGKILL fallback). |
| H14 | **testssl parser read the wrong JSON key.** This testssl build (3.3dev) emits `vulnerabilities`; the parser only read `findings` — so every TLS finding was silently missed (smoke test used a fake `findings` structure and passed falsely). | Findings loss | **FIXED** — parses `vulnerabilities` + `findings` + `protocols` severity rows; smoke test now uses the real 3.3dev structure. |
| H15 | **dnsx timeout re-scanned everything from scratch** (retry overwrote partial results, dropped `-r` resolvers). | Efficiency | **FIXED** — partial `dnsx.jsonl` is kept and continued; full re-scan only on total failure. |

## What shipped in this redesign

- **CLI** (`huntops.sh`): `-v/--verbose`, `--debug`, `--no-terminal`, `--no-color`,
  `--menu`, `--ssl/--no-ssl`, ASCII logo, help with examples (exit 2 on errors),
  interactive menu when run with no args on a tty. Dead `-w` removed.
- **Live terminals** (`lib/ui.sh` + `core.sh`): auto tmux session `huntops-<domain>`
  with `main` / `verbose` / `behind-scenes` windows; every log line teed to
  `$W/logs/verbose.log`; `--debug` also tees raw phase output to `debug.log`.
- **Deliverables** (`lib/outputs.sh`): `$W/<domain>.txt` + `$W/info-<domain>.txt`,
  referenced from report.md/html.
- **TLS** (`lib/vuln_tls.sh`): testssl.sh on each live host's IP:443, JSON-parsed
  into the finding streams (scheme-strip + logfile fallback for CDN-blocked hosts).
- **Record hygiene**: `esc_rec()` central sanitizer; race repro no longer
  newline-splits; sqlmap demotion; nmap IP pre-resolution; nuclei CVSS/ref.
