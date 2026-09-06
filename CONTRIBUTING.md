# Contributing to Bug-Stealer

Thank you for your interest in contributing! This repository contains two independent bug-bounty
recon + vulnerability scanners:

1. **`D3fault-death.sh`** — the flagship monolithic pipeline (~2350 lines, v2.0.0)
2. **`huntops/`** — modular CLI + `lib/*.sh` phases with tmux live windows
3. **`omni.sh`** — unified entry point that runs either or both

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/Bug-stealer.git`
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Test with the smoke suites:
   ```bash
   bash -n D3fault-death.sh                    # syntax check
   huntops/tests/smoke.sh                       # HuntOps regression suite
   tests/integration_smoke.sh                    # OMNI integration tests
   ```
6. Commit your changes with a clear message
7. Push to your fork and open a Pull Request

## Code Style

### Bash Scripts
- Use `#!/usr/bin/env bash` as the shebang
- Quote all variable expansions (`"$var"`)
- Use `local` for function-scoped variables
- Add a comment above every function explaining its purpose
- Run `shellcheck` on new/modified scripts before committing
- Prefer explicit error handling over `set -e` for recon code (tools fail a lot)

### Documentation
- Update `README.md` when adding features or changing CLI flags
- Keep the pipeline diagrams in sync with actual code
- Document any new environment variables in the config files

### Tests
- Add smoke-test checks for new phases/modules
- Ensure offline tests pass without network access
- Use the existing test harness patterns in `huntops/tests/smoke.sh`

## Reporting Bugs

Open an issue with:
- The exact command you ran
- The target type (domain/IP)
- Expected vs actual behavior
- Relevant log output (redact any sensitive data!)

## Security Considerations

⚠️ **Authorized use only.** This tool actively scans and probes targets. Only run it against
systems you own or have written permission to test. When reporting bugs, never include:
- Real scan results from unauthorized targets
- API keys or credentials
- Personal data from third parties

## Project Structure

```
Bug-stealer/
├── D3fault-death.sh          # Monolithic scanner (chronological pipeline)
├── huntops/                  # Modular scanner
│   ├── huntops.sh            # CLI driver
│   ├── config/               # Rates, caps, wordlists
│   ├── lib/                  # Phase modules (run_*.sh)
│   ├── data/                 # Wordlists, impact classes
│   └── tests/                # Smoke suite
├── omni.sh                   # Unified CLI (both engines)
├── config/                   # OMNI unified config
├── lib/                      # OMNI shared libs + adapters
└── tests/                    # Integration tests
```

## Questions?

Open a GitHub issue or reach out via the contact info in `README.md`.
