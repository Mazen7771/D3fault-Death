#!/usr/bin/env bash
# HuntOps — heuristic CVSS3.1 suggestion from an impact class. Verify with a real
# calculator (first.org/cvss) before submitting; these are starting points.
set -u

suggest_cvss() { # impact_class -> base score string
  local cls="$1"
  grep -F "$cls" "$IMPACT_CLASSES" 2>/dev/null | head -1 | cut -d'|' -f2
}
