#!/usr/bin/env bash
# HuntOps — markdown + single-file HTML report. Splits CONFIRMED / CANDIDATE / INFO.
set -u

RP="$W/report"
mkdir -p "$RP"

_html_esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

run_report() {
  local nf nc ni
  nf=$(count_lines "$FINDINGS"); nc=$(count_lines "$CANDIDATES"); ni=$(count_lines "$INFOFILE")
  log "generating report (confirmed=$nf candidate=$nc info=$ni)"

  _report_md "$nf" "$nc" "$ni"
  _report_html "$nf" "$nc" "$ni"
  ok "report -> $RP/huntops-report.html and $RP/summary.md"
}

_report_md() { # counts
  local nf="$1" nc="$2" ni="$3"
  {
    echo "# HuntOps report — ${TARGET:-unknown}"
    echo ""
    echo "- Run: $(date '+%Y-%m-%d %H:%M %Z')  mode: ${MODE:-bb}  tool: v${HUNTOPS_VERSION:-1.0.0}"
    echo "- Confirmed findings: **$nf**  |  Candidates (need manual validation): **$nc**  |  Info/excluded: $ni"
    echo "- Test account: ${TEST_ACCOUNT:-none}"
    echo ""
    echo "## CONFIRMED"
    [ -f "$FINDINGS" ] && sed 's/|/ | /g' "$FINDINGS"
    echo ""
    echo "## STRATEGY ENGINE FINDINGS (Ebb & Flow)"
    if [ -f "$W/strategy/strategy.log" ]; then
      grep -E 'HIT|hit' "$W/strategy/strategy.log" 2>/dev/null | head -20 | sed 's/^/  /'
      echo ""
    else
      echo "No strategy findings"
      echo ""
    fi
    echo "## CANDIDATES (verify before reporting)"
    [ -f "$CANDIDATES" ] && sed 's/|/ | /g' "$CANDIDATES"
    echo ""
    echo "## Assets"
    echo "- Subdomains: $(count_lines "$W/subdomains/final-resolved.txt")  | Live web: $(count_lines "$W/web/live-urls.txt")"
    echo "- Historical URLs: $(count_lines "$W/urls/historical.txt")  | Params: $(count_lines "$W/urls/params.txt")"
    echo ""
    echo "## Deliverables"
    echo "- Findings sheet: \`$W/$DOMAIN.txt\`"
    echo "- Recon dossier:  \`$W/info-$DOMAIN.txt\`"
    echo ""
    echo "## Phase status"
    [ -f "$PHASE_STATUS" ] && column -t "$PHASE_STATUS" 2>/dev/null || true
  } > "$RP/summary.md"
}

_report_html() {
  local nf="$1" nc="$2" ni="$3"
  {
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>HuntOps — '"$TARGET"'</title>'
    echo '<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#d8dde6}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:26px}h2{margin-top:32px;border-bottom:1px solid #2a2f3a;padding-bottom:6px}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13px}
td,th{border:1px solid #2a2f3a;padding:6px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#161a22}
.crit{color:#ff5d5d}.high{color:#ff9d45}.med{color:#ffd34d}.low{color:#7fd4ff}.info{color:#8b93a3}
code{background:#161a22;padding:1px 4px;border-radius:3px;font-size:12px}
pre{background:#161a22;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px}
.card{background:#161a22;border-radius:8px;padding:14px;margin:8px 0}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
</style></head><body><div class="wrap">'
    echo "<h1>HuntOps — ${TARGET:-unknown}</h1>"
    echo "<p>Run $(date '+%Y-%m-%d %H:%M %Z') · mode ${MODE:-bb} · v${HUNTOPS_VERSION:-1.0.0} · test account: ${TEST_ACCOUNT:-none}</p>"
    echo "<div class='card'><b>Confirmed:</b> $nf &nbsp;·&nbsp; <b>Candidates (manual):</b> $nc &nbsp;·&nbsp; <b>Info/excluded:</b> $ni</div>"

    echo '<h2>Strategy Engine — Ebb & Flow (Adaptive Attack-Vector Hunting)</h2>'
    if [ -f "$W/strategy/strategy.log" ]; then
      echo '<div class="card"><pre>'
      grep -E 'STRATEGY|HIT|miss' "$W/strategy/strategy.log" 2>/dev/null | head -30 | _html_esc
      echo '</pre></div>'
    else
      echo '<div class="card">No strategy findings</div>'
    fi

    echo '<h2>Confirmed findings</h2><table><tr><th>Sev</th><th>Tool</th><th>Host</th><th>Title</th><th>Detail</th></tr>'
    [ -f "$FINDINGS" ] && while IFS='|' read -r sev tool host title detail ref; do
      [ -z "$sev" ] && continue
      cls=$(echo "$sev" | tr '[:upper:]' '[:lower:]')
      echo "<tr><td class='$cls'>$sev</td><td>$(echo "$tool"|_html_esc)</td><td>$(echo "$host"|_html_esc)</td><td>$(echo "$title"|_html_esc)</td><td>$(echo "$detail"|_html_esc)<br><code>$(echo "$ref"|_html_esc)</code></td></tr>"
    done < "$FINDINGS"
    echo '</table>'

    echo '<h2>Candidates — needs manual validation</h2>'
    echo '<table><tr><th>Class</th><th>Host</th><th>Title</th><th>Conf</th><th>CVSS</th><th>Evidence / Repro</th></tr>'
    if [ -f "$CANDIDATES" ]; then
      while IFS='|' read -r kind cls host title conf ev repro ref cvss tag; do
        [ "$kind" = "CAND" ] || continue
        echo "<tr><td><span class='badge'>$cls</span></td><td>$(echo "$host"|_html_esc)</td><td>$(echo "$title"|_html_esc)</td><td>$conf</td><td>$cvss</td>"
        echo "<td>$(echo "$ev"|_html_esc)<br><pre>$(echo "$repro"|_html_esc)</pre><br><code>$(echo "$ref"|_html_esc)</code></td></tr>"
      done < "$CANDIDATES"
    fi
    echo '</table>'

    echo '<h2>Info / program-excluded (collapsed)</h2><details><summary>show</summary><table><tr><th>Tool</th><th>Host</th><th>Title</th></tr>'
    if [ -f "$INFOFILE" ]; then
      while IFS='|' read -r tool host title detail ref; do
        [ -z "$tool" ] && continue
        echo "<tr><td>$tool</td><td>$(echo "$host"|_html_esc)</td><td>$(echo "$title"|_html_esc)</td></tr>"
      done < "$INFOFILE"
    fi
    echo '</table></details>'

    echo '<h2>Assets</h2>'
    echo '<div class="card"><b>Subdomains:</b> '"$(count_lines "$W/subdomains/final-resolved.txt")"' · <b>Live web:</b> '"$(count_lines "$W/web/live-urls.txt")"' · <b>Historical URLs:</b> '"$(count_lines "$W/urls/historical.txt")"' · <b>Params:</b> '"$(count_lines "$W/urls/params.txt")"'</div>'
    echo '<h3>Validated hosts</h3><pre>'
    [ -f "$W/subdomains/final-resolved.txt" ] && command cat "$W/subdomains/final-resolved.txt" | _html_esc
    echo '</pre><h3>Live web</h3><pre>'
    [ -f "$W/web/live.txt" ] && command cat "$W/web/live.txt" | _html_esc
    echo '</pre>'

    echo '<h2>Deliverables</h2>'
    echo '<h3>Findings sheet</h3><pre>'
    [ -f "$W/$DOMAIN.txt" ] && command cat "$W/$DOMAIN.txt" | _html_esc
    echo '</pre><h3>Recon dossier</h3><pre>'
    [ -f "$W/info-$DOMAIN.txt" ] && command cat "$W/info-$DOMAIN.txt" | _html_esc
    echo '</pre>'

    echo '<h2>Phase status</h2><pre>'
    [ -f "$PHASE_STATUS" ] && column -t "$PHASE_STATUS" 2>/dev/null || true
    echo '</pre>'
    echo '</div></body></html>'
  } > "$RP/huntops-report.html"
}
