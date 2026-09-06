#!/usr/bin/env bash
# HuntOps — interactive UI: live tmux windows + interactive setup menu.
# Provides launch_live_windows() and interactive_menu() for huntops.sh.

# Launch a 3-window tmux session for the scan:
#   main           — the scan itself (huntops.sh re-exec, pinned -o workdir)
#   verbose        — tail -f of logs/verbose.log (every log/ok/warn/err, teed)
#   behind-scenes  — tail -f of logs/debug.log (raw phase output + dbg lines)
# The session is created detached, then we attach; on scan exit the main window
# kills the session (closing the live tails too). Returns via exit.
launch_live_windows() {
  command -v tmux >/dev/null 2>&1 || { warn "tmux not found — running without live windows"; return 1; }

  # Pin the workdir so the inner scan, the verbose tail and the behind-scenes
  # tail all agree on the same path before anything starts writing.
  W="$OUTROOT/$TARGET/$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$W/logs"

  local sess="huntops-$TARGET"
  # NB: session names contain the target's dot (huntops-coda.com), which tmux's
  # target resolution reads as "<session>.<pane>". A trailing ':' forces tmux to
  # treat the string as a whole session target on every reference.
  tmux kill-session -t "$sess:" 2>/dev/null

  # Rebuild the inner command from the original args + internal flags.
  # printf %q shell-quotes each element so args containing spaces survive the
  # tmux shell (e.g. -H 'Cookie: a b').
  local inner inner_q
  inner=("$HUNTOPS_ROOT/huntops.sh" "${ORIG_ARGS[@]}" --inside-tmux -o "$W")
  printf -v inner_q '%q ' "${inner[@]}"

  # main window: run the scan, persist its real exit code, then tear the
  # session down so attach returns (exit code is recovered below).
  local main_cmd
  main_cmd="$inner_q; rc=\$?; printf '%s' \"\$rc\" > '$W/logs/exit-code'; echo 'SCAN COMPLETE (exit \$rc) — closing live windows...'; sleep 3; tmux kill-session -t '$sess:' 2>/dev/null; exit \$rc"

  tmux new-session -d -s "$sess" -n main "$main_cmd" 2>/dev/null || return 1
  tmux new-window -t "$sess:" -n verbose \
    "until [ -f '$W/logs/verbose.log' ]; do sleep 1; done; clear; echo '== HuntOps VERBOSE — live scan steps =='; tail -f '$W/logs/verbose.log'" 2>/dev/null
  tmux new-window -t "$sess:" -n behind-scenes \
    "until [ -f '$W/logs/debug.log' ]; do sleep 1; done; clear; echo '== HuntOps BEHIND-THE-SCENES — raw tool output =='; tail -f '$W/logs/debug.log'" 2>/dev/null

  tmux select-window -t "$sess:"main
  ok "live windows launched (tmux: $sess) — 'main' | 'verbose' | 'behind-scenes'"
  warn "use Ctrl-b then w to switch windows; Ctrl-b d to detach (scan keeps running)"
  tmux attach-session -t "$sess:"
  # recover the scan's real exit code written by the main window
  local rc=0
  [ -f "$W/logs/exit-code" ] && rc=$(command cat "$W/logs/exit-code" 2>/dev/null || echo 0)
  exit "${rc:-0}"
}

# Simple interactive setup menu (used when run with no target on a tty).
interactive_menu() {
  printf '%s\n' "== HuntOps interactive setup =="
  printf 'Target domain or IP: '
  IFS= read -r TARGET || exit 1
  [ -z "$TARGET" ] && { printf 'no target given\n' >&2; exit 1; }
  printf 'Mode — 1) quick  2) bb (default)  3) deep : '
  IFS= read -r m || true
  case "$m" in
    1) MODE="quick" ;;
    3) MODE="deep" ;;
    *) MODE="bb" ;;
  esac
  printf 'Run with live windows? (default y) y/n : '
  IFS= read -r lv || true
  case "$lv" in n|N) NO_TERMINAL=1 ;; esac
}
