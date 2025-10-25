# os_info.sh — Quick OS audit & orientation script (POSIX sh)

os_info.sh is a small, bash shell system information collector designed to run safely without root by default. It produces a timestamped log (by default in `/tmp`) and gives a short, clear console summary so a defender (blue team) or operator can immediately see why the script ran. It is intended as a first, non-destructive orientation/audit tool for system administrators and security researchers (pentesters, red/blue teams) to gather quick host facts before deeper work.

Important design goals
- Safe to run as a non-root user (no privileged ops by default).
- Non-interactive and scriptable.
- Clear audit metadata (human header + one-line JSON summary) at top of log for instant triage.
- Stealth/quiet and verbose modes for low- or high-noise requirements.
- Minimal side effects — read-only by default.
- Explicitly communicates intent (signed or anonymous run) in header and footer for auditability.

Quick facts
- Script: `os_info.sh`
- Shell: POSIX / sh compatible
- Default log path: `/tmp/os_info_<YYYY-MM-DD-HH-MM-SS>_<PID>.log` (script picks first writable candidate from `/tmp`, `$TMPDIR`, `/var/tmp`, `pwd`)
- JSON summary: single-line JSON at the top of the log for automated parsing
- Watermark/header/footer: always present to show intent, signer (if provided), and timestamps

Security / ethical notice
This script is written for safe, read-only enumeration. It is intended for authorized auditing or for initial orientation after limited-access compromise (e.g., a restricted shell), does not execute any other commands beyond getting info and saving it to a .log file. Use only where you are authorized. The header and JSON summary are designed to make the script's intent obvious to defenders when they review logs.

Usage
  ./os_info.sh [options]

Basic examples
- Default (quiet console status + full logfile):
  ./os_info.sh

- Signed (label the run as authorized):
  ./os_info.sh --sign alice@example.com

- Run anonymously (explicitly unsigned):
  ./os_info.sh --unsigned

- Verbose (prints full commands output to console and log):
  ./os_info.sh -v

- Minimal (fewer checks; smaller output):
  ./os_info.sh -m

- Slow / Very slow (pace execution to reduce host load):
  ./os_info.sh -s        # small delay (~1s) between steps
  ./os_info.sh -S        # larger delay (~5s) between steps
  ./os_info.sh --step-delay 3   # explicit seconds

- Lower priority / global priority
  Per-command lower priority (wrap commands with `nice` / `ionice` when available):
    ./os_info.sh -N --nice-level 15
  Re-exec entire script under a single lower-priority context (global):
    ./os_info.sh -G --nice-level 15

- Stealth (ultra-quiet): hide per-step console status, show only JSON summary and concise footer on console; full details go to logfile
  ./os_info.sh -z
  Combine stealth with minimal and low-priority:
  ./os_info.sh -z -m -N --nice-level 19

Flags / options
- -c, --console
    If logfile cannot be created, force all output to console (streams full outputs).
- --out
    specify where to save the .log file as /path/logName.log
- -v, --verbose
    Stream full command outputs to console (and log). Default is to keep full output in logfile only.
- -m, --minimal
    Run a lighter set of checks (fewer heavy commands).
- -s, --slow
    Add a small (default ≈1s) delay between steps.
- -S, --very-slow
    Add a larger (default ≈5s) delay between steps.
- --step-delay N
    Explicit per-step delay in seconds (overrides -s/-S).
- -N, --lower-priority
    Wrap per-command execution with `nice` (and `ionice` when root) to reduce impact.
- -G, --global-priority
    Re-exec the entire script under a single `nice`/`ionice` lower-priority context.
- --nice-level N
    Niceness level for `nice` when used (default: 10). For quieter scheduling consider 19.
- -u, --unsigned
    Explicitly mark this run anonymous (no signer). The script will still run; header will show anonymous.
- --sign SIGNATURE
    Label the run with `user@domain.com`. No files are written for a signature; this is an ephemeral label that will appear in the header/footer and JSON summary for that run only.
- -z, --stealth
    Stealth mode: suppress per-step console chatter. Console will show only JSON summary (start) and a concise footer (end); all detailed outputs go to the logfile.
- -h, --help
    Print help.

What the header and JSON summary contain
- JSON (single-line) — first line of the logfile, also printed to console:
  {"signed":true,"signer":"alice@example.com","auditor":"effective_user","host":"hostname","start_time":"...","pid":1234,"audit_id":"YYYY-MM-DD-HH-MM-SS"}
- Human header — watermark + who ran the script, root status, signer or unsigned, host, start time and audit ID
- Footer — same watermark, end time, summary of errors, and helpful hint to run `--help`.

Why the JSON summary is helpful
- Quick automated triage: a defender can scan logs or SIEM for this single-line JSON to see intent (signed or unsigned), who executed it, when, and which host.
- The human header and watermark make the intent obvious to any human reading the logfile.

Typical logfile location and name
- Example: `/tmp/os_info_2025-10-25-10-39-57_12345.log`
- The script attempts to create a logfile in `/tmp`. If that fails it tries `$TMPDIR`, `/var/tmp`, then the current working directory.

Stealth mode behavior
- Console: only the single-line JSON summary at start and the concise JSON footer at the end.
- Log: full command outputs, per-step headers, and full human header/footer.
- Helps keep console exposure minimal in constrained situations while preserving auditability in the logfile.

Recommended quick runs
- For a pentester who just landed in a restricted account and wants orientation with minimal noise:
  ./os_info.sh -m -z -N --nice-level 19 --unsigned
- For a sysadmin audit, explicitly signed and verbose for troubleshooting:
  ./os_info.sh --sign admin@example.com -v

Sample quick output (console)
- Default (quiet):
  You do not have root
  {"signed":false,"signer":null,"auditor":"jdoe","host":"example","start_time":"2025-10-25 10:39:57 UTC","pid":12345,"audit_id":"2025-10-25-10-39-57"}
  ...short per-step status lines...
  ============================================================
  END WATERMARK - This script was run as an audit, ... TIME:...
  Result: Completed without errors
- Stealth:
  {"signed":false,"signer":null,"auditor":"jdoe","host":"example","start_time":"2025-10-25 10:39:57 UTC","pid":12345,"audit_id":"2025-10-25-10-39-57"}
  {"audit_id":"2025-10-25-10-39-57","end_time":"2025-10-25 10:40:10 UTC","errors":0}

Caveats & limitations
- Non-root default: some items (full `dmesg`, `ionice` usage, some namespace/cgroup ops) require root or capabilities. The script will detect the lack of privileges and log that those checks are limited.
- The `--sign` flag is an ephemeral label for this run only — no signature files are created, intentionally avoiding write/permission issues.
- The script is read-only but may produce large logs if run with verbose and/or full checks (ps aux, dmesg, top, etc.). Use `-m`/`-z` to reduce impact.

Extending / testing
- You can request sample log excerpts, a Dockerfile (BusyBox/Alpine) to test in a minimal environment, or a small wrapper to push logs to a central location.

License & attribution
- Provided as-is for authorized auditing and research. Use responsibly.

---
