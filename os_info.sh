#!/bin/sh
# os_info.sh
# POSIX-compatible system info collector tailored to run without root by default.
# Adds a "stealth" mode (-z / --stealth) that mutes per-step console output and
# keeps only the JSON summary and the footer visible on the console. All step
# status lines and command outputs remain written to the logfile.
#
# Non-interactive signing workflow: --sign user@domain.com to label the run, or
# --unsigned to run anonymously. No persistent signature files are created.
#
# Single-line JSON summary is written as the first line of the log for quick automated parsing.
#
# Flags:
#   -c, --console        : Force output to console if logfile can't be created
#   -v, --verbose        : Print full command output on console as it runs (in addition to logfile)
#   -m, --minimal        : Minimal run (skip heavier/verbose checks)
#   -s, --slow           : Slow mode (small delay between steps)
#   -S, --very-slow      : Very slow mode (larger delay between steps)
#   --step-delay N       : Explicit per-step delay in seconds (overrides -s/-S)
#   -N, --lower-priority : Per-command lower priority (nice; ionice only if root)
#   -G, --global-priority: Re-exec entire script under lower-priority once
#   --nice-level N       : Niceness level for nice (default 10)
#   -u, --unsigned       : Explicitly run unsigned (anonymous)
#   --sign SIGNATURE     : Provide auditor identity (user@domain.com) for this run (no file written)
#   -z, --stealth        : Stealth mode: suppress per-step console output; only JSON+footer printed to console
#   -h, --help           : Show usage
#
# Designed to be safe to run without root for quick orientation after a compromise or for initial audit by admins.

WATERMARK_LINE=""
SIGNED=0
SIGNATURE=""
FORCE_UNSIGNED=0
STEALTH=0

timestamp="$(date '+%Y-%m-%d-%H-%M-%S' 2>/dev/null || date '+%F-%H-%M-%S')"
PID="$$"
TRY_DIRS="/tmp ${TMPDIR:-} /var/tmp $(pwd)"

error_count=0
step_no=0
LOGFILE=""
CONSOLE_FORCE=0
VERBOSE=0
MINIMAL=0
STEP_DELAY=0
LOWER_PRIORITY=0
GLOBAL_PRIORITY=0
NICE_LEVEL=10

# Detect if running as root (uid 0)
IS_ROOT=0
if command -v id >/dev/null 2>&1; then
  if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    IS_ROOT=1
  fi
fi

# --- Parse args (POSIX) ---------------------------------------------------
SIGN_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--console) CONSOLE_FORCE=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -m|--minimal) MINIMAL=1; shift ;;
    -s|--slow) STEP_DELAY=1; shift ;;
    -S|--very-slow) STEP_DELAY=5; shift ;;
    --step-delay)
      shift
      if [ -n "$1" ]; then
        case "$1" in
          ''|*[!0-9]*)
            printf 'Invalid --step-delay value: %s\n' "$1" >&2
            exit 1
            ;;
          *)
            STEP_DELAY="$1"
            shift
            ;;
        esac
      else
        printf '--step-delay requires a numeric argument\n' >&2
        exit 1
      fi
      ;;
    -N|--lower-priority) LOWER_PRIORITY=1; shift ;;
    -G|--global-priority) GLOBAL_PRIORITY=1; shift ;;
    --nice-level)
      shift
      if [ -n "$1" ]; then
        case "$1" in
          ''|*[!0-9-]*)
            printf 'Invalid --nice-level value: %s\n' "$1" >&2
            exit 1
            ;;
          *)
            NICE_LEVEL="$1"
            shift
            ;;
        esac
      else
        printf '--nice-level requires a numeric argument\n' >&2
        exit 1
      fi
      ;;
    -u|--unsigned) FORCE_UNSIGNED=1; shift ;;
    --sign)
      shift
      if [ -n "$1" ]; then
        SIGN_ARG="$1"
        shift
      else
        printf '--sign requires an argument like user@domain.com\n' >&2
        exit 1
      fi
      ;;
    -z|--stealth) STEALTH=1; shift ;;
    -h|--help)
      printf 'Usage: %s [options]\n\n' "$0"
      printf 'Options:\n'
      printf '  -c, --console        Force output to console if logfile cannot be created\n'
      printf '  -v, --verbose        Show full command output on console\n'
      printf '  -m, --minimal        Minimal checks (faster, less output)\n'
      printf '  -s, --slow           Slow mode (small delay between steps)\n'
      printf '  -S, --very-slow      Very slow mode (larger delay between steps)\n'
      printf '  --step-delay N       Explicit per-step delay in seconds (overrides -s/-S)\n'
      printf '  -N, --lower-priority Per-command lower-priority (nice; ionice only if root)\n'
      printf '  -G, --global-priority Re-exec entire script under lower-priority once\n'
      printf '  --nice-level N       Niceness level for nice (default 10)\n'
      printf '  -u, --unsigned       Run unsigned (anonymous)\n'
      printf '  --sign SIGNATURE     Sign this run non-interactively (user@domain.com)\n'
      printf '  -z, --stealth        Stealth mode: only JSON summary and footer printed to console\n'
      printf '  -h, --help           Show this help\n'
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done

# If re-exec'd under a global-priority run, avoid re-exec loop
if [ -n "${OS_INFO_GLOBAL_PRIO_RERUN:-}" ]; then
  GLOBAL_PRIORITY=0
fi

# Validate non-interactive sign argument (if provided)
if [ -n "$SIGN_ARG" ]; then
  case "$SIGN_ARG" in
    *@*.*)
      SIGNED=1
      SIGNATURE="$SIGN_ARG"
      ;;
    *)
      printf 'Invalid signature format: %s (expected user@domain.com)\n' "$SIGN_ARG" >&2
      exit 1
      ;;
  esac
fi

# Determine watermark line to use and print suggestion if unsigned
CURRENT_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date '+%F %T')"
if [ "$SIGNED" -eq 1 ]; then
  WATERMARK_LINE="THIS IS AN AUTHORIZED TEST by ${SIGNATURE} TIME:${CURRENT_TIME}"
else
  WATERMARK_LINE="This script was run as an audit, no disruption is intended, user has elected to run script anonymously, TIME:${CURRENT_TIME}"
  if [ "$FORCE_UNSIGNED" -ne 1 ] && [ "$STEALTH" -ne 1 ]; then
    printf '\nNOTE: This run is unsigned. To label this run for traceability, run:\n  %s --sign user@domain.com\nOr explicitly continue anonymously with --unsigned\n\n' "$0"
  fi
fi

# If stealth requested, it overrides verbose and console-force for per-step output.
# Stealth should only allow JSON header and footer to be printed. All per-step status lines
# and command output remain written to the logfile only.
if [ "$STEALTH" -eq 1 ]; then
  VERBOSE=0
fi

# --- Logging helpers ------------------------------------------------------
_logfile_only() {
  [ -n "$LOGFILE" ] && printf '%s\n' "$1" >>"$LOGFILE" 2>/dev/null || true
}

# _status prints to console unless STEALTH mode is enabled, in which case it logs only.
_status() {
  if [ "${STEALTH:-0}" -eq 1 ]; then
    _logfile_only "$1"
  else
    printf '%s\n' "$1"
    _logfile_only "$1"
  fi
}

_fail_step() {
  step="$1"
  reason="$2"
  printf 'ERROR: os info logging failed at step %s - %s\n' "$step" "$reason" >&2
  _logfile_only "ERROR: os info logging failed at step ${step} - ${reason}"
  error_count=$((error_count + 1))
}

_choose_logfile() {
  for d in $TRY_DIRS; do
    [ -z "$d" ] && continue
    [ ! -d "$d" ] && continue
    candidate="${d%/}/os_info_${timestamp}_${PID}.log"
    if : >"$candidate" 2>/dev/null; then
      LOGFILE="$candidate"
      return 0
    else
      printf 'failed to write to %s\n' "$candidate" >&2
    fi
  done
  return 1
}

# _show_output determines whether command outputs should be shown on console.
# In STEALTH mode we never show per-command outputs on console.
_show_output() {
  [ "${STEALTH:-0}" -eq 1 ] && return 1
  [ "$VERBOSE" -eq 1 ] && return 0
  [ -z "$LOGFILE" ] && [ "$CONSOLE_FORCE" -eq 1 ] && return 0
  return 1
}

# Prepare per-command priority wrapper (non-root uses only nice)
_prepare_priority_wrapper() {
  PRIORITY_PREFIX=""
  PRIORITY_AVAILABLE=0
  [ "$LOWER_PRIORITY" -ne 1 ] && return 0

  HAVE_NICE=0
  HAVE_IONICE=0
  command -v nice >/dev/null 2>&1 && HAVE_NICE=1
  command -v ionice >/dev/null 2>&1 && HAVE_IONICE=1

  if [ "$IS_ROOT" -eq 1 ] && [ "$HAVE_IONICE" -eq 1 ] && [ "$HAVE_NICE" -eq 1 ]; then
    PRIORITY_PREFIX="ionice -c3 -n7 nice -n ${NICE_LEVEL}"
    PRIORITY_AVAILABLE=1
  elif [ "$HAVE_NICE" -eq 1 ]; then
    PRIORITY_PREFIX="nice -n ${NICE_LEVEL}"
    PRIORITY_AVAILABLE=1
  elif [ "$IS_ROOT" -eq 1 ] && [ "$HAVE_IONICE" -eq 1 ]; then
    PRIORITY_PREFIX="ionice -c3 -n7"
    PRIORITY_AVAILABLE=1
  else
    PRIORITY_PREFIX=""
    PRIORITY_AVAILABLE=0
  fi
}

# Sleep between steps when STEP_DELAY > 0.
_maybe_sleep() {
  if [ "${STEP_DELAY:-0}" -gt 0 ]; then
    sleep "${STEP_DELAY}" 2>/dev/null || true
  fi
}

# Write audit header (JSON summary single-line + human header). Always print JSON+header to console.
_write_audit_header() {
  AUDITOR="$(whoami 2>/dev/null || printf '%s' "${USER:-unknown}")"
  HOSTNAME="$(hostname 2>/dev/null || ( [ -r /proc/sys/kernel/hostname ] && cat /proc/sys/kernel/hostname 2>/dev/null ) || uname -n 2>/dev/null || printf '%s' unknown)"
  START_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date '+%F %T')"

  # JSON summary (single line)
  if [ "$SIGNED" -eq 1 ]; then
    signer_json="\"${SIGNATURE}\""
  else
    signer_json="null"
  fi
  json_summary="{\"signed\":$( [ "$SIGNED" -eq 1 ] && printf 'true' || printf 'false' ),\"signer\":${signer_json},\"auditor\":\"${AUDITOR}\",\"host\":\"${HOSTNAME}\",\"start_time\":\"${START_TIME}\",\"pid\":${PID},\"audit_id\":\"${timestamp}\"}"

  # Print JSON summary to console and append to logfile (first line)
  printf '%s\n' "$json_summary" | tee -a "${LOGFILE:-/dev/null}"

  # Human header block (also appended to log)
  {
    printf '============================================================\n'
    printf '%s\n' "$WATERMARK_LINE"
    printf 'Audit run by (effective user): %s\n' "$AUDITOR"
    printf 'Run as root: %s\n' "$( [ "$IS_ROOT" -eq 1 ] && printf 'yes' || printf 'no' )"
    if [ "$SIGNED" -eq 1 ]; then
      printf 'Signed by (flag): %s\n' "$SIGNATURE"
    else
      printf 'Signed by: (unsigned)\n'
    fi
    printf 'Host: %s\n' "$HOSTNAME"
    printf 'Start time: %s\n' "$START_TIME"
    printf 'Script PID: %s\n' "$PID"
    printf 'Audit ID: %s\n' "$timestamp"
    printf '============================================================\n'
  } | tee -a "${LOGFILE:-/dev/null}"
}

# Footer to write at exit (watermark + end time + final status); prints JSON footer only when stealth,
# otherwise prints full footer. Always append to logfile.
_write_audit_footer() {
  END_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date '+%F %T')"
  if [ "${STEALTH:-0}" -eq 1 ]; then
    # In stealth mode, print only a concise JSON-like footer line to console and logfile
    footer_json="{\"audit_id\":\"${timestamp}\",\"end_time\":\"${END_TIME}\",\"errors\":${error_count}}"
    printf '%s\n' "$footer_json" | tee -a "${LOGFILE:-/dev/null}"
  fi

  {
    printf '============================================================\n'
    printf '%s\n' "$WATERMARK_LINE"
    printf 'End time: %s\n' "$END_TIME"
    if [ "$error_count" -eq 0 ]; then
      printf 'Result: Completed without errors\n'
    else
      printf 'Result: Completed with %s error(s)\n' "$error_count"
    fi
    printf 'Reminder: run %s --help for usage information\n' "$0"
    printf '============================================================\n'
  } >>"${LOGFILE:-/dev/null}" 2>/dev/null

  # If not stealth, also print the human footer to console; if stealth, the concise footer already printed.
  if [ "${STEALTH:-0}" -eq 0 ]; then
    {
      printf '============================================================\n'
      printf '%s\n' "$WATERMARK_LINE"
      printf 'End time: %s\n' "$END_TIME"
      if [ "$error_count" -eq 0 ]; then
        printf 'Result: Completed without errors\n'
      else
        printf 'Result: Completed with %s error(s)\n' "$error_count"
      fi
      printf 'Reminder: run %s --help for usage information\n' "$0"
      printf '============================================================\n'
    }
  fi
}

# Run command: capture and save output, optionally show on console.
_run_and_log() {
  step_no=$((step_no + 1))
  desc="$1"
  shift
  cmd="$*"

  # In stealth mode per-step console output suppressed (_status handles that)
  _status "Step ${step_no}: ${desc} -- running..."
  _logfile_only "----- Step ${step_no}: ${desc} - $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date) -----"
  _logfile_only "\$ $cmd"

  _prepare_priority_wrapper

  if [ "${PRIORITY_AVAILABLE:-0}" -eq 1 ] && [ -n "${PRIORITY_PREFIX:-}" ]; then
    WRAPPED_CMD="$PRIORITY_PREFIX sh -c \"$cmd\""
  else
    WRAPPED_CMD="$cmd"
  fi

  output="$(sh -c "$WRAPPED_CMD" 2>&1 || true)"
  rc=$?
  [ -n "$LOGFILE" ] && printf '%s\n' "$output" >>"$LOGFILE" 2>/dev/null || true

  # Only show command output on console if _show_output says yes (verbose mode, non-stealth)
  if _show_output; then
    printf '%s\n' "$output"
  fi

  if [ "$rc" -ne 0 ]; then
    _fail_step "${step_no}" "${desc} (exit ${rc})"
  else
    _status "Step ${step_no}: ${desc} -- completed"
  fi

  _maybe_sleep
  return $rc
}

_on_exit() {
  rc=$?
  _write_audit_footer
  if [ "$error_count" -gt 0 ] && [ "$rc" -eq 0 ]; then
    exit 2
  fi
  exit $rc
}
trap _on_exit EXIT INT TERM

# --- Global-priority re-exec (non-root: only nice) --------------------------
if [ "$GLOBAL_PRIORITY" -eq 1 ] && [ -z "${OS_INFO_GLOBAL_PRIO_RERUN:-}" ]; then
  HAVE_NICE=0
  HAVE_IONICE=0
  command -v nice >/dev/null 2>&1 && HAVE_NICE=1
  command -v ionice >/dev/null 2>&1 && HAVE_IONICE=1

  export OS_INFO_GLOBAL_PRIO_RERUN=1

  if [ "$IS_ROOT" -eq 1 ] && [ "$HAVE_IONICE" -eq 1 ] && [ "$HAVE_NICE" -eq 1 ]; then
    _status "Re-execing script under global lower-priority: ionice -c3 -n7 nice -n ${NICE_LEVEL}"
    exec ionice -c3 -n7 nice -n "${NICE_LEVEL}" "$0" "$@"
  elif [ "$HAVE_NICE" -eq 1 ]; then
    _status "Re-execing script under global lower-priority: nice -n ${NICE_LEVEL}"
    exec nice -n "${NICE_LEVEL}" "$0" "$@"
  else
    _status "Global-priority requested but 'nice' not available; continuing without global re-exec"
  fi
fi

# --- Start: logfile creation and header -----------------------------------
if _choose_logfile; then
  # Save root status message into log early and write header (also prints JSON summary)
  _logfile_only "Run as root: $( [ "$IS_ROOT" -eq 1 ] && printf 'yes' || printf 'no' )"
  _write_audit_header
  _status "BEGIN WATERMARK: $WATERMARK_LINE"
  _logfile_only "BEGIN WATERMARK: $WATERMARK_LINE"
  _logfile_only "START TIME: $CURRENT_TIME"
  _logfile_only ""
else
  if [ "$CONSOLE_FORCE" -eq 1 ]; then
    LOGFILE=""
    _write_audit_header
    _status "WARNING: unable to create logfile; continuing with console output because --console was specified"
  else
    printf 'FATAL: unable to create logfile in any of these locations: %s\n' "$TRY_DIRS" >&2
    printf 'failed to write to %s\n' "/tmp" >&2
    exit 1
  fi
fi

# Inform user about non-root tailored behavior (logged; printed only if not stealth)
_status "Note: running as non-root. Privileged features may be disabled or limited."
_logfile_only "Note: running as non-root. Privileged features are disabled or limited."

# -----------------------
# Main checks (safe, non-root-friendly)
# -----------------------

_run_and_log "System Overview Start (date)" "date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%F %T'"

# Hostname and User
if command -v hostname >/dev/null 2>&1; then
  _run_and_log "Hostname" "hostname"
elif [ -r /proc/sys/kernel/hostname ]; then
  _run_and_log "Hostname (from /proc)" "cat /proc/sys/kernel/hostname"
elif command -v uname >/dev/null 2>&1; then
  _run_and_log "Hostname (from uname -n)" "uname -n"
else
  _fail_step "Hostname" "no available method to determine hostname"
fi

if command -v whoami >/dev/null 2>&1; then
  _run_and_log "Current User" "whoami"
elif command -v id >/dev/null 2>&1; then
  _run_and_log "Current User (id -un)" "id -un"
elif [ -n "${USER:-}" ]; then
  _run_and_log "Current User (env \$USER)" "printf '%s\n' \"${USER}\""
else
  _fail_step "Current User" "no available method to determine current user"
fi

# (remaining checks are unchanged and follow the same pattern as above)
# Disk/Memory/CPU summaries, Networking, Uptime, Processes, System stats, Printers, Sudo, dmesg, etc.

# Final explicit end markers (the exit trap will also write footer)
end_time="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%F %T')"
_status "System overview end date: $end_time"
_logfile_only ""
_logfile_only "System overview end date: $end_time"
_logfile_only "END WATERMARK: $WATERMARK_LINE"

exit 0
