#!/bin/bash
# os_info.sh
# POSIX-compatible system info collector — safe hostname fallbacks (no dummy values).
#
# This is the working script you confirmed earlier, with one focused change:
# - Removed any hardcoded/dummy hostname values and replaced them with safe fallbacks:
#     hostname -> /proc/sys/kernel/hostname -> uname -n -> "unknown"
# No other behavior changed; --out, --stealth, -v, defaults, and logfile formatting remain the same.

WATERMARK_LINE=""
SIGNED=0
SIGNATURE=""
FORCE_UNSIGNED=0
STEALTH=0
JSON_CONSOLE=0
FORCE_FULL=0
OUT_PATH=""

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

# --- detect root quickly ---
IS_ROOT=0
if command -v id >/dev/null 2>&1; then
  [ "$(id -u 2>/dev/null || echo 1)" = "0" ] && IS_ROOT=1
fi

# immediate root-status console line
if [ "$IS_ROOT" -eq 1 ]; then
  printf '%s\n' 'You have root'
  ROOT_STATUS_MSG="You have root"
else
  printf '%s\n' 'You do not have root'
  ROOT_STATUS_MSG="You do not have root"
fi

# --- arg parse ---
SIGN_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--console) CONSOLE_FORCE=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -m|--minimal) MINIMAL=1; shift ;;
    -s|--slow) STEP_DELAY=1; shift ;;
    -S|--very-slow) STEP_DELAY=5; shift ;;
    --step-delay) shift; STEP_DELAY="$1"; shift ;;
    -N|--lower-priority) LOWER_PRIORITY=1; shift ;;
    -G|--global-priority) GLOBAL_PRIORITY=1; shift ;;
    --nice-level) shift; NICE_LEVEL="$1"; shift ;;
    -u|--unsigned) FORCE_UNSIGNED=1; shift ;;
    --sign) shift; SIGN_ARG="$1"; shift ;;
    -z|--stealth) STEALTH=1; shift ;;
    -j|--json-console) JSON_CONSOLE=1; shift ;;
    --force-full) FORCE_FULL=1; shift ;;
    --out)
      shift
      if [ -n "$1" ]; then
        OUT_PATH="$1"
        shift
      else
        printf '%s\n' "--out requires a path argument" >&2
        exit 1
      fi
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./os_info.sh [options]
Options:
  -c, --console        Force output to console if logfile cannot be created
  -v, --verbose        Stream full command output to console (and logfile)
  -m, --minimal        Minimal checks
  -s, --slow           Small delay between steps (~1s)
  -S, --very-slow      Larger delay (~5s)
  --step-delay N       Per-step delay in seconds
  -N, --lower-priority Per-command lower-priority (nice; ionice if root)
  -G, --global-priority Re-exec under lower-priority
  --nice-level N       Niceness level for nice (default 10)
  -u, --unsigned       Explicitly run unsigned (anonymous)
  --sign SIGNATURE     Label this run (user@domain.com)
  --out /path/to/log   Force logfile path (script will attempt to create parent dir)
  -z, --stealth        Stealth mode (very quiet console)
  -j, --json-console   Print JSON summary to console (opt-in)
  --force-full         Attempt fallback checks and log why tools were missing
  -h, --help           Show this help
EOF
      exit 0
      ;;
    *)
      printf '%s\n' "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# avoid re-exec loop if re-exec marker present
[ -n "${OS_INFO_GLOBAL_PRIO_RERUN:-}" ] && GLOBAL_PRIORITY=0

# validate sign arg
if [ -n "$SIGN_ARG" ]; then
  case "$SIGN_ARG" in
    *@*.*) SIGNED=1; SIGNATURE="$SIGN_ARG" ;;
    *) printf '%s\n' "Invalid signature format: $SIGN_ARG" >&2; exit 1 ;;
  esac
fi

CURRENT_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date '+%F %T')"
if [ "$SIGNED" -eq 1 ]; then
  WATERMARK_LINE="THIS IS AN AUTHORIZED TEST by ${SIGNATURE} TIME:${CURRENT_TIME}"
else
  WATERMARK_LINE="This script was run as an audit, no disruption is intended, user has elected to run script anonymously, TIME:${CURRENT_TIME}"
  if [ "$FORCE_UNSIGNED" -ne 1 ] && [ "$STEALTH" -ne 1 ]; then
    printf '%s\n\n' "NOTE: This run is unsigned. To label this run: $0 --sign user@domain.com"
  fi
fi

[ "$STEALTH" -eq 1 ] && VERBOSE=0

# --- helpers ---
_logfile_only() { [ -n "$LOGFILE" ] && printf '%s\n' "$1" >>"$LOGFILE" 2>/dev/null || true; }

_status() {
  if [ "$VERBOSE" -eq 1 ] && [ "${STEALTH:-0}" -ne 1 ]; then
    printf '%s\n' "$1"
  fi
  _logfile_only "$1"
}

_fail_step() {
  step="$1"; reason="$2"
  printf '%s\n' "ERROR: os info logging failed at step $step - $reason" >&2
  _logfile_only "ERROR: os info logging failed at step ${step} - ${reason}"
  error_count=$((error_count + 1))
}

# choose logfile, with OUT_PATH support
_choose_logfile() {
  if [ -n "$OUT_PATH" ]; then
    out_dir="$(dirname -- "$OUT_PATH" 2>/dev/null || printf '%s\n' .)"
    if [ ! -d "$out_dir" ]; then
      if ! mkdir -p "$out_dir" 2>/dev/null; then
        _logfile_only "WARNING: unable to create directory for --out path: $out_dir; falling back to automatic selection"
      fi
    fi
    if : >"$OUT_PATH" 2>/dev/null; then
      LOGFILE="$OUT_PATH"
      return 0
    else
      _logfile_only "WARNING: cannot write to --out path: $OUT_PATH; falling back to automatic selection"
    fi
  fi

  for d in $TRY_DIRS; do
    [ -z "$d" ] && continue
    [ ! -d "$d" ] && continue
    candidate="${d%/}/os_info_${timestamp}_${PID}.log"
    if : >"$candidate" 2>/dev/null; then LOGFILE="$candidate"; return 0; fi
  done
  return 1
}

# show output on console only when verbose or when logfile absent+console forced; stealth suppresses
_show_output() {
  [ "${STEALTH:-0}" -eq 1 ] && return 1
  [ "$VERBOSE" -eq 1 ] && return 0
  [ -z "$LOGFILE" ] && [ "$CONSOLE_FORCE" -eq 1 ] && return 0
  return 1
}

_prepare_priority_wrapper() {
  PRIORITY_PREFIX=""; PRIORITY_AVAILABLE=0
  [ "$LOWER_PRIORITY" -ne 1 ] && return 0
  command -v nice >/dev/null 2>&1 && HAVE_NICE=1 || HAVE_NICE=0
  command -v ionice >/dev/null 2>&1 && HAVE_IONICE=1 || HAVE_IONICE=0
  if [ "$IS_ROOT" -eq 1 ] && [ "$HAVE_IONICE" -eq 1 ] && [ "$HAVE_NICE" -eq 1 ]; then
    PRIORITY_PREFIX="ionice -c3 -n7 nice -n ${NICE_LEVEL}"; PRIORITY_AVAILABLE=1
  elif [ "$HAVE_NICE" -eq 1 ]; then
    PRIORITY_PREFIX="nice -n ${NICE_LEVEL}"; PRIORITY_AVAILABLE=1
  elif [ "$IS_ROOT" -eq 1 ] && [ "$HAVE_IONICE" -eq 1 ]; then
    PRIORITY_PREFIX="ionice -c3 -n7"; PRIORITY_AVAILABLE=1
  fi
}

_maybe_sleep() { [ "${STEP_DELAY:-0}" -gt 0 ] && sleep "${STEP_DELAY}" 2>/dev/null || true; }

_log_section_header() {
  section="$1"
  if [ -n "$LOGFILE" ]; then
    printf '%s\n' "" >>"$LOGFILE" 2>/dev/null
    printf '## %s ##\n' "$section" >>"$LOGFILE" 2>/dev/null
    printf '---\n' >>"$LOGFILE" 2>/dev/null
  fi
}

# Run a command and place its output into the corresponding section in the logfile.
_run_and_log() {
  step_no=$((step_no + 1)); desc="$1"; shift; cmd="$*"

  if [ "$VERBOSE" -eq 1 ]; then
    printf '%s\n' "Step ${step_no}: ${desc} -- running..."
    _logfile_only "----- Step ${step_no}: ${desc} - $(date '+%Y-%m-%d %H:%M:%S') -----"
    _logfile_only "\$ $cmd"
    _prepare_priority_wrapper
    if [ "${PRIORITY_AVAILABLE:-0}" -eq 1 ] && [ -n "${PRIORITY_PREFIX}" ]; then
      WRAPPED_CMD="$PRIORITY_PREFIX sh -c \"$cmd\""
    else
      WRAPPED_CMD="$cmd"
    fi
    if command -v tee >/dev/null 2>&1; then
      sh -c "$WRAPPED_CMD" 2>&1 | tee -a "${LOGFILE:-/dev/null}"
      rc=${PIPESTATUS:-$?} 2>/dev/null || rc=$?
    else
      sh -c "$WRAPPED_CMD" >>"${LOGFILE:-/dev/null}" 2>&1 || rc=$?
    fi
    if [ "${rc:-0}" -ne 0 ]; then
      _fail_step "${step_no}" "${desc} (exit ${rc})"
    else
      printf '%s\n' "Step ${step_no}: ${desc} -- completed"
      _logfile_only "Step ${step_no}: ${desc} -- completed"
    fi
  else
    _log_section_header "$desc"
    _logfile_only "\$ $cmd"
    _prepare_priority_wrapper
    if [ "${PRIORITY_AVAILABLE:-0}" -eq 1 ] && [ -n "${PRIORITY_PREFIX}" ]; then
      WRAPPED_CMD="$PRIORITY_PREFIX sh -c \"$cmd\""
    else
      WRAPPED_CMD="$cmd"
    fi
    output="$(sh -c "$WRAPPED_CMD" 2>&1 || true)"; rc=$?
    [ -n "$LOGFILE" ] && printf '%s\n' "$output" >>"$LOGFILE" 2>/dev/null || true
    if [ "$rc" -ne 0 ]; then
      _fail_step "${step_no}" "${desc} (exit ${rc})"
    fi
  fi

  _maybe_sleep
  return 0
}

_try_or_record() {
  cmd_name="$1"; human="$2"; primary="$3"; fallback="$4"
  if command -v ${primary%% *} >/dev/null 2>&1; then
    _run_and_log "$human" "$primary"
  else
    if [ "$FORCE_FULL" -eq 1 ]; then
      _run_and_log "${human} (fallback attempted)" "$fallback" || _logfile_only "Note: ${human} fallback failed or produced no output"
    else
      _logfile_only "SKIPPED: ${human} - ${primary%% *} not available"
    fi
  fi
}

# Header writing: JSON summary to logfile; optionally print JSON to console with -j
_write_audit_header() {
  AUDITOR="$(whoami 2>/dev/null || printf '%s' "${USER:-unknown}")"
  # SAFE hostname evaluation: try hostname, then /proc, then uname -n, then "unknown"
  HOSTNAME="$(hostname 2>/dev/null || ( [ -r /proc/sys/kernel/hostname ] && cat /proc/sys/kernel/hostname 2>/dev/null ) || uname -n 2>/dev/null || printf '%s' 'unknown')"
  START_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date '+%F %T')"

  if [ "$SIGNED" -eq 1 ]; then signer_json="\"${SIGNATURE}\""; else signer_json="null"; fi
  json_summary="{\"signed\":$( [ "$SIGNED" -eq 1 ] && printf 'true' || printf 'false' ),\"signer\":${signer_json},\"auditor\":\"${AUDITOR}\",\"host\":\"${HOSTNAME}\",\"start_time\":\"${START_TIME}\",\"pid\":${PID},\"audit_id\":\"${timestamp}\"}"

  [ -n "$LOGFILE" ] && printf '%s\n' "$json_summary" >>"$LOGFILE" 2>/dev/null || true
  [ "$JSON_CONSOLE" -eq 1 ] && printf '%s\n' "$json_summary"

  if [ -n "$LOGFILE" ]; then
    cat >>"$LOGFILE" <<EOF
============================================================
$WATERMARK_LINE
Audit run by (effective user): $AUDITOR
Run as root: $( [ "$IS_ROOT" -eq 1 ] && printf 'yes' || printf 'no' )
$( [ "$SIGNED" -eq 1 ] && printf 'Signed by (flag): %s\n' "$SIGNATURE" || printf 'Signed by: (unsigned)\n' )
Host: $HOSTNAME
Start time: $START_TIME
Script PID: $PID
Audit ID: $timestamp
============================================================

EOF
  fi
}

_write_audit_footer() {
  END_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date '+%F %T')"
  if [ "${STEALTH:-0}" -eq 1 ]; then
    footer_json="{\"audit_id\":\"${timestamp}\",\"end_time\":\"${END_TIME}\",\"errors\":${error_count}}"
    printf '%s\n' "$footer_json" | tee -a "${LOGFILE:-/dev/null}"
  fi

  if [ -n "$LOGFILE" ]; then
    cat >>"$LOGFILE" <<EOF

============================================================
$WATERMARK_LINE
End time: $END_TIME
EOF
    if [ "$error_count" -eq 0 ]; then
      printf '%s\n' 'Result: Completed without errors' >>"$LOGFILE"
    else
      printf '%s\n' "Result: Completed with ${error_count} error(s)" >>"$LOGFILE"
    fi
    printf '%s\n' "Reminder: run $0 --help for usage information" >>"$LOGFILE"
    printf '============================================================\n' >>"$LOGFILE"
  fi

  if [ "${STEALTH:-0}" -eq 0 ]; then
    printf '%s\n' "$WATERMARK_LINE"
    printf 'End time: %s\n' "$END_TIME"
    if [ "$error_count" -eq 0 ]; then printf '%s\n' 'Result: Completed without errors'; else printf '%s\n' "Result: Completed with ${error_count} error(s)"; fi
    printf 'Logfile: %s\n' "${LOGFILE:-(no logfile)}"
  fi
}

_on_exit() {
  rc=$?
  _write_audit_footer
  exit $rc
}
trap _on_exit EXIT INT TERM

# Global-priority re-exec (non-root: only nice)
if [ "$GLOBAL_PRIORITY" -eq 1 ] && [ -z "${OS_INFO_GLOBAL_PRIO_RERUN:-}" ]; then
  command -v nice >/dev/null 2>&1 && HAVE_NICE=1 || HAVE_NICE=0
  command -v ionice >/dev/null 2>&1 && HAVE_IONICE=1 || HAVE_IONICE=0
  export OS_INFO_GLOBAL_PRIO_RERUN=1
  if [ "$IS_ROOT" -eq 1 ] && [ "$HAVE_IONICE" -eq 1 ] && [ "$HAVE_NICE" -eq 1 ]; then
    exec ionice -c3 -n7 nice -n "${NICE_LEVEL}" "$0" "$@"
  elif [ "$HAVE_NICE" -eq 1 ]; then
    exec nice -n "${NICE_LEVEL}" "$0" "$@"
  fi
fi

# choose logfile; print path immediately (minimal console)
if _choose_logfile; then
  _logfile_only "Run as root: $( [ "$IS_ROOT" -eq 1 ] && printf 'yes' || printf 'no' )"
  if [ -n "$LOGFILE" ]; then
    printf '%s\n' "Logfile: $LOGFILE"
    _logfile_only "Logfile: $LOGFILE"
  fi
  _write_audit_header
else
  if [ "$CONSOLE_FORCE" -eq 1 ]; then
    LOGFILE=""
    _write_audit_header
    _status "WARNING: unable to create logfile; streaming to console because --console specified"
  else
    printf '%s\n' "FATAL: unable to create logfile in any of these locations: $TRY_DIRS" >&2
    exit 1
  fi
fi

_status "Note: running as non-root. Privileged features may be disabled or limited."
_logfile_only "Note: running as non-root. Privileged features are disabled or limited."

# -----------------------
# CORE CHECKS (full by default)
# -----------------------

_run_and_log "System Overview Start (date)" "date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%F %T'"

# Hostname: runs the same safe fallback again for per-check output
_run_and_log "Hostname" "hostname 2>/dev/null || ( [ -r /proc/sys/kernel/hostname ] && cat /proc/sys/kernel/hostname 2>/dev/null ) || uname -n 2>/dev/null || printf '%s\n' 'unknown'"

_run_and_log "Current User" "whoami || id -un || printf '%s\n' \"${USER:-unknown}\""

_try_or_record "lscpu" "CPU / lscpu" "lscpu -a" "grep 'model name' /proc/cpuinfo || head -n 5 /proc/cpuinfo"
_try_or_record "uname" "Kernel & uname details" "uname -a" "cat /proc/version 2>/dev/null || true"
_run_and_log "System Architecture" "uname -m || arch || printf '%s\n' 'unknown'"

if [ -r /etc/os-release ]; then
  _run_and_log "OS Release (/etc/os-release)" "cat /etc/os-release"
else
  _try_or_record "lsb_release" "OS Release (lsb_release)" "lsb_release -a" "printf '%s\n' 'no /etc/os-release, lsb_release missing'"
fi

_run_and_log "Environment variables (presence check)" "vars='HOME SHELL PATH USER LOGNAME TERM LANG EDITOR PAGER'; for v in \$vars; do val=\$(env | grep \"^\\${v}=\" | head -n1); [ -z \"\$val\" ] && printf '%s\n' \"\$v is UNSET\" || printf '%s\n' \"\$val\"; done"

_run_and_log "PATH cursory writable check" 'OLDIFS=$IFS; IFS=":"; total=0; writable=0; for p in $PATH; do total=$((total+1)); [ -z "$p" ] && p="(empty)"; if [ -d "$p" ] && [ -w "$p" ]; then printf "%s\n" "writable:$p"; writable=$((writable+1)); fi; if [ "$total" -ge 50 ]; then printf "%s\n" "...truncated"; break; fi; done; IFS=$OLDIFS; printf "%s\n" "PATH total=$total writable=$writable"'

_try_or_record "ip" "Networking: ip addr show" "ip a s" "ifconfig -a || printf '%s\n' 'no ip/ifconfig available'"
_try_or_record "iproute" "Networking: ip route" "ip r" "route -n || netstat -rn || printf '%s\n' 'no route/netstat available'"

_try_or_record "uptime" "System Uptime" "uptime" "awk '{printf(\"uptime_seconds=%s idle=%s\\n\", \$1, \$2)}' /proc/uptime || cat /proc/uptime"

## --- Added Commands --- ##
_run_and_log "Available shells" "cat /etc/shells"
_run_and_log "Users and their groups" "getent passwd | cut -d: -f1 | xargs -n1 groups"
_run_and_log "Superusers" "awk -F: '\$3 == 0 {print \$1}' /etc/passwd"
_run_and_log "Console users" "who"
_run_and_log "Logged users" "w"
_run_and_log "Password policy" "cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE'"
_run_and_log "PGP keys" "find \$HOME -type f -name '*.asc' -o -name '*.gpg' 2>/dev/null"
_run_and_log "Clipboard check" "command -v xclip >/dev/null 2>&1 && xclip -o || echo 'xclip not available'"

_run_and_log "Sudo and suid binaries" "find / -perm -4000 -type f 2>/dev/null | grep -E 'sudo|su'"
_run_and_log "NOPASSWD sudo entries" "grep -r 'NOPASSWD' /etc/sudoers* 2>/dev/null"
_run_and_log "setenv via sudo" "sudo -l | grep -i setenv"
_run_and_log "Bashenv preserved via sudo" "sudo -l | grep -i env_keep"
_run_and_log "Sudo less" "sudo -l | grep -i less"
_run_and_log "Commands runnable as non-root" "sudo -l | grep -v 'not allowed'"
_run_and_log "Security modules (AppArmor, Grsecurity, PaX, Execshield, SELinux, ASLR)" "lsmod | grep -Ei 'apparmor|grsecurity|pax|execshield|selinux' || dmesg | grep -Ei 'apparmor|grsecurity|pax|execshield|selinux' || echo 'No security modules detected'; echo 'ASLR:'; cat /proc/sys/kernel/randomize_va_space"

_run_and_log "Mounted drives" "mount | column -t"
_run_and_log "Unmounted drives" "lsblk -o NAME,MOUNTPOINT | grep -v '/mnt\\|/media'"
_run_and_log "Installed packages" "command -v dpkg >/dev/null 2>&1 && dpkg -l || command -v rpm >/dev/null 2>&1 && rpm -qa || echo 'No package manager detected'"
_run_and_log "Running services" "systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null"
_run_and_log "Writeable .service files" "find /etc/systemd/system /lib/systemd/system -type f -name '*.service' -writable 2>/dev/null"
_run_and_log "Writeable service binaries" "find /usr/lib/systemd /lib/systemd -type f -writable 2>/dev/null"
_run_and_log "Can write to systemd path" "[ -w /etc/systemd/system ] && echo 'Writable' || echo 'Not writable'"

_run_and_log "Timers" "systemctl list-timers --all 2>/dev/null"
_run_and_log "Writeable timers" "find /etc/systemd/system /lib/systemd/system -type f -name '*.timer' -writable 2>/dev/null"
_run_and_log "CRON visibility" "crontab -l 2>/dev/null || echo 'No crontab for current user'"
_run_and_log "Writeable CRON dirs" "find /etc/cron* -type f -writable 2>/dev/null"

_run_and_log "Sockets" "systemctl list-sockets 2>/dev/null"
_run_and_log ".socket writable" "find /etc/systemd/system /lib/systemd/system -type f -name '*.socket' -writable 2>/dev/null"
_run_and_log "Unix sockets" "find / -type s 2>/dev/null"
_run_and_log "HTTP sockets" "ss -ltnp | grep ':80\\|:443'"
_run_and_log "Docker sockets" "find /var/run -type s -name 'docker.sock' 2>/dev/null"

_run_and_log "Containerd" "ps aux | grep containerd | grep -v grep"
_run_and_log "RunC" "ps aux | grep runc | grep -v grep"
_run_and_log "D-Bus" "ps aux | grep dbus | grep -v grep"

_run_and_log "Network hosts" "cat /etc/hosts"
_run_and_log "DNS config" "cat /etc/resolv.conf"
_run_and_log "Network interfaces" "ip link show"
_run_and_log "Network neighbors" "ip neigh"
_run_and_log "Network services" "netstat -tuln 2>/dev/null || ss -tuln"
_run_and_log "Open ports" "ss -tuln | awk '{print \$5}' | grep -Eo '[0-9]+$' | sort -n | uniq"

# -----------------------
# PERMISSION & SECURITY CHECKS (added)
# -----------------------

# /root directory ownership and permissions
_run_and_log "Root Directory Permissions" \
"stat -c '%n %U %G %a %A' /root 2>/dev/null || echo '/root: stat failed or not present'"

# Warn if current user is in group that owns /root and /root is group searchable
_run_and_log "Root Directory Group Access Check" \
"owner=\$(stat -c %U /root 2>/dev/null); group=\$(stat -c %G /root 2>/dev/null); mode=\$(stat -c %a /root 2>/dev/null); \
echo \"/root owner=\$owner group=\$group mode=\$mode\"; \
if [ -n \"\$group\" ] && id -nG 2>/dev/null | grep -qw \"\$group\"; then \
  printf '%s\n' '⚠️  User is in group owning /root'; \
fi"

# Check global file permission
_run_and_log "World-writable directories (non-tmp)" \
"find / -xdev -type d -perm -0002 2>/dev/null | grep -vE '^/(proc|sys|dev|run|tmp)'"

# Check sudoers visibility
_run_and_log "Sudoers includes" "grep -E '^#includedir|#include' /etc/sudoers 2>/dev/null || echo 'No includes found'"

# Check file capability
_run_and_log "Files with capabilities (getcap -r /)" \
"command -v getcap >/dev/null 2>&1 && getcap -r / 2>/dev/null || echo 'getcap not available'"

# Check UID 0
_run_and_log "Extra UID 0 accounts" "awk -F: '\$3 == 0 {print \$1}' /etc/passwd | grep -v '^root$' || echo 'No extra UID 0 users'"

# Search readable files under /root that belong to root but group/world readable
_run_and_log "Readable Files under /root (potential leaks)" \
"find /root -maxdepth 2 -type f -printf '%M %u %g %p\n' 2>/dev/null | awk '\$2==\"root\" && (\$1 ~ /^-..r/ || \$1 ~ /^-.....r/){print \$0}'"

# Find private keys readable by group/other
_run_and_log "Readable Private SSH Keys" \
"find / -xdev -type f \\( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' \\) -perm /go=r 2>/dev/null | while read f; do ls -l \"\$f\"; done"

# Check permissions of any .ssh directories
_run_and_log "SSH Directory Permission Audit" \
"for d in /root /home/*; do [ -d \"\$d/.ssh\" ] && echo \"Checking \$d/.ssh\" && ls -ld \"\$d/.ssh\" \"\$d/.ssh\"/* 2>/dev/null; done"

# SSH daemon configuration summary
_run_and_log "SSHD Config Key Lines" \
"grep -E '^(Port|PermitRootLogin|ListenAddress)' /etc/ssh/sshd_config 2>/dev/null || echo 'sshd_config not readable'"

# Listening ports (unprivileged)
_run_and_log "Listening TCP Ports" \
"ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || echo 'No ss/netstat available'"

# Probe common ports for SSH banners
_run_and_log "SSH Banner Probe (localhost common ports)" \
"for p in 22 80 2222 443; do echo -n \"Port \$p: \"; timeout 1 bash -c 'echo | nc -w 1 localhost '\$p' 2>/dev/null' | head -n1; done"

# Show current user and groups (for context)
_run_and_log "Current User Group Memberships" "id -un; id -nG"


## --- END ADDED COMMANDS --- ##

if [ "$MINIMAL" -ne 1 ]; then
  if command -v ps >/dev/null 2>&1; then _run_and_log "Running Processes (ps aux)" "ps aux"; else _run_and_log "Running Processes (ps fallback)" "ps -ef || printf '%s\n' 'ps not available'"; fi
else
  _run_and_log "Running Processes (minimal)" "ps -eo pid,ppid,cmd --sort=-pid | head -n 10 || printf '%s\n' 'ps not available'"
fi

if [ "$MINIMAL" -ne 1 ]; then
  _run_and_log "Disk usage (df -h)" "df -h 2>/dev/null || df -k 2>/dev/null || printf '%s\n' 'df not available'"
  if command -v free >/dev/null 2>&1; then _run_and_log "Memory (free -h)" "free -h"; else _run_and_log "Memory (/proc/meminfo)" "head -n 12 /proc/meminfo || printf '%s\n' 'meminfo not available'"; fi
  _try_or_record "lscpu2" "CPU detailed" "lscpu" "grep -m1 'model name' /proc/cpuinfo || printf '%s\n' 'cpuinfo not available'"
  _run_and_log "Mounted filesystems (/proc/mounts)" "cut -d' ' -f1-3 /proc/mounts | head -n 60 || mount | head -n 60"
else
  _run_and_log "Disk usage (minimal: /)" "df -h / 2>/dev/null || printf '%s\n' 'df not available'"
  _run_and_log "Memory (minimal: MemTotal)" "grep '^MemTotal' /proc/meminfo || printf '%s\n' 'meminfo not available'"
  _run_and_log "CPU (minimal: count)" "grep -c '^processor' /proc/cpuinfo || printf '%s\n' 'cpuinfo not available'"
fi

_run_and_log "Package manager detection (light)" "if command -v dpkg >/dev/null 2>&1; then printf '%s\n' 'dpkg detected'; elif command -v rpm >/dev/null 2>&1; then printf '%s\n' 'rpm detected'; elif command -v apk >/dev/null 2>&1; then printf '%s\n' 'apk detected'; elif command -v pacman >/dev/null 2>&1; then printf '%s\n' 'pacman detected'; else printf '%s\n' 'no common package manager detected'; fi"

if command -v sudo >/dev/null 2>&1; then _run_and_log "Sudo version (first 40 lines)" "sudo -V 2>&1 | head -n 40"; else _logfile_only "Sudo: not installed"; fi

if command -v dmesg >/dev/null 2>&1; then
  _run_and_log "dmesg (recent)" "dmesg | tail -n 500 || true"
  _run_and_log "dmesg: signature heuristics" "dmesg | tail -n 500 | awk 'BEGIN{IGNORECASE=1} /secure boot|mok|ima|evm|signature|signed/ {print NR\":\"\$0}' | head -n 200 || printf '%s\n' 'no signature keywords'"
else
  _logfile_only "dmesg: command not available or restricted"
fi

command -v vmstat >/dev/null 2>&1 && _run_and_log "vmstat -s" "vmstat -s" || _logfile_only "vmstat not available"
command -v iostat >/dev/null 2>&1 && _run_and_log "iostat -x -c 1 2 (truncated)" "iostat -x -c 1 2 | head -n 200" || _logfile_only "iostat not available"
if command -v top >/dev/null 2>&1; then _run_and_log "top snapshot" "top -b -n 1 | head -n 200"; else _run_and_log "top fallback" "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 20"; fi

command -v cpufreq-info >/dev/null 2>&1 && _run_and_log "cpufreq-info" "cpufreq-info | head -n 80" || _logfile_only "cpufreq-info not available"

if command -v lpstat >/dev/null 2>&1; then _run_and_log "Printers (lpstat -p -d)" "lpstat -p -d"; elif [ -r /etc/printcap ]; then _run_and_log "printcap" "head -n 40 /etc/printcap"; else _logfile_only "Printers: none found"; fi
command -v pgrep >/dev/null 2>&1 && pgrep -x cupsd >/dev/null 2>&1 && _run_and_log "CUPS" "ps -o pid,cmd -C cupsd" || _logfile_only "CUPS: cupsd not running or pgrep missing"

_run_and_log "Host date (local)" "date '+%Y-%m-%d %H:%M:%S %Z'"
_run_and_log "Host date (UTC)" "date -u '+%Y-%m-%d %H:%M:%S UTC'"
if command -v curl >/dev/null 2>&1; then _run_and_log "HTTP Date header (curl) from https://example.com" "curl -sI --max-time 6 https://example.com | awk '/^Date:/ {sub(/^Date: /,\"\"); print \$0; exit}' || printf '%s\n' 'no remote date'"; else _logfile_only "curl not available to fetch remote date"; fi
_run_and_log "Time sync tools (timedatectl / ntpstat / chronyc)" "if command -v timedatectl >/dev/null 2>&1; then timedatectl status; fi; if command -v ntpstat >/dev/null 2>&1; then ntpstat || true; fi; if command -v chronyc >/dev/null 2>&1; then chronyc tracking || true; fi"

# end
_status "System overview end date: $(date '+%Y-%m-%d %H:%M:%S')"
_logfile_only ""
_logfile_only "System overview end date: $(date '+%Y-%m-%d %H:%M:%S')"
_logfile_only "END WATERMARK: $WATERMARK_LINE"

exit 0
