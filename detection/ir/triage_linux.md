# Linux Host Triage — Oxide RAT

All paths and commands verified against oxide source code (S1-S4.5).

---

## Quick Triage (5 minutes)

```bash
# 1. Check for oxide binary at stable path (persistence/mod.rs:79)
ls -la ~/.local/share/oxide/oxide-update

# 2. Check running processes
ps aux | grep oxide-update

# 3. Check outbound connections on C2 port (default 4444)
ss -tnp | grep 4444

# 4. Check for screenshot artifact
ls -la /tmp/.oxide_screenshot.png
```

If any of the above return results, proceed to full investigation.

---

## Persistence Investigation

### Cron (T1053.003)
```bash
# Check current user crontab for @reboot entry
crontab -l | grep '@reboot.*oxide'

# Check root crontab (if accessible)
sudo -A crontab -l 2>/dev/null | grep '@reboot.*oxide'
```
Artifact: `@reboot /home/<user>/.local/share/oxide/oxide-update`

### Systemd User Service (T1543.002)
```bash
# Check if service file exists
ls -la ~/.config/systemd/user/oxide-update.service

# Check if service is ENABLED (ls only checks existence — must use systemctl)
systemctl --user is-enabled oxide-update.service

# Check service status
systemctl --user status oxide-update.service

# View full service file
cat ~/.config/systemd/user/oxide-update.service
```
Expected content:
```
[Unit]
Description=System Update Service

[Service]
ExecStart=~/.local/share/oxide/oxide-update
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
```

### Bash Profile (T1546.004)
```bash
# Search for marker in profile files
grep -n '# oxide-persistence' ~/.bashrc ~/.bash_profile 2>/dev/null

# Show context around marker
grep -A1 '# oxide-persistence' ~/.bashrc ~/.bash_profile 2>/dev/null
```
Artifact: `# oxide-persistence` followed by `<path>/oxide-update &`

---

## Binary Investigation

```bash
# File details
file ~/.local/share/oxide/oxide-update
ls -la ~/.local/share/oxide/
sha256sum ~/.local/share/oxide/oxide-update

# Check binary strings for version
strings ~/.local/share/oxide/oxide-update | grep -E "0\.[0-9]+\.[0-9]+"

# Check for linked libraries (oxide is dynamically linked per ELF output)
ldd ~/.local/share/oxide/oxide-update
```

---

## Network Investigation

```bash
# Active connections on port 4444
ss -tnp | grep 4444

# All connections by oxide process (replace PID)
lsof -p PID | grep ESTABLISHED

# Check listening ports (panel may be running locally)
ss -tlnp | grep 4444

# Recent DNS queries (requires systemd-resolved or dnsmasq logs)
journalctl -u systemd-resolved --since "1 hour ago" 2>/dev/null | grep -i oxide

# Check for C2 host in /etc/hosts (manual config)
grep -i oxide /etc/hosts
```

---

## Screenshot Artifacts

```bash
# Check for recent screenshot
ls -la /tmp/.oxide_screenshot.png

# Check /tmp for related artifacts
ls -lat /tmp/ | head -20
```

---

## Log Sources

| Source | Command | What to look for |
|--------|---------|-----------------|
| auditd | `ausearch -i -ts recent -k cred_access` | File access patterns |
| systemd journal | `journalctl -xe --since "2 hours ago"` | Service start events |
| auth.log | `grep -i oxide /var/log/auth.log` | Auth events |
| syslog | `grep -i oxide /var/log/syslog` | System events |
| bash history | `grep oxide ~/.bash_history` | Manual commands |

---

## Containment Commands

```bash
# Kill implant process
kill -9 $(pgrep oxide-update)

# Remove persistence (cron)
crontab -l | grep -v 'oxide' | crontab -

# Remove persistence (systemd)
systemctl --user stop oxide-update.service 2>/dev/null
systemctl --user disable oxide-update.service 2>/dev/null
rm ~/.config/systemd/user/oxide-update.service
systemctl --user daemon-reload

# Remove persistence (bash profile)
sed -i '/# oxide-persistence/,+1d' ~/.bashrc ~/.bash_profile

# Remove binary
rm -f ~/.local/share/oxide/oxide-update
rmdir ~/.local/share/oxide/ 2>/dev/null
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Indicator |
|-----------|-----|-----------|
| Cron persistence | T1053.003 | `@reboot` in crontab |
| Systemd persistence | T1543.002 | `oxide-update.service` |
| Bash profile persistence | T1546.004 | `# oxide-persistence` in .bashrc |
| Remote shell | T1059.004 | `/bin/sh -c` child processes |
| Screen capture | T1113 | `/tmp/.oxide_screenshot.png` |
| C2 beaconing | T1071.001 | Port 4444 outbound TLS |
