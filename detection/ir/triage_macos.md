# macOS Host Triage — Oxide RAT

All paths verified against oxide source code (S1-S4.5).
Stable binary path (persistence/mod.rs:77): `~/Library/Application Support/oxide/oxide`

---

## Quick Triage (5 minutes)

```bash
# 1. Check LaunchAgent plist (persistence/darwin/launch_agent.rs:7)
ls -la ~/Library/LaunchAgents/com.oxide.update.plist

# 2. Check binary at stable path
ls -la ~/Library/Application\ Support/oxide/oxide

# 3. Check running processes
ps aux | grep -E "oxide" | grep -v grep

# 4. Check LoginItems
osascript -e 'tell application "System Events" to get name of every login item'
```

---

## Persistence Investigation

### LaunchAgent (T1543.001)

```bash
# Check plist existence
cat ~/Library/LaunchAgents/com.oxide.update.plist
```

Expected plist content:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.oxide.update</string>
  <key>ProgramArguments</key><array><string>/path/to/oxide</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
</dict></plist>
```

```bash
# Check if LaunchAgent is currently loaded
launchctl list | grep com.oxide.update

# Check launchctl print output
launchctl print gui/$(id -u)/com.oxide.update 2>/dev/null
```

**Note:** LaunchAgents only activate on GUI login, not bare system reboot.

### LoginItem (T1547.015)

```bash
# List all LoginItems (AppleScript)
osascript -e 'tell application "System Events" to get name of every login item'
osascript -e 'tell application "System Events" to get path of every login item'

# Check BTM database (macOS 13+ — Behind The Mac)
# LoginItems registered via osascript appear in BTM
sfltool dumpbtm 2>/dev/null | grep -i oxide
```

LoginItem name is `oxide` (set in AppleScript: `name:"oxide"`).
On macOS 13+ (Ventura), system shows a notification when LoginItem is registered.

---

## Binary Investigation

```bash
# File details
file ~/Library/Application\ Support/oxide/oxide
ls -la ~/Library/Application\ Support/oxide/oxide
shasum -a 256 ~/Library/Application\ Support/oxide/oxide

# Check code signing (Rust binaries are typically ad-hoc signed)
codesign -vvv ~/Library/Application\ Support/oxide/oxide 2>&1

# Check Gatekeeper status
spctl --assess -vv ~/Library/Application\ Support/oxide/oxide 2>&1
```

---

## Network Investigation

```bash
# Connections on port 4444
lsof -i :4444

# All connections by oxide process
lsof -p PID -i

# Network connections (macOS netstat)
netstat -anp tcp | grep 4444
```

---

## Log Investigation

```bash
# Unified Log — LaunchAgent events
log show --predicate 'subsystem == "com.apple.launchd"' --last 2h 2>/dev/null | grep -i oxide

# Unified Log — process creation
log show --predicate 'eventMessage contains "oxide"' --last 2h 2>/dev/null

# FSEvents — file creation in LaunchAgents directory
log show --predicate 'subsystem == "com.apple.fsevents"' \
  --last 2h 2>/dev/null | grep LaunchAgents

# Console log for BTM notifications (macOS 13+)
log show --predicate 'subsystem == "com.apple.backgroundtaskmanagement"' \
  --last 2h 2>/dev/null | grep -i oxide
```

---

## Containment Commands

```bash
# Unload LaunchAgent
launchctl bootout gui/$(id -u)/com.oxide.update 2>/dev/null

# Remove plist
rm ~/Library/LaunchAgents/com.oxide.update.plist

# Remove LoginItem
osascript -e 'tell application "System Events" to delete login item "oxide"'

# Kill process
pkill -f oxide

# Remove binary
rm -rf ~/Library/Application\ Support/oxide/
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Indicator |
|-----------|-----|-----------|
| LaunchAgent | T1543.001 | `com.oxide.update.plist` |
| LoginItem | T1547.015 | `oxide` login item |
| C2 beaconing | T1071.001 | Port 4444 outbound TLS |
