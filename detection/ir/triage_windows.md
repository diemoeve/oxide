# Windows Host Triage — Oxide RAT

All paths and registry keys verified against oxide source code (S1-S4.5).
Stable binary path (persistence/mod.rs:75): `AppData\Roaming\Microsoft\Update\oxide.exe`

---

## Quick Triage (5 minutes)

```powershell
# 1. Check registry Run key (persistence/windows/registry.rs:5-6)
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select OxideSystemUpdate

# 2. Check scheduled task (persistence/windows/scheduled_task.rs)
schtasks /query /fo LIST /tn OxideSystemUpdate 2>&1

# 3. Check for binary at stable path
Test-Path "$env:APPDATA\Roaming\Microsoft\Update\oxide.exe"
# NOTE: actual path is AppData\Roaming\Microsoft\Update\oxide.exe
Get-Item "$env:APPDATA\Roaming\Microsoft\Update\oxide.exe" -ErrorAction SilentlyContinue

# 4. Check outbound connections on port 4444
netstat -ano | findstr :4444
```

---

## Persistence Investigation

### Registry Run Key (T1547.001)
```powershell
# Check for OxideSystemUpdate value
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty $runKey | Select-Object OxideSystemUpdate

# Full registry key dump
Get-ItemProperty $runKey
```
Sysmon EID 13 (RegistrySet) will have captured the creation.

### Scheduled Task (T1053.005)
```cmd
schtasks /query /fo LIST /tn OxideSystemUpdate
schtasks /query /xml /tn OxideSystemUpdate
```
Expected properties:
- Task name: `OxideSystemUpdate`
- Trigger: `OnLogon` (user logon — not SYSTEM level)
- Action: `%APPDATA%\Roaming\Microsoft\Update\oxide.exe`
- No `/rl highest` flag (runs as current user, not elevated)

---

## Binary Investigation

```powershell
# File details
$path = "$env:APPDATA\Roaming\Microsoft\Update\oxide.exe"
Get-Item $path | Select-Object FullName, Length, CreationTime, LastWriteTime

# SHA-256 hash
Get-FileHash $path -Algorithm SHA256

# Check for digital signature (Rust binaries are typically unsigned)
Get-AuthenticodeSignature $path
```

---

## Network Investigation

```cmd
# Active connections (colon prefix prevents matching PID numbers)
netstat -ano | findstr :4444

# Map PID to process
# (Replace XXXX with PID from netstat output)
tasklist /FI "PID eq XXXX"

# All connections by process name
# PowerShell
Get-NetTCPConnection | Where-Object {$_.RemotePort -eq 4444} | 
  Select-Object LocalAddress, RemoteAddress, RemotePort, State, OwningProcess
```

---

## Event Log Investigation

```powershell
# Sysmon EID 13 — Registry value set for OxideSystemUpdate
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 13
} | Where-Object { $_.Message -match 'OxideSystemUpdate' } |
  Select-Object TimeCreated, Message | Format-List

# Sysmon EID 1 — schtasks.exe creating OxideSystemUpdate task
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 1
} | Where-Object { $_.Message -match 'OxideSystemUpdate' } |
  Select-Object TimeCreated, Message | Format-List

# Sysmon EID 3 — Outbound network connection to port 4444
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 3
} | Where-Object { $_.Message -match ':4444' } |
  Select-Object TimeCreated, Message | Format-List
```

---

## Containment Commands

```powershell
# Kill implant process (replace PID)
Stop-Process -Id XXXX -Force

# Remove registry persistence
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OxideSystemUpdate"

# Remove scheduled task
schtasks /delete /tn OxideSystemUpdate /f

# Remove binary
Remove-Item "$env:APPDATA\Roaming\Microsoft\Update\oxide.exe" -Force
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Indicator |
|-----------|-----|-----------|
| Registry Run key | T1547.001 | `OxideSystemUpdate` value |
| Scheduled task | T1053.005 | `OxideSystemUpdate` task, onlogon trigger |
| C2 beaconing | T1071.001 | Port 4444 outbound TLS |
