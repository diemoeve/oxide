# Memory Analysis — Oxide RAT

## Overview

Oxide is a compiled Rust binary. It loads into process memory at runtime.
Key memory artifacts:
- Heap: JSON packet data, check-in payload fields, command strings
- Stack: Function arguments, temporary buffers
- .rodata/.data: String literals compiled into the binary (all verified strings)

---

## Memory Acquisition

### Linux

```bash
# gcore: creates core file from running process (preferred method)
# /proc/PID/mem cannot be read directly by strings or YARA (permission denied)
sudo gcore -o /tmp/oxide_dump PID
# Produces: /tmp/oxide_dump.PID

# Alternative: dd from /proc maps (requires root, complex)
# Read /proc/PID/maps to find memory ranges, then dd each range
# gcore is simpler and more reliable

# List memory regions
cat /proc/PID/maps
```

### Windows

```powershell
# ProcDump (Sysinternals)
procdump.exe -ma PID oxide_dump.dmp

# Task Manager: right-click process → Create dump file

# WinPmem for full memory image
winpmem_mini_x64.exe output.raw
```

---

## YARA Memory Scanning

```bash
# Scan live process (requires root; -p is the correct flag)
# --scan-proc does NOT exist in YARA
sudo yara -p PID detection/yara/oxide_memory.yar

# Scan memory dump (gcore output)
yara detection/yara/oxide_memory.yar /tmp/oxide_dump.PID

# Scan with all three rule files
for rule in detection/yara/*.yar; do
    echo "--- $rule ---"
    yara "$rule" /tmp/oxide_dump.PID
done
```

---

## String Extraction

```bash
# Extract strings from gcore dump
# strings works on dump files; does NOT work on /proc/PID/mem
strings /tmp/oxide_dump.PID | grep -E "(oxide|checkin|heartbeat|persist)"

# Filter for JSON packet data (present during active C2 session)
strings /tmp/oxide_dump.PID | grep -E '"(hwid|hostname|os|persistence)"'

# Find C2 host in config data
strings /tmp/oxide_dump.PID | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

# Find command handler names
strings /tmp/oxide_dump.PID | grep -E "^(shell|file_list|file_download|screenshot|process_list|persist_status|persist_remove)$"
```

---

## Key Memory Indicators

After a check-in, these JSON field names should be present in heap memory:

```
"hwid"           - hardware ID (SHA-256 of /etc/machine-id)
"hostname"       - system hostname
"os"             - "linux" | "windows" | "darwin"
"arch"           - "x86_64" | "aarch64"
"username"       - current user
"privileges"     - "user" | "admin"
"av"             - detected AV/EDR names
"exe_path"       - path to implant binary
"version"        - "0.1.0"
"persistence"    - array of persistence status objects
"checkin"        - packet type string
"heartbeat"      - packet type string (during active session)
```

These field names survive Rust optimizations and appear as string literals
in .rodata section of the compiled binary.

---

## Volatility (Windows Dump)

```bash
# Identify profile
vol -f dump.mem imageinfo

# List processes
vol -f dump.mem windows.pslist

# List process command lines
vol -f dump.mem windows.cmdline

# Scan for strings (yarascan plugin)
vol -f dump.mem yarascan --yara-file detection/yara/oxide_memory.yar

# Network connections at time of dump
vol -f dump.mem windows.netscan | grep 4444

# DLL list for injection detection
vol -f dump.mem windows.dlllist --pid PID
```

---

## Volatile Data to Capture First

Before killing the process or rebooting, capture:

1. Full process memory (`gcore PID`)
2. Network connections (`ss -tnp` / `netstat -ano`)
3. Open file descriptors (`lsof -p PID`)
4. Process environment (`cat /proc/PID/environ | tr '\0' '\n'`)
5. Process memory maps (`cat /proc/PID/maps`)
6. TLS session keys if SSLKEYLOGFILE was set

This order matters: network connections and environment may be lost after process termination.
