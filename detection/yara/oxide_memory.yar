/*
 * oxide_memory.yar
 * Memory scanning rules for the oxide RAT implant.
 * No file header requirements — suitable for in-memory scanning.
 *
 * Usage:
 *   sudo yara -p PID detection/yara/oxide_memory.yar       # live process (root required)
 *   yara detection/yara/oxide_memory.yar core.PID          # memory dump via gcore
 *   yara detection/yara/oxide_memory.yar dump.mem          # full memory dump
 *
 * Note: `yara --scan-proc` does NOT exist. Use -p PID.
 *
 * MITRE ATT&CK: T1071.001, T1573.001
 */

rule oxide_memory_core {
    meta:
        description     = "Oxide RAT implant in process memory — core indicators"
        author          = "diemoeve"
        date            = "2026-04-10"

    strings:
        // C2 SNI — present in all builds, survives in heap/stack
        $sni            = "oxide-c2" ascii

        // Logging strings — present in rodata
        $log1           = "[*] Connecting to" ascii
        $log2           = "[+] TLS handshake complete" ascii
        $log3           = "[+] Persistence installed:" ascii

        // Command handler names — registered in dispatcher
        $cmd_shell      = "shell" ascii fullword
        $cmd_file_list  = "file_list" ascii
        $cmd_file_dl    = "file_download" ascii
        $cmd_screenshot = "screenshot" ascii fullword
        $cmd_proc_list  = "process_list" ascii
        $cmd_persist_s  = "persist_status" ascii
        $cmd_persist_r  = "persist_remove" ascii

        // Persistence path — written to stable path on install
        $pers_path      = ".local/share/oxide/oxide-update" ascii

        // Screenshot temp path
        $screenshot_path = "/tmp/.oxide_screenshot.png" ascii

        // Crypto error strings
        // Packet type strings — appear in JSON data structures in memory
        $pkt_checkin    = "checkin" ascii fullword
        $pkt_heartbeat  = "heartbeat" ascii fullword
        $pkt_command    = "command" ascii fullword
        $pkt_response   = "response" ascii fullword

    condition:
        // No magic check — works against any memory region
        filesize < 100MB and
        (
            ($sni and 2 of ($cmd*)) or
            ($sni and 1 of ($log*)) or
            (3 of ($cmd*) and 1 of ($pkt*)) or
            ($pers_path and $sni) or
            ($screenshot_path and 2 of ($cmd*))
        )
}

rule oxide_memory_active_session {
    meta:
        description     = "Oxide RAT with active C2 session — checkin data in memory"
        author          = "diemoeve"
        date            = "2026-04-10"

    strings:
        // JSON field names from check-in packet (present in heap during active session)
        $field_hwid     = "\"hwid\"" ascii
        $field_hostname = "\"hostname\"" ascii
        $field_persist  = "\"persistence\"" ascii
        $field_version  = "\"version\"" ascii

        // Session identifiers
        $pkt_checkin    = "checkin" ascii fullword
        $sni            = "oxide-c2" ascii

    condition:
        filesize < 100MB and
        $sni and
        $pkt_checkin and
        2 of ($field*)
}
