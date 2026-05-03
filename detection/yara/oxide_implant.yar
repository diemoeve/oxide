/*
 * oxide_implant.yar
 * Detection rules for the oxide RAT implant binary.
 *
 * All strings verified present in compiled binary via strings(1).
 * Platform notes:
 *   Linux ELF: cross-platform + linux-specific identifiers
 *   Windows PE: OxideSystemUpdate only in Windows build (cfg-guarded)
 *   macOS Mach-O: com.oxide.update only in macOS build (cfg-guarded)
 *
 * MITRE ATT&CK: T1059.004, T1071.001, T1573.001
 */

rule oxide_implant_linux {
    meta:
        description = "Oxide RAT implant — Linux ELF binary (post-S12)"
        author      = "diemoeve"
        date        = "2026-04-11"

    strings:
        $cmd1       = "file_list" ascii fullword
        $cmd2       = "file_download" ascii fullword
        $cmd3       = "process_list" ascii fullword
        $cmd4       = "persist_status" ascii fullword
        $cmd5       = "persist_remove" ascii fullword
        $pers1      = "user-autostart" ascii
        $pers2      = "sys-update.service" ascii
        $pers3      = ".sysmon/sys-update" ascii
        $crypto1    = "data too short for decryption" ascii
        $av1        = "falcon-sensor" ascii
        $av2        = "elastic-agent" ascii
        $svc        = "Description=System Update Service" ascii
        $beacon_ep  = "/c2/beacon" ascii

    condition:
        uint32(0) == 0x464c457f 
        and filesize < 20MB 
        and (
            3 of ($cmd*) or
            2 of ($pers*) or
            ($crypto1 and $beacon_ep and 2 of ($cmd*)) or
            ($av1 and $av2 and 1 of ($cmd*)) or
            ($svc and 1 of ($pers*))
        )
}

rule oxide_implant_windows {
    meta:
        description = "Oxide RAT implant — Windows PE binary (post-S12 obfuscated)"
        author      = "diemoeve"
        date        = "2026-04-11"
        note        = "Post-S12: string-based detections removed. Relies on runtime-required command dispatch strings, crypto error, and HTTP C2 endpoint."

    strings:
        // Command dispatch strings — not obfuscated (must be readable at runtime)
        $cmd1       = "file_list" ascii fullword
        $cmd2       = "file_download" ascii fullword
        $cmd3       = "process_list" ascii fullword
        $cmd4       = "persist_status" ascii fullword
        $cmd5       = "persist_remove" ascii fullword
        $cmd6       = "steal" ascii fullword

        // Crypto error from oxide-shared — not obfuscated
        $crypto1    = "data too short for decryption" ascii

        // HTTP C2 endpoint — runtime required for http-transport builds
        $beacon_ep  = "/c2/beacon" ascii

        // Packet field names — serde_json, not obfuscated
        $pkt1       = "session_id" ascii
        $pkt2       = "command_type" ascii

    condition:
        uint16(0) == 0x5a4d
        and filesize < 20MB 
        and (
            (4 of ($cmd*) and $crypto1) or
            ($beacon_ep and 3 of ($cmd*)) or
            ($beacon_ep and $crypto1 and $pkt1 and $pkt2) or
            (5 of ($cmd*) and $pkt1)
        )
}

rule oxide_implant_macos {
    meta:
        description = "Oxide RAT implant — macOS Mach-O binary"
        author      = "diemoeve"
        date        = "2026-04-10"

    strings:
        $label      = "com.oxide.update" ascii
        $la_path    = "Library/LaunchAgents" ascii
        $macos_path = "Application Support/oxide/oxide" ascii
        $sni        = "oxide-c2" ascii
        $log1       = "[+] TLS handshake complete" ascii
        $cmd1       = "file_list" ascii
        $cmd2       = "file_download" ascii
        $cmd3       = "process_list" ascii
        $crypto1    = "data too short for decryption" ascii

    condition:
        ( 
            uint32(0) == 0xfeedfacf or
            uint32(0) == 0xfeedface 
        ) 
        and filesize < 20MB 
        and (
            ($label and $sni) or
            ($la_path and $macos_path and 1 of ($cmd*)) or
            ($label and $log1 and $crypto1) or
            ($sni and 2 of ($cmd*) and $macos_path)
        )
}
