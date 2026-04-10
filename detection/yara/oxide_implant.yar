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

private rule is_elf {
    condition:
        uint32(0) == 0x464c457f
}

private rule is_pe {
    condition:
        uint16(0) == 0x5a4d
}

private rule is_macho {
    condition:
        uint32(0) == 0xfeedfacf or
        uint32(0) == 0xfeedface
}

rule oxide_implant_linux {
    meta:
        description = "Oxide RAT implant — Linux ELF binary"
        author      = "diemoeve"
        date        = "2026-04-10"

    strings:
        $sni            = "oxide-c2" ascii
        $log1           = "[*] Connecting to" ascii
        $log2           = "[+] TLS handshake complete" ascii
        $log3           = "[+] Persistence installed:" ascii
        $cmd1           = "file_list" ascii
        $cmd2           = "file_download" ascii
        $cmd3           = "screenshot" ascii fullword
        $cmd4           = "process_list" ascii
        $cmd5           = "persist_status" ascii
        $cmd6           = "persist_remove" ascii
        $pers1          = "# oxide-persistence" ascii
        $pers2          = "oxide-update.service" ascii
        $pers3          = ".local/share/oxide/oxide-update" ascii
        $tmpfile        = "/tmp/.oxide_screenshot.png" ascii
        $crypto1        = "data too short for decryption" ascii
        $av1            = "falcon-sensor" ascii
        $av2            = "elastic-agent" ascii
        $svc            = "Description=System Update Service" ascii

    condition:
        is_elf and filesize < 20MB and
        $sni and
        (
            2 of ($log*) or
            3 of ($cmd*) or
            2 of ($pers*) or
            ($tmpfile and $crypto1) or
            ($av1 and $av2 and 1 of ($cmd*)) or
            ($svc and 1 of ($pers*))
        )
}

rule oxide_implant_windows {
    meta:
        description = "Oxide RAT implant — Windows PE binary"
        author      = "diemoeve"
        date        = "2026-04-10"

    strings:
        $reg_value  = "OxideSystemUpdate" ascii wide
        $win_path   = "Microsoft\\Update\\oxide.exe" ascii wide
        $sni        = "oxide-c2" ascii
        $log1       = "[+] TLS handshake complete" ascii
        $cmd1       = "file_list" ascii
        $cmd2       = "file_download" ascii
        $cmd3       = "screenshot" ascii fullword
        $cmd4       = "process_list" ascii
        $crypto1    = "data too short for decryption" ascii

    condition:
        is_pe and filesize < 20MB and
        (
            ($reg_value and $sni) or
            ($win_path and 2 of ($cmd*)) or
            ($reg_value and 1 of ($cmd*) and $crypto1) or
            ($sni and 3 of ($cmd*) and $log1)
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
        is_macho and filesize < 20MB and
        (
            ($label and $sni) or
            ($la_path and $macos_path and 1 of ($cmd*)) or
            ($label and $log1 and $crypto1) or
            ($sni and 2 of ($cmd*) and $macos_path)
        )
}
