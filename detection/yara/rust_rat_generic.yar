/*
 * rust_rat_generic.yar
 * Generic Rust RAT indicators — not oxide-specific.
 * Designed for future use with oxide-loader (S5) and oxide-stealer (S6)
 * once those components are built.
 *
 * These patterns identify Rust-based RATs using tokio async runtime,
 * rustls TLS, and AES-GCM encryption — a common modern RAT stack.
 *
 * Low confidence standalone; high confidence when combined with
 * behavioral indicators or oxide_implant.yar.
 *
 * MITRE ATT&CK: T1071.001, T1573.001
 */

rule rust_rat_generic_tokio_tls {
    meta:
        description     = "Rust binary using tokio + rustls stack — possible RAT"
        author          = "diemoeve"
        date            = "2026-04-10"
        confidence      = "low — generic indicator, confirm with behavioral data"

    strings:
        // Rust runtime panic string — present in all non-stripped Rust binaries
        $rust_panic     = "panicked at" ascii

        // rustls TLS artifacts
        $rustls1        = "PinnedCertVerifier" ascii
        $rustls2        = "Tls12NotOffered" ascii
        $rustls3        = "ServerCertVerified" ascii
        $rustls4        = "rustls::client" ascii

        // Generic C2 behavior
        $c2_connect     = "TCP connect failed" ascii
        $c2_tls         = "TLS handshake failed" ascii
        $c2_replay      = "sequence number replay" ascii

    condition:
        (
            uint32(0) == 0x464c457f or  // ELF
            uint16(0) == 0x5a4d or       // PE
            uint32(0) == 0xfeedfacf or   // Mach-O 64-bit
            uint32(0) == 0xfeedface      // Mach-O 32-bit
        ) and
        filesize < 30MB and
        $rust_panic and
        2 of ($rustls*) and
        ($c2_connect or $c2_tls or $c2_replay)
}

rule rust_rat_aes_gcm_transport {
    meta:
        description     = "Rust binary with AES-GCM over TLS transport — double-encrypted C2 pattern"
        author          = "diemoeve"
        date            = "2026-04-10"
        confidence      = "medium — specific pattern, confirm with network data"

    strings:
        $rust_panic     = "panicked at" ascii

        // Double-encryption indicators: AES-GCM errors + TLS errors in same binary
        $aes_short      = "data too short for decryption" ascii
        $aes_fail       = "decryption failed" ascii
        $replay         = "replay detected" ascii

        $tls_fail       = "TLS handshake failed" ascii
        $tls_cert       = "PinnedCertVerifier" ascii

    condition:
        (
            uint32(0) == 0x464c457f or
            uint16(0) == 0x5a4d or
            uint32(0) == 0xfeedfacf or
            uint32(0) == 0xfeedface
        ) and
        filesize < 30MB and
        $rust_panic and
        (1 of ($aes*) or $replay) and
        ($tls_fail or $tls_cert)
}
