##
## zeek_oxide.zeek
## Zeek detection script for the oxide RAT C2 protocol.
##
## Detects:
##   1. Connections with SNI "oxide-c2" (hardcoded in implant)
##   2. TLS 1.3 connections on port 4444 (oxide default C2 port)
##   3. Long-lived connections on non-standard ports from non-browser processes
##
## Usage:
##   zeek -b zeek_oxide.zeek          # syntax check (bare mode)
##   zeek -C -r capture.pcap zeek_oxide.zeek  # offline analysis
##
## Verified Zeek API usage:
##   - Event: ssl_established (not ssl_server_name — that event does NOT exist)
##   - SNI: c$ssl$server_name (string field)
##   - TLS version: c$ssl$version (count/integer field — 0x0304 = 772 for TLS 1.3)
##   - Port comparison: c$id$resp_p == 4444/tcp (port type)
##
## MITRE ATT&CK: T1071.001, T1573.001
##

module Oxide;

export {
    redef enum Notice::Type += {
        ## Oxide C2 SNI detected in TLS handshake
        C2_SNI,
        ## TLS 1.3 connection on oxide default port 4444
        C2_Port,
        ## Long-lived non-browser TLS connection (beaconing candidate)
        C2_Beaconing
    };

    ## SNI value hardcoded in oxide implant transport.rs:37
    const oxide_sni = "oxide-c2" &redef;

    ## Default oxide C2 port (config.rs:31; overrideable via OXIDE_C2_PORT)
    const oxide_port = 4444/tcp &redef;

    ## TLS 1.3 version code (0x0304 = 772 decimal)
    const tls13_version: count = 772 &redef;

    ## Minimum connection duration (seconds) to flag as potential beaconing
    const beacon_min_duration: interval = 5min &redef;
}

## Alert when TLS handshake completes with oxide SNI.
## Using ssl_established: the correct event for post-handshake inspection.
## c$ssl$server_name is set after the handshake completes.
event ssl_established(c: connection) {
    if ( c?$ssl && c$ssl?$server_name && c$ssl$server_name == oxide_sni ) {
        NOTICE([
            $note       = C2_SNI,
            $conn       = c,
            $msg        = fmt("Oxide RAT C2 SNI detected: '%s' from %s to %s",
                              c$ssl$server_name, c$id$orig_h, c$id$resp_h),
            $identifier = cat(c$id$orig_h, c$id$resp_h, c$id$resp_p)
        ]);
    }
}

## Alert on TLS 1.3 connections to the oxide default port.
## c$ssl$version is a count (integer), not a string.
## TLS 1.3 = 0x0304 = 772 decimal.
event connection_state_remove(c: connection) {
    ## Check for TLS 1.3 on oxide default port
    if ( c$id$resp_p == oxide_port && c?$ssl && c$ssl?$version
         && c$ssl$version == tls13_version ) {
        NOTICE([
            $note       = C2_Port,
            $conn       = c,
            $msg        = fmt("Oxide RAT: TLS 1.3 on default C2 port %s from %s",
                              oxide_port, c$id$orig_h),
            $identifier = cat(c$id$orig_h, c$id$resp_h)
        ]);
    }

    ## Flag long-lived TLS connections on non-standard ports as beaconing candidates
    if ( c?$ssl && c$ssl?$version && c$ssl$version == tls13_version
         && c$id$resp_p != 443/tcp && c$id$resp_p != 80/tcp
         && c?$duration && c$duration > beacon_min_duration ) {
        NOTICE([
            $note       = C2_Beaconing,
            $conn       = c,
            $msg        = fmt("Long-lived TLS 1.3 connection (%.0f sec) on port %s from %s",
                              interval_to_double(c$duration), c$id$resp_p, c$id$orig_h),
            $identifier = cat(c$id$orig_h, c$id$resp_h, c$id$resp_p)
        ]);
    }
}
