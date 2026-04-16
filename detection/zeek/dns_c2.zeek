##! DNS C2 detection — thresholds from jbaggs/anomalous-dns (code-confirmed).
##! query FQDN > 90 chars | unique subdomains > 8/hr | TXT response > 544 bytes
##! oxide tunes to ~79 chars, <8 subdomains/hr at steady state.

@load base/protocols/dns
@load base/frameworks/notice

module DNSC2;

export {
    redef enum Notice::Type += {
        LongQuery,
        HighUniqueSubdomains,
        LargeTXTResponse,
    };
    const long_query_len   = 90  &redef;
    const unique_sub_limit = 8   &redef;
    const large_txt_bytes  = 544 &redef;
}

global src_subs: table[addr, string] of set[string] &create_expire=1hr &redef;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| > long_query_len )
        NOTICE([$note=LongQuery, $conn=c,
                $msg=fmt("DNS FQDN %d chars: %s", |query|, query),
                $identifier=cat(c$id$orig_h, query)]);

    local parts = split_string(query, /\./);
    if ( |parts| >= 2 )
        {
        local apex = parts[|parts|-2] + "." + parts[|parts|-1];
        if ( [c$id$orig_h, apex] !in src_subs )
            src_subs[c$id$orig_h, apex] = set();
        add src_subs[c$id$orig_h, apex][query];
        if ( |src_subs[c$id$orig_h, apex]| > unique_sub_limit )
            NOTICE([$note=HighUniqueSubdomains, $conn=c,
                    $msg=fmt("%s: >%d unique subdomains of %s/hr",
                             c$id$orig_h, unique_sub_limit, apex),
                    $identifier=cat(c$id$orig_h, apex)]);
        }
    }

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)
    {
    if ( Site::is_local_addr(c$id$resp_h) ) return;
    local n = 0;
    for ( s in strs ) n += |s|;
    if ( n > large_txt_bytes )
        NOTICE([$note=LargeTXTResponse, $conn=c,
                $msg=fmt("TXT %d bytes from %s", n, c$id$resp_h),
                $identifier=cat(c$id$resp_h, msg$query)]);
    }
