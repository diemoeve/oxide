//! Minimal DNS wire format for TXT queries. No deps beyond std.

// Transport consumers (T5, T7) are not yet wired in; suppress until then.
#![allow(dead_code)]

/// Encode a DNS name into length-prefixed wire format labels.
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0); // root label
    out
}

/// Build a DNS TXT query packet in wire format.
pub fn build_txt_query(qname: &str, id: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]);                        // flags: RD=1
    pkt.extend_from_slice(&[0x00, 0x01]);                        // QDCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR=0
    pkt.extend_from_slice(&encode_name(qname));
    pkt.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);            // QTYPE=TXT QCLASS=IN
    pkt
}

/// Extract concatenated TXT string content from a DNS response.
/// Returns None if ANCOUNT=0 or no TXT data found.
pub fn parse_txt_rdata(resp: &[u8]) -> Option<Vec<u8>> {
    if resp.len() < 12 { return None; }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if ancount == 0 { return None; }
    let mut pos = 12;
    // skip question name
    loop {
        if pos >= resp.len() { return None; }
        if resp[pos] & 0xC0 == 0xC0 { pos += 2; break; }
        let l = resp[pos] as usize;
        if l == 0 { pos += 1; break; }
        pos += 1 + l;
    }
    pos += 4; // skip QTYPE + QCLASS
    // skip answer name (may be pointer)
    if pos >= resp.len() { return None; }
    if resp[pos] & 0xC0 == 0xC0 { pos += 2; } else {
        loop {
            if pos >= resp.len() { return None; }
            let l = resp[pos] as usize;
            if l == 0 { pos += 1; break; }
            pos += 1 + l;
        }
    }
    pos += 8; // TYPE(2) + CLASS(2) + TTL(4)
    if pos + 2 > resp.len() { return None; }
    let rdlen = u16::from_be_bytes([resp[pos], resp[pos+1]]) as usize;
    pos += 2;
    if pos + rdlen > resp.len() { return None; }
    let rdata = &resp[pos..pos+rdlen];
    let mut txt = Vec::new();
    let mut i = 0;
    while i < rdata.len() {
        let slen = rdata[i] as usize;
        i += 1;
        if i + slen > rdata.len() { break; }
        txt.extend_from_slice(&rdata[i..i+slen]);
        i += slen;
    }
    if txt.is_empty() { None } else { Some(txt) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_name_structure() {
        let enc = encode_name("abc.def.com");
        assert_eq!(enc[0], 3);
        assert_eq!(&enc[1..4], b"abc");
        assert_eq!(*enc.last().unwrap(), 0);
    }

    #[test]
    fn build_query_correct_id() {
        let q = build_txt_query("test.lab", 0xABCD);
        assert_eq!(q[0], 0xAB);
        assert_eq!(q[1], 0xCD);
        assert_eq!(q[5], 0x01); // QDCOUNT low byte = 1
    }

    #[test]
    fn parse_empty_ancount_none() {
        let mut resp = vec![0u8; 12];
        resp[7] = 0; // ANCOUNT = 0
        assert!(parse_txt_rdata(&resp).is_none());
    }
}
