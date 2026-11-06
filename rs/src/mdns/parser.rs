use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::mdns::packet::{DNSPacket, DNSQuestion, DNSResourceRecord, MdnsParsingError};

fn resolve_pointer(data: &[u8], offset: usize, len_byte: u8, visited: &mut HashSet<usize>) -> Result<String, MdnsParsingError> {
    if offset + 1 >= data.len() {
        return Err(MdnsParsingError("Compression pointer truncated".to_string()));
    }

    let ptr_offset = (((len_byte & 0x3F) as usize) << 8) | (data[offset + 1] as usize);

    if visited.contains(&ptr_offset) {
        return Err(MdnsParsingError("Infinite recursion loop in compression pointers".to_string()));
    }
    if visited.len() > 20 {
        return Err(MdnsParsingError("Exceeded maximum compression pointer redirection depth (20)".to_string()));
    }

    visited.insert(ptr_offset);
    let (sub_name, _) = parse_name_internal(data, ptr_offset, visited)?;
    Ok(sub_name)
}

fn parse_name_internal(data: &[u8], mut offset: usize, visited: &mut HashSet<usize>) -> Result<(String, usize), MdnsParsingError> {
    let mut labels = Vec::new();
    let next_offset;

    loop {
        if offset >= data.len() {
            return Err(MdnsParsingError("Offset out of packet bounds while parsing name".to_string()));
        }

        let len_byte = data[offset];

        if (len_byte & 0xC0) == 0xC0 {
            let sub_name = resolve_pointer(data, offset, len_byte, visited)?;
            next_offset = offset + 2;
            if !sub_name.is_empty() {
                labels.push(sub_name);
            }
            break;
        }

        if (len_byte & 0xC0) != 0 {
            return Err(MdnsParsingError(format!("Unsupported label prefix byte 0x{:02x}", len_byte)));
        }

        if len_byte == 0 {
            offset += 1;
            next_offset = offset;
            break;
        }

        offset += 1;
        let len_usize = len_byte as usize;
        if offset + len_usize > data.len() {
            return Err(MdnsParsingError("Label length exceeds packet boundary".to_string()));
        }

        let label_bytes = &data[offset..offset + len_usize];
        let label = String::from_utf8_lossy(label_bytes).into_owned();
        labels.push(label);
        
        offset += len_usize;
    }

    Ok((labels.join("."), next_offset))
}

pub fn parse_name(data: &[u8], offset: usize) -> Result<(String, usize), MdnsParsingError> {
    let mut visited = HashSet::new();
    parse_name_internal(data, offset, &mut visited)
}

fn parse_rr(data: &[u8], mut offset: usize) -> Result<(DNSResourceRecord, usize), MdnsParsingError> {
    let (name, next_offset) = parse_name(data, offset)?;
    offset = next_offset;

    if offset + 10 > data.len() {
        return Err(MdnsParsingError(format!("Resource Record metadata truncated for name: {}", name)));
    }

    let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    let ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
    let rdlen = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
    
    offset += 10;

    if offset + rdlen > data.len() {
        return Err(MdnsParsingError(format!("Resource Record data truncated for name: {}", name)));
    }

    let rdata = data[offset..offset + rdlen].to_vec();
    let curr_offset = offset;
    offset += rdlen;

    let mut target_name = None;
    let mut rdata_summary = None;

    match rtype {
        1 => { // A
            if rdlen == 4 {
                let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                rdata_summary = Some(ip.to_string());
            }
        }
        28 => { // AAAA
            if rdlen == 16 {
                if let Ok(octets) = <[u8; 16]>::try_from(&rdata[0..16]) {
                    let ip = Ipv6Addr::from(octets);
                    rdata_summary = Some(ip.to_string());
                }
            }
        }
        12 => { // PTR
            if let Ok((parsed_target, _)) = parse_name(data, curr_offset) {
                rdata_summary = Some(parsed_target.clone());
                target_name = Some(parsed_target);
            }
        }
        2 | 5 => { // NS, CNAME
            if let Ok((parsed_target, _)) = parse_name(data, curr_offset) {
                rdata_summary = Some(parsed_target);
            }
        }
        33 => { // SRV
            if rdlen > 6 {
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                if let Ok((parsed_target, _)) = parse_name(data, curr_offset + 6) {
                    if priority == 0 && weight == 0 {
                        rdata_summary = Some(format!("{}:{}", parsed_target, port));
                    } else {
                        rdata_summary = Some(format!("{}:{} (prio={}, weight={})", parsed_target, port, priority, weight));
                    }
                    target_name = Some(parsed_target);
                }
            }
        }
        16 => { // TXT
            let mut txt_parts = Vec::new();
            let mut pos = 0;
            while pos < rdata.len() {
                let slen = rdata[pos] as usize;
                pos += 1;
                if pos + slen > rdata.len() {
                    break;
                }
                let s = String::from_utf8_lossy(&rdata[pos..pos + slen]).into_owned();
                if !s.is_empty() {
                    txt_parts.push(s);
                }
                pos += slen;
            }
            if !txt_parts.is_empty() {
                rdata_summary = Some(txt_parts.join(", "));
            }
        }
        47 => { // NSEC
            if let Ok((next_domain, _)) = parse_name(data, curr_offset) {
                rdata_summary = Some(next_domain);
            }
        }
        _ => {}
    }

    Ok((DNSResourceRecord {
        name,
        rtype,
        rclass,
        ttl,
        rdata,
        target_name,
        rdata_summary,
    }, offset))
}

pub fn parse_mdns_packet(data: &[u8]) -> Result<DNSPacket, MdnsParsingError> {
    if data.len() < 12 {
        return Err(MdnsParsingError("Packet too short to contain a DNS header".to_string()));
    }

    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut offset = 12;
    let mut packet = DNSPacket {
        transaction_id,
        flags,
        ..Default::default()
    };

    for _ in 0..qdcount {
        let (name, next_offset) = parse_name(data, offset)?;
        offset = next_offset;

        if offset + 4 > data.len() {
            return Err(MdnsParsingError(format!("Question metadata truncated for name: {}", name)));
        }

        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;

        packet.questions.push(DNSQuestion { name, qtype, qclass });
    }

    for _ in 0..ancount {
        let (rr, next_offset) = parse_rr(data, offset)?;
        packet.answers.push(rr);
        offset = next_offset;
    }

    for _ in 0..nscount {
        let (rr, next_offset) = parse_rr(data, offset)?;
        packet.authorities.push(rr);
        offset = next_offset;
    }

    for _ in 0..arcount {
        let (rr, next_offset) = parse_rr(data, offset)?;
        packet.additionals.push(rr);
        offset = next_offset;
    }

    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rdata_summaries() {
        let mut pkt = DNSPacket::new();
        pkt.flags = 0x8400; // Response
        pkt.answers.push(DNSResourceRecord {
            name: "host.local".to_string(),
            rtype: 1, // A
            rclass: 1,
            ttl: 120,
            rdata: vec![192, 168, 1, 42],
            target_name: None,
            rdata_summary: None,
        });
        pkt.answers.push(DNSResourceRecord {
            name: "_http._tcp.local".to_string(),
            rtype: 12, // PTR
            rclass: 1,
            ttl: 4500,
            rdata: Vec::new(),
            target_name: Some("web._http._tcp.local".to_string()),
            rdata_summary: None,
        });
        pkt.additionals.push(DNSResourceRecord {
            name: "web._http._tcp.local".to_string(),
            rtype: 33, // SRV
            rclass: 1,
            ttl: 120,
            rdata: vec![0, 0, 0, 0, 0x1f, 0x90], // port 8080
            target_name: Some("host.local".to_string()),
            rdata_summary: None,
        });
        pkt.additionals.push(DNSResourceRecord {
            name: "web._http._tcp.local".to_string(),
            rtype: 16, // TXT
            rclass: 1,
            ttl: 4500,
            rdata: vec![7, b'p', b'a', b't', b'h', b'=', b'/', b'a', 5, b'v', b'e', b'r', b'=', b'1'],
            target_name: None,
            rdata_summary: None,
        });

        let raw = pkt.serialize().unwrap();
        let parsed = parse_mdns_packet(&raw).unwrap();

        assert_eq!(parsed.answers[0].rdata_summary.as_deref(), Some("192.168.1.42"));
        assert_eq!(parsed.answers[1].rdata_summary.as_deref(), Some("web._http._tcp.local"));
        assert_eq!(parsed.additionals[0].rdata_summary.as_deref(), Some("host.local:8080"));
        assert_eq!(parsed.additionals[1].rdata_summary.as_deref(), Some("path=/a, ver=1"));
    }
}
