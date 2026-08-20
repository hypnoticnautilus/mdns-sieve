use std::collections::HashSet;
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
    let mut stepped_over_pointer = false;
    let mut next_offset = offset;

    loop {
        if offset >= data.len() {
            return Err(MdnsParsingError("Offset out of packet bounds while parsing name".to_string()));
        }

        let len_byte = data[offset];

        if (len_byte & 0xC0) == 0xC0 {
            let sub_name = resolve_pointer(data, offset, len_byte, visited)?;
            if !stepped_over_pointer {
                next_offset = offset + 2;
                stepped_over_pointer = true;
            }
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
            if !stepped_over_pointer {
                next_offset = offset;
            }
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

    if rtype == 12 { // PTR
        if let Ok((parsed_target, _)) = parse_name(data, curr_offset) {
            target_name = Some(parsed_target);
        }
    } else if rtype == 33 { // SRV
        if rdlen > 6 {
            if let Ok((parsed_target, _)) = parse_name(data, curr_offset + 6) {
                target_name = Some(parsed_target);
            }
        }
    }

    Ok((DNSResourceRecord {
        name,
        rtype,
        rclass,
        ttl,
        rdata,
        target_name,
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
