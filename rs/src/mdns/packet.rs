use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone)]
pub struct MdnsParsingError(pub String);

impl fmt::Display for MdnsParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MdnsParsingError: {}", self.0)
    }
}

impl std::error::Error for MdnsParsingError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub target_name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DNSPacket {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSResourceRecord>,
    pub authorities: Vec<DNSResourceRecord>,
    pub additionals: Vec<DNSResourceRecord>,
}

impl DNSPacket {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    pub fn extract_names(&self) -> HashSet<String> {
        let mut names = HashSet::new();
        for q in &self.questions {
            names.insert(q.name.clone());
        }
        for rr in self.answers.iter().chain(self.authorities.iter()).chain(self.additionals.iter()) {
            names.insert(rr.name.clone());
            if let Some(target) = &rr.target_name {
                names.insert(target.clone());
            }
        }
        names
    }

    pub fn serialize(&self) -> Result<Vec<u8>, MdnsParsingError> {
        let mut buffer = Vec::new();
        
        let qdcount = self.questions.len() as u16;
        let ancount = self.answers.len() as u16;
        let nscount = self.authorities.len() as u16;
        let arcount = self.additionals.len() as u16;

        buffer.extend_from_slice(&self.transaction_id.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&qdcount.to_be_bytes());
        buffer.extend_from_slice(&ancount.to_be_bytes());
        buffer.extend_from_slice(&nscount.to_be_bytes());
        buffer.extend_from_slice(&arcount.to_be_bytes());

        let mut compression_dict: HashMap<String, u16> = HashMap::new();

        for q in &self.questions {
            write_name(&q.name, &mut compression_dict, &mut buffer)?;
            buffer.extend_from_slice(&q.qtype.to_be_bytes());
            buffer.extend_from_slice(&q.qclass.to_be_bytes());
        }

        let mut serialize_rr_list = |rrs: &Vec<DNSResourceRecord>, buffer: &mut Vec<u8>, comp_dict: &mut HashMap<String, u16>| -> Result<(), MdnsParsingError> {
            for rr in rrs {
                write_name(&rr.name, comp_dict, buffer)?;
                buffer.extend_from_slice(&rr.rtype.to_be_bytes());
                buffer.extend_from_slice(&rr.rclass.to_be_bytes());
                buffer.extend_from_slice(&rr.ttl.to_be_bytes());

                let rdlen_offset = buffer.len();
                buffer.extend_from_slice(&[0, 0]); // Placeholder for rdlen

                let start_rdata = buffer.len();

                if rr.rtype == 12 && rr.target_name.is_some() {
                    write_name(rr.target_name.as_ref().unwrap(), comp_dict, buffer)?;
                } else if rr.rtype == 33 && rr.target_name.is_some() {
                    let mut priority = 0u16;
                    let mut weight = 0u16;
                    let mut port = 0u16;

                    if rr.rdata.len() >= 6 {
                        priority = u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]);
                        weight = u16::from_be_bytes([rr.rdata[2], rr.rdata[3]]);
                        port = u16::from_be_bytes([rr.rdata[4], rr.rdata[5]]);
                    }

                    buffer.extend_from_slice(&priority.to_be_bytes());
                    buffer.extend_from_slice(&weight.to_be_bytes());
                    buffer.extend_from_slice(&port.to_be_bytes());

                    write_name(rr.target_name.as_ref().unwrap(), comp_dict, buffer)?;
                } else {
                    buffer.extend_from_slice(&rr.rdata);
                }

                let rdlen = (buffer.len() - start_rdata) as u16;
                let rdlen_bytes = rdlen.to_be_bytes();
                buffer[rdlen_offset] = rdlen_bytes[0];
                buffer[rdlen_offset + 1] = rdlen_bytes[1];
            }
            Ok(())
        };

        serialize_rr_list(&self.answers, &mut buffer, &mut compression_dict)?;
        serialize_rr_list(&self.authorities, &mut buffer, &mut compression_dict)?;
        serialize_rr_list(&self.additionals, &mut buffer, &mut compression_dict)?;

        Ok(buffer)
    }
}

pub fn write_name(name: &str, compression_dict: &mut HashMap<String, u16>, buffer: &mut Vec<u8>) -> Result<(), MdnsParsingError> {
    let canon_name = name.trim_end_matches('.').to_lowercase();
    if canon_name.is_empty() {
        buffer.push(0);
        return Ok(());
    }

    if let Some(&offset) = compression_dict.get(&canon_name) {
        let ptr = 0xC000 | offset;
        buffer.extend_from_slice(&ptr.to_be_bytes());
        return Ok(());
    }

    let current_offset = buffer.len() as u16;
    if current_offset < 0x3FFF {
        compression_dict.insert(canon_name.clone(), current_offset);
    }

    let parts = canon_name.split('.');
    for part in parts {
        let part_bytes = part.as_bytes();
        if part_bytes.len() > 63 {
            return Err(MdnsParsingError("DNS label too long".to_string()));
        }
        buffer.push(part_bytes.len() as u8);
        buffer.extend_from_slice(part_bytes);
    }
    buffer.push(0);
    Ok(())
}
