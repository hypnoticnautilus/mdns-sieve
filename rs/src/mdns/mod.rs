pub mod packet;
pub mod parser;

pub use packet::{DNSPacket, DNSQuestion, DNSResourceRecord, MdnsParsingError};
pub use parser::{parse_mdns_packet, parse_name};
