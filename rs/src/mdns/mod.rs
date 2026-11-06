pub mod packet;
pub mod parser;

pub use packet::{DNSPacket, DNSResourceRecord};
pub use parser::parse_mdns_packet;
