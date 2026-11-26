use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SsdpMethod {
    MSearch,
    Notify,
    Response,
}

impl SsdpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            SsdpMethod::MSearch => "M-SEARCH",
            SsdpMethod::Notify => "NOTIFY",
            SsdpMethod::Response => "RESPONSE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpPacket {
    pub method: SsdpMethod,
    pub st: Option<String>,
    pub nt: Option<String>,
    pub nts: Option<String>,
    pub usn: Option<String>,
    pub location: Option<String>,
    pub server: Option<String>,
    pub mx: Option<u32>,
    pub man: Option<String>,
}

impl SsdpPacket {
    /// Returns the primary service/target type (`ST` for M-SEARCH/200 OK, `NT` for NOTIFY).
    pub fn service_type(&self) -> Option<&str> {
        self.st.as_deref().or(self.nt.as_deref())
    }
}

/// Parses an HTTP-over-UDP (HTTPMU) SSDP packet.
pub fn parse_ssdp_packet(data: &[u8]) -> Option<SsdpPacket> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");
    let start_line = lines.next()?.trim();

    // Fallback to \n if \r\n wasn't used
    let (start_line, remaining_lines): (&str, Vec<&str>) = if start_line.contains('\n') {
        let mut lf_lines = text.split('\n');
        let first = lf_lines.next()?.trim();
        (first, lf_lines.collect())
    } else {
        (start_line, lines.collect())
    };

    let upper_start = start_line.to_ascii_uppercase();
    let method = if upper_start.starts_with("M-SEARCH ") {
        SsdpMethod::MSearch
    } else if upper_start.starts_with("NOTIFY ") {
        SsdpMethod::Notify
    } else if upper_start.starts_with("HTTP/1.") && upper_start.contains(" 200 ") {
        SsdpMethod::Response
    } else {
        return None;
    };

    let mut packet = SsdpPacket {
        method,
        st: None,
        nt: None,
        nts: None,
        usn: None,
        location: None,
        server: None,
        mx: None,
        man: None,
    };

    for line in remaining_lines {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if value.is_empty() {
                continue;
            }
            match name.as_str() {
                "st" => packet.st = Some(value),
                "nt" => packet.nt = Some(value),
                "nts" => packet.nts = Some(value),
                "usn" => packet.usn = Some(value),
                "location" => packet.location = Some(value),
                "server" => packet.server = Some(value),
                "mx" => packet.mx = value.parse::<u32>().ok(),
                "man" => packet.man = Some(value),
                _ => {}
            }
        }
    }

    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_msearch() {
        let raw = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n";
        let pkt = parse_ssdp_packet(raw).expect("should parse M-SEARCH");
        assert_eq!(pkt.method, SsdpMethod::MSearch);
        assert_eq!(pkt.st.as_deref(), Some("urn:schemas-upnp-org:device:MediaRenderer:1"));
        assert_eq!(pkt.mx, Some(3));
        assert_eq!(pkt.man.as_deref(), Some("\"ssdp:discover\""));
        assert_eq!(pkt.service_type(), Some("urn:schemas-upnp-org:device:MediaRenderer:1"));
    }

    #[test]
    fn test_parse_notify() {
        let raw = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nLOCATION: http://192.168.1.50:1400/xml/device_description.xml\r\nUSN: uuid:RINCON_000E5876543201400::upnp:rootdevice\r\n\r\n";
        let pkt = parse_ssdp_packet(raw).expect("should parse NOTIFY");
        assert_eq!(pkt.method, SsdpMethod::Notify);
        assert_eq!(pkt.nt.as_deref(), Some("upnp:rootdevice"));
        assert_eq!(pkt.nts.as_deref(), Some("ssdp:alive"));
        assert_eq!(pkt.location.as_deref(), Some("http://192.168.1.50:1400/xml/device_description.xml"));
        assert_eq!(pkt.usn.as_deref(), Some("uuid:RINCON_000E5876543201400::upnp:rootdevice"));
        assert_eq!(pkt.service_type(), Some("upnp:rootdevice"));
    }

    #[test]
    fn test_parse_response() {
        let raw = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.2.10:8008/ssdp/device-desc.xml\r\nST: urn:dial-multiscreen-org:service:dial:1\r\nUSN: uuid:1234::urn:dial-multiscreen-org:service:dial:1\r\n\r\n";
        let pkt = parse_ssdp_packet(raw).expect("should parse 200 OK");
        assert_eq!(pkt.method, SsdpMethod::Response);
        assert_eq!(pkt.st.as_deref(), Some("urn:dial-multiscreen-org:service:dial:1"));
        assert_eq!(pkt.usn.as_deref(), Some("uuid:1234::urn:dial-multiscreen-org:service:dial:1"));
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_ssdp_packet(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_ssdp_packet(b"\xff\xfe\xfd").is_none());
    }
}
