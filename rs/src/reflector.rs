use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use socket2::{Socket, Domain, Type, Protocol};
use libc;
use crate::config::AppConfig;
use crate::server::CommandServerManager;
use crate::mdns::{parse_mdns_packet, DNSPacket, DNSResourceRecord, MdnsParsingError};
use std::time::{SystemTime, UNIX_EPOCH};

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

pub struct Reflector {
    config: Arc<AppConfig>,
    manager: Arc<Mutex<CommandServerManager>>,
}

impl Reflector {
    pub fn new(config: Arc<AppConfig>, manager: Arc<Mutex<CommandServerManager>>) -> Self {
        Self { config, manager }
    }

    pub async fn run(&self) {
        let mut sockets = HashMap::new();

        for iface in &self.config.interfaces {
            match setup_socket(iface) {
                Ok(sock) => {
                    match UdpSocket::from_std(sock.into()) {
                        Ok(async_sock) => {
                            sockets.insert(iface.clone(), Arc::new(async_sock));
                            println!("Successfully bound and joined multicast on interface {}", iface);
                        }
                        Err(e) => eprintln!("Failed to create async socket for {}: {}", iface, e),
                    }
                }
                Err(e) => eprintln!("Failed to setup socket for {}: {}", iface, e),
            }
        }

        if sockets.is_empty() {
            eprintln!("No interfaces successfully bound. Exiting reflector loop.");
            return;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, std::net::SocketAddr, Vec<u8>)>(1000);

        for (iface, sock) in &sockets {
            let sock_clone = sock.clone();
            let tx_clone = tx.clone();
            let iface_clone = iface.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    if let Ok((len, addr)) = sock_clone.recv_from(&mut buf).await {
                        let _ = tx_clone.send((iface_clone.clone(), addr, buf[..len].to_vec())).await;
                    }
                }
            });
        }

        while let Some((src_iface, src_addr, data)) = rx.recv().await {
            let src_ip = match src_addr {
                std::net::SocketAddr::V4(v4) => v4.ip().to_string(),
                _ => continue,
            };

            if let Ok(mut packet) = parse_mdns_packet(&data) {
                let mut question_names = HashSet::new();
                for q in &packet.questions {
                    question_names.insert(q.name.clone());
                }

                let mut answer_names = HashSet::new();
                for rr in packet.answers.iter().chain(packet.authorities.iter()).chain(packet.additionals.iter()) {
                    answer_names.insert(rr.name.clone());
                    if let Some(t) = &rr.target_name {
                        answer_names.insert(t.clone());
                    }
                }

                if question_names.is_empty() && answer_names.is_empty() {
                    continue;
                }

                let is_resp = packet.is_response();
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();

                let mut allowed_names: HashMap<String, Vec<String>> = HashMap::new();
                let mut disallowed_names: HashMap<String, Vec<String>> = HashMap::new();

                let mut mgr = self.manager.lock().await;

                for (dst_iface, dst_sock) in &sockets {
                    if dst_iface == &src_iface {
                        continue;
                    }

                    if !self.config.rewrite_mixed_packets {
                        let should_fwd = self.config.should_forward(&src_iface, dst_iface, &question_names, Some(&answer_names));
                        if should_fwd {
                            let _ = dst_sock.send_to(&data, (MDNS_ADDR, MDNS_PORT)).await;
                            for name in question_names.iter().chain(answer_names.iter()) {
                                allowed_names.entry(name.clone()).or_default().push(dst_iface.clone());
                            }
                            mgr.collect_stats(
                                &src_iface, &src_ip, "forwarded", &allowed_names, &disallowed_names,
                                timestamp, is_resp, 0, 0, 0, 0
                            );
                        } else {
                            for name in question_names.iter().chain(answer_names.iter()) {
                                disallowed_names.entry(name.clone()).or_default().push(dst_iface.clone());
                            }
                            mgr.collect_stats(
                                &src_iface, &src_ip, "dropped", &allowed_names, &disallowed_names,
                                timestamp, is_resp, 0, 0, 0, 0
                            );
                        }
                    } else {
                        let mut rewritten_packet = DNSPacket::new();
                        rewritten_packet.transaction_id = packet.transaction_id;
                        rewritten_packet.flags = packet.flags;

                        let mut kept_q = 0;
                        let mut kept_a = 0;
                        let mut dropped_q = 0;
                        let mut dropped_a = 0;

                        for q in &packet.questions {
                            if self.config.should_forward_question(&src_iface, dst_iface, &q.name) {
                                rewritten_packet.questions.push(q.clone());
                                allowed_names.entry(q.name.clone()).or_default().push(dst_iface.clone());
                                kept_q += 1;
                            } else {
                                disallowed_names.entry(q.name.clone()).or_default().push(dst_iface.clone());
                                dropped_q += 1;
                            }
                        }

                        let mut filter_rrs = |rrs: &Vec<DNSResourceRecord>, out: &mut Vec<DNSResourceRecord>| {
                            for rr in rrs {
                                if self.config.should_forward_record(&src_iface, dst_iface, &rr.name, rr.target_name.as_deref(), is_resp) {
                                    out.push(rr.clone());
                                    allowed_names.entry(rr.name.clone()).or_default().push(dst_iface.clone());
                                    if let Some(t) = &rr.target_name {
                                        allowed_names.entry(t.clone()).or_default().push(dst_iface.clone());
                                    }
                                    kept_a += 1;
                                } else {
                                    disallowed_names.entry(rr.name.clone()).or_default().push(dst_iface.clone());
                                    if let Some(t) = &rr.target_name {
                                        disallowed_names.entry(t.clone()).or_default().push(dst_iface.clone());
                                    }
                                    dropped_a += 1;
                                }
                            }
                        };

                        filter_rrs(&packet.answers, &mut rewritten_packet.answers);
                        filter_rrs(&packet.authorities, &mut rewritten_packet.authorities);
                        filter_rrs(&packet.additionals, &mut rewritten_packet.additionals);

                        if kept_q > 0 || kept_a > 0 {
                            if let Ok(rewritten_data) = rewritten_packet.serialize() {
                                let _ = dst_sock.send_to(&rewritten_data, (MDNS_ADDR, MDNS_PORT)).await;
                                mgr.collect_stats(
                                    &src_iface, &src_ip, "rewritten", &allowed_names, &disallowed_names,
                                    timestamp, is_resp, kept_q, kept_a, dropped_q, dropped_a
                                );
                            }
                        } else if dropped_q > 0 || dropped_a > 0 {
                            mgr.collect_stats(
                                &src_iface, &src_ip, "dropped", &allowed_names, &disallowed_names,
                                timestamp, is_resp, 0, 0, dropped_q, dropped_a
                            );
                        }
                    }
                }
            }
        }
    }
}

fn setup_socket(ifname: &str) -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;

    // Bind to wildcard
    socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)))?;

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = socket.bind_device(Some(ifname.as_bytes())) {
            eprintln!("SO_BINDTODEVICE failed for {}: {}", ifname, e);
        }
    }

    let _ = socket.join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED);
    socket.set_multicast_ttl_v4(255)?;
    socket.set_multicast_loop_v4(false)?;
    socket.set_nonblocking(true)?;

    Ok(socket)
}
