use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use socket2::{Socket, Domain, Type, Protocol};
use crate::config::AppConfig;
use crate::server::CommandServerManager;
use crate::mdns::{parse_mdns_packet, DNSPacket, DNSResourceRecord};
use crate::database::{Disposition, MessageItemRecord, MessageRecord, PacketSection, PacketType};
use std::time::{SystemTime, UNIX_EPOCH};

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

pub struct Reflector {
    config: Arc<AppConfig>,
    manager: Arc<Mutex<CommandServerManager>>,
}

fn compute_item_disposition(fwd: &[String], drop: &[String]) -> Disposition {
    if fwd.is_empty() {
        Disposition::Dropped
    } else if drop.is_empty() {
        Disposition::Forwarded
    } else {
        Disposition::PartiallyForwarded
    }
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

            if let Ok(packet) = parse_mdns_packet(&data) {
                let total_items = packet.questions.len()
                    + packet.answers.len()
                    + packet.authorities.len()
                    + packet.additionals.len();

                if total_items == 0 {
                    continue;
                }

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

                let is_resp = packet.is_response();
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();

                // Per-item forwarded and dropped destination interface lists
                let mut q_routing: Vec<(Vec<String>, Vec<String>)> = vec![(Vec::new(), Vec::new()); packet.questions.len()];
                let mut ans_routing: Vec<(Vec<String>, Vec<String>)> = vec![(Vec::new(), Vec::new()); packet.answers.len()];
                let mut auth_routing: Vec<(Vec<String>, Vec<String>)> = vec![(Vec::new(), Vec::new()); packet.authorities.len()];
                let mut add_routing: Vec<(Vec<String>, Vec<String>)> = vec![(Vec::new(), Vec::new()); packet.additionals.len()];

                for (dst_iface, dst_sock) in &sockets {
                    if dst_iface == &src_iface {
                        continue;
                    }

                    if !self.config.rewrite_mixed_packets {
                        let should_fwd = self.config.should_forward(&src_iface, dst_iface, &question_names, Some(&answer_names));
                        if should_fwd {
                            let _ = dst_sock.send_to(&data, (MDNS_ADDR, MDNS_PORT)).await;
                            for entry in q_routing.iter_mut()
                                .chain(ans_routing.iter_mut())
                                .chain(auth_routing.iter_mut())
                                .chain(add_routing.iter_mut())
                            {
                                entry.0.push(dst_iface.clone());
                            }
                        } else {
                            for entry in q_routing.iter_mut()
                                .chain(ans_routing.iter_mut())
                                .chain(auth_routing.iter_mut())
                                .chain(add_routing.iter_mut())
                            {
                                entry.1.push(dst_iface.clone());
                            }
                        }
                    } else {
                        let mut rewritten_packet = DNSPacket::new();
                        rewritten_packet.transaction_id = packet.transaction_id;
                        rewritten_packet.flags = packet.flags;

                        let mut kept_count = 0usize;
                        let mut dropped_count = 0usize;

                        for (idx, q) in packet.questions.iter().enumerate() {
                            if self.config.should_forward_question(&src_iface, dst_iface, &q.name) {
                                rewritten_packet.questions.push(q.clone());
                                q_routing[idx].0.push(dst_iface.clone());
                                kept_count += 1;
                            } else {
                                q_routing[idx].1.push(dst_iface.clone());
                                dropped_count += 1;
                            }
                        }

                        let mut filter_rrs = |rrs: &Vec<DNSResourceRecord>,
                                              out: &mut Vec<DNSResourceRecord>,
                                              routing: &mut Vec<(Vec<String>, Vec<String>)>| {
                            for (idx, rr) in rrs.iter().enumerate() {
                                if self.config.should_forward_record(&src_iface, dst_iface, &rr.name, rr.target_name.as_deref(), is_resp) {
                                    out.push(rr.clone());
                                    routing[idx].0.push(dst_iface.clone());
                                    kept_count += 1;
                                } else {
                                    routing[idx].1.push(dst_iface.clone());
                                    dropped_count += 1;
                                }
                            }
                        };

                        filter_rrs(&packet.answers, &mut rewritten_packet.answers, &mut ans_routing);
                        filter_rrs(&packet.authorities, &mut rewritten_packet.authorities, &mut auth_routing);
                        filter_rrs(&packet.additionals, &mut rewritten_packet.additionals, &mut add_routing);

                        if kept_count > 0 {
                            if dropped_count == 0 {
                                // Unmodified packet: send raw bytes directly
                                let _ = dst_sock.send_to(&data, (MDNS_ADDR, MDNS_PORT)).await;
                            } else if let Ok(rewritten_data) = rewritten_packet.serialize() {
                                let _ = dst_sock.send_to(&rewritten_data, (MDNS_ADDR, MDNS_PORT)).await;
                            }
                        }
                    }
                }

                // Build MessageItemRecord entries and aggregate message-level routing
                let mut items = Vec::with_capacity(total_items);
                let mut msg_fwd_set = HashSet::new();
                let mut msg_drop_set = HashSet::new();

                for (idx, q) in packet.questions.iter().enumerate() {
                    let (ref mut fwd, ref mut drop) = q_routing[idx];
                    fwd.sort();
                    drop.sort();
                    for f in fwd.iter() { msg_fwd_set.insert(f.clone()); }
                    for d in drop.iter() { msg_drop_set.insert(d.clone()); }

                    let disp = compute_item_disposition(fwd, drop);
                    items.push(MessageItemRecord {
                        id: None,
                        message_id: None,
                        section: PacketSection::Question as u8,
                        name: q.name.clone(),
                        rr_type: q.qtype,
                        rr_class: q.qclass & 0x7FFF,
                        ttl: None,
                        rdata_summary: None,
                        disposition: disp as u8,
                        forwarded_interfaces: fwd.join(","),
                        dropped_interfaces: drop.join(","),
                    });
                }

                let mut append_rr_items = |rrs: &Vec<DNSResourceRecord>,
                                           routing: &mut Vec<(Vec<String>, Vec<String>)>,
                                           section: PacketSection| {
                    for (idx, rr) in rrs.iter().enumerate() {
                        let (ref mut fwd, ref mut drop) = routing[idx];
                        fwd.sort();
                        drop.sort();
                        for f in fwd.iter() { msg_fwd_set.insert(f.clone()); }
                        for d in drop.iter() { msg_drop_set.insert(d.clone()); }

                        let disp = compute_item_disposition(fwd, drop);
                        items.push(MessageItemRecord {
                            id: None,
                            message_id: None,
                            section: section as u8,
                            name: rr.name.clone(),
                            rr_type: rr.rtype,
                            rr_class: rr.rclass & 0x7FFF,
                            ttl: Some(rr.ttl),
                            rdata_summary: rr.rdata_summary.clone(),
                            disposition: disp as u8,
                            forwarded_interfaces: fwd.join(","),
                            dropped_interfaces: drop.join(","),
                        });
                    }
                };

                append_rr_items(&packet.answers, &mut ans_routing, PacketSection::Answer);
                append_rr_items(&packet.authorities, &mut auth_routing, PacketSection::Authority);
                append_rr_items(&packet.additionals, &mut add_routing, PacketSection::Additional);

                let all_forwarded = items.iter().all(|i| i.disposition == Disposition::Forwarded as u8);
                let all_dropped = items.iter().all(|i| i.disposition == Disposition::Dropped as u8);

                let msg_disposition = if all_forwarded {
                    Disposition::Forwarded
                } else if all_dropped {
                    Disposition::Dropped
                } else {
                    Disposition::PartiallyForwarded
                };

                let mut msg_fwd_vec: Vec<String> = msg_fwd_set.into_iter().collect();
                msg_fwd_vec.sort();
                let mut msg_drop_vec: Vec<String> = msg_drop_set.into_iter().collect();
                msg_drop_vec.sort();

                let message_record = MessageRecord {
                    id: None,
                    timestamp,
                    src_ip,
                    src_interface: src_iface,
                    packet_type: if is_resp { PacketType::Response as u8 } else { PacketType::Query as u8 },
                    disposition: msg_disposition as u8,
                    forwarded_interfaces: msg_fwd_vec.join(","),
                    dropped_interfaces: msg_drop_vec.join(","),
                    items,
                };

                let mut mgr = self.manager.lock().await;
                mgr.record_message(message_record);
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
