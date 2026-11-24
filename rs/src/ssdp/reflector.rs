use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex};

use crate::config::AppConfig;
use crate::server::CommandServerManager;
use crate::ssdp::{parse_ssdp_packet, SsdpMethod};

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

pub struct SsdpReflector {
    config_rx: watch::Receiver<Arc<AppConfig>>,
    server_mgr: Arc<Mutex<CommandServerManager>>,
    verbose: bool,
}

impl SsdpReflector {
    pub fn new(
        config_rx: watch::Receiver<Arc<AppConfig>>,
        server_mgr: Arc<Mutex<CommandServerManager>>,
        verbose: bool,
    ) -> Self {
        Self {
            config_rx,
            server_mgr,
            verbose,
        }
    }

    pub async fn run(&mut self) {
        loop {
            let cfg = self.config_rx.borrow().clone();
            if !cfg.ssdp_enabled || cfg.ssdp_interfaces.is_empty() {
                if self.verbose {
                    eprintln!(
                        "[SSDP] Disabled or no interfaces configured (enabled={}, interfaces={:?})",
                        cfg.ssdp_enabled, cfg.ssdp_interfaces
                    );
                }
                if self.config_rx.changed().await.is_err() {
                    break;
                }
                continue;
            }

            if self.verbose {
                eprintln!("[SSDP] Starting reflector on interfaces: {:?}", cfg.ssdp_interfaces);
            }

            if let Err(e) = self.run_loop(&cfg).await {
                eprintln!("[SSDP] Reflector error: {}", e);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    res = self.config_rx.changed() => {
                        if res.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn run_loop(&mut self, cfg: &Arc<AppConfig>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let iface_ips = resolve_interface_ips(&cfg.ssdp_interfaces);
        if self.verbose {
            eprintln!("[SSDP] Resolved interface IPs: {:?}", iface_ips);
        }
        if iface_ips.is_empty() {
            return Err("No valid IPv4 addresses found for configured SSDP interfaces".into());
        }

        let (pkt_tx, mut pkt_rx) = mpsc::channel::<(String, SocketAddrV4, Vec<u8>)>(256);
        let mut recv_tasks = Vec::new();
        let mut out_sockets: HashMap<String, Arc<UdpSocket>> = HashMap::new();

        for (iface, ip) in &iface_ips {
            let recv_sock = create_ssdp_multicast_socket(iface, *ip)?;
            let out_sock = create_outbound_socket(iface, *ip)?;
            out_sockets.insert(iface.clone(), Arc::new(out_sock));

            let tx = pkt_tx.clone();
            let iface_name = iface.clone();
            let verbose = self.verbose;
            let handle = tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match recv_sock.recv_from(&mut buf).await {
                        Ok((len, SocketAddr::V4(src_v4))) => {
                            if tx.send((iface_name.clone(), src_v4, buf[..len].to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            if verbose {
                                eprintln!("[SSDP] recv_from error on {}: {}", iface_name, e);
                            }
                            break;
                        }
                    }
                }
            });
            recv_tasks.push(handle);
        }
        drop(pkt_tx);

        loop {
            tokio::select! {
                Some((src_iface, src_v4, data)) = pkt_rx.recv() => {
                    // Ignore packets originating from our own interface IPs
                    if iface_ips.values().any(|ip| ip == src_v4.ip()) {
                        continue;
                    }

                    let pkt = match parse_ssdp_packet(&data) {
                        Some(p) => p,
                        None => continue,
                    };

                    if self.verbose {
                        eprintln!(
                            "[SSDP] {} from {} on {} (ST/NT={:?}, USN={:?})",
                            pkt.method.as_str(),
                            src_v4,
                            src_iface,
                            pkt.service_type(),
                            pkt.usn
                        );
                    }

                    let mut fwd_ifaces = Vec::new();
                    let mut drp_ifaces = Vec::new();

                    match pkt.method {
                        SsdpMethod::MSearch => {
                            let wait_secs = pkt.mx.unwrap_or(3).clamp(1, 10) + 1;
                            for (dst_iface, dst_ip) in &iface_ips {
                                if dst_iface == &src_iface {
                                    continue;
                                }
                                if cfg.should_forward_ssdp(&pkt, &src_iface, dst_iface) {
                                    fwd_ifaces.push(dst_iface.clone());
                                    if let Some(reply_sock) = out_sockets.get(&src_iface).cloned() {
                                        let payload = data.clone();
                                        let cfg_clone = cfg.clone();
                                        let mgr_clone = self.server_mgr.clone();
                                        let src_iface_c = src_iface.clone();
                                        let dst_iface_c = dst_iface.clone();
                                        let dst_ip_c = *dst_ip;
                                        let verbose = self.verbose;
                                        tokio::spawn(async move {
                                            forward_msearch_and_relay_replies(
                                                payload,
                                                src_v4,
                                                src_iface_c,
                                                dst_iface_c,
                                                dst_ip_c,
                                                reply_sock,
                                                wait_secs,
                                                cfg_clone,
                                                mgr_clone,
                                                verbose,
                                            ).await;
                                        });
                                    }
                                } else {
                                    drp_ifaces.push(dst_iface.clone());
                                }
                            }
                        }
                        SsdpMethod::Notify => {
                            let mcast_dest = SocketAddrV4::new(SSDP_ADDR, SSDP_PORT);
                            for (dst_iface, _) in &iface_ips {
                                if dst_iface == &src_iface {
                                    continue;
                                }
                                if cfg.should_forward_ssdp(&pkt, &src_iface, dst_iface) {
                                    if let Some(sock) = out_sockets.get(dst_iface) {
                                        if let Err(e) = sock.send_to(&data, mcast_dest).await {
                                            if self.verbose {
                                                eprintln!("[SSDP] Failed to forward NOTIFY to {}: {}", dst_iface, e);
                                            }
                                        }
                                    }
                                    fwd_ifaces.push(dst_iface.clone());
                                } else {
                                    drp_ifaces.push(dst_iface.clone());
                                }
                            }
                        }
                        SsdpMethod::Response => {
                            continue;
                        }
                    }

                    if self.verbose {
                        eprintln!(
                            "[SSDP] {} from {} ({}) -> forwarded={:?}, dropped={:?}",
                            pkt.method.as_str(), src_v4.ip(), src_iface, fwd_ifaces, drp_ifaces
                        );
                    }

                    let disp = if fwd_ifaces.is_empty() && !drp_ifaces.is_empty() {
                        2u8
                    } else if !fwd_ifaces.is_empty() && !drp_ifaces.is_empty() {
                        1u8
                    } else {
                        0u8
                    };

                    let mgr = self.server_mgr.lock().await;
                    if let Some(ref db) = mgr.db_manager {
                        db.record_ssdp_message(
                            &src_v4.ip().to_string(),
                            &src_iface,
                            pkt.method.as_str(),
                            pkt.service_type(),
                            pkt.usn.as_deref(),
                            pkt.location.as_deref(),
                            disp,
                            &fwd_ifaces,
                            &drp_ifaces,
                        );
                    }
                }
                res = self.config_rx.changed() => {
                    for h in recv_tasks {
                        h.abort();
                    }
                    if res.is_err() {
                        return Ok(());
                    }
                    if self.verbose {
                        eprintln!("[SSDP] Configuration changed, reloading reflector...");
                    }
                    return Ok(());
                }
            }
        }
    }
}

async fn forward_msearch_and_relay_replies(
    payload: Vec<u8>,
    orig_src: SocketAddrV4,
    orig_iface: String,
    dst_iface: String,
    dst_ip: Ipv4Addr,
    reply_sock: Arc<UdpSocket>,
    wait_secs: u32,
    cfg: Arc<AppConfig>,
    server_mgr: Arc<Mutex<CommandServerManager>>,
    verbose: bool,
) {
    let eph_sock = match UdpSocket::bind(SocketAddrV4::new(dst_ip, 0)).await {
        Ok(s) => s,
        Err(e) => {
            if verbose {
                eprintln!("[SSDP] Failed to bind ephemeral socket on {} ({}): {}", dst_iface, dst_ip, e);
            }
            return;
        }
    };

    let mcast_dest = SocketAddrV4::new(SSDP_ADDR, SSDP_PORT);
    if let Err(e) = eph_sock.send_to(&payload, mcast_dest).await {
        if verbose {
            eprintln!("[SSDP] Failed to send M-SEARCH on {}: {}", dst_iface, e);
        }
        return;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs as u64);
    let mut buf = [0u8; 8192];

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, eph_sock.recv_from(&mut buf)).await {
            Ok(Ok((len, SocketAddr::V4(responder)))) => {
                let data = &buf[..len];
                if let Some(pkt) = parse_ssdp_packet(data) {
                    if pkt.method == SsdpMethod::Response {
                        let allowed = cfg.should_forward_ssdp(&pkt, &dst_iface, &orig_iface);
                        if verbose {
                            eprintln!(
                                "[SSDP] 200 OK from {} on {} -> {} ({}) allowed={}",
                                responder, dst_iface, orig_src, orig_iface, allowed
                            );
                        }
                        if allowed {
                            let _ = reply_sock.send_to(data, orig_src).await;
                        }
                        let (disp, fwd, drp) = if allowed {
                            (0u8, vec![orig_iface.clone()], Vec::new())
                        } else {
                            (2u8, Vec::new(), vec![orig_iface.clone()])
                        };
                        let mgr = server_mgr.lock().await;
                        if let Some(ref db) = mgr.db_manager {
                            db.record_ssdp_message(
                                &responder.ip().to_string(),
                                &dst_iface,
                                pkt.method.as_str(),
                                pkt.service_type(),
                                pkt.usn.as_deref(),
                                pkt.location.as_deref(),
                                disp,
                                &fwd,
                                &drp,
                            );
                        }
                    }
                }
            }
            _ => break,
        }
    }
}

fn create_ssdp_multicast_socket(
    ifname: &str,
    ip: Ipv4Addr,
) -> Result<UdpSocket, Box<dyn std::error::Error + Send + Sync>> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SSDP_PORT)))?;
    #[cfg(target_os = "linux")]
    if let Err(e) = socket.bind_device(Some(ifname.as_bytes())) {
        eprintln!("[SSDP] SO_BINDTODEVICE failed for {}: {}", ifname, e);
    }
    socket.join_multicast_v4(&SSDP_ADDR, &ip)?;
    let _ = socket.set_multicast_loop_v4(false);

    let std_sock: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

fn create_outbound_socket(
    ifname: &str,
    ip: Ipv4Addr,
) -> Result<UdpSocket, Box<dyn std::error::Error + Send + Sync>> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(ip, 0)))?;
    #[cfg(target_os = "linux")]
    if let Err(e) = socket.bind_device(Some(ifname.as_bytes())) {
        eprintln!("[SSDP] Outbound SO_BINDTODEVICE failed for {}: {}", ifname, e);
    }
    let _ = socket.set_multicast_if_v4(&ip);
    let _ = socket.set_multicast_loop_v4(false);
    let std_sock: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

fn resolve_interface_ips(interfaces: &[String]) -> HashMap<String, Ipv4Addr> {
    let mut map = HashMap::new();
    #[cfg(unix)]
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) == 0 && !ifaddrs.is_null() {
            let mut cur = ifaddrs;
            while !cur.is_null() {
                let ifa = &*cur;
                if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                    if (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                        if let Ok(name) = CStr::from_ptr(ifa.ifa_name).to_str() {
                            if interfaces.iter().any(|i| i == name) && !map.contains_key(name) {
                                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                                map.insert(name.to_string(), ip);
                            }
                        }
                    }
                }
                cur = ifa.ifa_next;
            }
            libc::freeifaddrs(ifaddrs);
        }
    }
    map
}
