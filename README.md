# mdns-sieve

`mdns-sieve` is a lightweight Multicast DNS (mDNS) reflector and filtering daemon. It forwards mDNS queries and responses across multiple isolated network interfaces (subnets/VLANs) using glob-style rules to control which services and hostnames are visible across zones.

Designed for low-end hardware and resource-constrained environments (like OpenWrt routers and Raspberry Pis), the codebase is self-recovering and dependency-free.

---

## Why Deploy `mdns-sieve` on Your Network?

Traditional mDNS reflectors (like Avahi's reflector mode or `mdns-repeater`) operate as mirrors that repeat all mDNS packets across all interfaces. In segmented network environments containing IoT devices, this introduces security and performance issues.

`mdns-sieve` addresses these concerns by providing:

### 1. Prevention of Network Reconnaissance (Scanning)
A compromised IoT device (such as a smart plug, IP camera, or smart TV) can be used to scan the network using mDNS queries.
* **Without Filtering:** A query looking for servers, workstations, or file shares is reflected to other networks. Personal computers and NAS devices respond, providing a map of local devices and IPs.
* **With mdns-sieve:** You can define rules that prevent mDNS queries originating from the IoT network from reaching other interfaces.

### 2. Mitigation of Service Spoofing and Cache Poisoning
mDNS is unauthenticated, meaning clients trust any response they hear on the network.
* **Without Filtering:** A device on the IoT VLAN can broadcast responses claiming to be a local network printer or file share. Laptops on other VLANs may route print jobs or credentials to the device.
* **With mdns-sieve:** Unsolicited advertisements/answers from the IoT network are blocked from entering other zones unless explicitly allowed.

### 3. Reduced Attack Surface on Local Devices
Many operating systems run background services that respond to mDNS queries. Blocking incoming queries from other segments prevents local machines from leaking their presence or service versions.

### 4. Reduced Wi-Fi Multicast Noise
IoT devices often broadcast state advertisements. Since multicast Wi-Fi frames are transmitted at slow baseline rates, this consumes airtime. Blocking these unsolicited packets at the reflector prevents them from flooding the Wi-Fi, reducing CPU usage on connected devices.

---

## Quick Start

The daemon is written in Rust (`rs/`) and embeds the web dashboard directly into the binary.

### 1. Build the Binary
If you have a local Rust toolchain installed, you can compile it natively:
```bash
cd rs/
cargo build --release
```
For cross-compilation (e.g. to ARM targets like Raspberry Pi), we provide a wrapper script that uses Docker:
```bash
./rs/cargo.sh build --release --target aarch64-unknown-linux-musl
```

### 2. Configure mdns-sieve
Create a `config.yaml` file to define your active interfaces, rules, tracking options, and web server options. Example:
```yaml
interfaces:
  - eth0   # Trusted LAN
  - wlan0  # IoT Wi-Fi

default_action: drop
rewrite_mixed_packets: true
forward_known_answers: false

rules:
  # Forward Trusted devices casting to IoT Chromecast
  - action: forward
    services:
      - "_googlecast._tcp.local"
    src: "*"
    dst: "*"

# Database persistence for tracking packets
tracking:
  enabled: true
  db_path: "/var/lib/mdns-sieve/responses.db"
  flush_interval_seconds: 5
  retention_days: 7
  max_records: 50000

# Embedded Web GUI / JSON API
web_server:
  enabled: true
  host: "0.0.0.0"
  port: 8080
```

### 3. Run the Daemon
The daemon requires the `CAP_NET_RAW` capability to bind sockets to specific network interfaces using `SO_BINDTODEVICE`.

You can grant this capability to the compiled binary using `setcap` to run without root privileges:
```bash
sudo setcap cap_net_raw+ep rs/target/release/mdns-sieve
./rs/target/release/mdns-sieve --config config.yaml
```

Alternatively, you can run the daemon directly using `sudo`:
```bash
sudo ./rs/target/release/mdns-sieve --config config.yaml
```

### 4. Access the Web GUI
Open `http://your_server:8080` in your browser to access the dashboard.

---

## Web Dashboard

`mdns-sieve` provides a responsive web interface (with dark and light mode themes) to inspect network activity in real time.

### Features

#### Live Dashboard & Network Traffic Graph
Displays real-time KPI counters and trend lines showing total, forwarded, partially forwarded, and dropped mDNS messages.

#### Message History Explorer
Provides a detailed, paginated log of received mDNS queries and responses:
* **Granular Dispositions**: Color-coded indicator dots (Forwarded, Partially Forwarded, Dropped) at both the packet level and individual question/resource-record level, with tooltips showing ingress and routed destination interfaces.
* **Expandable Packet Inspection**: Expand any message to inspect its individual questions and resource records (`Answer`, `Authority`, `Additional`), including decoded record data (`A`, `AAAA`, `PTR`, `SRV`, `TXT`, `CNAME`, `NS`, `NSEC`), TTLs, and copy-to-clipboard actions.
* **Multi-Facet Filtering**: Filter messages by query name, record name or data, source IP, ingress interface, destination interface, disposition, packet type, and time range.

#### Telemetry & SQLite Persistence
When tracking is enabled, the daemon persists traffic metrics to an SQLite database (default: `/var/lib/mdns-sieve/responses.db`).
* **In-Memory Buffering**: The system records metrics in-memory first to minimize disk writes, periodically flushing batch messages and records.
* **Automated Pruning**: Telemetry history is pruned based on configurable `retention_days` and `max_records` limits to bound database growth.
* **Shutdown Handling**: Catches termination signals (`SIGINT` and `SIGTERM`) to flush all pending memory buffers to disk before exiting.

#### Stats Reset & Database Purging
GUI controls allowing users to reset dashboard counters and purge SQLite tracking history.

---

## Project Structure

This repository is organized as follows:
* `rs/` — Rust package (Core reflector daemon, internal JSON API, and Web GUI).
  * `src/mdns/` — Custom binary mDNS parser with recursion pointer protection.
  * `src/config.rs` — YAML configuration rule validation and matching engine.
  * `src/reflector.rs` — Linux `SO_BINDTODEVICE` isolated sockets and recovery event loop.
  * `src/database.rs` — SQLite DatabaseManager for metrics persistence and automated pruning.
  * `src/server.rs` — `axum` HTTP server providing stats, message history queries, and the embedded Web GUI.
  * `src/main.rs` — CLI entrypoint, configuration loading, and signal handling.
* `pkg/apk/` — Alpine Linux packaging scripts and Docker build environments.
