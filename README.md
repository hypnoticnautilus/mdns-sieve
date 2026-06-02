# mdns-sieve

`mdns-sieve` is a lightweight, dependency-free Multicast DNS (mDNS) reflector and filtering daemon. It allows you to safely forward mDNS queries and responses across multiple isolated network interfaces (subnets/VLANs) while using fine-grained glob-style rules to control exactly which services and hostnames are visible across zones.

Designed specifically for low-end hardware and resource-constrained environments (like OpenWrt routers and Raspberry Pis), the codebase is built to be ultra-robust, self-recovering, and completely dependency-free.

---

## Why Deploy `mdns-sieve` on Your Network?

Traditional mDNS reflectors (like Avahi's reflector mode or `mdns-repeater`) operate as simple "blind mirrors"—they repeat all mDNS packets across all interfaces. In segmented home or enterprise environments containing untrusted IoT devices, this introduces critical security and performance issues.

`mdns-sieve` addresses these concerns by providing:

### 1. Prevention of Network Reconnaissance (Scanning)
A compromised IoT device (such as a smart plug, IP camera, or smart TV) is a common entry point for attackers. Once compromised, attackers scan the network using mDNS queries.
* **Without Filtering:** A query looking for servers, workstations, or file shares is reflected to your trusted network. Your personal computers and NAS devices respond, providing the attacker with a complete map of your trusted devices and IPs.
* **With mdns-sieve:** You can explicitly define rule policies that prevent mDNS queries originating from the IoT network from ever reaching your trusted interfaces. Your high-value devices remain invisible.

### 2. Mitigation of Service Spoofing and Cache Poisoning
mDNS is unauthenticated, meaning clients trust any response they hear on the network.
* **Without Filtering:** A compromised device on the IoT VLAN can broadcast fake responses claiming to be your local network printer or file share. Laptops on the trusted VLAN may route sensitive print jobs or credentials directly to the attacker.
* **With mdns-sieve:** Unsolicited advertisements/answers from the IoT network are blocked from entering your trusted zone unless explicitly whitelisted.

### 3. Reduced Attack Surface on Trusted Devices
Many operating systems run background services that automatically respond to mDNS queries (even if their port-level firewalls block incoming connections). Blocking incoming queries from untrusted segments prevents your trusted machines from leaking their presence or service versions.

### 4. Reduced Wi-Fi Multicast Noise (Better Battery Life)
IoT devices are notoriously chatty, broadcasting state advertisements constantly. Since multicast Wi-Fi frames are transmitted at slow baseline rates, this eats up airtime. Blocking these unsolicited packets at the reflector prevents them from flooding your trusted Wi-Fi, saving battery life and CPU cycles on your phones and laptops.

---

## Project Structure

This repository is organized as follows:
* `py/` — Production-grade Python 3.10+ package.
  * `src/mdns_sieve/mdns_parser.py` — Custom binary mDNS parser with recursion pointer protection.
  * `src/mdns_sieve/config.py` — YAML configuration rule validation and matching engine.
  * `src/mdns_sieve/reflector.py` — Linux `SO_BINDTODEVICE` isolated sockets and recovery event loop.
  * `src/mdns_sieve/main.py` — CLI entrypoint, logging levels, and signal handling.
  * `tests/` — Mock-based unit and integration test suite.

---

## Quick Start (Python Version)

### 1. Build the Wheel
Navigate to the `py/` directory and compile the package:
```bash
cd py/
python3 -m venv .venv
.venv/bin/pip install tox
.venv/bin/pip wheel --no-deps -w dist .
```

### 2. Configure mdns-sieve
Create a `config.yaml` file to define your active interfaces and sieve rules:
```yaml
interfaces:
  - eth0   # Trusted LAN
  - wlan0  # IoT Wi-Fi

default_action: deny

rules:
  # Allow Trusted devices to cast to IoT Chromecast
  - action: allow
    services:
      - "_googlecast._tcp.local"
    src: "*"
    dst: "*"
```

### 3. Run the Daemon
Since the daemon manages raw multicast sockets and binds to protected port `5353`, it must be run with root privileges:
```bash
sudo .venv/bin/mdns-sieve --config config.yaml -vv
```
* Use `-v` to log denied/blocked packets.
* Use `-vv` to log both denied packets and successfully forwarded packets.
