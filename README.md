# IoT TCP Fingerprinting Tool

Prototype tool for identifying IoT devices based on TCP/IP stack characteristics.

This tool combines **active probing** and **passive packet capture** to extract stable TCP features from a device. These features are canonicalized and hashed using SHA-256, producing a fingerprint that reflects the device's network stack behavior.

---

## Overview

The fingerprint generation pipeline follows these steps:

1. Active scan of the target device using Nmap
2. Short packet capture of device traffic
3. Trigger TCP responses using SYN probes
4. Extract TCP/IP features from captured packets
5. Canonicalize stable features
6. Generate a SHA-256 fingerprint

---

## Requirements

### System Tools (must be available in `PATH`)

| Tool        | Role                                              |
| ----------- | ------------------------------------------------- |
| **nmap**    | UPnP discovery (some scripts use `sudo nmap`)     |
| **nping**   | SYN probes (bundled with Nmap)                    |
| **dumpcap** | PCAP capture (Wireshark / `wireshark-common`)     |
| **tshark**  | TCP option extraction from PCAP                   |
| **p0f**     | Offline TCP fingerprinting from PCAP              |
| **sudo**    | Required on Linux for scanning and packet capture |

---

### Python

* **Python 3.8+**
* Dependencies listed in `requirements.txt`

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/GT-IoTEdu/fingerprint.git
cd fingerprint
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate   # Linux / macOS
# .venv\Scripts\activate    # Windows

pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Install system dependencies (Ubuntu / Debian example)

```bash
sudo apt update
sudo apt install -y nmap wireshark-common tshark p0f python3 python3-pip python3-venv
```

Notes:

* `dumpcap` and `tshark` are included in `wireshark-common`
* `nping` is included with `nmap`
* Optional: allow packet capture without sudo

```bash
sudo usermod -aG wireshark "$USER"
# Log out and log back in
```

> ⚠️ Some workflows still require `sudo` because Nmap UPnP internally invokes privileged scans.

---

### 4. Verify installation

```bash
nmap --version
nping --version
dumpcap -v
tshark --version
p0f -h || true
python3 -c "import requests; print('ok')"
```

---

## Execution

Run commands from the repository root directory.

---

## Usage (Quick Reference)

```bash
sudo python3 iot_id_fingerprint.py runs 192.168.1.100 --seconds 60 --iface wlan0
```

### Parameters

* `runs` → Output directory
* `target IP` → Device to fingerprint
* `seconds` → Capture duration
* `iface` → Network interface

---

## Output

The tool generates:

* PCAP file (packet capture)
* `fingerprint.json` (complete data bundle)
* `features_canon.json` / `features_canon.txt`
* `fingerprint_sha256.txt` (final hash)
* `fingerprint_pipeline.log` (execution logs)

---

## Utilities

### Find Capture Interface

```bash
dumpcap -D
```

Interfaces are listed numerically. The interface name appears after the first dot (e.g., `eth0`, `wlan0`, `enp0s3`).

To identify the default route interface:

```bash
ip route get 8.8.8.8
```

---

### Network Inventory (`iot_scanner.py`)

```bash
python3 iot_scanner.py
```

* Scans the entire local network
* Uses `ip neighbor` for MAC address resolution (Linux)

> ⚠️ On non-Linux systems, MAC addresses may appear as `Unknown`.

---

### Example Output

```
[*] Starting Network Scanner...
    (Full Network)

=================================================================
DEVICE INVENTORY
=================================================================
IP: 192.168.59.1 | MAC: 0A:00:27:00:00:17
   Manufacturer: MyPublicWiFi - Your Login
   Model Name: Unknown
--------------------------------------------------
IP: 192.168.59.2 | MAC: 08:00:27:6F:8B:95
   Name: _gateway
   Manufacturer: pfSense - Login
   Model Name: Unknown
--------------------------------------------------
IP: 192.168.59.106 | MAC: D0:76:02:F5:81:9C
   Name: Smart TV Pro
   Manufacturer: TCL
   Model Name: Smart TV Pro
   UDN: uuid:ff3e3ffd-7577-497c-bbbb-bffc6fe2feff
   SERVER: UPnP/1.0, DLNADOC/1.50 Platinum/1.0.5.13
--------------------------------------------------
```

---

## Troubleshooting

### Device Not Detected in Scanner

If your device does not appear when running `iot_scanner.py` or during fingerprinting, check the following:

---

### ✔️ Quick Checklist

* [ ] Same Wi-Fi / LAN
* [ ] Correct interface (`--iface`)
* [ ] Running with `sudo`
* [ ] Device is powered on and active
* [ ] No network isolation enabled
* [ ] Correct IP address

---

### 1. Same Network Segment

The scanner only detects devices in the same local network.

```bash
ip a
```

Ensure your device IP matches the same subnet (e.g., `192.168.1.x`).

> ⚠️ Devices on VPNs, guest networks, or VLANs may not be visible.

---

### 2. Correct Network Interface

List interfaces:

```bash
dumpcap -D
```

Find active interface:

```bash
ip route get 8.8.8.8
```

Use it explicitly:

```bash
--iface wlan0
```

---

### 3. Firewall or Network Isolation

Some networks block device discovery:

* AP / Client isolation (Wi-Fi)
* Firewalls blocking:

  * ICMP (ping)
  * UPnP (UDP 1900)
  * TCP responses

Test connectivity:

```bash
ping <DEVICE_IP>
```

---

### 4. Device Inactive or in Standby

Some IoT devices sleep when idle.

**Solutions:**

* Wake the device (turn screen on, interact)
* Generate traffic (streaming, apps)
* Increase capture duration:

```bash
--seconds 120
```

---

### 5. Insufficient Permissions

Run with elevated privileges:

```bash
sudo python3 iot_scanner.py
```

Check dumpcap permissions:

```bash
getcap $(which dumpcap)
```

---

### 6. IP Address Changed (DHCP)

Rediscover devices:

```bash
ip neighbor
```

Or rescan:

```bash
python3 iot_scanner.py
```

---

### 7. Verify with Nmap

```bash
nmap -sn 192.168.1.0/24
```

If the device is not detected here, the issue is not with this tool.

---
