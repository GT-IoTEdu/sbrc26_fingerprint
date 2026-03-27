# IoT TCP Fingerprinting Tool

Prototype tool for identifying IoT devices based on characteristics of the TCP/IP stack.

The tool performs active probing and passive packet capture to extract stable TCP features from a device.  
These features are canonicalized and transformed into a SHA-256 hash, generating a fingerprint that reflects the device's network stack behavior.

## Overview

The fingerprint generation process follows these steps:

1. Active scan of the target device using Nmap
2. Short packet capture of the device traffic
3. Trigger TCP responses using SYN probes
4. Extract TCP/IP features from the captured packets
5. Canonicalize stable features
6. Generate a SHA-256 fingerprint

## Requirements

### System tools (must be on `PATH` or configured)

| Tool | Role |
|------|------|
| **nmap** | UPnP discovery (`sudo nmap` is used for some scripts) |
| **nping** | SYN probes (usually bundled with Nmap) |
| **dumpcap** | PCAP capture (Wireshark / `wireshark-common`) |
| **tshark** | TCP option extraction from PCAP |
| **p0f** | Offline TCP fingerprint from PCAP |
| **sudo** | Required on Linux for `nmap` and often for `dumpcap` / capture |

### Python

- **Python 3.8+**
- Dependencies listed in `requirements.txt` (see [Installation](#installation)).

---

## Installation

### 1. Clone and enter the repository

```bash
git clone https://github.com/GT-IoTEdu/fingerprint.git
cd fingerprint
```

### 2. Python virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate   # Linux / macOS
# .venv\Scripts\activate    # Windows CMD/PowerShell
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Install system packages (example: Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y nmap wireshark-common tshark p0f python3 python3-pip python3-venv
```

- **dumpcap** and **tshark** come from `wireshark-common`.
- **nping** is included with the **nmap** package on most distributions.
- Grant your user capture rights (optional alternative to always using `sudo`):

  ```bash
  sudo usermod -aG wireshark "$USER"
  # log out and back in
  ```

  Many workflows still run the main script with `sudo` because **Nmap UPnP** invokes `sudo nmap` internally.


### 4. Verify tools

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

Run from the repository.


## Usage (quick reference)

```bash
sudo python3 iot_id_fingerprint.py runs 192.168.1.100 --seconds 60 --iface "Wi-Fi"
```

Parameters:

- `runs` → output directory  
- `target IP` → device to fingerprint 
- `seconds` → capture duration  
- `iface` → network interface  

---

## Output

The tool generates:

- Packet capture (PCAP)
- `fingerprint.json` (full bundle)
- `features_canon.json` / `features_canon.txt` (canonical object and string)
- `fingerprint_sha256.txt` (hex digest)
- `fingerprint_pipeline.log` (per-run logging when using the main script)

## Utils

### Finding the capture interface


```bash
dumpcap -D
```

Each line is numbered; the name is the token after the first dot (e.g. `eth0`, `wlan0`, `enp0s3`).

 you can see which interface carries the default route:

```bash
ip route get 8.8.8.8
```

### Network inventory (`iot_scanner.py`)


```bash
python3 iot_scanner.py                    # whole network
```

**Note:** MAC addresses are read from `ip neighbor` on Linux; on other systems they may show as `Unknown`. Some Nmap UPnP modes may need appropriate privileges.

Example output:

```
[*] Iniciando Scanner de Rede...
    (Rede completa)  

=================================================================
INVENTÁRIO DE DISPOSITIVOS
=================================================================
IP: 192.168.59.1 | MAC: 0A:00:27:00:00:17
   Manufacturer: MyPublicWiFi - Your Login
   Model Name: Unknown
--------------------------------------------------
IP: 192.168.59.2 | MAC: 08:00:27:6F:8B:95
   Nome: _gateway
   Manufacturer: pfSense - Login
   Model Name: Unknown
--------------------------------------------------
IP: 192.168.59.106 | MAC: D0:76:02:F5:81:9C
   Nome: Android
   Manufacturer: TCL
   Model Name: Smart TV Pro
   UDN: uuid:ff3e3ffd-7577-497c-bbbb-bffc6fe2feff
   SERVER: UPnP/1.0, DLNADOC/1.50 Platinum/1.0.5.13
--------------------------------------------------
```
