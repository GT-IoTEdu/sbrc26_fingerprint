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

### 4. Windows

- Install [Npcap](https://npcap.com/) or WinPcap for capture.
- Install **Wireshark** (includes **dumpcap** and **tshark**).
- Install **Nmap** for Windows (includes **nping** where available).
- **p0f**: the script can run **p0f via WSL** (`--wsl_distro` optional). Install p0f inside WSL and ensure PCAP paths are reachable.

### 5. Verify tools

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

Run from the repository directory (or ensure `canonicalize_features.py` sits next to `iot_id_fingerprint.py`).

### Single target (default mode)

```bash
sudo python3 iot_id_fingerprint.py runs 192.168.1.100 --seconds 60 --iface "Wi-Fi"
```

Arguments:

| Argument | Description |
|----------|-------------|
| `runs` | Output root directory (created if needed) |
| `192.168.1.100` | Target IP |
| `--seconds` | PCAP duration in seconds |
| `--iface` | Capture interface name or `dumpcap -D` index |
| `--canon_policy` | `stable` (default) or `rich` — controls extra fields in the canonical JSON before hashing |
| `--mode` | `target` (default) or `network` — SSDP discovery then fingerprint each host |
| `--log-console` | Mirror logs to stderr |
| `--wsl_distro` | Windows only: WSL distro name for p0f |

List interfaces:

```bash
dumpcap -D
```

### Network mode (SSDP discovery)

```bash
sudo python3 iot_id_fingerprint.py runs --mode network --seconds 60 --iface eth0
```

Produces `runs/scan_<timestamp>/` with per-host folders and `scan_summary.json`.

### Recompute hash from an existing bundle

```bash
python3 fingerprint_hash.py runs/192.168.1.100_20250101_120000/fingerprint.json --policy stable
```

### Canonicalize only (CLI)

```bash
python3 canonicalize_features.py runs/.../fingerprint.json --policy stable
```

---

## Usage (quick reference)

```bash
sudo python3 iot_id_fingerprint.py runs 192.168.1.100 --seconds 60 --iface "Wi-Fi"
```

Parameters:

- `runs` → output directory  
- `target IP` → device to fingerprint (omit in `--mode network`)  
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

## Research Context

This tool is being developed as part of the **IoTEdu project**, aiming to explore techniques for identifying IoT devices through network fingerprinting.
