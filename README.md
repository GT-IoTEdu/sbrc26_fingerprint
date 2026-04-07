# IoT-ID: Deterministic Device Identity from Hybrid Network Fingerprinting

IoT-ID is a prototype tool for identifying IoT devices through deterministic fingerprints derived from TCP/IP stack characteristics.

The tool combines **active probing** and **passive traffic analysis** to extract stable network features, which are then canonicalized and hashed using SHA-256. The resulting fingerprint represents a reproducible identity of the device, independent of IP address and resilient to MAC address randomization.


## Presentation Requirements and Planning

This section describes the requirements and planning for the SBRC demonstration, including the necessary setup to effectively showcase the tool.

### Demonstration Requirements (Lab Setup)

* A Linux machine or Linux virtual machine connected to the same subnet as the target devices (bridge networking mode when applicable).
* Devices available on the same LAN (e.g., smart TVs, IoT devices, smartphones), preferably active during the demonstration.
* All tools listed in the **Dependencies** section properly installed and configured.
* Sufficient privileges (`sudo`) to perform packet capture and active probing.

### Presentation Plan

* **Network Discovery:**
  Identify active devices using `iot_net_scanner.py`, either across the entire network or targeting a specific IP range.

* **Fingerprint Generation:**
  Execute the fingerprinting pipeline using:
  `sudo python3 iot_id_fingerprint.py runs <TARGET_IP> --seconds <SECONDS> --iface <INTERFACE>`

  Explain the role of each parameter:

  * `<TARGET_IP>`: target device address
  * `<SECONDS>`: duration of packet capture
  * `<INTERFACE>`: network interface used for monitoring

* **Operational Requirements:**
  Clarify why root privileges and promiscuous mode are required:

  * Packet capture requires elevated permissions.
  * Promiscuous mode allows capturing all traffic on the network segment.

* **Virtual Machine Considerations:**
  If using a VM, ensure that the hypervisor is configured to allow promiscuous mode on the network interface (e.g., enabling “Allow All” or equivalent settings).

---

# Overview

IoT-ID implements a hybrid fingerprinting pipeline composed of:

1. Active scanning using Nmap
2. Controlled packet capture using dumpcap
3. TCP SYN probing via nping
4. Passive fingerprint extraction using p0f
5. TCP feature extraction from PCAP using tshark
6. Canonicalization of stable features
7. SHA-256 hash generation

The goal is to produce a **deterministic and reproducible device identity** based solely on network behavior.

---

# Repository Structure

- `iot_id_fingerprint.py` → Main fingerprinting pipeline
- `iot_net_scanner.py` → Network discovery utility
- `runs/` → Output directory (captures, logs, fingerprints)
- `requirements.txt` → Python dependencies
- `README.md` → Documentation

---

# Badges Considered

This artifact targets the following SBRC badges:

- **Available (SeloD)**
- **Functional (SeloF)**
- **Reusable / Sustainable (SeloS)**
- **Reproducible (SeloR)**

---

# Basic Information

## Execution Environment

- OS: Linux (Ubuntu 20.04+ recommended)
- Python: 3.8+
- Network: Local network (LAN)
- Privileges: `sudo` required for packet capture and scanning

## Hardware Requirements

- CPU: 2+ cores
- RAM: 4 GB or more
- Disk: at least 1 GB free

---

# Dependencies

## System Tools

| Tool        | Purpose |
|-------------|--------|
| nmap        | Active scanning and UPnP discovery |
| nping       | TCP SYN probing |
| dumpcap     | Packet capture |
| tshark      | TCP feature extraction |
| p0f         | Passive fingerprinting |

## Installation (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y nmap wireshark-common tshark p0f python3 python3-pip python3-venv
```

---

## Python Dependencies

```bash
pip install -r requirements.txt
```

---

# Security Considerations

⚠️ IoT-ID performs active probing and packet capture.

- Generates TCP SYN traffic
- Captures network packets (PCAP)
- May trigger IDS/IPS alerts

Recommendations:

- Use only in controlled environments
- Do not run on unauthorized networks
- Ensure compliance with institutional policies

---

# Installation

```bash
git clone https://github.com/GT-IoTEdu/sbrc26_fingerprint.git
cd sbrc26_fingerprint

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

---

# Minimal Working Example

## How to Find the Network Address of a Device

To discover devices on your local network, run:

 ```bash
  sudo python3 iot_net_scanner.py
```
## Expected outputs:
```bash
[*] Starting Network Scanner...
    (Full network scan)

=================================================================
DEVICE INVENTORY
=================================================================
IP: 192.168.59.106 | MAC: D0:76:02:F5:81:9C
   Name: Smart TV Pro
   Manufacturer: TCL
   Model Name: Smart TV Pro
   UDN: uuid:25f02330-1d54-ad02-544c-99ffb213ca35
   SERVER: UPnP/1.0, DLNADOC/1.50 Platinum/1.0.5.13
--------------------------------------------------
...
```

Run a basic fingerprint extraction:

```bash
sudo python3 iot_id_fingerprint.py runs <TARGET_IP> --seconds 60 --iface <INTERFACE>
```

## Expected outputs:

```bash
VirtualBox:~ sudo python3 iot_id_fingerprint.py runs 192.168.59.106 --seconds 60 --iface enp0s3
[*] Running Nmap ...
[*] UPnP identity detected ...
[*] Capturing PCAP with dumpcap (async) ...
[*] Probing common ports with nping SYN (ports=80,443,22,445,139,3389,8080,8443,9100,5357, count=3) ...
[*] Running p0f (native) (offline -r) ...
[*] Extracting SYN/SYN+ACK TCP features from PCAP via tshark ...

=== CANON_STRING ===
{"nmap":{"manufacturer":"TCL","model_name":"Smart TV Pro","name":"Smart TV Pro","server":"UPnP/1.0, DLNADOC/1.50 Platinum/1.0.5.13"},"p0f":{"extracted":{"server_synack_raw_sig_set":["4:64+0:0:1460:65535,0:mss:df:0"]}},"pcap_syn":{"mss":"1460","ttl":"64","window_size":"65535"}}

=== FINGERPRINT_HASH ===
e20c48257b98e86fa11d7c4444e7e5da7176a1b328719ea5f46f831951392d51

[OK] Saved:
  runs/192.168.59.106_20260324_214710/features_canon.json
  runs/192.168.59.106_20260324_214710/features_canon.txt
  runs/192.168.59.106_20260324_214710/fingerprint_sha256.txt

[OK] Bundle salvo em:
 /home/carregando/fullprint/runs/192.168.59.106_20260324_214710

[OK] Log de pipeline: runs/192.168.59.106_20260324_214710/fingerprint_pipeline.log

=== TIMING (rodada) ===
nmap              : 1m 36.79s
dumpcap_capture   : 1m 00.26s
nping_probe       : 29.11s
p0f_native        : 13.5 ms
tshark_syn_fallback: 2.01s
canon_plus_hash   : 0.8 ms
TOTAL             : 2m 39.10s
```
## Understanding the Generated Data
- `runs/` — root directory provided to the CLI; contains one subdirectory per execution (`<IP>_timestamp`) with all artifacts generated during that run.

- `features_canon.json` — human-readable JSON object containing the canonical subset (from `nmap`, `p0f`, and `pcap_syn`, depending on host type and policy).

- `features_canon.txt` — single-line file containing the **CANON_STRING** (compact JSON, UTF-8) used as input to the hash.

- `fingerprint_sha256.txt` — single-line file containing the SHA-256 hash (lowercase hexadecimal) of the canonical string.

- `fingerprint_pipeline.log` — detailed log of pipeline stages, execution times, and errors for debugging purposes.
---

# Experiments

This section describes how to reproduce the main claims of the paper.

---

## Claim 1 – Deterministic Fingerprints

**Objective:** Verify fingerprint stability across multiple executions (E.g.5).

### Procedure

# Usage

```bash
cd /fingerprint
chmod +x fingerprint_subnet.sh
./fingerprint_subnet.sh
```
# Output

The tool generates:

- PCAP capture
- `fingerprint.json`
- Canonical feature representation
- SHA-256 fingerprint
- Logs

By default the script runs **5 fingerprint passes per discovered IP** (folders get distinct timestamps each time). Use `-r N` to change the count (e.g. `-r 1` for a single pass per host).

The table presents the devices evaluated in the study, including their categories, manufacturers, models, and the respective quantities used in the tests.

| Device        | Manufacturer         | Model                      | Qty. |
|---------------|----------------------|----------------------------|------|
| Game Console  | Microsoft            | Xbox One                   | 1    |
| IP Camera     | TP-Link              | C500 (Model A)             | 3    |
| IP Camera     | Vlx LED EXcelente    | Speed Dome Solar (Model B) | 1    |
| Router        | FiberHome            | HG6143D                    | 1    |
| Router        | TP-Link              | EC220-G5                   | 1    |
| Smart Bulb    | Avant NEO            | RGB E27                    | 1    |
| Smart TV      | TCL                  | UnionTV                    | 1    |
| Smart TV      | TCL                  | Smart TV Pro               | 1    |
| Smart TV      | Samsung              | UN32J4303                  | 2    |
| Smart TV      | Samsung              | QN55Q60TAGXZD              | 1    |
| TV Box        | Xiaomi               | MiTV-AESP0                 | 1    |
| Wi-Fi Printer | HP                   | Deskjet 4640               | 1    |

### Result Fingerprint

- Identical SHA-256 fingerprints across runs

| Device                     | SHA-256 Fingerprint                                              |
|----------------------------|------------------------------------------------------------------|
| TV TCL (UnionTV)           | 994f131342176c20415565dab0adf2666b160422d3df1511c0a37ae135985add |
| Router FiberHome           | 14407342dc69a801f52f6cead97d00e5260b7206072f145e6fde19e07cb1f157 |
| Smart Bulb                 | 993e9afc860d624a332822679ea4efc3490c2734ba84ad160c8d36abf0d546f7 |
| TV TCL (Smart TV Pro)      | e20c48257b98e86fa11d7c4444e7e5da7176a1b328719ea5f46f831951392d51 |
| TV Samsung (1)             | 1f4e8c4af2be567b929cf5b7409c57d648ea062262eeab566e11e32c1b437e94 |
| TV Xiaomi                  | 6397f4729927379fde73d5c1ea234ef1070d3785b4f271c562fa4cb688be2d48 |
| TV Samsung 55"             | 410528d091cb14cea300d79e74348087fc3a1b351584c919650c3a6f24ec18d1 |
| Printer                    | 93ef878c8f2de4eab5a5c780b1dc146d28df337116d8e93019bd9f4cc78c41df |
| Xbox One                   | 50f1736613c079a70b2d094c680cd8f9027adeb34ca7e90e7c4322a73492eb01 |
| TV Samsung (2)             | 1f4e8c4af2be567b929cf5b7409c57d648ea062262eeab566e11e32c1b437e94 |
| Router TP-Link             | dce0ee76d22f60bec93ce4f6478a9ffe439b2b6e914bafbafe0048685402b2cc |
| IP Camera Model A (1)      | c61f28839b696b65307cef2db341e976fadf10012d9c0f01f6a490b1e3e5742f |
| IP Camera Model A (2)      | c61f28839b696b65307cef2db341e976fadf10012d9c0f01f6a490b1e3e5742f |
| IP Camera Model A (3)      | c61f28839b696b65307cef2db341e976fadf10012d9c0f01f6a490b1e3e5742f |
| IP Camera Model B          | 5b60133e2971f571f7a4ceadd55041a78771b65189e64c0f891eb687ab37bc74 |
---


### Expected Result

- Identical SHA-256 fingerprints across executions for the same device

---




# Reproducibility Notes

- Experiments should be executed in a stable network environment  
- Device activity may influence captured traffic  
- It is recommended to repeat experiments under similar network conditions  
- To obtain the same SHA-256 fingerprint, the device must have identical hardware and software configurations, as listed in the device table.
---

Full reproducibility, in the strict sense, is not entirely achievable in this context, as the experiments depend on **physical IoT devices**, which cannot be perfectly replicated across different environments. Identical fingerprints can only be reproduced when using the **same devices**.

To address this limitation, the following validation strategy is adopted:

- Use available IoT or networked devices in the local network  
- Ensure devices are **network-visible**  
- Execute the IoT-ID pipeline across multiple devices  

Expected behavior:

- The same device produces a **stable fingerprint**  
- Different devices produce **distinct fingerprints**  

This approach ensures **functional and comparative reproducibility**, even without identical hardware.

---

# LICENSE

Copyright (c) 2025 RNP – National Research and Education Network (Brazil)

This code was developed under the Hackers do Bem Program and is licensed under the terms of the BSD License. It may be freely used, modified, and distributed, including for commercial purposes, provided that this copyright notice is retained.
This software is provided "as is", without any warranty, express or implied, including, but not limited to, warranties of merchantability or fitness for a particular purpose. RNP and the authors shall not be held liable for any damages or losses arising from the use of this software.
