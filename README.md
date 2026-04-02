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

**Objective:** Verify fingerprint stability across multiple executions.

### Procedure

1. Identify a target IoT device in your local network:

```bash
python3 iot_scanner.py
```

2. Identify your active network interface:

```bash
dumpcap -D
```

or

```bash
ip route get 8.8.8.8
```

3. Run the fingerprinting process multiple times:

```bash
for i in {1..5}; do
  sudo python3 iot_id_fingerprint.py runs <TARGET_IP> --seconds 60 --iface <INTERFACE>
done
```

---

### Parameters

- `<TARGET_IP>` → IP address of a device in your local network  
- `<INTERFACE>` → active network interface (e.g., wlan0, eth0, enp0s3)

---

### Expected Result

- Identical SHA-256 fingerprints across executions for the same device

---

### Notes

- Replace `<TARGET_IP>` and `<INTERFACE>` according to your environment  
- Ensure the IoT device is active during all executions  
- Use the same network conditions to minimize variability 

---

# Usage

```bash
sudo python3 iot_id_fingerprint.py runs <TARGET_IP> --seconds <SECONDS> --iface <INTERFACE>
```

---

# Output

The tool generates:

- PCAP capture
- `fingerprint.json`
- Canonical feature representation
- SHA-256 fingerprint
- Logs

---

# Reproducibility Notes

- Experiments should be executed in a stable network environment  
- Device activity may influence captured traffic  
- It is recommended to repeat experiments under similar network conditions  

---

Full reproducibility, in the strict sense, is not entirely achievable in this context, as the experiments depend on **physical IoT devices**, which cannot be perfectly replicated across different environments. Identical fingerprints can only be reproduced when using the **same devices**.

To address this limitation, the following validation strategy is adopted:

- Use available IoT or networked devices in the local network  
- Ensure devices are **distinct and network-visible**  
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
