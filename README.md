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
- `iot_scanner.py` → Network discovery utility
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

Run a basic fingerprint extraction:

```bash
sudo python3 iot_id_fingerprint.py runs <TARGET_IP> --seconds 60 --iface <INTERFACE>
```

## Expected outputs:
[*] Running Nmap ...
[*] UPnP identity detected ...
[*] Capturing PCAP with dumpcap (async) ...
[*] Probing common ports with nping SYN ...
[*] Running p0f (native) (offline -r) ...
[*] Extracting SYN/SYN+ACK TCP features ...

=== CANON_STRING ===
{"nmap":{"manufacturer":"TCL","model_name":"Smart TV Pro","name":"Smart TV Pro","server":"UPnP/1.0, DLNADOC/1.50 Platinum/1.0.5.13"},"p0f":{"extracted":{"server_synack_raw_sig_set":["4:64+0:0:1460:65535,0:mss:df:0"]}},"pcap_syn":{"mss":"1460","ttl":"64","window_size":"65535"}}

=== FINGERPRINT_HASH ===
e20c48257b98e86fa11d7c4444e7e5da7176a1b328719ea5f46f831951392d51

- PCAP capture file
- `fingerprint.json`
- `features_canon.json`
- `fingerprint_sha256.txt`
- Execution logs

This confirms that the tool is correctly installed and operational.

---

# Experiments

This section describes how to reproduce the main claims of the paper.

---

## Claim 1 – Deterministic Fingerprints

**Objective:** Verify fingerprint stability across multiple executions.

### Procedure

```bash
for i in {1..5}; do
  sudo python3 iot_id_fingerprint.py runs 192.168.1.100 --seconds 60 --iface wlan0
done
```

### Expected Result

- Identical SHA-256 fingerprints across runs

---

## Claim 2 – Hybrid Fingerprinting Improves Discrimination

**Objective:** Evaluate the benefit of combining active and passive features.

### Procedure

Compare:

- Nmap-only features
- p0f-only features
- Hybrid pipeline (IoT-ID)

### Expected Result

- Hybrid approach yields more distinctive fingerprints

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
- Recommended to repeat experiments under similar conditions

---

# LICENSE

