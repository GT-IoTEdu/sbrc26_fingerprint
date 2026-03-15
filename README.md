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

External tools required:

- nmap
- nping
- tshark
- dumpcap
- p0f

Python version:

- Python 3.8+

## Usage

Example:

```bash
sudo python3 bundle_snapshot.py runs 192.168.1.100 --seconds 60 --iface "Wi-Fi"
```

Parameters:

- `runs` → output directory  
- `target IP` → device to fingerprint  
- `seconds` → capture duration  
- `iface` → network interface  

## Output

The tool generates:

- Packet capture (PCAP)
- Extracted TCP/IP features
- Canonical fingerprint string
- SHA-256 device fingerprint

## Research Context

This tool is being developed as part of the **IoTEdu project**, aiming to explore techniques for identifying IoT devices through network fingerprinting.
