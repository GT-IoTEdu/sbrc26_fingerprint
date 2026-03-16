# Project Guidelines

## Overview

IoT device TCP/IP fingerprinting tool (IoTEdu research). Performs active network probing to extract stable TCP stack features, canonicalizes them, and produces a deterministic SHA-256 fingerprint.

**Pipeline:**

```
nmap_snapshot.py → dumpcap (PCAP) + nping (SYN probes) → p0f analysis
    → feature extraction (tshark fallback) → canonicalize_features.py → fingerprint_hash.py
```

## Architecture

| File                       | Role                                                           |
| -------------------------- | -------------------------------------------------------------- |
| `bundle_snapshot.py`       | Orchestrator — runs the full pipeline end-to-end               |
| `nmap_snapshot.py`         | Nmap wrapper — produces `.raw.txt` and `.norm.txt`             |
| `canonicalize_features.py` | Normalizes bundle JSON into a stable, deterministic object     |
| `fingerprint_hash.py`      | Computes SHA-256 (or other hashlib algo) from canonical string |

Files are also usable standalone via CLI.

## Build and Run

**No pip install** — only Python standard library is used.

**Requirements (system tools, must be on PATH):**

- `nmap`, `nping`, `p0f`, `tshark`, `dumpcap` (Wireshark)
- Python 3.8+
- On Windows: WSL required for `p0f`, `tshark`, `nmap`, `nping`

**Full pipeline:**

```bash
# Requires elevated privileges for packet capture
sudo python3 bundle_snapshot.py <outdir> <target_ip> [options]

# Example
sudo python3 bundle_snapshot.py runs 192.168.1.100 --seconds 60 --iface "Wi-Fi"

# Windows with WSL
python bundle_snapshot.py runs 192.168.1.100 --iface "Wi-Fi" --wsl_distro Ubuntu
```

**Standalone tools:**

```bash
python3 nmap_snapshot.py snapshots 192.168.1.100 -T4 -sV -sC -O -Pn
python3 canonicalize_features.py fingerprint.json --policy stable --outdir out/
python3 fingerprint_hash.py bundle.json --policy stable --algo sha256 --debug
```

## Conventions

- **Cross-platform path handling**: Windows paths are converted to WSL (`/mnt/c/…`) via `win_to_wsl_path()`. Always use `pathlib.Path` for local paths.
- **Shell invocation**: Use the local `run(cmd)` / `run_bytes(cmd)` helpers (subprocess wrappers with error handling) — do not call `subprocess.run` directly in pipeline code.
- **Canonicalization is deterministic**: `dumps_canon()` always uses `sort_keys=True, separators=(",",":")`. Never change serialization without updating `fingerprint_hash.py`.
- **Two policies**: `stable` (conservative, no MTU, preferred) and `rich` (reserved). Default to `stable`.
- **Fallback chain**: p0f raw signatures → tshark SYN/SYN+ACK feature extraction. Never silently skip both.
- **Prune nulls**: `prune_none()` is called before serialization — do not add null/empty fields to the canonical object.
- **Output layout**: All run artifacts go under `<outdir>/<ip>_<timestamp>/` with sub-folders `nmap/`, `pcaps/`, `p0f/`.

## Key Output Files

```
runs/<ip>_<ts>/
├── nmap/nmap_*.raw.txt          # Raw nmap output
├── nmap/nmap_*.norm.txt         # Normalized, parseable nmap
├── pcaps/capture_*.pcap         # PCAP capture
├── p0f/p0f_*.raw.txt            # P0f analysis
├── fingerprint.json             # Full raw bundle
├── features_canon.json          # Canonicalized features
├── features_canon.txt           # Minified JSON (CANON_STRING)
└── fingerprint_sha256.txt       # Final SHA-256 hash
```

## Pitfalls

- `dumpcap` and raw-socket probes require `sudo` / elevated privileges.
- On Windows, `p0f` only works inside WSL — always pass `--wsl_distro` when running from Windows.
- The `is_placeholder_not_captured(x)` helper in `canonicalize_features.py` detects Portuguese-language placeholder strings left by the capture process — do not remove this check.
- Timing matters: `--probe_delay` must allow dumpcap to start before SYN probes are sent.
