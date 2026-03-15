#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime


# -----------------------------
# Helpers
# -----------------------------
def run_command(cmd: list[str]) -> str:
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    return p.stdout


def mac_oui(mac: str) -> str:
    mac = mac.strip().lower()
    parts = mac.split(":")
    return ":".join(parts[:3]).upper() if len(parts) >= 3 else ""


def extract_first(pattern: str, raw: str) -> str | None:
    m = re.search(pattern, raw, re.MULTILINE)
    return m.group(1).strip() if m else None


def extract_scan_report_target(raw: str) -> str | None:
    return extract_first(r"^Nmap scan report for (.+)$", raw)


def extract_network_distance(raw: str) -> str | None:
    return extract_first(r"^Network Distance:\s*(.+)$", raw)


def extract_service_info(raw: str) -> str | None:
    return extract_first(r"^Service Info:\s*(.+)$", raw)


def extract_mac_line(raw: str) -> tuple[str | None, str | None]:
    # Ex: MAC Address: D8:1F:12:3A:66:4D (Tuya Smart)
    m = re.search(
        r"^MAC Address:\s*([0-9A-Fa-f:]{17})(?:\s*\((.*?)\))?$",
        raw,
        re.MULTILINE
    )
    if not m:
        return None, None
    mac = m.group(1).upper()
    vendor = m.group(2).strip() if m.group(2) else None
    return mac, vendor


def extract_device_type(raw: str) -> str | None:
    return extract_first(r"^Device type:\s*(.+)$", raw)


def extract_running(raw: str) -> str | None:
    return extract_first(r"^Running:\s*(.+)$", raw)


def extract_os_details(raw: str) -> str | None:
    return extract_first(r"^OS details:\s*(.+)$", raw)


def extract_os_cpe(raw: str) -> str | None:
    return extract_first(r"^OS CPE:\s*(.+)$", raw)


def extract_ports(raw: str) -> list[str]:
    """
    Extrai apenas as linhas da tabela de portas.
    Exemplo:
      8009/tcp open  http    Amazon Whisperplay DIAL REST service
      9080/tcp open  glrpc?
    """
    lines = raw.splitlines()
    out = []
    in_table = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("PORT") and "STATE" in stripped and "SERVICE" in stripped:
            in_table = True
            continue

        if not in_table:
            continue

        # Fim da tabela principal
        if (
            stripped == ""
            or line.startswith("MAC Address:")
            or line.startswith("Device type:")
            or line.startswith("Running:")
            or line.startswith("OS CPE:")
            or line.startswith("OS details:")
            or line.startswith("Network Distance:")
            or line.startswith("Service Info:")
            or line.startswith("Host script results:")
            or line.startswith("OS and Service detection performed.")
            or line.startswith("Nmap done:")
            or line.startswith("No exact")
        ):
            break

        # Ignora linhas de scripts/banners que começam com |
        if stripped.startswith("|") or stripped.startswith("|_"):
            continue

        if re.match(r"^\d+\/\w+\s+\w+\s+\S+", stripped):
            out.append(stripped)

    return out


# -----------------------------
# TCP/IP stable fields from OS:SCAN fingerprint
# -----------------------------
def extract_tcpip_stable_from_os_scan(raw: str) -> dict:
    stable = {}

    # Junta todas as linhas OS:
    os_lines = []
    for line in raw.splitlines():
        if line.startswith("OS:"):
            os_lines.append(line[3:].strip())

    os_blob = "".join(os_lines)

    if not os_blob:
        return stable

    # P= dentro do SCAN(...)
    m = re.search(r"SCAN\([^\)]*%P=([^%)]*)", os_blob)
    if m:
        stable["P"] = m.group(1).strip()

    def grab(name: str):
        mm = re.search(rf"{name}\((.*?)\)", os_blob)
        return mm.group(1).strip() if mm else None

    for key in ["OPS", "WIN", "ECN", "U1", "IE"]:
        val = grab(key)
        if val:
            stable[key] = val

    return stable


# -----------------------------
# Optional application hints
# -----------------------------
def extract_fingerprint_strings_probe(raw: str) -> str | None:
    """
    Captura o primeiro probe listado em fingerprint-strings, se existir.
    Exemplo:
      | fingerprint-strings:
      |   FourOhFourRequest:
    """
    m = re.search(r"^\|\s*fingerprint-strings:\s*$", raw, re.MULTILINE)
    if not m:
        return None

    m2 = re.search(r"^\|\s{3}([A-Za-z0-9_-]+):\s*$", raw[m.end():], re.MULTILINE)
    return m2.group(1) if m2 else None


def extract_server_banner(raw: str) -> str | None:
    """
    Procura por 'Server: X' nas respostas capturadas pelo Nmap.
    """
    m = re.search(r"^\|\s+Server:\s*(.+)$", raw, re.MULTILINE)
    return m.group(1).strip() if m else None


# -----------------------------
# Host scripts stable
# -----------------------------
def extract_host_scripts_stable(raw: str) -> list[str]:
    lines = raw.splitlines()
    out = []
    in_scripts = False
    keep_current = False

    whitelist = {"smb2-security-mode"}

    for line in lines:
        if line.strip() == "Host script results:":
            in_scripts = True
            continue

        if not in_scripts:
            continue

        if line.startswith("Nmap done:"):
            break

        m = re.match(r"^\|\s*([a-zA-Z0-9_-]+):\s*$", line)
        if m:
            script_name = m.group(1)
            keep_current = script_name in whitelist
            if keep_current:
                out.append(f"| {script_name}:")
            continue

        if keep_current:
            # remove campos temporais
            if re.search(r"\bdate:\b", line, re.IGNORECASE):
                continue
            if re.search(r"\d{4}-\d{2}-\d{2}T", line):
                continue
            if line.startswith("|") or line.startswith("|_"):
                out.append(line.rstrip())

    return out


# -----------------------------
# Build NORM (unified)
# -----------------------------
def build_norm(raw: str) -> str:
    target = extract_scan_report_target(raw) or "<alvo>"
    ports = extract_ports(raw)

    dtype = extract_device_type(raw)
    running = extract_running(raw)
    os_cpe = extract_os_cpe(raw)
    osdet = extract_os_details(raw)

    out = []
    out.append(f"Nmap scan report for {target}")
    out.append("")

    out.append("Identity / platform:")
    if dtype:
        out.append(f"  device_type={dtype}")
    if running:
        out.append(f"  running={running}")
    if os_cpe:
        out.append(f"  os_cpe={os_cpe}")
    if osdet:
        out.append(f"  os_details={osdet}")
    out.append("")

    out.append("PORT    STATE SERVICE         VERSION")
    out.extend(ports if ports else ["<sem portas detectadas>"])
    out.append("")

    return "\n".join(out).strip() + "\n"

# -----------------------------
# Main
# -----------------------------
def main():
    if len(sys.argv) < 3:
        print("Uso:")
        print("  python3 nmap_snapshot.py <pasta_saida> <ip> [args do nmap...]")
        print("Exemplo:")
        print("  python3 nmap_snapshot.py snapshots 192.168.1.103 -T4 -sV -sC -O -Pn")
        sys.exit(1)

    out_dir = Path(sys.argv[1])
    ip = sys.argv[2]
    nmap_args = sys.argv[3:] or ["-T4", "-sV", "-sC", "-O", "-Pn"]

    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["nmap"] + nmap_args + [ip]
    raw = run_command(cmd)
    norm = build_norm(raw)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path = out_dir / f"nmap_{ip}_{ts}.raw.txt"
    norm_path = out_dir / f"nmap_{ip}_{ts}.norm.txt"

    raw_path.write_text(raw, encoding="utf-8", errors="ignore")
    norm_path.write_text(norm, encoding="utf-8", errors="ignore")

    print(f"[OK] RAW  -> {raw_path}")
    print(f"[OK] NORM -> {norm_path}")


if __name__ == "__main__":
    main()
