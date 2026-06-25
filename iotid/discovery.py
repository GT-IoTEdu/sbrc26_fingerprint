"""
Identidade do dispositivo via nmap/UPnP e classificação host_kind (iot/mobile).

Consome a descoberta UPnP/SSDP partilhada (`iotid.upnp`) e adiciona a varredura
nmap específica do pipeline (`upnp-info` com sudo) e a sonda nmap leve usada no
modo mobile.
"""

from __future__ import annotations

import subprocess

from .tshark import norm_passive_token
from .upnp import fetch_upnp_raw, sorted_ssdp_locations, ssdp_probe


def fetch_upnp_description(url: str):
    """
    Vista normalizada do device-desc.xml para o pipeline: apenas
    friendlyName/manufacturer/modelName, com strip e vazio convertido em None.
    """
    raw = fetch_upnp_raw(url)
    if raw is None:
        return None
    return {
        "friendlyName": raw["friendlyName"].strip() or None,
        "manufacturer": raw["manufacturer"].strip() or None,
        "modelName": raw["modelName"].strip() or None,
    }


def nmap_upnp_scan(target: str):
    """
    Usa Nmap UPnP focado no alvo.
    """
    try:
        cmd = ["sudo", "nmap", "-sV", "-Pn", "--script", "upnp-info", target]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return {}, ""

    devices = {target: {}}

    for line in out.splitlines():
        line = line.strip()

        if "Server:" in line:
            devices[target]["server"] = line.split("Server:", 1)[-1].strip()

        if "Manufacturer:" in line:
            devices[target]["manufacturer"] = line.split("Manufacturer:", 1)[-1].strip()

        if "Model Name:" in line:
            devices[target]["model_name"] = line.split("Model Name:", 1)[-1].strip()

        if "Name:" in line:
            devices[target]["name"] = line.split("Name:", 1)[-1].strip()

    return devices, out


def nmap_mobile_scan(target: str) -> dict:
    """
    Sonda leve de portas comuns em telemóveis (SSH ADB RTSP, etc.) para banners / -sV.
    """
    try:
        cmd = [
            "sudo",
            "nmap",
            "-Pn",
            "-sV",
            "--version-intensity",
            "1",
            "-p",
            "22,5555,8080,554,62078,843,5228",
            "-script-timeout",
            "25s",
            "--host-timeout",
            "95s",
            target,
        ]
        raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=125)
    except subprocess.TimeoutExpired:
        return {"error": "nmap_mobile_timeout", "service_lines": []}
    except Exception as e:
        return {"error": str(e), "service_lines": []}

    hints = []
    for line in raw.splitlines():
        t = line.strip()
        if "/tcp" in t or "/udp" in t:
            if any(x in t for x in (" open ", "open ", "Open ", "/tcp", "/udp")):
                hints.append(norm_passive_token(t, 400))
    return {
        "service_lines": sorted(set(hints))[:30],
        "raw_chars": len(raw),
    }


def infer_host_kind(nmap_block: dict) -> str:
    """
    'iot' se UPnP/Nmap preencheu fabricante ou modelo; caso contrário tratamos como
    host 'mobile' (telemóvel, tablet, portátil, router sem UPnP, etc.).
    """
    if not isinstance(nmap_block, dict):
        return "mobile"
    m = (nmap_block.get("manufacturer") or "").strip()
    mo = (nmap_block.get("model_name") or "").strip()
    if m or mo:
        return "iot"
    return "mobile"


def collect_upnp_identity(target_ip: str):
    """
    Retorna o bloco final que entrará em bundle['nmap'].
    Mantém apenas:
      - server
      - name
      - manufacturer
      - model_name
    """
    final = {
        "report_for": target_ip,
        "server": None,
        "name": None,
        "manufacturer": None,
        "model_name": None,
    }

    nmap_raw, nmap_stdout = nmap_upnp_scan(target_ip)
    ssdp_raw = ssdp_probe(target_ip)

    ninfo = nmap_raw.get(target_ip, {})
    if ninfo.get("server"):
        final["server"] = ninfo["server"]
    if ninfo.get("name"):
        final["name"] = ninfo["name"]
    if ninfo.get("manufacturer"):
        final["manufacturer"] = ninfo["manufacturer"]
    if ninfo.get("model_name"):
        final["model_name"] = ninfo["model_name"]

    sinfo = ssdp_raw.get(target_ip)
    if sinfo:
        if not final["server"] and sinfo.get("srv"):
            final["server"] = sinfo["srv"]

        locs = sinfo.get("locs") or set()
        for url in sorted_ssdp_locations(locs if isinstance(locs, set) else set(locs)):
            xml = fetch_upnp_description(url)
            if not xml:
                continue

            if not final["name"] and xml.get("friendlyName"):
                final["name"] = xml["friendlyName"]

            if not final["manufacturer"] and xml.get("manufacturer"):
                final["manufacturer"] = xml["manufacturer"]

            if not final["model_name"] and xml.get("modelName"):
                final["model_name"] = xml["modelName"]

            if all([final["server"], final["name"], final["manufacturer"], final["model_name"]]):
                break

    return final, nmap_stdout


def ssdp_results_to_jsonable(ssdp_raw: dict) -> dict:
    """Converte resultado de ssdp_probe para JSON (sets → listas ordenadas)."""
    out: dict = {}
    for ip, data in (ssdp_raw or {}).items():
        locs = data.get("locs") or set()
        loc_list = sorted(locs) if isinstance(locs, set) else list(locs)
        out[ip] = {"locs": loc_list, "srv": data.get("srv")}
    return out
