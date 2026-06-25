#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared SSDP, UPnP and local-network discovery utilities."""

from __future__ import annotations

import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

SSDP_TIMEOUT = 2.0


def fetch_upnp_description(url: str) -> Optional[Dict[str, Optional[str]]]:
    """Fetch a UPnP device-description XML and return normalized identity fields."""
    try:
        response = requests.get(url, timeout=1.5)
        if response.status_code != 200:
            return None

        root = ET.fromstring(response.content)
        ns = {"ns": "urn:schemas-upnp-org:device-1-0"}
        device = root.find("ns:device", ns)
        if device is None:
            return None

        return {
            "friendlyName": _clean_xml_text(device.findtext("ns:friendlyName", "", ns)),
            "manufacturer": _clean_xml_text(device.findtext("ns:manufacturer", "", ns)),
            "modelName": _clean_xml_text(device.findtext("ns:modelName", "", ns)),
            "udn": _clean_xml_text(device.findtext("ns:UDN", "", ns)),
        }
    except Exception:
        return None


def _clean_xml_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


def nmap_upnp_scan(target: Optional[str] = None, sudo: bool = False) -> Tuple[Dict[str, Dict[str, str]], str]:
    """Run nmap UPnP discovery and parse a compact identity block per IP."""
    try:
        prefix = ["sudo"] if sudo else []
        if target:
            cmd = prefix + ["nmap", "-sV", "-Pn", "--script", "upnp-info", target]
        else:
            cmd = prefix + ["nmap", "-T4", "--script", "broadcast-upnp-info"]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return {}, ""

    devices: Dict[str, Dict[str, str]] = {target: {}} if target else {}
    current_ip = target

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not target:
            ip_match = re.search(r"Location:.*http://([\d\.]+):", line)
            if ip_match:
                current_ip = ip_match.group(1)
                devices[current_ip] = {}

        if target and current_ip and current_ip not in devices:
            devices[current_ip] = {}

        if current_ip and current_ip in devices:
            _parse_nmap_identity_line(devices[current_ip], line)

    return devices, output


def _parse_nmap_identity_line(device: Dict[str, str], line: str) -> None:
    if "Server:" in line:
        device["server"] = line.split("Server:", 1)[-1].strip()
    if "Manufacturer:" in line:
        device["manufacturer"] = line.split("Manufacturer:", 1)[-1].strip()
    if "Model Name:" in line:
        device["model_name"] = line.split("Model Name:", 1)[-1].strip()
    if "Name:" in line:
        device["name"] = line.split("Name:", 1)[-1].strip()


def sorted_ssdp_locations(locations: Iterable[str]) -> List[str]:
    """Return a stable order for device-description URLs announced via SSDP."""
    def sort_key(url: str) -> tuple:
        try:
            parsed = urlparse(url)
            port = parsed.port
            if port is None:
                port = 80 if (parsed.scheme or "http") in ("http", "") else 443
            return (port, parsed.path or "", url.lower())
        except Exception:
            return (99999, "", url)

    return sorted(locations, key=sort_key)


def ssdp_probe(target: Optional[str] = None, timeout: float = SSDP_TIMEOUT) -> Dict[str, Dict[str, Any]]:
    """Send a multicast M-SEARCH and collect LOCATION/SERVER responses."""
    message = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST:239.255.255.250:1900",
        'MAN:"ssdp:discover"',
        "MX:2",
        "ST:ssdp:all",
        "",
        "",
    ]).encode()

    results: Dict[str, Dict[str, Any]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(message, ("239.255.255.250", 1900))
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if target and ip != target:
                    continue

                content = data.decode(errors="ignore")
                location = re.search(r"LOCATION:\s*(http://[^\r\n]+)", content, re.IGNORECASE)
                server = re.search(r"SERVER:\s*([^\r\n]+)", content, re.IGNORECASE)

                if ip not in results:
                    results[ip] = {"locs": set(), "srv": None}
                if location:
                    results[ip]["locs"].add(location.group(1).strip())
                if server:
                    results[ip]["srv"] = server.group(1).strip()
            except socket.timeout:
                break
    finally:
        sock.close()

    return results


def collect_upnp_identity(target_ip: str) -> Tuple[Dict[str, Optional[str]], str]:
    """Collect the stable UPnP/Nmap identity block used by the raw fingerprint bundle."""
    final: Dict[str, Optional[str]] = {
        "report_for": target_ip,
        "server": None,
        "name": None,
        "manufacturer": None,
        "model_name": None,
    }

    nmap_raw, nmap_stdout = nmap_upnp_scan(target_ip, sudo=True)
    ssdp_raw = ssdp_probe(target_ip)

    nmap_info = nmap_raw.get(target_ip, {})
    _fill_missing(final, "server", nmap_info.get("server"))
    _fill_missing(final, "name", nmap_info.get("name"))
    _fill_missing(final, "manufacturer", nmap_info.get("manufacturer"))
    _fill_missing(final, "model_name", nmap_info.get("model_name"))

    ssdp_info = ssdp_raw.get(target_ip)
    if ssdp_info:
        _fill_missing(final, "server", ssdp_info.get("srv"))
        for url in sorted_ssdp_locations(ssdp_info.get("locs") or set()):
            xml = fetch_upnp_description(url)
            if not xml:
                continue
            _fill_missing(final, "name", xml.get("friendlyName"))
            _fill_missing(final, "manufacturer", xml.get("manufacturer"))
            _fill_missing(final, "model_name", xml.get("modelName"))
            if all([final["server"], final["name"], final["manufacturer"], final["model_name"]]):
                break

    return final, nmap_stdout


def _fill_missing(target: Dict[str, Optional[str]], key: str, value: Optional[str]) -> None:
    if not target.get(key) and value:
        target[key] = value


def ssdp_results_to_jsonable(ssdp_raw: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Convert ssdp_probe results to JSON-safe values."""
    output = {}
    for ip, data in (ssdp_raw or {}).items():
        locations = data.get("locs") or set()
        if isinstance(locations, set):
            loc_list = sorted(locations)
        else:
            loc_list = list(locations)
        output[ip] = {"locs": loc_list, "srv": data.get("srv")}
    return output


def get_arp_table() -> Dict[str, str]:
    """Return the local ARP/neighbor table as IP -> MAC."""
    table = {}
    try:
        result = subprocess.run(["ip", "neighbor"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line)
            if ip and mac:
                table[ip.group(1)] = mac.group(0).upper()
    except Exception:
        pass
    return table
