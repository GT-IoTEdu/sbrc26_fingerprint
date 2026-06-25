#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iot_net_scanner.py

Inventario leve da LAN (sem captura PCAP). Combina tres fontes para listar
dispositivos com IP/MAC e identidade UPnP:

  - ARP    : tabela `ip neighbor` (IP -> MAC)
  - SSDP   : M-SEARCH multicast + leitura do device-desc XML
  - Nmap   : script upnp-info (alvo unico) ou broadcast-upnp-info (rede toda)

Uso:
  python iot_net_scanner.py            # rede inteira
  python iot_net_scanner.py 192.168.1.50   # apenas um alvo
"""

from __future__ import annotations

import re
import subprocess
import sys

from upnp_discovery import fetch_upnp_description, nmap_upnp_scan, sort_locations, ssdp_probe


def nmap_broadcast() -> dict:
    """broadcast-upnp-info para descobrir varios dispositivos de uma vez."""
    try:
        out = subprocess.check_output(["nmap", "-T4", "--script", "broadcast-upnp-info"],
                                      text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return {}

    devices: dict = {}
    current = None
    labels = {"Server:": "server", "Manufacturer:": "manufacturer",
              "Model Name:": "model_name", "Name:": "name"}
    for line in out.splitlines():
        line = line.strip()
        m = re.search(r"Location:.*http://([\d.]+):", line)
        if m:
            current = m.group(1)
            devices.setdefault(current, {})
        if current:
            for label, key in labels.items():
                if label in line:
                    devices[current][key] = line.split(label, 1)[-1].strip()
    return devices


def arp_table() -> dict:
    """Mapeia IP -> MAC a partir de `ip neighbor`."""
    table: dict = {}
    try:
        out = subprocess.run(["ip", "neighbor"], capture_output=True, text=True).stdout
    except Exception:
        return table
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line)
        if ip and mac:
            table[ip.group(1)] = mac.group(0).upper()
    return table


def enrich_with_ssdp(ip: str, device: dict, ssdp_entry: dict) -> None:
    """Completa campos faltantes do device com SSDP/XML, evitando lixo generico."""
    device.setdefault("server", None)
    if not device["server"]:
        device["server"] = ssdp_entry.get("srv")
    for url in sort_locations(ssdp_entry.get("locs") or []):
        xml = fetch_upnp_description(url)
        if not xml:
            continue
        generic = ("Microsoft" in (xml.get("manufacturer") or "")
                   or "Windows Media Player" in (xml.get("modelName") or ""))
        if generic and device.get("manufacturer"):
            continue
        device["udn"] = device.get("udn") or xml.get("udn")
        device["name"] = device.get("name") or xml.get("friendlyName")
        device["manufacturer"] = device.get("manufacturer") or xml.get("manufacturer")
        device["model_name"] = device.get("model_name") or xml.get("modelName")


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"[*] Scanner de rede ({'alvo ' + target if target else 'rede completa'}) ...")

    ssdp = ssdp_probe(target)
    if target:
        nmap_info, _ = nmap_upnp_scan(target, sudo=False)
        nmap_devices = {target: nmap_info} if nmap_info else {target: {}}
    else:
        nmap_devices = nmap_broadcast()
    arp = arp_table()

    if target:
        ips = [target]
    else:
        ips = sorted(set(ssdp) | set(nmap_devices) | set(arp),
                     key=lambda x: tuple(int(p) for p in x.split(".")))

    print("\n" + "=" * 65 + "\nINVENTARIO DE DISPOSITIVOS\n" + "=" * 65)
    for ip in ips:
        if not target and ip not in ssdp and ip not in nmap_devices:
            continue
        device = dict(nmap_devices.get(ip, {}))
        if ip in ssdp:
            enrich_with_ssdp(ip, device, ssdp[ip])

        print(f"IP: {ip} | MAC: {arp.get(ip, 'Unknown')}")
        if device.get("name"):
            print(f"   Nome: {device['name']}")
        print(f"   Manufacturer: {device.get('manufacturer') or 'Unknown'}")
        print(f"   Model Name: {device.get('model_name') or 'Unknown'}")
        if device.get("udn"):
            print(f"   UDN: {device['udn']}")
        if device.get("server"):
            print(f"   SERVER: {device['server']}")
        print("-" * 50)


if __name__ == "__main__":
    main()
