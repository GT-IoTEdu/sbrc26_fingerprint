#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network inventory scanner used before running the fingerprint pipeline."""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

from .upnp import fetch_upnp_description, get_arp_table, nmap_upnp_scan as _shared_nmap_upnp_scan, ssdp_probe


def nmap_upnp_scan(target: Optional[str] = None) -> Dict[str, Dict[str, str]]:
    """Legacy scanner view of nmap UPnP results."""
    devices, _ = _shared_nmap_upnp_scan(target=target, sudo=False)
    return {
        ip: {
            **{key: value for key, value in data.items() if key != "model_name"},
            **({"model": data["model_name"]} if data.get("model_name") else {}),
        }
        for ip, data in devices.items()
    }


def main(argv: Optional[List[str]] = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    target_ip = argv[0] if argv else None

    target_label = f"Alvo: {target_ip}" if target_ip else "Rede completa"
    print("[*] Iniciando Scanner de Rede...")
    print(f"    ({target_label})")

    ssdp_raw = ssdp_probe(target_ip)
    nmap_raw = nmap_upnp_scan(target_ip)
    arp_table = get_arp_table()

    if target_ip:
        all_ips = [target_ip]
    else:
        all_ips = sorted(set(ssdp_raw.keys()) | set(nmap_raw.keys()) | set(arp_table.keys()), key=_ip_sort_key)

    print("\n" + "=" * 65 + "\nINVENTÁRIO DE DISPOSITIVOS\n" + "=" * 65)

    for ip in all_ips:
        if not target_ip and ip not in ssdp_raw and ip not in nmap_raw:
            continue
        _print_inventory_row(ip, nmap_raw.get(ip, {}), ssdp_raw.get(ip), arp_table)


def _print_inventory_row(ip: str, nmap_info: Dict[str, Any], ssdp_info: Optional[Dict[str, Any]], arp_table: Dict[str, str]) -> None:
    result = {
        "ip": ip,
        "mac": arp_table.get(ip, "Unknown"),
        "name": nmap_info.get("name"),
        "manufacturer": nmap_info.get("manufacturer", "Unknown"),
        "model": nmap_info.get("model", "Unknown"),
        "server": nmap_info.get("server"),
        "udn": None,
    }

    if ssdp_info:
        if not result["server"]:
            result["server"] = ssdp_info.get("srv")

        for url in ssdp_info.get("locs", set()):
            xml = fetch_upnp_description(url)
            if not xml:
                continue

            is_generic = "Microsoft" in (xml.get("manufacturer") or "") or "Windows Media Player" in (xml.get("modelName") or "")
            if not is_generic or result["manufacturer"] == "Unknown":
                result["udn"] = xml.get("udn", result["udn"])
                if not result["name"]:
                    result["name"] = xml.get("friendlyName")
                if result["manufacturer"] == "Unknown":
                    result["manufacturer"] = xml.get("manufacturer")
                if result["model"] == "Unknown":
                    result["model"] = xml.get("modelName")

    print(f"IP: {result['ip']} | MAC: {result['mac']}")
    if result["name"]:
        print(f"   Nome: {result['name']}")
    print(f"   Manufacturer: {result['manufacturer']}")
    print(f"   Model Name: {result['model']}")
    if result["udn"]:
        print(f"   UDN: {result['udn']}")
    if result["server"]:
        print(f"   SERVER: {result['server']}")
    print("-" * 50)


def _ip_sort_key(addr: str) -> tuple:
    try:
        return tuple(int(part) for part in addr.split("."))
    except ValueError:
        return (0,)


if __name__ == "__main__":
    main()
