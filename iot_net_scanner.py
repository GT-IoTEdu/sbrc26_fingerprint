#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
iot_net_scanner.py

Utilitário de inventário de rede: descobre dispositivos via SSDP/UPnP + Nmap e
cruza com a tabela ARP local para listar IP, MAC, fabricante e modelo.

Ferramenta independente do pipeline de fingerprint. Partilha a descoberta
UPnP/SSDP de baixo nível (`iotid.upnp`), mas mantém a sua própria varredura Nmap
(modo broadcast / sem sudo) e o seu esquema de saída (chave "model", campo UDN).
"""

from __future__ import annotations

import re
import subprocess
import sys

from iotid.upnp import fetch_upnp_raw, ssdp_probe


def nmap_upnp_scan(target=None):
    """Executa o Nmap focado no script de UPnP."""
    try:
        if target:
            # Para alvo único, o upnp-info é mais detalhado
            cmd = ["nmap", "-sV", "-Pn", "--script", "upnp-info", target]
        else:
            # Para rede inteira, o broadcast é mais rápido
            cmd = ["nmap", "-T4", "--script", "broadcast-upnp-info"]

        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return {}

    devices = {}
    current_ip = target if target else None

    for line in out.splitlines():
        line = line.strip()

        if not target:
            ip_match = re.search(r"Location:.*http://([\d\.]+):", line)
            if ip_match:
                current_ip = ip_match.group(1)
                devices[current_ip] = {}
        elif current_ip and current_ip not in devices:
            devices[current_ip] = {}

        if current_ip and current_ip in devices:
            if "Server:" in line: devices[current_ip]["server"] = line.split("Server:")[-1].strip()
            if "Manufacturer:" in line: devices[current_ip]["manufacturer"] = line.split("Manufacturer:")[-1].strip()
            if "Model Name:" in line: devices[current_ip]["model"] = line.split("Model Name:")[-1].strip()
            if "Name:" in line: devices[current_ip]["name"] = line.split("Name:")[-1].strip()
    return devices


def get_arp_table():
    """Mapeia IPs e MACs locais."""
    table = {}
    try:
        res = subprocess.run(["ip", "neighbor"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line)
            if ip and mac: table[ip.group(1)] = mac.group(0).upper()
    except Exception:
        pass
    return table


def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else None

    alvo_txt = f"Alvo: {target_ip}" if target_ip else "Rede completa"
    print("[*] Iniciando Scanner de Rede...")
    print(f"    ({alvo_txt})")

    ssdp_raw = ssdp_probe(target_ip, recv_bufsize=2048)
    nmap_raw = nmap_upnp_scan(target_ip)
    arp_table = get_arp_table()

    if target_ip:
        all_ips = [target_ip]
    else:
        all_ips = sorted(set(ssdp_raw.keys()) | set(nmap_raw.keys()) | set(arp_table.keys()),
                        key=lambda x: list(map(int, x.split('.'))))

    print("\n" + "=" * 65 + "\nINVENTÁRIO DE DISPOSITIVOS\n" + "=" * 65)

    for ip in all_ips:
        if not target_ip and ip not in ssdp_raw and ip not in nmap_raw: continue

        # Dados base vindos do Nmap (Geralmente mais precisos para hardware)
        nmap_info = nmap_raw.get(ip, {})
        res = {
            "ip": ip, "mac": arp_table.get(ip, "Unknown"),
            "name": nmap_info.get("name"),
            "manufacturer": nmap_info.get("manufacturer", "Unknown"),
            "model": nmap_info.get("model", "Unknown"),
            "server": nmap_info.get("server"),
            "udn": None
        }

        # Processamento SSDP e XML com filtro de prioridade
        if ip in ssdp_raw:
            if not res["server"]: res["server"] = ssdp_raw[ip]["srv"]

            for url in ssdp_raw[ip]["locs"]:
                xml = fetch_upnp_raw(url)
                if xml:
                    # Se o XML for genérico (Microsoft/DLNA), só usamos se não tivermos nada melhor
                    is_generic = "Microsoft" in (xml.get("manufacturer") or "") or \
                                 "Windows Media Player" in (xml.get("modelName") or "")

                    if not is_generic or res["manufacturer"] == "Unknown":
                        res["udn"] = xml.get("udn", res["udn"])
                        if not res["name"]: res["name"] = xml.get("friendlyName")
                        if res["manufacturer"] == "Unknown": res["manufacturer"] = xml.get("manufacturer")
                        if res["model"] == "Unknown": res["model"] = xml.get("modelName")

        # Exibição
        print(f"IP: {res['ip']} | MAC: {res['mac']}")
        if res["name"]:
            print(f"   Nome: {res['name']}")
        print(f"   Manufacturer: {res['manufacturer']}")
        print(f"   Model Name: {res['model']}")
        if res['udn']: print(f"   UDN: {res['udn']}")
        if res['server']: print(f"   SERVER: {res['server']}")
        print("-" * 50)


if __name__ == "__main__":
    main()
