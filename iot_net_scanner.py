#!/usr/bin/env python3

import subprocess
import re
import socket
import json
import requests
import sys
import xml.etree.ElementTree as ET

# --- Configurações ---
SSDP_TIMEOUT = 2.0

def fetch_upnp_description(url):
    """Extrai detalhes do XML de localização do dispositivo."""
    try:
        r = requests.get(url, timeout=1.5)
        if r.status_code != 200: return None
        
        root = ET.fromstring(r.content)
        ns = {'ns': 'urn:schemas-upnp-org:device-1-0'}
        device = root.find('ns:device', ns)
        
        if device is not None:
            return {
                "friendlyName": device.findtext('ns:friendlyName', '', ns),
                "manufacturer": device.findtext('ns:manufacturer', '', ns),
                "modelName": device.findtext('ns:modelName', '', ns),
                "udn": device.findtext('ns:UDN', '', ns)
            }
    except:
        pass
    return None

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
    except:
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

def ssdp_probe(target=None):
    """Descoberta rápida via multicast UDP."""
    msg = '\r\n'.join([
        'M-SEARCH * HTTP/1.1', 'HOST:239.255.255.250:1900',
        'MAN:"ssdp:discover"', 'MX:2', 'ST:ssdp:all', '', ''
    ]).encode()

    results = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SSDP_TIMEOUT)
    try:
        sock.sendto(msg, ('239.255.255.250', 1900))
        while True:
            try:
                data, addr = sock.recvfrom(2048)
                ip, content = addr[0], data.decode(errors='ignore')
                
                if target and ip != target: continue

                loc = re.search(r"LOCATION:\s*(http://[^\r\n]+)", content, re.IGNORECASE)
                srv = re.search(r"SERVER:\s*([^\r\n]+)", content, re.IGNORECASE)
                
                if ip not in results: results[ip] = {"locs": set(), "srv": None}
                if loc: results[ip]["locs"].add(loc.group(1).strip())
                if srv: results[ip]["srv"] = srv.group(1).strip()
            except socket.timeout: break
    finally:
        sock.close()
    return results

def get_arp_table():
    """Mapeia IPs e MACs locais."""
    table = {}
    try:
        res = subprocess.run(["ip", "neighbor"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line)
            if ip and mac: table[ip.group(1)] = mac.group(0).upper()
    except: pass
    return table

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else None

    alvo_txt = f"Alvo: {target_ip}" if target_ip else "Rede completa"
    print("[*] Iniciando Scanner de Rede...")
    print(f"    ({alvo_txt})")

    ssdp_raw = ssdp_probe(target_ip)
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
                xml = fetch_upnp_description(url)
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