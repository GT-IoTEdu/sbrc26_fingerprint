#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upnp_discovery.py

Descoberta UPnP/SSDP compartilhada pelas ferramentas do repositorio
(iot_id_fingerprint.py e iot_net_scanner.py).

Expoe quatro primitivas:
  - ssdp_probe()            : M-SEARCH multicast -> {ip: {"locs", "srv"}}
  - fetch_upnp_description() : le o device-desc XML de uma LOCATION
  - nmap_upnp_scan()         : nmap --script upnp-info para um alvo
  - collect_upnp_identity()  : combina nmap + SSDP/XML numa identidade unica
"""

from __future__ import annotations

import re
import socket
import subprocess
from urllib.parse import urlparse

import requests

# UPnP XML vem de dispositivos nao confiaveis da rede: defusedxml protege contra
# XXE / billion-laughs. Se nao estiver instalado, cai no parser da stdlib.
try:
    from defusedxml.ElementTree import fromstring as xml_fromstring
except ImportError:  # pragma: no cover
    from xml.etree.ElementTree import fromstring as xml_fromstring

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_TIMEOUT = 2.0
_UPNP_NS = {"ns": "urn:schemas-upnp-org:device-1-0"}

_SSDP_MSEARCH = "\r\n".join([
    "M-SEARCH * HTTP/1.1",
    "HOST:239.255.255.250:1900",
    'MAN:"ssdp:discover"',
    "MX:2",
    "ST:ssdp:all",
    "", "",
]).encode()

_LOC_RE = re.compile(r"LOCATION:\s*(http://[^\r\n]+)", re.IGNORECASE)
_SRV_RE = re.compile(r"SERVER:\s*([^\r\n]+)", re.IGNORECASE)


def ssdp_probe(target: str | None = None, timeout: float = SSDP_TIMEOUT) -> dict:
    """Envia um M-SEARCH e coleta respostas SSDP.

    Retorna {ip: {"locs": set[str], "srv": str | None}}. Se ``target`` for dado,
    apenas respostas desse IP sao mantidas.
    """
    results: dict = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(_SSDP_MSEARCH, SSDP_ADDR)
        while True:
            try:
                data, (ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                break
            if target and ip != target:
                continue
            text = data.decode(errors="ignore")
            entry = results.setdefault(ip, {"locs": set(), "srv": None})
            loc = _LOC_RE.search(text)
            srv = _SRV_RE.search(text)
            if loc:
                entry["locs"].add(loc.group(1).strip())
            if srv:
                entry["srv"] = srv.group(1).strip()
    return results


def fetch_upnp_description(url: str) -> dict | None:
    """Le o device-desc XML de ``url`` e devolve identidade, ou None."""
    try:
        resp = requests.get(url, timeout=1.5)
        if resp.status_code != 200:
            return None
        device = xml_fromstring(resp.content).find("ns:device", _UPNP_NS)
    except Exception:
        return None
    if device is None:
        return None

    def field(tag: str) -> str | None:
        return (device.findtext(f"ns:{tag}", "", _UPNP_NS) or "").strip() or None

    return {
        "friendlyName": field("friendlyName"),
        "manufacturer": field("manufacturer"),
        "modelName": field("modelName"),
        "udn": field("UDN"),
    }


_NMAP_LABELS = {
    "Server:": "server",
    "Manufacturer:": "manufacturer",
    "Model Name:": "model_name",
    "Name:": "name",
}


def nmap_upnp_scan(target: str, sudo: bool = True) -> tuple[dict, str]:
    """Executa ``nmap --script upnp-info`` no alvo.

    Retorna (campos_extraidos, stdout_cru). Falhas devolvem ({}, "").
    """
    cmd = (["sudo"] if sudo else []) + ["nmap", "-sV", "-Pn", "--script", "upnp-info", target]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return {}, ""

    info: dict = {}
    for line in out.splitlines():
        line = line.strip()
        for label, key in _NMAP_LABELS.items():
            if label in line:
                info[key] = line.split(label, 1)[-1].strip()
    return info, out


def sort_locations(locs) -> list[str]:
    """Ordena LOCATIONs por (porta, path, url) para um fetch deterministico.

    Varios servicos no mesmo IP anunciam portas diferentes (TV em :8008 vs Windows
    Media Player em :8443); ordenar prioriza portas menores e torna o resultado
    reprodutivel.
    """
    def key(url: str) -> tuple:
        try:
            p = urlparse(url)
            port = p.port or (443 if p.scheme == "https" else 80)
            return (port, p.path or "", url.lower())
        except Exception:
            return (99999, "", url)

    return sorted(locs, key=key)


def collect_upnp_identity(target_ip: str, sudo: bool = True) -> tuple[dict, str]:
    """Combina nmap upnp-info + SSDP/XML numa unica identidade do dispositivo.

    Retorna (identity, nmap_stdout) onde identity tem as chaves
    server / name / manufacturer / model_name (cada uma str ou None).
    """
    identity = {
        "report_for": target_ip,
        "server": None,
        "name": None,
        "manufacturer": None,
        "model_name": None,
    }

    nmap_info, nmap_out = nmap_upnp_scan(target_ip, sudo=sudo)
    for key in ("server", "name", "manufacturer", "model_name"):
        if nmap_info.get(key):
            identity[key] = nmap_info[key]

    ssdp = ssdp_probe(target_ip).get(target_ip)
    if ssdp:
        identity["server"] = identity["server"] or ssdp["srv"]
        for url in sort_locations(ssdp["locs"]):
            xml = fetch_upnp_description(url)
            if not xml:
                continue
            identity["name"] = identity["name"] or xml["friendlyName"]
            identity["manufacturer"] = identity["manufacturer"] or xml["manufacturer"]
            identity["model_name"] = identity["model_name"] or xml["modelName"]
            if all(identity[k] for k in ("server", "name", "manufacturer", "model_name")):
                break

    return identity, nmap_out


def ssdp_to_jsonable(ssdp_raw: dict) -> dict:
    """Converte a saida de ssdp_probe (sets) para algo serializavel em JSON."""
    return {
        ip: {"locs": sorted(data.get("locs") or []), "srv": data.get("srv")}
        for ip, data in (ssdp_raw or {}).items()
    }
