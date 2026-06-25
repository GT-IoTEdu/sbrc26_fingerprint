"""
Descoberta UPnP/SSDP partilhada entre o scanner de rede e o pipeline.

Concentra o que era genuinamente duplicado em `iot_net_scanner.py` e
`iot_id_fingerprint.py`:

- `ssdp_probe`     : M-SEARCH multicast (parametriza apenas o tamanho do buffer
                     de receção, que diferia entre os dois chamadores).
- `fetch_upnp_raw` : GET + parse do device-desc.xml, devolvendo os campos crus
                     (friendlyName, manufacturer, modelName, udn). Cada chamador
                     aplica a sua própria normalização sobre este resultado.
- `sorted_ssdp_locations` : ordem determinística de LOCATIONs para fetch.

A varredura `nmap` permanece em cada ferramenta: o pipeline usa `upnp-info` com
`sudo` e devolve um esquema diferente do modo broadcast do scanner, pelo que
não constitui duplicação real.
"""

from __future__ import annotations

import re
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests

SSDP_TIMEOUT = 2.0

_UPNP_NS = {"ns": "urn:schemas-upnp-org:device-1-0"}

_SSDP_MSEARCH = "\r\n".join([
    "M-SEARCH * HTTP/1.1",
    "HOST:239.255.255.250:1900",
    'MAN:"ssdp:discover"',
    "MX:2",
    "ST:ssdp:all",
    "",
    "",
]).encode()

_LOC_RE = re.compile(r"LOCATION:\s*(http://[^\r\n]+)", re.IGNORECASE)
_SRV_RE = re.compile(r"SERVER:\s*([^\r\n]+)", re.IGNORECASE)


def fetch_upnp_raw(url: str):
    """
    Obtém e faz parse do device-desc.xml de um dispositivo UPnP.

    Devolve um dict com os campos crus (sem normalização):
      {"friendlyName", "manufacturer", "modelName", "udn"}
    ou None se a resposta não for 200, o XML não tiver <device> ou ocorrer erro.
    """
    try:
        r = requests.get(url, timeout=1.5)
        if r.status_code != 200:
            return None

        root = ET.fromstring(r.content)
        device = root.find("ns:device", _UPNP_NS)

        if device is not None:
            return {
                "friendlyName": device.findtext("ns:friendlyName", "", _UPNP_NS),
                "manufacturer": device.findtext("ns:manufacturer", "", _UPNP_NS),
                "modelName": device.findtext("ns:modelName", "", _UPNP_NS),
                "udn": device.findtext("ns:UDN", "", _UPNP_NS),
            }
    except Exception:
        pass

    return None


def ssdp_probe(target: str | None = None, recv_bufsize: int = 4096):
    """
    Descoberta rápida via multicast UDP (M-SEARCH ssdp:all).

    `recv_bufsize` controla o tamanho máximo lido por datagrama (o scanner usa
    2048; o pipeline usa 4096). `target` filtra respostas a um único IP.
    """
    results: dict = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SSDP_TIMEOUT)

    try:
        sock.sendto(_SSDP_MSEARCH, ("239.255.255.250", 1900))

        while True:
            try:
                data, addr = sock.recvfrom(recv_bufsize)
                ip = addr[0]
                if target and ip != target:
                    continue

                content = data.decode(errors="ignore")

                loc = _LOC_RE.search(content)
                srv = _SRV_RE.search(content)

                if ip not in results:
                    results[ip] = {"locs": set(), "srv": None}

                if loc:
                    results[ip]["locs"].add(loc.group(1).strip())

                if srv:
                    results[ip]["srv"] = srv.group(1).strip()

            except socket.timeout:
                break
    finally:
        sock.close()

    return results


def sorted_ssdp_locations(locs: set[str]) -> list[str]:
    """
    Ordem estável para fetch de device-desc.xml.

    Vários serviços no mesmo IP anunciam LOCATION em portas diferentes (ex. TV em
    :8008 vs Windows Media Player em :8443). Iterar um set() ou a ordem de chegada
    UDP é não-determinística; ordenar por (porta, path, URL) prioriza portas menores
    e torna o fingerprint reprodutível.
    """

    def sort_key(u: str) -> tuple:
        try:
            p = urlparse(u)
            port = p.port
            if port is None:
                port = 80 if (p.scheme or "http") in ("http", "") else 443
            return (port, p.path or "", u.lower())
        except Exception:
            return (99999, "", u)

    return sorted(locs, key=sort_key)
