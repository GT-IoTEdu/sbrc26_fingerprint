#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Additional mobile-host evidence collected outside the canonical hash."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Dict, Set

from .runtime import decode_bytes, run_bytes
from .tshark_features import norm_passive_token


def extract_mobile_passive_tshark(pcap_path: Path, ip: str) -> Dict[str, object]:
    """Collect DHCP, HTTP, TLS, mDNS and NBNS hints from a PCAP for mobile-like hosts."""
    log = logging.getLogger("fingerprint.mobile_passive")
    empty: Dict[str, object] = {
        "dhcp_hostname_set": [],
        "dhcp_vendor_class_set": [],
        "http_user_agent_set": [],
        "tls_sni_set": [],
        "mdns_name_set": [],
        "nbns_name_set": [],
    }

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        empty["error"] = "pcap_missing_or_empty"
        return empty

    def tshark_collect(display_filter: str, *fields: str) -> Set[str]:
        cmd = ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
        for field in fields:
            cmd.extend(["-e", field])

        rc, outb, errb = run_bytes(cmd)
        if errb:
            log.debug("tshark passive stderr: %s", decode_bytes(errb)[:500])
        if rc != 0:
            return set()

        found = set()
        for line in decode_bytes(outb).splitlines():
            for col in line.split("\t"):
                value = norm_passive_token(col.strip()) if col.strip() else ""
                if value and value not in ("<MISSING>",):
                    found.add(value)
        return found

    dhcp_h = tshark_collect(f"(dhcp || bootp) && ip.src=={ip}", "dhcp.option.hostname")
    dhcp_v = tshark_collect(
        f"(dhcp || bootp) && ip.src=={ip}",
        "dhcp.option.vendor_class_id",
        "dhcp.option.class_id",
    )

    if not dhcp_h:
        dhcp_h |= tshark_collect(f"bootp && ip.src=={ip}", "dhcp.option.hostname")
    if not dhcp_v:
        dhcp_v |= tshark_collect(f"bootp && ip.src=={ip}", "dhcp.option.vendor_class_id")

    http_ua = tshark_collect(f"http.user_agent && ip.src=={ip}", "http.user_agent")
    tls_sni = tshark_collect(f"tls.handshake.type == 1 && ip.src=={ip}", "tls.handshake.extensions_server_name")
    mdns = tshark_collect(f"udp.port==5353 && ip.src=={ip}", "dns.qry.name", "mdns.cname")
    nbns = tshark_collect(f"nbns && ip.src=={ip}", "nbns.name")

    result = {
        "dhcp_hostname_set": sorted(dhcp_h),
        "dhcp_vendor_class_set": sorted(dhcp_v),
        "http_user_agent_set": sorted(http_ua),
        "tls_sni_set": sorted(tls_sni),
        "mdns_name_set": sorted(mdns),
        "nbns_name_set": sorted(nbns),
    }
    nonempty = sum(1 for value in result.values() if value)
    log.info(
        "mobile_passive summary ip=%s nonempty_groups=%s dhcp_vendors=%s user_agents=%s",
        ip,
        nonempty,
        len(dhcp_v),
        len(http_ua),
    )
    return result


def nmap_mobile_scan(target: str) -> Dict[str, object]:
    """Run a lightweight nmap service probe for ports often useful in mobile-host studies."""
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
    except Exception as exc:  # Preserve original best-effort behavior.
        return {"error": str(exc), "service_lines": []}

    hints = []
    for line in raw.splitlines():
        text = line.strip()
        if "/tcp" in text or "/udp" in text:
            if any(token in text for token in (" open ", "open ", "Open ", "/tcp", "/udp")):
                hints.append(norm_passive_token(text, 400))

    return {
        "service_lines": sorted(set(hints))[:30],
        "raw_chars": len(raw),
    }
