#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p0f raw-output parsing and feature extraction."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict

P0F_BLOCK_RE = re.compile(r"\.-\[\s*(.*?)\s*\]-\n\|\n(.*?)\n`----", re.S)


def parse_p0f_raw(p0f_text: str) -> Dict[str, Any]:
    warnings = [line.strip() for line in p0f_text.splitlines() if "WARNING:" in line]

    blocks = []
    for header, body in P0F_BLOCK_RE.findall(p0f_text):
        fields = {}
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("|"):
                line = line[1:].strip()
            if " = " in line:
                key, value = line.split(" = ", 1)
                fields[key.strip()] = value.strip()
        blocks.append({"header": header.strip(), "fields": fields})

    processed_packets = None
    match = re.search(r"Processed\s+(\d+)\s+packets", p0f_text)
    if match:
        processed_packets = int(match.group(1))

    return {
        "warnings": warnings,
        "summary": {
            "processed_packets": processed_packets,
            "blocks_count": len(blocks),
        },
        "blocks": blocks,
    }


def p0f_addr_matches_field(target_ip: str, field_value: str) -> bool:
    """Return True when a p0f client/server field points to the target IP."""
    if not field_value or not target_ip:
        return False

    field_value = field_value.strip()
    if field_value.startswith(target_ip + "/") or field_value.startswith(target_ip + ":"):
        return True

    head = re.split(r"[\s/(]", field_value, maxsplit=1)[0]
    return head == target_ip


def _add_if_present(target: set, value: Any) -> None:
    if value:
        target.add(value)


def extract_p0f_sets(p0f_parsed: Dict[str, Any], target_ip: str) -> Dict[str, Any]:
    """Extract stable p0f feature sets for a target IP."""
    client_syn_sigs = set()
    client_mtus = set()
    client_oses = set()

    server_synack_sigs = set()
    server_mtus = set()
    server_oses = set()

    for block in p0f_parsed.get("blocks", []):
        header = (block.get("header") or "").lower()
        fields = block.get("fields", {})

        client_matches = p0f_addr_matches_field(target_ip, fields.get("client", ""))
        server_matches = p0f_addr_matches_field(target_ip, fields.get("server", ""))

        if "(syn)" in header and client_matches:
            _add_if_present(client_syn_sigs, fields.get("raw_sig"))
            _add_if_present(client_oses, fields.get("os"))

        if "(mtu)" in header and client_matches:
            _add_if_present(client_mtus, fields.get("raw_mtu"))

        if "(syn+ack)" in header and server_matches:
            _add_if_present(server_synack_sigs, fields.get("raw_sig"))
            _add_if_present(server_oses, fields.get("os"))

        if "(mtu)" in header and server_matches:
            _add_if_present(server_mtus, fields.get("raw_mtu"))

    extracted = {
        "client_syn_raw_sig_set": sorted(client_syn_sigs),
        "client_mtu_set": sorted(client_mtus),
        "client_os_set": sorted(client_oses),
        "server_synack_raw_sig_set": sorted(server_synack_sigs),
        "server_mtu_set": sorted(server_mtus),
        "server_os_set": sorted(server_oses),
    }

    log = logging.getLogger("fingerprint.p0f_extract")
    log.info(
        "extract_p0f_sets target=%s client_syn=%d server_synack=%d client_mtu=%d server_mtu=%d",
        target_ip,
        len(client_syn_sigs),
        len(server_synack_sigs),
        len(client_mtus),
        len(server_mtus),
    )
    log.debug("extract_p0f_sets client_syn_raw_sig_set=%s", extracted["client_syn_raw_sig_set"])
    log.debug("extract_p0f_sets server_synack_raw_sig_set=%s", extracted["server_synack_raw_sig_set"])
    return extracted
