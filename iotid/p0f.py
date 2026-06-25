"""Parsing do output cru do p0f e extração de conjuntos estáveis por IP."""

from __future__ import annotations

import logging
import re

P0F_BLOCK_RE = re.compile(r"\.-\[\s*(.*?)\s*\]-\n\|\n(.*?)\n`----", re.S)


def parse_p0f_raw(p0f_text: str):
    warnings = []
    for line in p0f_text.splitlines():
        if "WARNING:" in line:
            warnings.append(line.strip())

    blocks = []
    for header, body in P0F_BLOCK_RE.findall(p0f_text):
        fields = {}
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("|"):
                line = line[1:].strip()
            if " = " in line:
                k, v = line.split(" = ", 1)
                fields[k.strip()] = v.strip()
        blocks.append({"header": header.strip(), "fields": fields})

    processed_packets = None
    m = re.search(r"Processed\s+(\d+)\s+packets", p0f_text)
    if m:
        processed_packets = int(m.group(1))

    return {
        "warnings": warnings,
        "summary": {
            "processed_packets": processed_packets,
            "blocks_count": len(blocks),
        },
        "blocks": blocks,
    }


def _p0f_addr_matches_field(target_ip: str, field_val: str) -> bool:
    """True se o campo client/server do bloco p0f corresponde ao IP alvo (várias grafias)."""
    if not field_val or not target_ip:
        return False
    s = field_val.strip()
    if s.startswith(target_ip + "/") or s.startswith(target_ip + ":"):
        return True
    # "192.168.1.1/12345 (distance 12)" ou prefixo antes de espaço
    head = re.split(r"[\s/(]", s, maxsplit=1)[0]
    return head == target_ip


def extract_p0f_sets(p0f_parsed: dict, target_ip: str):
    """
    Extrai conjuntos estáveis do p0f para o IP alvo.
    """
    client_syn_sigs = set()
    client_mtus = set()
    client_oses = set()

    server_synack_sigs = set()
    server_mtus = set()
    server_oses = set()

    for b in p0f_parsed.get("blocks", []):
        header_l = (b.get("header") or "").lower()
        fields = b.get("fields", {})

        if "(syn)" in header_l and _p0f_addr_matches_field(target_ip, fields.get("client", "")):
            rs = fields.get("raw_sig")
            if rs:
                client_syn_sigs.add(rs)
            os_guess = fields.get("os")
            if os_guess:
                client_oses.add(os_guess)

        if "(mtu)" in header_l and _p0f_addr_matches_field(target_ip, fields.get("client", "")):
            mtu = fields.get("raw_mtu")
            if mtu:
                client_mtus.add(mtu)

        if "(syn+ack)" in header_l and _p0f_addr_matches_field(target_ip, fields.get("server", "")):
            rs = fields.get("raw_sig")
            if rs:
                server_synack_sigs.add(rs)
            os_guess = fields.get("os")
            if os_guess:
                server_oses.add(os_guess)

        if "(mtu)" in header_l and _p0f_addr_matches_field(target_ip, fields.get("server", "")):
            mtu = fields.get("raw_mtu")
            if mtu:
                server_mtus.add(mtu)

    out = {
        "client_syn_raw_sig_set": sorted(client_syn_sigs),
        "client_mtu_set": sorted(client_mtus),
        "client_os_set": sorted(client_oses),
        "server_synack_raw_sig_set": sorted(server_synack_sigs),
        "server_mtu_set": sorted(server_mtus),
        "server_os_set": sorted(server_oses),
    }
    plog = logging.getLogger("fingerprint.p0f_extract")
    plog.info(
        "extract_p0f_sets target=%s client_syn=%d server_synack=%d client_mtu=%d server_mtu=%d",
        target_ip,
        len(client_syn_sigs),
        len(server_synack_sigs),
        len(client_mtus),
        len(server_mtus),
    )
    plog.debug("extract_p0f_sets client_syn_raw_sig_set=%s", out["client_syn_raw_sig_set"])
    plog.debug("extract_p0f_sets server_synack_raw_sig_set=%s", out["server_synack_raw_sig_set"])
    return out
