#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Feature extraction from PCAP files through tshark."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional, Set

from .runtime import decode_bytes, run_bytes


def extract_tcp_syn_features_tshark(pcap_path: Path, ip: str) -> Dict[str, Optional[str]]:
    """
    Extract features from the first SYN+ACK packet from the target.
    If unavailable, fall back to the first SYN packet from the target, then to IP TTL only.
    """
    log = logging.getLogger("fingerprint.tshark")
    feats = {
        "source": "tshark_syn_fallback",
        "filters_tried": [],
        "chosen_filter": None,
        "ttl": None,
        "window_size": None,
        "mss": None,
        "ws": None,
        "sack_perm": None,
        "ts_present": None,
        "options_order": None,
    }

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        feats["error"] = "pcap_missing_or_empty"
        log.warning("tshark pcap missing or empty path=%s", pcap_path)
        return feats

    log.info("tshark start pcap=%s size_bytes=%s ip=%s", pcap_path, pcap_path.stat().st_size, ip)

    filters = [
        f"ip.src=={ip} && tcp.flags.syn==1 && tcp.flags.ack==1",
        f"ip.src=={ip} && tcp.flags.syn==1 && tcp.flags.ack==0",
    ]

    def append_stderr(error_text: str) -> None:
        if error_text:
            feats["tshark_stderr"] = (feats.get("tshark_stderr", "") + "\n" + error_text).strip()

    def try_filter(display_filter: str):
        feats["filters_tried"].append(display_filter)
        cmd = [
            "tshark", "-r", str(pcap_path),
            "-Y", display_filter,
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "ip.ttl",
            "-e", "tcp.window_size_value",
            "-e", "tcp.options.mss_val",
            "-e", "tcp.options.wscale.shift",
            "-e", "tcp.options.sack_perm",
            "-e", "tcp.options.timestamp",
        ]
        rc, outb, errb = run_bytes(cmd)
        text = decode_bytes(outb).strip()
        append_stderr(decode_bytes(errb).strip())

        if rc != 0 or not text:
            log.debug("tshark try_filter no rows rc=%s filter=%s", rc, display_filter)
            return None

        lines = text.splitlines()
        first = lines[0]
        log.info("tshark try_filter filter=%s matching_lines=%s first_row=%r", display_filter, len(lines), first)
        cols = first.split("\t")

        def col(index: int):
            return cols[index] if index < len(cols) and cols[index] != "" else None

        parsed = {
            "ttl": col(0),
            "window_size": col(1),
            "mss": col(2),
            "ws": col(3),
            "sack_perm": col(4),
            "ts_present": "1" if col(5) is not None else "0",
        }

        opt_cmd = [
            "tshark", "-r", str(pcap_path),
            "-Y", display_filter,
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "tcp.options",
        ]
        rc2, outb2, errb2 = run_bytes(opt_cmd)
        text2 = decode_bytes(outb2).strip()
        append_stderr(decode_bytes(errb2).strip())

        if rc2 == 0 and text2:
            parsed["options_order"] = _extract_tcp_options_order(text2.splitlines()[0].lower())

        log.debug(
            "tshark parsed fields ttl=%s win=%s mss=%s ws=%s opts=%s",
            parsed.get("ttl"),
            parsed.get("window_size"),
            parsed.get("mss"),
            parsed.get("ws"),
            parsed.get("options_order"),
        )
        return parsed

    for display_filter in filters:
        chosen = try_filter(display_filter)
        if chosen:
            feats["chosen_filter"] = display_filter
            feats.update(chosen)
            log.info(
                "tshark done chosen_filter=%s ttl=%s window_size=%s mss=%s ws=%s options_order=%s",
                display_filter,
                feats.get("ttl"),
                feats.get("window_size"),
                feats.get("mss"),
                feats.get("ws"),
                feats.get("options_order"),
            )
            return feats

    def try_ip_ttl_only(display_filter: str, ttl_field: str, label: str) -> bool:
        feats["filters_tried"].append(label)
        cmd = [
            "tshark", "-r", str(pcap_path),
            "-Y", display_filter,
            "-T", "fields",
            "-E", "separator=\t",
            "-e", ttl_field,
        ]
        rc, outb, errb = run_bytes(cmd)
        text = decode_bytes(outb).strip()
        append_stderr(decode_bytes(errb).strip())
        if rc != 0 or not text:
            return False

        for line in text.splitlines():
            ttl = line.split("\t")[0].strip()
            if ttl:
                feats["chosen_filter"] = label
                feats["ttl"] = ttl
                feats["fallback"] = "ip_layer_ttl_only"
                log.warning("tshark using %s ttl=%s (sem SYN/SYN+ACK TCP de %s no PCAP)", label, ttl, ip)
                return True
        return False

    if ":" not in ip:
        if try_ip_ttl_only(f"ip.src=={ip}", "ip.ttl", f"ip.src=={ip} (ttl_only)"):
            return feats
    else:
        if try_ip_ttl_only(f"ipv6.src=={ip}", "ipv6.hlim", f"ipv6.src=={ip} (hlim_only)"):
            return feats

    feats["error"] = "no_syn_or_synack_found"
    log.warning("tshark no SYN/SYN+ACK nor IP TTL lines for ip=%s", ip)
    return feats


def _extract_tcp_options_order(options_line: str) -> Optional[str]:
    def pos(key: str) -> int:
        position = options_line.find(key)
        return position if position >= 0 else 10 ** 9

    keys = [
        ("mss", "mss"),
        ("sack_perm", "sack_perm"),
        ("timestamp", "ts"),
        ("wscale", "ws"),
        ("nop", "nop"),
        ("eol", "eol"),
    ]
    found = sorted((pos(needle), tag) for needle, tag in keys if pos(needle) < 10 ** 9)
    return ",".join(tag for _, tag in found) if found else None


def norm_passive_token(text: str, max_len: int = 512) -> str:
    text = " ".join(text.split()).strip()
    return text[:max_len] if len(text) > max_len else text
