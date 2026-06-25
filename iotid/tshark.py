"""Extração de features TCP (SYN/SYN+ACK) e pistas passivas via tshark."""

from __future__ import annotations

import logging
from pathlib import Path

from .proc import decode_bytes, run_bytes


def norm_passive_token(s: str, max_len: int = 512) -> str:
    s = " ".join(s.split()).strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


def extract_tcp_syn_features_tshark(pcap_path: Path, ip: str):
    """
    Fallback: tenta extrair features do 1º SYN+ACK do alvo.
    Se não achar, tenta o 1º SYN do alvo.
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

    def try_filter(dfilter: str):
        feats["filters_tried"].append(dfilter)

        cmd1 = [
            "tshark", "-r", str(pcap_path),
            "-Y", dfilter,
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "ip.ttl",
            "-e", "tcp.window_size_value",
            "-e", "tcp.options.mss_val",
            "-e", "tcp.options.wscale.shift",
            "-e", "tcp.options.sack_perm",
            "-e", "tcp.options.timestamp",
        ]
        rc, outb, errb = run_bytes(cmd1)
        txt = decode_bytes(outb).strip()
        err = decode_bytes(errb).strip()

        if err:
            feats["tshark_stderr"] = (feats.get("tshark_stderr", "") + "\n" + err).strip()

        if rc != 0 or not txt:
            log.debug("tshark try_filter no rows rc=%s filter=%s", rc, dfilter)
            return None

        lines = txt.splitlines()
        first = lines[0]
        log.info(
            "tshark try_filter filter=%s matching_lines=%s first_row=%r",
            dfilter,
            len(lines),
            first,
        )
        cols = first.split("\t")

        def col(i):
            return cols[i] if i < len(cols) and cols[i] != "" else None

        local = {
            "ttl": col(0),
            "window_size": col(1),
            "mss": col(2),
            "ws": col(3),
            "sack_perm": col(4),
            "ts_present": "1" if col(5) is not None else "0",
        }

        cmd2 = [
            "tshark", "-r", str(pcap_path),
            "-Y", dfilter,
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "tcp.options"
        ]
        rc2, outb2, errb2 = run_bytes(cmd2)
        txt2 = decode_bytes(outb2).strip()
        err2 = decode_bytes(errb2).strip()

        if err2:
            feats["tshark_stderr"] = (feats.get("tshark_stderr", "") + "\n" + err2).strip()

        if rc2 == 0 and txt2:
            opt_line = txt2.splitlines()[0].lower()

            def pos(key):
                p = opt_line.find(key)
                return p if p >= 0 else 10**9

            keys = [
                ("mss", "mss"),
                ("sack_perm", "sack_perm"),
                ("timestamp", "ts"),
                ("wscale", "ws"),
                ("nop", "nop"),
                ("eol", "eol"),
            ]
            found = []
            for needle, tag in keys:
                p = pos(needle)
                if p < 10**9:
                    found.append((p, tag))
            found.sort(key=lambda x: x[0])
            if found:
                local["options_order"] = ",".join(t for _, t in found)

        log.debug("tshark parsed fields ttl=%s win=%s mss=%s ws=%s opts=%s", local.get("ttl"), local.get("window_size"), local.get("mss"), local.get("ws"), local.get("options_order"))
        return local

    for f in filters:
        chosen = try_filter(f)
        if chosen:
            feats["chosen_filter"] = f
            feats.update(chosen)
            log.info(
                "tshark done chosen_filter=%s ttl=%s window_size=%s mss=%s ws=%s options_order=%s",
                f,
                feats.get("ttl"),
                feats.get("window_size"),
                feats.get("mss"),
                feats.get("ws"),
                feats.get("options_order"),
            )
            return feats

    # IPv4: qualquer pacote com origem no alvo (UDP/DNS, ICMP, etc.) — comum em telemóveis
    # sem SYN TCP visível na janela ou quando nping não gera SYN+ACK no PCAP.
    def try_ip_ttl_only(dfilter: str, ttl_field: str, label: str):
        feats["filters_tried"].append(label)
        cmd_ttl = [
            "tshark", "-r", str(pcap_path),
            "-Y", dfilter,
            "-T", "fields",
            "-E", "separator=\t",
            "-e", ttl_field,
        ]
        rc, outb, errb = run_bytes(cmd_ttl)
        txt = decode_bytes(outb).strip()
        err = decode_bytes(errb).strip()
        if err:
            feats["tshark_stderr"] = (feats.get("tshark_stderr", "") + "\n" + err).strip()
        if rc != 0 or not txt:
            return False
        for line in txt.splitlines():
            ttl = line.split("\t")[0].strip()
            if ttl:
                feats["chosen_filter"] = label
                feats["ttl"] = ttl
                feats["fallback"] = "ip_layer_ttl_only"
                log.warning(
                    "tshark using %s ttl=%s (sem SYN/SYN+ACK TCP de %s no PCAP)",
                    label,
                    ttl,
                    ip,
                )
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


def extract_mobile_passive_tshark(pcap_path: Path, ip: str) -> dict:
    """
    Pistas passivas típicas de telemóveis/tablets: DHCP (hostname, vendor class —
    frequentemente contém 'android-dhcp-*'), HTTP User-Agent, SNI TLS, mDNS/NBNS.
    """
    log = logging.getLogger("fingerprint.mobile_passive")
    empty: dict = {
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

    def tshark_collect(display_filter: str, *elems: str) -> set:
        cmd = ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
        for e in elems:
            cmd.extend(["-e", e])
        rc, outb, errb = run_bytes(cmd)
        if errb:
            log.debug("tshark passive stderr: %s", decode_bytes(errb)[:500])
        if rc != 0:
            return set()
        found: set = set()
        for line in decode_bytes(outb).splitlines():
            for col in line.split("\t"):
                c = norm_passive_token(col.strip()) if col.strip() else ""
                if c and c not in ("<MISSING>",):
                    found.add(c)
        return found

    dhcp_h = tshark_collect(f"(dhcp || bootp) && ip.src=={ip}", "dhcp.option.hostname")
    dhcp_v = tshark_collect(
        f"(dhcp || bootp) && ip.src=={ip}",
        "dhcp.option.vendor_class_id",
        "dhcp.option.class_id",
    )
    # Algumas versões usam campos genéricos no Bootp
    if not dhcp_h:
        dhcp_h |= tshark_collect(f"bootp && ip.src=={ip}", "dhcp.option.hostname")
    if not dhcp_v:
        dhcp_v |= tshark_collect(f"bootp && ip.src=={ip}", "dhcp.option.vendor_class_id")

    http_ua = tshark_collect(f"http.user_agent && ip.src=={ip}", "http.user_agent")
    tls_sni = tshark_collect(
        f"tls.handshake.type == 1 && ip.src=={ip}",
        "tls.handshake.extensions_server_name",
    )
    mdns = tshark_collect(f"udp.port==5353 && ip.src=={ip}", "dns.qry.name", "mdns.cname")
    nbns = tshark_collect(f"nbns && ip.src=={ip}", "nbns.name")

    out = {
        "dhcp_hostname_set": sorted(dhcp_h),
        "dhcp_vendor_class_set": sorted(dhcp_v),
        "http_user_agent_set": sorted(http_ua),
        "tls_sni_set": sorted(tls_sni),
        "mdns_name_set": sorted(mdns),
        "nbns_name_set": sorted(nbns),
    }
    nonempty = sum(1 for k, v in out.items() if v)
    log.info(
        "mobile_passive summary ip=%s nonempty_groups=%s dhcp_vendors=%s user_agents=%s",
        ip,
        nonempty,
        len(dhcp_v),
        len(http_ua),
    )
    return out
