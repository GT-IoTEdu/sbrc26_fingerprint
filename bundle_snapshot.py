#!/usr/bin/env python3
import argparse
import logging
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import re
import json
import os
import hashlib
import time
import socket
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

# ------------------------------------------------------------
# canonização (separada em canonicalize_features.py)
# ------------------------------------------------------------
try:
    from canonicalize_features import build_canon, dumps_canon
except Exception as e:
    build_canon = None
    dumps_canon = None
    _CANON_IMPORT_ERR = e
else:
    _CANON_IMPORT_ERR = None


SSDP_TIMEOUT = 2.0


def run(cmd, check=True):
    """
    Executa comando e retorna (stdout_text, stderr_text).
    """
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out = p.stdout or b""
    err = p.stderr or b""

    try:
        text_out = out.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text_out = out.decode("latin-1", errors="replace")

    try:
        text_err = err.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text_err = err.decode("latin-1", errors="replace")

    if check and p.returncode != 0:
        raise RuntimeError(
            f"Command failed ({p.returncode}): {' '.join(cmd)}\n\nSTDOUT:\n{text_out}\n\nSTDERR:\n{text_err}"
        )
    return text_out, text_err


def run_bytes(cmd):
    """Retorna (rc, stdout_bytes, stderr_bytes)."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, (p.stdout or b""), (p.stderr or b"")


def decode_bytes(out: bytes) -> str:
    try:
        return out.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return out.decode("latin-1", errors="replace")


def setup_fingerprint_logging(run_dir: Path, level: str, console: bool) -> logging.Logger:
    """
    Configura o logger pai `fingerprint` (pipeline + canon + tshark).
    Escreve em run_dir/fingerprint_pipeline.log.
    """
    root = logging.getLogger("fingerprint")
    root.handlers.clear()
    root.setLevel(logging.DEBUG)
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    fh = logging.FileHandler(run_dir / "fingerprint_pipeline.log", encoding="utf-8")
    fh.setLevel(lvl)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    if console:
        sh = logging.StreamHandler()
        sh.setLevel(lvl)
        sh.setFormatter(fmt)
        root.addHandler(sh)

    root.propagate = False
    return root


def win_to_wsl_path(path: Path) -> str:
    """
    Converte caminho do Windows para WSL:
      C:\\Users\\...\\file.pcap  ->  /mnt/c/Users/.../file.pcap

    Em Linux/macOS: apenas retorna o caminho POSIX normal.
    """
    p = path.resolve()

    if os.name != "nt":
        return str(p)

    drive = p.drive
    if not drive:
        return p.as_posix()

    drive_letter = drive[0].lower()
    rest = p.as_posix().split(":", 1)[1]
    return f"/mnt/{drive_letter}{rest}"


# -------------------------
# Parse do p0f (RAW)
# -------------------------
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


def write_text(path: Path, s: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(s, encoding="utf-8", errors="replace")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
        errors="replace",
    )


def fmt_secs(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds*1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    m = int(seconds // 60)
    s = seconds - (m * 60)
    return f"{m}m {s:05.2f}s"


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


def _norm_passive_token(s: str, max_len: int = 512) -> str:
    s = " ".join(s.split()).strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


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
                c = _norm_passive_token(col.strip()) if col.strip() else ""
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


def nmap_mobile_scan(target: str) -> dict:
    """
    Sonda leve de portas comuns em telemóveis (SSH ADB RTSP, etc.) para banners / -sV.
    """
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
    except Exception as e:
        return {"error": str(e), "service_lines": []}

    hints = []
    for line in raw.splitlines():
        t = line.strip()
        if "/tcp" in t or "/udp" in t:
            if any(x in t for x in (" open ", "open ", "Open ", "/tcp", "/udp")):
                hints.append(_norm_passive_token(t, 400))
    return {
        "service_lines": sorted(set(hints))[:30],
        "raw_chars": len(raw),
    }


def infer_host_kind(nmap_block: dict) -> str:
    """
    'iot' se UPnP/Nmap preencheu fabricante ou modelo; caso contrário tratamos como
    host 'mobile' (telemóvel, tablet, portátil, router sem UPnP, etc.).
    """
    if not isinstance(nmap_block, dict):
        return "mobile"
    m = (nmap_block.get("manufacturer") or "").strip()
    mo = (nmap_block.get("model_name") or "").strip()
    if m or mo:
        return "iot"
    return "mobile"


# ------------------------------------------------------------
# UPNP helpers
# ------------------------------------------------------------
def fetch_upnp_description(url: str):
    try:
        r = requests.get(url, timeout=1.5)
        if r.status_code != 200:
            return None

        root = ET.fromstring(r.content)
        ns = {"ns": "urn:schemas-upnp-org:device-1-0"}
        device = root.find("ns:device", ns)

        if device is not None:
            return {
                "friendlyName": device.findtext("ns:friendlyName", "", ns).strip() or None,
                "manufacturer": device.findtext("ns:manufacturer", "", ns).strip() or None,
                "modelName": device.findtext("ns:modelName", "", ns).strip() or None,
            }
    except Exception:
        pass

    return None


def nmap_upnp_scan(target: str):
    """
    Usa Nmap UPnP focado no alvo.
    """
    try:
        cmd = ["sudo", "nmap", "-sV", "-Pn", "--script", "upnp-info", target]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return {}, ""

    devices = {target: {}}

    for line in out.splitlines():
        line = line.strip()

        if "Server:" in line:
            devices[target]["server"] = line.split("Server:", 1)[-1].strip()

        if "Manufacturer:" in line:
            devices[target]["manufacturer"] = line.split("Manufacturer:", 1)[-1].strip()

        if "Model Name:" in line:
            devices[target]["model_name"] = line.split("Model Name:", 1)[-1].strip()

        if "Name:" in line:
            devices[target]["name"] = line.split("Name:", 1)[-1].strip()

    return devices, out


def _sorted_ssdp_locations(locs: set[str]) -> list[str]:
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


def ssdp_probe(target: str | None = None):
    msg = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST:239.255.255.250:1900",
        'MAN:"ssdp:discover"',
        "MX:2",
        "ST:ssdp:all",
        "",
        "",
    ]).encode()

    results = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SSDP_TIMEOUT)

    try:
        sock.sendto(msg, ("239.255.255.250", 1900))

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if target and ip != target:
                    continue

                content = data.decode(errors="ignore")

                loc = re.search(r"LOCATION:\s*(http://[^\r\n]+)", content, re.IGNORECASE)
                srv = re.search(r"SERVER:\s*([^\r\n]+)", content, re.IGNORECASE)

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


def collect_upnp_identity(target_ip: str):
    """
    Retorna o bloco final que entrará em bundle['nmap'].
    Mantém apenas:
      - server
      - name
      - manufacturer
      - model_name
    """
    final = {
        "report_for": target_ip,
        "server": None,
        "name": None,
        "manufacturer": None,
        "model_name": None,
    }

    nmap_raw, nmap_stdout = nmap_upnp_scan(target_ip)
    ssdp_raw = ssdp_probe(target_ip)

    ninfo = nmap_raw.get(target_ip, {})
    if ninfo.get("server"):
        final["server"] = ninfo["server"]
    if ninfo.get("name"):
        final["name"] = ninfo["name"]
    if ninfo.get("manufacturer"):
        final["manufacturer"] = ninfo["manufacturer"]
    if ninfo.get("model_name"):
        final["model_name"] = ninfo["model_name"]

    sinfo = ssdp_raw.get(target_ip)
    if sinfo:
        if not final["server"] and sinfo.get("srv"):
            final["server"] = sinfo["srv"]

        locs = sinfo.get("locs") or set()
        for url in _sorted_ssdp_locations(locs if isinstance(locs, set) else set(locs)):
            xml = fetch_upnp_description(url)
            if not xml:
                continue

            if not final["name"] and xml.get("friendlyName"):
                final["name"] = xml["friendlyName"]

            if not final["manufacturer"] and xml.get("manufacturer"):
                final["manufacturer"] = xml["manufacturer"]

            if not final["model_name"] and xml.get("modelName"):
                final["model_name"] = xml["modelName"]

            if all([final["server"], final["name"], final["manufacturer"], final["model_name"]]):
                break

    return final, nmap_stdout


def ssdp_results_to_jsonable(ssdp_raw: dict) -> dict:
    """Converte resultado de ssdp_probe para JSON (sets → listas ordenadas)."""
    out: dict = {}
    for ip, data in (ssdp_raw or {}).items():
        locs = data.get("locs") or set()
        loc_list = sorted(locs) if isinstance(locs, set) else list(locs)
        out[ip] = {"locs": loc_list, "srv": data.get("srv")}
    return out


def run_single_fingerprint(
    run_dir: Path,
    target_ip: str,
    ts: str,
    args: argparse.Namespace,
) -> dict:
    """
    Executa o pipeline completo para um IP: UPnP/Nmap, PCAP, p0f, tshark, hash.
    Retorna dict com tmarks, fp_hash, total_elapsed, sucesso canon.
    """
    t_total0 = time.perf_counter()
    tmarks: dict = {}

    nmap_dir = run_dir / "nmap"
    pcap_dir = run_dir / "pcaps"
    p0f_dir = run_dir / "p0f"

    for d in (nmap_dir, pcap_dir, p0f_dir):
        d.mkdir(parents=True, exist_ok=True)

    setup_fingerprint_logging(run_dir, args.log_level, args.log_console)
    log = logging.getLogger("fingerprint.pipeline")
    log.info(
        "=== run start ip=%s ts=%s mode=%s canon_policy=%s log_level=%s ===",
        target_ip,
        ts,
        getattr(args, "mode", "target"),
        args.canon_policy,
        args.log_level,
    )
    log.debug(
        "args seconds=%s iface=%s probe_count=%s probe_delay=%s wsl_distro=%s dumpcap_path=%s",
        args.seconds,
        args.iface,
        args.probe_count,
        args.probe_delay,
        args.wsl_distro,
        args.dumpcap_path,
    )

    # -------------------------
    # 1) NMAP / UPNP
    # -------------------------
    print(f"[*] Running Nmap (alvo {target_ip}) ...")
    log.info("STAGE nmap_upnp START")
    t0 = time.perf_counter()

    nmap_parsed, upnp_stdout = collect_upnp_identity(target_ip)

    tmarks["nmap"] = time.perf_counter() - t0
    log.info(
        "STAGE nmap_upnp END elapsed=%s server=%r name=%r manufacturer=%r model_name=%r",
        fmt_secs(tmarks["nmap"]),
        nmap_parsed.get("server"),
        nmap_parsed.get("name"),
        nmap_parsed.get("manufacturer"),
        nmap_parsed.get("model_name"),
    )
    log.debug("nmap_upnp stdout_chars=%s", len(upnp_stdout or ""))

    write_text(nmap_dir / "bundle_nmap_stdout.txt", upnp_stdout)
    write_json(nmap_dir / "bundle_nmap_identity.json", nmap_parsed)

    if any([
        nmap_parsed.get("server"),
        nmap_parsed.get("name"),
        nmap_parsed.get("manufacturer"),
        nmap_parsed.get("model_name"),
    ]):
        print("[*] UPnP identity detected ...")
    else:
        print("[*] No UPnP identity fields detected.")

    host_kind = infer_host_kind(nmap_parsed)
    log.info("host_kind=%s (iot=UPnP com fabricante ou modelo; mobile=resto)", host_kind)
    if host_kind == "mobile":
        print(
            "[*] Sem identidade IoT/UPnP (fabricante/modelo) — classificação: mobile; "
            "SHA-256: apenas p0f (SYN cliente) + pcap_syn (MSS/opções TCP/TTL/janela). "
            "(DHCP/nmap extra ficam só no fingerprint.json para estudo.)"
        )

    mobile_passive: dict = {}
    mobile_nmap: dict = {}

    # -------------------------
    # 2) CAPTURA PCAP (dumpcap) + SYN probe (nping)
    # -------------------------
    print("[*] Capturing PCAP with dumpcap (async) ...")
    log.info("STAGE pcap_capture START duration_s=%s filter_host=%s", args.seconds, target_ip)
    t0 = time.perf_counter()
    pcap_path = pcap_dir / f"capture_{target_ip}_{ts}.pcap"

    capture_cmd = [
        args.dumpcap_path,
        "-i", args.iface,
        "-w", str(pcap_path),
        "-a", f"duration:{args.seconds}",
        "-f", f"host {target_ip}",
    ]
    log.debug("dumpcap_cmd=%s", " ".join(capture_cmd))

    cap_p = subprocess.Popen(capture_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(max(0.0, args.probe_delay))

    t_probe0 = time.perf_counter()
    probe_used = False
    probe_ports = [80, 443, 22, 445, 139, 3389, 8080, 8443, 9100, 5357]

    ports_csv = ",".join(str(p) for p in probe_ports)
    print(f"[*] Probing common ports with nping SYN (ports={ports_csv}, count={args.probe_count}) ...")
    nping_cmd = [
        "nping",
        "--tcp",
        "-p", ports_csv,
        "--flags", "syn",
        "--count", str(args.probe_count),
        target_ip,
    ]
    log.info("STAGE nping_probe cmd=%s", " ".join(nping_cmd))
    np_out, np_err = run(nping_cmd, check=False)
    log.debug("nping rc_ok stdout_chars=%s stderr_chars=%s", len(np_out or ""), len(np_err or ""))
    write_text(run_dir / "nping_stdout.txt", np_out)
    if np_err.strip():
        write_text(run_dir / "nping_stderr.txt", np_err)
    probe_used = True

    tmarks["nping_probe"] = time.perf_counter() - t_probe0

    out_b, err_b = cap_p.communicate()
    cap_out = decode_bytes(out_b or b"")
    cap_err = decode_bytes(err_b or b"")

    tmarks["dumpcap_capture"] = time.perf_counter() - t0
    write_text(pcap_dir / "bundle_dumpcap_stdout.txt", cap_out)
    write_text(pcap_dir / "bundle_dumpcap_stderr.txt", cap_err)

    pcap_sz = pcap_path.stat().st_size if pcap_path.exists() else 0
    log.info(
        "STAGE pcap_capture END elapsed=%s pcap_path=%s size_bytes=%s",
        fmt_secs(tmarks["dumpcap_capture"]),
        pcap_path,
        pcap_sz,
    )

    p0f_raw_path = p0f_dir / f"p0f_{target_ip}_{ts}.raw.txt"

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        log.warning("STAGE p0f_tshark SKIP reason=pcap_missing_or_empty")
        print("[!] PCAP não foi criado ou está vazio; pulando p0f/tshark.")
        print("    Verifique:")
        print("    - Nome/índice correto da interface (dumpcap -D)")
        print("    - Permissões (tshark/dumpcap pode exigir sudo/capabilities)")
        print("    - Filtro/host correto (IP realmente gerando tráfego)")

        p0f_out, p0f_err = "", "skipped: pcap_missing_or_empty"
        write_text(p0f_raw_path, p0f_out)
        write_text(p0f_dir / f"p0f_{target_ip}_{ts}.stderr.txt", p0f_err)

        p0f_parsed = {
            "error": "pcap_missing_or_empty",
            "warnings": [],
            "summary": {"processed_packets": None, "blocks_count": 0},
            "blocks": [],
            "extracted": {},
        }
        pcap_syn = {"error": "pcap_missing_or_empty"}
        log.info(
            "STAGE tshark_syn_fallback SKIPPED (no pcap) pcap_syn=%s",
            json.dumps(pcap_syn, ensure_ascii=False, sort_keys=True),
        )
        if host_kind == "mobile":
            print("[*] Modo mobile: sonda nmap (só JSON; não entra no SHA-256) ...")
            t_m = time.perf_counter()
            mobile_nmap = nmap_mobile_scan(target_ip)
            tmarks["nmap_mobile"] = time.perf_counter() - t_m
            mobile_passive = {"error": "pcap_missing_or_empty"}

    else:
        # -------------------------
        # 3) P0F (Windows via WSL / Linux/macOS nativo)
        # -------------------------
        log.info("STAGE p0f START")
        t0 = time.perf_counter()
        if os.name == "nt":
            print("[*] Running p0f in WSL (offline -r) ...")
            pcap_arg = win_to_wsl_path(pcap_path)

            wsl_prefix = ["wsl", "--"]
            if args.wsl_distro:
                wsl_prefix = ["wsl", "-d", args.wsl_distro, "--"]

            p0f_cmd = wsl_prefix + ["p0f", "-r", pcap_arg]
            log.debug("p0f_cmd=%s", " ".join(p0f_cmd))
            p0f_out, p0f_err = run(p0f_cmd, check=False)
            tmarks["p0f_wsl"] = time.perf_counter() - t0
        else:
            print("[*] Running p0f (native) (offline -r) ...")
            pcap_arg = str(pcap_path.resolve())
            p0f_cmd = ["p0f", "-r", pcap_arg]
            log.debug("p0f_cmd=%s", " ".join(p0f_cmd))
            p0f_out, p0f_err = run(p0f_cmd, check=False)
            tmarks["p0f_native"] = time.perf_counter() - t0

        write_text(p0f_raw_path, p0f_out)
        write_text(p0f_dir / f"p0f_{target_ip}_{ts}.stderr.txt", p0f_err)

        p0f_parsed = parse_p0f_raw(p0f_out)
        summ = p0f_parsed.get("summary", {})
        log.info(
            "STAGE p0f parse summary processed_packets=%s blocks_count=%s warnings=%s",
            summ.get("processed_packets"),
            summ.get("blocks_count"),
            len(p0f_parsed.get("warnings") or []),
        )
        p0f_parsed["extracted"] = extract_p0f_sets(p0f_parsed, target_ip)

        # -------------------------
        # 3b) SYN/SYN+ACK features via tshark
        # -------------------------
        print("[*] Extracting SYN/SYN+ACK TCP features from PCAP via tshark ...")
        log.info("STAGE tshark_syn_fallback START")
        t0 = time.perf_counter()
        pcap_syn = extract_tcp_syn_features_tshark(pcap_path, target_ip)
        tmarks["tshark_syn_fallback"] = time.perf_counter() - t0
        log.info(
            "STAGE tshark_syn_fallback END elapsed=%s pcap_syn=%s",
            fmt_secs(tmarks["tshark_syn_fallback"]),
            json.dumps(pcap_syn, ensure_ascii=False, sort_keys=True),
        )

        if host_kind == "mobile":
            print("[*] Modo mobile: extraindo DHCP/HTTP/TLS/mDNS + nmap (só JSON; SHA só p0f+pcap_syn) ...")
            t_mp = time.perf_counter()
            mobile_passive = extract_mobile_passive_tshark(pcap_path, target_ip)
            tmarks["mobile_passive_tshark"] = time.perf_counter() - t_mp
            t_nm = time.perf_counter()
            mobile_nmap = nmap_mobile_scan(target_ip)
            tmarks["nmap_mobile"] = time.perf_counter() - t_nm

    # -------------------------
    # 4) Fingerprint JSON (bundle bruto)
    # -------------------------
    fingerprint = {
        "meta": {
            "ts": ts,
            "ip": target_ip,
            "host_kind": host_kind,
            "mode": getattr(args, "mode", "target"),
            "seconds": args.seconds,
            "iface": args.iface,
            "wsl_distro": args.wsl_distro if os.name == "nt" else None,
            "probe_used": bool(probe_used),
            "probe_ports": probe_ports,
            "probe_count": args.probe_count,
        },
        "paths": {
            "run_dir": str(run_dir.resolve()),
            "pcap_path": str(pcap_path),
            "p0f_raw_path": str(p0f_raw_path),
        },
        "nmap": nmap_parsed,
        "p0f": p0f_parsed,
        "pcap_syn": pcap_syn,
    }
    if host_kind == "mobile":
        fingerprint["mobile_passive"] = mobile_passive
        fingerprint["mobile_nmap"] = mobile_nmap

    fp_json_path = run_dir / "fingerprint.json"
    write_json(fp_json_path, fingerprint)
    log.info("STAGE bundle_json written path=%s", fp_json_path)

    # -------------------------
    # 5) Canonização + Hash
    # -------------------------
    canon_obj = None
    canon_str = None
    fp_hash = None

    if build_canon is None or dumps_canon is None:
        log.error("STAGE canon_hash ABORT import_failed err=%s", _CANON_IMPORT_ERR)
        print("\n[!] Canonização/Hash: não foi possível importar canonicalize_features.py")
        print(f"    Erro: {_CANON_IMPORT_ERR}")
        print("    Dica: garanta que canonicalize_features.py está na mesma pasta do bundle_snapshot.py")
    else:
        log.info("STAGE canon_hash START policy=%s", args.canon_policy)
        t0 = time.perf_counter()
        try:
            canon_obj = build_canon(fingerprint, policy=args.canon_policy)
            canon_str = dumps_canon(canon_obj)
            fp_hash = hashlib.sha256(canon_str.encode("utf-8")).hexdigest()
            log.info(
                "STAGE canon_hash OK canon_str_len=%s sha256=%s",
                len(canon_str),
                fp_hash,
            )
            log.debug("CANON_STRING=%s", canon_str)

            canon_json_path = run_dir / "features_canon.json"
            canon_txt_path = run_dir / "features_canon.txt"
            hash_txt_path = run_dir / "fingerprint_sha256.txt"

            write_json(canon_json_path, canon_obj)
            write_text(canon_txt_path, canon_str + "\n")
            write_text(hash_txt_path, fp_hash + "\n")

            tmarks["canon_plus_hash"] = time.perf_counter() - t0

            print("\n=== CANON_STRING ===")
            print(canon_str)
            print("\n=== FINGERPRINT_HASH ===")
            print(fp_hash)

            print("\n[OK] Saved:")
            print(f"  {canon_json_path}")
            print(f"  {canon_txt_path}")
            print(f"  {hash_txt_path}")

        except Exception as e:
            tmarks["canon_plus_hash"] = time.perf_counter() - t0
            log.exception("STAGE canon_hash FAIL elapsed=%s", fmt_secs(tmarks["canon_plus_hash"]))
            print("\n[!] Canonização/Hash falhou:")
            print(f"    {e}")

    # -------------------------
    # 6) Resumo + TIMING
    # -------------------------
    total_elapsed = time.perf_counter() - t_total0
    log.info(
        "=== run end total=%s tmarks=%s log_file=%s ===",
        fmt_secs(total_elapsed),
        {k: fmt_secs(v) for k, v in tmarks.items()},
        run_dir / "fingerprint_pipeline.log",
    )
    print("\n[OK] Bundle salvo em:")
    print(f" {run_dir.resolve()}")
    print(f"\n[OK] Log de pipeline: {run_dir / 'fingerprint_pipeline.log'}")

    print("\n=== TIMING (rodada) ===")
    for key in ["nmap", "dumpcap_capture", "nping_probe", "p0f_wsl", "p0f_native", "tshark_syn_fallback", "canon_plus_hash"]:
        if key in tmarks:
            print(f"{key:18s}: {fmt_secs(tmarks[key])}")
    print(f"{'TOTAL':18s}: {fmt_secs(total_elapsed)}")

    return {
        "target_ip": target_ip,
        "run_dir": run_dir,
        "tmarks": tmarks,
        "fp_hash": fp_hash,
        "total_elapsed": total_elapsed,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Fingerprint TCP/UPnP: modo target (um IP) ou network (SSDP + um fingerprint por host).",
    )
    ap.add_argument("outroot", help="Pasta raiz de saída, ex: runs")
    ap.add_argument(
        "ip",
        nargs="?",
        default=None,
        help="IP alvo (obrigatório com --mode target), ex: 192.168.1.102",
    )
    ap.add_argument(
        "--mode",
        choices=["target", "network"],
        default="target",
        help="target: apenas o IP indicado; network: M-SEARCH SSDP sem filtro e fingerprint de cada host descoberto.",
    )
    ap.add_argument("--seconds", type=int, default=60, help="Duração da captura PCAP")
    ap.add_argument("--iface", required=True, help="Interface do dumpcap (nome ou índice do dumpcap -D)")
    ap.add_argument("--wsl_distro", default=None, help="Nome da distro WSL (opcional). Ex: Ubuntu-22.04")
    ap.add_argument("--dumpcap_path", default="dumpcap", help="Caminho do dumpcap se não estiver no PATH")
    ap.add_argument("--canon_policy", choices=["stable", "rich"], default="stable",
                    help="stable: nmap só manufacturer+model_name; rich: inclui server e name (mais volátil).")
    ap.add_argument("--probe_count", type=int, default=3,
                    help="Quantidade de SYN probes por porta.")
    ap.add_argument("--probe_delay", type=float, default=2.0,
                    help="Segundos de espera após iniciar dumpcap antes do probe.")
    ap.add_argument(
        "--log-level",
        default="DEBUG",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Nível mínimo dos logs (ficheiro fingerprint_pipeline.log e consola se --log-console).",
    )
    ap.add_argument(
        "--log-console",
        action="store_true",
        help="Espelha logs no stderr (além do ficheiro).",
    )
    ap.add_argument(
        "--scan-max-hosts",
        type=int,
        default=0,
        help="Modo network: máximo de hosts a fingerprintar (0 = todos os descobertos por SSDP).",
    )

    args = ap.parse_args()

    if args.mode == "target":
        if not args.ip:
            ap.error("Modo target: indique o IP alvo, ex: python bundle_snapshot.py runs 192.168.1.10 --iface eth0")
        Path(args.outroot).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = Path(args.outroot) / f"{args.ip}_{ts}"
        run_single_fingerprint(run_dir, args.ip, ts, args)
        return

    # --- modo network: SSDP aberto + um run por IP ---
    if args.ip:
        print("[*] Modo network: o argumento posicional 'ip' é ignorado.")
    Path(args.outroot).mkdir(parents=True, exist_ok=True)
    batch_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_root = Path(args.outroot) / f"scan_{batch_ts}"
    scan_root.mkdir(parents=True, exist_ok=True)

    print("[*] Modo network: M-SEARCH SSDP (respostas de qualquer IP na LAN) ...")
    ssdp_raw = ssdp_probe(None)
    write_json(scan_root / "ssdp_discovery.json", ssdp_results_to_jsonable(ssdp_raw))

    def _ip_sort_key(addr: str) -> tuple:
        try:
            return tuple(int(p) for p in addr.split("."))
        except ValueError:
            return (0,)

    hosts = sorted(ssdp_raw.keys(), key=_ip_sort_key)
    if args.scan_max_hosts and args.scan_max_hosts > 0:
        hosts = hosts[: args.scan_max_hosts]

    if not hosts:
        print(
            "[!] Nenhum host descoberto via SSDP. "
            "Use --mode target com IP fixo, ou verifique multicast/firewall na interface."
        )
        sys.exit(1)

    print(f"[*] {len(hosts)} host(s): {', '.join(hosts)}")
    summary_rows = []
    for i, host_ip in enumerate(hosts, 1):
        print(f"\n{'=' * 60}\n[*] [{i}/{len(hosts)}] Fingerprint: {host_ip}\n{'=' * 60}")
        run_dir = scan_root / f"{host_ip}_{batch_ts}"
        row = run_single_fingerprint(run_dir, host_ip, batch_ts, args)
        summary_rows.append(
            {
                "ip": host_ip,
                "sha256": row.get("fp_hash"),
                "run_dir": str(row["run_dir"].resolve()),
            }
        )

    summary_path = scan_root / "scan_summary.json"
    write_json(
        summary_path,
        {
            "mode": "network",
            "batch_ts": batch_ts,
            "hosts": summary_rows,
        },
    )
    print(f"\n[OK] Scan de rede concluído. Resumo: {summary_path.resolve()}")


if __name__ == "__main__":
    main()
