#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iot_id_fingerprint.py

Pipeline de fingerprint de dispositivos (Linux). Para cada IP alvo:

  1. Identidade UPnP/Nmap   (upnp_discovery.collect_upnp_identity)
  2. Captura PCAP           (dumpcap) + sonda SYN ativa (nping)
  3. Assinatura passiva     (p0f offline sobre o PCAP)
  4. Features TCP do SYN    (tshark); em hosts mobile, tambem pistas DHCP/HTTP/TLS
  5. Bundle bruto           -> fingerprint.json
  6. Canonicalizacao + hash -> features_canon.* + fingerprint_sha256.txt

Modos:
  target  : um IP indicado.
  network : descobre hosts por SSDP e roda o pipeline para cada um.

Requisitos: nmap, dumpcap, nping, tshark, p0f. Captura/probe exigem privilegios
(rode com sudo ou conceda capabilities a dumpcap/nping).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from canonicalize_features import build_canon, dumps_canon
from upnp_discovery import collect_upnp_identity, ssdp_probe, ssdp_to_jsonable

DEFAULT_PROBE_PORTS = [80, 443, 22, 445, 139, 3389, 8080, 8443, 9100, 5357]
MOBILE_NMAP_PORTS = "22,5555,8080,554,62078,843,5228"

log = logging.getLogger("fingerprint")


# ----------------------------------------------------------------------
# Helpers de shell / IO
# ----------------------------------------------------------------------
def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def run(cmd: list[str], check: bool = False, timeout: float | None = None) -> tuple[int, str, str]:
    """Executa um comando e retorna (returncode, stdout, stderr) ja decodificados."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    out, err = _decode(p.stdout or b""), _decode(p.stderr or b"")
    if check and p.returncode != 0:
        raise RuntimeError(f"Comando falhou ({p.returncode}): {' '.join(cmd)}\n{err}")
    return p.returncode, out, err


def tshark_rows(pcap: Path, dfilter: str, *fields: str) -> list[list[str]]:
    """Roda tshark com um display filter e campos -e; devolve linhas tabuladas."""
    cmd = ["tshark", "-r", str(pcap), "-Y", dfilter, "-T", "fields", "-E", "separator=\t"]
    for field in fields:
        cmd += ["-e", field]
    rc, out, _ = run(cmd)
    if rc != 0 or not out.strip():
        return []
    return [line.split("\t") for line in out.strip().splitlines()]


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True),
                    encoding="utf-8", errors="replace")


def fmt_secs(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    return f"{int(seconds // 60)}m {seconds % 60:05.2f}s"


def default_iface() -> str | None:
    """Interface da rota por defeito (equivalente a `ip route get 8.8.8.8`)."""
    rc, out, _ = run(["ip", "route", "get", "8.8.8.8"])
    if rc == 0:
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            return m.group(1)
    return None


# ----------------------------------------------------------------------
# p0f: parse e extracao de assinaturas
# ----------------------------------------------------------------------
_P0F_BLOCK_RE = re.compile(r"\.-\[\s*(.*?)\s*\]-\n\|\n(.*?)\n`----", re.S)


def parse_p0f_raw(text: str) -> dict:
    """Quebra a saida do p0f em blocos {header, fields}."""
    blocks = []
    for header, body in _P0F_BLOCK_RE.findall(text):
        fields = {}
        for line in body.splitlines():
            line = line.strip().lstrip("|").strip()
            if " = " in line:
                k, v = line.split(" = ", 1)
                fields[k.strip()] = v.strip()
        blocks.append({"header": header.strip(), "fields": fields})
    m = re.search(r"Processed\s+(\d+)\s+packets", text)
    return {
        "summary": {"processed_packets": int(m.group(1)) if m else None,
                    "blocks_count": len(blocks)},
        "blocks": blocks,
    }


def _addr_matches(target_ip: str, field_val: str) -> bool:
    """True se o campo client/server do bloco p0f e do IP alvo."""
    if not field_val or not target_ip:
        return False
    head = re.split(r"[\s/(]", field_val.strip(), maxsplit=1)[0]
    return head == target_ip


def extract_p0f_sets(parsed: dict, target_ip: str) -> dict:
    """Coleta as raw_sig de SYN (cliente) e SYN+ACK (servidor) do IP alvo."""
    client_syn, server_synack = set(), set()
    for block in parsed.get("blocks", []):
        header = block.get("header", "").lower()
        fields = block.get("fields", {})
        if "(syn)" in header and _addr_matches(target_ip, fields.get("client", "")):
            if fields.get("raw_sig"):
                client_syn.add(fields["raw_sig"])
        elif "(syn+ack)" in header and _addr_matches(target_ip, fields.get("server", "")):
            if fields.get("raw_sig"):
                server_synack.add(fields["raw_sig"])
    return {
        "client_syn_raw_sig_set": sorted(client_syn),
        "server_synack_raw_sig_set": sorted(server_synack),
    }


# ----------------------------------------------------------------------
# tshark: features do SYN/SYN+ACK e pistas passivas mobile
# ----------------------------------------------------------------------
_OPTION_TAGS = [("mss", "mss"), ("sack_perm", "sack_perm"), ("timestamp", "ts"),
                ("wscale", "ws"), ("nop", "nop"), ("eol", "eol")]


def _options_order(options_line: str) -> str | None:
    """Ordem das opcoes TCP a partir do campo textual tcp.options."""
    line = options_line.lower()
    found = sorted((line.find(needle), tag) for needle, tag in _OPTION_TAGS if needle in line)
    return ",".join(tag for _, tag in found) or None


def extract_syn_features(pcap: Path, ip: str) -> dict:
    """Extrai features do 1o SYN+ACK do alvo; senao do 1o SYN; senao so o TTL."""
    if not pcap.exists() or pcap.stat().st_size == 0:
        return {"error": "pcap_missing_or_empty"}

    cols = ["ip.ttl", "tcp.window_size_value", "tcp.options.mss_val",
            "tcp.options.wscale.shift", "tcp.options.sack_perm", "tcp.options.timestamp"]
    for dfilter in (f"ip.src=={ip} && tcp.flags.syn==1 && tcp.flags.ack==1",
                    f"ip.src=={ip} && tcp.flags.syn==1 && tcp.flags.ack==0"):
        rows = tshark_rows(pcap, dfilter, *cols)
        if not rows:
            continue
        row = rows[0]
        col = lambda i: row[i] if i < len(row) and row[i] else None
        feats = {
            "chosen_filter": dfilter,
            "ttl": col(0), "window_size": col(1), "mss": col(2), "ws": col(3),
            "sack_perm": col(4), "ts_present": "1" if col(5) else "0",
            "options_order": None,
        }
        opts = tshark_rows(pcap, dfilter, "tcp.options")
        if opts and opts[0]:
            feats["options_order"] = _options_order(opts[0][0])
        return feats

    # Sem SYN/SYN+ACK TCP visivel: cai para o TTL de qualquer pacote do alvo.
    is_v6 = ":" in ip
    rows = tshark_rows(pcap, f"{'ipv6.src' if is_v6 else 'ip.src'}=={ip}",
                       "ipv6.hlim" if is_v6 else "ip.ttl")
    for row in rows:
        if row and row[0].strip():
            return {"ttl": row[0].strip(), "fallback": "ip_layer_ttl_only"}
    return {"error": "no_syn_or_synack_found"}


def _norm_token(s: str, max_len: int = 512) -> str:
    return " ".join(s.split()).strip()[:max_len]


def extract_mobile_passive(pcap: Path, ip: str) -> dict:
    """Pistas passivas tipicas de telemoveis: DHCP, HTTP UA, SNI TLS, mDNS, NBNS."""
    if not pcap.exists() or pcap.stat().st_size == 0:
        return {"error": "pcap_missing_or_empty"}

    def collect(dfilter: str, *fields: str) -> list[str]:
        tokens = set()
        for row in tshark_rows(pcap, dfilter, *fields):
            for col in row:
                tok = _norm_token(col.strip())
                if tok and tok != "<MISSING>":
                    tokens.add(tok)
        return sorted(tokens)

    return {
        "dhcp_hostname_set": collect(f"(dhcp || bootp) && ip.src=={ip}", "dhcp.option.hostname"),
        "dhcp_vendor_class_set": collect(f"(dhcp || bootp) && ip.src=={ip}",
                                         "dhcp.option.vendor_class_id", "dhcp.option.class_id"),
        "http_user_agent_set": collect(f"http.user_agent && ip.src=={ip}", "http.user_agent"),
        "tls_sni_set": collect(f"tls.handshake.type == 1 && ip.src=={ip}",
                               "tls.handshake.extensions_server_name"),
        "mdns_name_set": collect(f"udp.port==5353 && ip.src=={ip}", "dns.qry.name", "mdns.cname"),
        "nbns_name_set": collect(f"nbns && ip.src=={ip}", "nbns.name"),
    }


def nmap_mobile_scan(target: str) -> dict:
    """Sonda leve de portas comuns em telemoveis para banners (-sV)."""
    cmd = ["sudo", "nmap", "-Pn", "-sV", "--version-intensity", "1", "-p", MOBILE_NMAP_PORTS,
           "--script-timeout", "25s", "--host-timeout", "95s", target]
    try:
        raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=125)
    except subprocess.TimeoutExpired:
        return {"error": "nmap_mobile_timeout", "service_lines": []}
    except Exception as e:
        return {"error": str(e), "service_lines": []}
    lines = {_norm_token(line.strip(), 400) for line in raw.splitlines()
             if ("/tcp" in line or "/udp" in line)}
    return {"service_lines": sorted(lines)[:30], "raw_chars": len(raw)}


def infer_host_kind(identity: dict) -> str:
    """'iot' se UPnP/Nmap deu fabricante ou modelo; senao 'mobile'."""
    if (identity.get("manufacturer") or "").strip() or (identity.get("model_name") or "").strip():
        return "iot"
    return "mobile"


# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------
def setup_logging(run_dir: Path, level: str, console: bool) -> None:
    log.handlers.clear()
    log.setLevel(getattr(logging, level.upper(), logging.INFO))
    log.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s", "%Y-%m-%dT%H:%M:%S")
    fh = logging.FileHandler(run_dir / "fingerprint_pipeline.log", encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)


# ----------------------------------------------------------------------
# Pipeline de um host
# ----------------------------------------------------------------------
def capture_and_probe(pcap_path: Path, args: argparse.Namespace, target_ip: str) -> None:
    """Captura PCAP com dumpcap (async) enquanto dispara uma sonda SYN com nping."""
    cap = subprocess.Popen(
        [args.dumpcap_path, "-i", args.iface, "-w", str(pcap_path),
         "-a", f"duration:{args.seconds}", "-f", f"host {target_ip}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(max(0.0, args.probe_delay))

    ports_csv = ",".join(str(p) for p in args.probe_ports)
    print(f"[*] Sonda nping SYN (ports={ports_csv}, count={args.probe_count}) ...")
    run(["nping", "--tcp", "-p", ports_csv, "--flags", "syn",
         "--count", str(args.probe_count), target_ip])
    cap.communicate()


def run_single_fingerprint(run_dir: Path, target_ip: str, ts: str, args: argparse.Namespace) -> dict:
    """Executa o pipeline completo para um IP e devolve um resumo."""
    t_total = time.perf_counter()
    tmarks: dict = {}
    run_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(run_dir, args.log_level, args.log_console)
    log.info("=== run start ip=%s ts=%s policy=%s ===", target_ip, ts, args.canon_policy)

    # 1) Identidade UPnP / Nmap
    print(f"[*] Nmap/UPnP (alvo {target_ip}) ...")
    t0 = time.perf_counter()
    identity, nmap_stdout = collect_upnp_identity(target_ip)
    tmarks["nmap"] = time.perf_counter() - t0
    write_text(run_dir / "nmap" / "upnp_stdout.txt", nmap_stdout)
    write_json(run_dir / "nmap" / "upnp_identity.json", identity)

    host_kind = infer_host_kind(identity)
    log.info("host_kind=%s identity=%s", host_kind, {k: identity.get(k) for k in
             ("server", "name", "manufacturer", "model_name")})
    print(f"[*] host_kind={host_kind}"
          + ("" if host_kind == "iot" else " (sem identidade UPnP; SHA usa so p0f+pcap_syn)"))

    # 2) Captura PCAP + sonda SYN
    print("[*] Captura PCAP (dumpcap) + sonda nping ...")
    pcap_path = run_dir / "pcaps" / f"capture_{target_ip}_{ts}.pcap"
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    capture_and_probe(pcap_path, args, target_ip)
    tmarks["capture"] = time.perf_counter() - t0
    pcap_size = pcap_path.stat().st_size if pcap_path.exists() else 0
    log.info("pcap path=%s size=%s", pcap_path, pcap_size)

    p0f_raw_path = run_dir / "p0f" / f"p0f_{target_ip}_{ts}.raw.txt"
    mobile_passive: dict = {}
    mobile_nmap: dict = {}

    # 3) p0f + 4) tshark
    if not pcap_size:
        print("[!] PCAP vazio/inexistente; pulando p0f/tshark. "
              "Verifique a interface (dumpcap -D), permissoes e o trafego do alvo.")
        p0f_parsed = {"error": "pcap_missing_or_empty", "extracted": {}}
        pcap_syn = {"error": "pcap_missing_or_empty"}
        if host_kind == "mobile":
            mobile_nmap = nmap_mobile_scan(target_ip)
            mobile_passive = {"error": "pcap_missing_or_empty"}
    else:
        print("[*] p0f (offline) ...")
        t0 = time.perf_counter()
        _, p0f_out, p0f_err = run(["p0f", "-r", str(pcap_path.resolve())])
        tmarks["p0f"] = time.perf_counter() - t0
        write_text(p0f_raw_path, p0f_out)
        write_text(run_dir / "p0f" / f"p0f_{target_ip}_{ts}.stderr.txt", p0f_err)
        p0f_parsed = parse_p0f_raw(p0f_out)
        p0f_parsed["extracted"] = extract_p0f_sets(p0f_parsed, target_ip)

        print("[*] Features TCP do SYN/SYN+ACK (tshark) ...")
        t0 = time.perf_counter()
        pcap_syn = extract_syn_features(pcap_path, target_ip)
        tmarks["tshark"] = time.perf_counter() - t0

        if host_kind == "mobile":
            print("[*] Mobile: pistas passivas DHCP/HTTP/TLS + nmap (so JSON) ...")
            mobile_passive = extract_mobile_passive(pcap_path, target_ip)
            mobile_nmap = nmap_mobile_scan(target_ip)

    # 5) Bundle bruto
    bundle = {
        "meta": {
            "ts": ts, "ip": target_ip, "host_kind": host_kind,
            "mode": getattr(args, "mode", "target"), "seconds": args.seconds,
            "iface": args.iface, "probe_ports": args.probe_ports,
            "probe_count": args.probe_count,
        },
        "paths": {"run_dir": str(run_dir.resolve()), "pcap_path": str(pcap_path),
                  "p0f_raw_path": str(p0f_raw_path)},
        "nmap": identity,
        "p0f": p0f_parsed,
        "pcap_syn": pcap_syn,
    }
    if host_kind == "mobile":
        bundle["mobile_passive"] = mobile_passive
        bundle["mobile_nmap"] = mobile_nmap
    write_json(run_dir / "fingerprint.json", bundle)

    # 6) Canonicalizacao + hash
    fp_hash = None
    try:
        canon_obj = build_canon(bundle, policy=args.canon_policy)
        canon_str = dumps_canon(canon_obj)
        fp_hash = hashlib.sha256(canon_str.encode("utf-8")).hexdigest()
        write_json(run_dir / "features_canon.json", canon_obj)
        write_text(run_dir / "features_canon.txt", canon_str + "\n")
        write_text(run_dir / "fingerprint_sha256.txt", fp_hash + "\n")
        log.info("canon ok sha256=%s", fp_hash)
        print(f"\n=== CANON_STRING ===\n{canon_str}\n\n=== FINGERPRINT_HASH ===\n{fp_hash}")
    except Exception as e:
        log.exception("canon/hash falhou")
        print(f"\n[!] Canonicalizacao/Hash falhou: {e}")

    if args.cleanup:
        removed = 0
        for raw in (pcap_path, p0f_raw_path):
            try:
                if raw.exists():
                    raw.unlink()
                    removed += 1
            except OSError as err:
                log.warning("cleanup falhou path=%s err=%s", raw, err)
        print(f"[*] --cleanup: {removed} artefato(s) bruto(s) removido(s).")

    total = time.perf_counter() - t_total
    log.info("=== run end total=%s ===", fmt_secs(total))
    print(f"\n[OK] Bundle: {run_dir.resolve()}")
    print("\n=== TIMING ===")
    for key, value in tmarks.items():
        print(f"{key:12s}: {fmt_secs(value)}")
    print(f"{'TOTAL':12s}: {fmt_secs(total)}")

    return {"target_ip": target_ip, "run_dir": run_dir, "fp_hash": fp_hash, "total": total}


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Fingerprint TCP/UPnP de dispositivos (modo target ou network).")
    ap.add_argument("outroot", help="Pasta raiz de saida (ex: runs)")
    ap.add_argument("ip", nargs="?", help="IP alvo (obrigatorio no modo target)")
    ap.add_argument("--mode", choices=["target", "network"], default="target",
                    help="target: o IP indicado; network: descobre hosts por SSDP.")
    ap.add_argument("--iface", help="Interface de captura (default: rota por defeito)")
    ap.add_argument("--seconds", type=int, default=60, help="Duracao da captura PCAP")
    ap.add_argument("--dumpcap-path", default="dumpcap", help="Caminho do dumpcap")
    ap.add_argument("--canon-policy", choices=["stable", "rich"], default="stable",
                    help="stable: nmap so manufacturer+model_name; rich: inclui server e name.")
    ap.add_argument("--probe-ports", default=",".join(str(p) for p in DEFAULT_PROBE_PORTS),
                    help="Portas da sonda SYN, separadas por virgula.")
    ap.add_argument("--probe-count", type=int, default=3, help="SYN probes por porta.")
    ap.add_argument("--probe-delay", type=float, default=2.0,
                    help="Espera (s) apos iniciar o dumpcap antes da sonda.")
    ap.add_argument("--cleanup", action="store_true",
                    help="Remove artefatos brutos (.pcap e p0f.raw.txt) ao fim.")
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ap.add_argument("--log-console", action="store_true", help="Espelha logs no stderr.")
    ap.add_argument("--scan-max-hosts", type=int, default=0,
                    help="Modo network: maximo de hosts (0 = todos).")
    return ap


def main() -> None:
    args = build_parser().parse_args()

    # Parametrizacao flexivel: interface auto-detectada e portas como lista.
    if not args.iface:
        args.iface = default_iface()
        if not args.iface:
            sys.exit("[!] Nao foi possivel detetar a interface; use --iface.")
        print(f"[*] Interface auto-detetada: {args.iface}")
    try:
        args.probe_ports = [int(p) for p in str(args.probe_ports).split(",") if p.strip()]
    except ValueError:
        sys.exit("[!] --probe-ports invalido (use inteiros separados por virgula).")

    Path(args.outroot).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.mode == "target":
        if not args.ip:
            sys.exit("[!] Modo target: indique o IP, ex: iot_id_fingerprint.py runs 192.168.1.10")
        run_single_fingerprint(Path(args.outroot) / f"{args.ip}_{ts}", args.ip, ts, args)
        return

    # Modo network: descobre hosts via SSDP e roda o pipeline em cada um.
    scan_root = Path(args.outroot) / f"scan_{ts}"
    scan_root.mkdir(parents=True, exist_ok=True)
    print("[*] Modo network: M-SEARCH SSDP ...")
    ssdp_raw = ssdp_probe(None)
    write_json(scan_root / "ssdp_discovery.json", ssdp_to_jsonable(ssdp_raw))

    def ip_key(addr: str) -> tuple:
        try:
            return tuple(int(p) for p in addr.split("."))
        except ValueError:
            return (0,)

    hosts = sorted(ssdp_raw, key=ip_key)
    if args.scan_max_hosts > 0:
        hosts = hosts[:args.scan_max_hosts]
    if not hosts:
        sys.exit("[!] Nenhum host via SSDP. Use --mode target ou verifique multicast/firewall.")

    print(f"[*] {len(hosts)} host(s): {', '.join(hosts)}")
    rows = []
    for i, host_ip in enumerate(hosts, 1):
        print(f"\n{'=' * 60}\n[*] [{i}/{len(hosts)}] {host_ip}\n{'=' * 60}")
        row = run_single_fingerprint(scan_root / f"{host_ip}_{ts}", host_ip, ts, args)
        rows.append({"ip": host_ip, "sha256": row["fp_hash"],
                     "run_dir": str(row["run_dir"].resolve())})

    write_json(scan_root / "scan_summary.json", {"mode": "network", "batch_ts": ts, "hosts": rows})
    print(f"\n[OK] Scan concluido: {scan_root.resolve()}")


if __name__ == "__main__":
    main()
