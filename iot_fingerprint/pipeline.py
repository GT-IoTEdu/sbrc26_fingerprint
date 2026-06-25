#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Main IoT-ID fingerprinting pipeline and CLI."""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .canonical import build_canon, dumps_canon
from .hashing import compute_hash_from_canon_string
from .mobile import extract_mobile_passive_tshark, nmap_mobile_scan
from .p0f import extract_p0f_sets, parse_p0f_raw
from .runtime import decode_bytes, fmt_secs, run, setup_fingerprint_logging, win_to_wsl_path, write_json, write_text
from .tshark_features import extract_tcp_syn_features_tshark
from .upnp import collect_upnp_identity, ssdp_probe, ssdp_results_to_jsonable

PROBE_PORTS = [80, 443, 22, 445, 139, 3389, 8080, 8443, 9100, 5357]
TIMING_KEYS = [
    "nmap",
    "dumpcap_capture",
    "nping_probe",
    "p0f_wsl",
    "p0f_native",
    "tshark_syn_fallback",
    "canon_plus_hash",
]


def infer_host_kind(nmap_block: Dict[str, Any]) -> str:
    """Classify as IoT when UPnP/Nmap identified manufacturer or model, else mobile."""
    if not isinstance(nmap_block, dict):
        return "mobile"
    manufacturer = (nmap_block.get("manufacturer") or "").strip()
    model_name = (nmap_block.get("model_name") or "").strip()
    return "iot" if (manufacturer or model_name) else "mobile"


class RunContext:
    """Small context object grouping paths and mutable timing for a single run."""

    def __init__(self, run_dir: Path, target_ip: str, ts: str, args: argparse.Namespace) -> None:
        self.run_dir = run_dir
        self.target_ip = target_ip
        self.ts = ts
        self.args = args
        self.tmarks: Dict[str, float] = {}
        self.nmap_dir = run_dir / "nmap"
        self.pcap_dir = run_dir / "pcaps"
        self.p0f_dir = run_dir / "p0f"
        self.pcap_path = self.pcap_dir / f"capture_{target_ip}_{ts}.pcap"
        self.p0f_raw_path = self.p0f_dir / f"p0f_{target_ip}_{ts}.raw.txt"

    def create_dirs(self) -> None:
        for path in (self.nmap_dir, self.pcap_dir, self.p0f_dir):
            path.mkdir(parents=True, exist_ok=True)


def run_single_fingerprint(run_dir: Path, target_ip: str, ts: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Run the complete fingerprint pipeline for one target IP."""
    ctx = RunContext(run_dir, target_ip, ts, args)
    ctx.create_dirs()
    total_start = time.perf_counter()

    setup_fingerprint_logging(run_dir, args.log_level, args.log_console)
    log = logging.getLogger("fingerprint.pipeline")
    _log_run_start(log, target_ip, ts, args)

    nmap_parsed, host_kind = _stage_upnp_identity(ctx, log)
    mobile_passive: Dict[str, Any] = {}
    mobile_nmap: Dict[str, Any] = {}

    capture_result = _stage_capture_and_probe(ctx, log)
    p0f_parsed, pcap_syn = _stage_packet_analysis(ctx, log, host_kind)

    if host_kind == "mobile":
        mobile_passive, mobile_nmap = _stage_mobile_evidence(ctx, log, pcap_available=_pcap_available(ctx.pcap_path))

    fingerprint = _build_fingerprint_bundle(
        ctx=ctx,
        host_kind=host_kind,
        nmap_parsed=nmap_parsed,
        p0f_parsed=p0f_parsed,
        pcap_syn=pcap_syn,
        probe_used=capture_result["probe_used"],
        mobile_passive=mobile_passive,
        mobile_nmap=mobile_nmap,
    )
    fp_json_path = run_dir / "fingerprint.json"
    write_json(fp_json_path, fingerprint)
    log.info("STAGE bundle_json written path=%s", fp_json_path)

    fp_hash = _stage_canon_hash(ctx, log, fingerprint)

    total_elapsed = time.perf_counter() - total_start
    _print_run_summary(ctx, log, total_elapsed)

    return {
        "target_ip": target_ip,
        "run_dir": run_dir,
        "tmarks": ctx.tmarks,
        "fp_hash": fp_hash,
        "total_elapsed": total_elapsed,
    }


def _log_run_start(log: logging.Logger, target_ip: str, ts: str, args: argparse.Namespace) -> None:
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


def _stage_upnp_identity(ctx: RunContext, log: logging.Logger) -> Tuple[Dict[str, Any], str]:
    print(f"[*] Running Nmap (alvo {ctx.target_ip}) ...")
    log.info("STAGE nmap_upnp START")
    started = time.perf_counter()

    nmap_parsed, upnp_stdout = collect_upnp_identity(ctx.target_ip)

    ctx.tmarks["nmap"] = time.perf_counter() - started
    log.info(
        "STAGE nmap_upnp END elapsed=%s server=%r name=%r manufacturer=%r model_name=%r",
        fmt_secs(ctx.tmarks["nmap"]),
        nmap_parsed.get("server"),
        nmap_parsed.get("name"),
        nmap_parsed.get("manufacturer"),
        nmap_parsed.get("model_name"),
    )
    log.debug("nmap_upnp stdout_chars=%s", len(upnp_stdout or ""))

    write_text(ctx.nmap_dir / "bundle_nmap_stdout.txt", upnp_stdout)
    write_json(ctx.nmap_dir / "bundle_nmap_identity.json", nmap_parsed)

    if any([nmap_parsed.get("server"), nmap_parsed.get("name"), nmap_parsed.get("manufacturer"), nmap_parsed.get("model_name")]):
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

    return nmap_parsed, host_kind


def _stage_capture_and_probe(ctx: RunContext, log: logging.Logger) -> Dict[str, Any]:
    print("[*] Capturing PCAP with dumpcap (async) ...")
    log.info("STAGE pcap_capture START duration_s=%s filter_host=%s", ctx.args.seconds, ctx.target_ip)
    started = time.perf_counter()

    capture_cmd = [
        ctx.args.dumpcap_path,
        "-i", ctx.args.iface,
        "-w", str(ctx.pcap_path),
        "-a", f"duration:{ctx.args.seconds}",
        "-f", f"host {ctx.target_ip}",
    ]
    log.debug("dumpcap_cmd=%s", " ".join(capture_cmd))
    capture_process = subprocess.Popen(capture_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(max(0.0, ctx.args.probe_delay))

    probe_started = time.perf_counter()
    ports_csv = ",".join(str(port) for port in PROBE_PORTS)
    print(f"[*] Probing common ports with nping SYN (ports={ports_csv}, count={ctx.args.probe_count}) ...")
    nping_cmd = [
        "nping",
        "--tcp",
        "-p", ports_csv,
        "--flags", "syn",
        "--count", str(ctx.args.probe_count),
        ctx.target_ip,
    ]
    log.info("STAGE nping_probe cmd=%s", " ".join(nping_cmd))
    np_out, np_err = run(nping_cmd, check=False)
    log.debug("nping rc_ok stdout_chars=%s stderr_chars=%s", len(np_out or ""), len(np_err or ""))
    write_text(ctx.run_dir / "nping_stdout.txt", np_out)
    if np_err.strip():
        write_text(ctx.run_dir / "nping_stderr.txt", np_err)

    ctx.tmarks["nping_probe"] = time.perf_counter() - probe_started

    out_b, err_b = capture_process.communicate()
    cap_out = decode_bytes(out_b or b"")
    cap_err = decode_bytes(err_b or b"")

    ctx.tmarks["dumpcap_capture"] = time.perf_counter() - started
    write_text(ctx.pcap_dir / "bundle_dumpcap_stdout.txt", cap_out)
    write_text(ctx.pcap_dir / "bundle_dumpcap_stderr.txt", cap_err)

    pcap_size = ctx.pcap_path.stat().st_size if ctx.pcap_path.exists() else 0
    log.info(
        "STAGE pcap_capture END elapsed=%s pcap_path=%s size_bytes=%s",
        fmt_secs(ctx.tmarks["dumpcap_capture"]),
        ctx.pcap_path,
        pcap_size,
    )
    return {"probe_used": True}


def _stage_packet_analysis(ctx: RunContext, log: logging.Logger, host_kind: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not _pcap_available(ctx.pcap_path):
        return _handle_missing_pcap(ctx, log)

    p0f_parsed = _run_p0f(ctx, log)
    pcap_syn = _extract_syn_features(ctx, log)
    return p0f_parsed, pcap_syn


def _handle_missing_pcap(ctx: RunContext, log: logging.Logger) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    log.warning("STAGE p0f_tshark SKIP reason=pcap_missing_or_empty")
    print("[!] PCAP não foi criado ou está vazio; pulando p0f/tshark.")
    print("    Verifique:")
    print("    - Nome/índice correto da interface (dumpcap -D)")
    print("    - Permissões (tshark/dumpcap pode exigir sudo/capabilities)")
    print("    - Filtro/host correto (IP realmente gerando tráfego)")

    write_text(ctx.p0f_raw_path, "")
    write_text(ctx.p0f_dir / f"p0f_{ctx.target_ip}_{ctx.ts}.stderr.txt", "skipped: pcap_missing_or_empty")

    p0f_parsed = {
        "error": "pcap_missing_or_empty",
        "warnings": [],
        "summary": {"processed_packets": None, "blocks_count": 0},
        "blocks": [],
        "extracted": {},
    }
    pcap_syn = {"error": "pcap_missing_or_empty"}
    log.info("STAGE tshark_syn_fallback SKIPPED (no pcap) pcap_syn=%s", json.dumps(pcap_syn, ensure_ascii=False, sort_keys=True))
    return p0f_parsed, pcap_syn


def _run_p0f(ctx: RunContext, log: logging.Logger) -> Dict[str, Any]:
    log.info("STAGE p0f START")
    started = time.perf_counter()

    if os.name == "nt":
        print("[*] Running p0f in WSL (offline -r) ...")
        pcap_arg = win_to_wsl_path(ctx.pcap_path)
        wsl_prefix = ["wsl", "--"]
        if ctx.args.wsl_distro:
            wsl_prefix = ["wsl", "-d", ctx.args.wsl_distro, "--"]
        p0f_cmd = wsl_prefix + ["p0f", "-r", pcap_arg]
        log.debug("p0f_cmd=%s", " ".join(p0f_cmd))
        p0f_out, p0f_err = run(p0f_cmd, check=False)
        ctx.tmarks["p0f_wsl"] = time.perf_counter() - started
    else:
        print("[*] Running p0f (native) (offline -r) ...")
        pcap_arg = str(ctx.pcap_path.resolve())
        p0f_cmd = ["p0f", "-r", pcap_arg]
        log.debug("p0f_cmd=%s", " ".join(p0f_cmd))
        p0f_out, p0f_err = run(p0f_cmd, check=False)
        ctx.tmarks["p0f_native"] = time.perf_counter() - started

    write_text(ctx.p0f_raw_path, p0f_out)
    write_text(ctx.p0f_dir / f"p0f_{ctx.target_ip}_{ctx.ts}.stderr.txt", p0f_err)

    p0f_parsed = parse_p0f_raw(p0f_out)
    summary = p0f_parsed.get("summary", {})
    log.info(
        "STAGE p0f parse summary processed_packets=%s blocks_count=%s warnings=%s",
        summary.get("processed_packets"),
        summary.get("blocks_count"),
        len(p0f_parsed.get("warnings") or []),
    )
    p0f_parsed["extracted"] = extract_p0f_sets(p0f_parsed, ctx.target_ip)
    return p0f_parsed


def _extract_syn_features(ctx: RunContext, log: logging.Logger) -> Dict[str, Any]:
    print("[*] Extracting SYN/SYN+ACK TCP features from PCAP via tshark ...")
    log.info("STAGE tshark_syn_fallback START")
    started = time.perf_counter()
    pcap_syn = extract_tcp_syn_features_tshark(ctx.pcap_path, ctx.target_ip)
    ctx.tmarks["tshark_syn_fallback"] = time.perf_counter() - started
    log.info(
        "STAGE tshark_syn_fallback END elapsed=%s pcap_syn=%s",
        fmt_secs(ctx.tmarks["tshark_syn_fallback"]),
        json.dumps(pcap_syn, ensure_ascii=False, sort_keys=True),
    )
    return pcap_syn


def _stage_mobile_evidence(ctx: RunContext, log: logging.Logger, pcap_available: bool) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not pcap_available:
        print("[*] Modo mobile: sonda nmap (só JSON; não entra no SHA-256) ...")
        started = time.perf_counter()
        mobile_nmap = nmap_mobile_scan(ctx.target_ip)
        ctx.tmarks["nmap_mobile"] = time.perf_counter() - started
        return {"error": "pcap_missing_or_empty"}, mobile_nmap

    print("[*] Modo mobile: extraindo DHCP/HTTP/TLS/mDNS + nmap (só JSON; SHA só p0f+pcap_syn) ...")
    passive_started = time.perf_counter()
    mobile_passive = extract_mobile_passive_tshark(ctx.pcap_path, ctx.target_ip)
    ctx.tmarks["mobile_passive_tshark"] = time.perf_counter() - passive_started

    nmap_started = time.perf_counter()
    mobile_nmap = nmap_mobile_scan(ctx.target_ip)
    ctx.tmarks["nmap_mobile"] = time.perf_counter() - nmap_started
    return mobile_passive, mobile_nmap


def _build_fingerprint_bundle(
    ctx: RunContext,
    host_kind: str,
    nmap_parsed: Dict[str, Any],
    p0f_parsed: Dict[str, Any],
    pcap_syn: Dict[str, Any],
    probe_used: bool,
    mobile_passive: Dict[str, Any],
    mobile_nmap: Dict[str, Any],
) -> Dict[str, Any]:
    fingerprint = {
        "meta": {
            "ts": ctx.ts,
            "ip": ctx.target_ip,
            "host_kind": host_kind,
            "mode": getattr(ctx.args, "mode", "target"),
            "seconds": ctx.args.seconds,
            "iface": ctx.args.iface,
            "wsl_distro": ctx.args.wsl_distro if os.name == "nt" else None,
            "probe_used": bool(probe_used),
            "probe_ports": PROBE_PORTS,
            "probe_count": ctx.args.probe_count,
        },
        "paths": {
            "run_dir": str(ctx.run_dir.resolve()),
            "pcap_path": str(ctx.pcap_path),
            "p0f_raw_path": str(ctx.p0f_raw_path),
        },
        "nmap": nmap_parsed,
        "p0f": p0f_parsed,
        "pcap_syn": pcap_syn,
    }
    if host_kind == "mobile":
        fingerprint["mobile_passive"] = mobile_passive
        fingerprint["mobile_nmap"] = mobile_nmap
    return fingerprint


def _stage_canon_hash(ctx: RunContext, log: logging.Logger, fingerprint: Dict[str, Any]) -> Optional[str]:
    log.info("STAGE canon_hash START policy=%s", ctx.args.canon_policy)
    started = time.perf_counter()
    fp_hash = None
    try:
        canon_obj = build_canon(fingerprint, policy=ctx.args.canon_policy)
        canon_str = dumps_canon(canon_obj)
        fp_hash = compute_hash_from_canon_string(canon_str, algo="sha256")
        log.info("STAGE canon_hash OK canon_str_len=%s sha256=%s", len(canon_str), fp_hash)
        log.debug("CANON_STRING=%s", canon_str)

        canon_json_path = ctx.run_dir / "features_canon.json"
        canon_txt_path = ctx.run_dir / "features_canon.txt"
        hash_txt_path = ctx.run_dir / "fingerprint_sha256.txt"
        write_json(canon_json_path, canon_obj)
        write_text(canon_txt_path, canon_str + "\n")
        write_text(hash_txt_path, fp_hash + "\n")

        ctx.tmarks["canon_plus_hash"] = time.perf_counter() - started

        print("\n=== CANON_STRING ===")
        print(canon_str)
        print("\n=== FINGERPRINT_HASH ===")
        print(fp_hash)
        print("\n[OK] Saved:")
        print(f"  {canon_json_path}")
        print(f"  {canon_txt_path}")
        print(f"  {hash_txt_path}")
    except Exception as exc:
        ctx.tmarks["canon_plus_hash"] = time.perf_counter() - started
        log.exception("STAGE canon_hash FAIL elapsed=%s", fmt_secs(ctx.tmarks["canon_plus_hash"]))
        print("\n[!] Canonização/Hash falhou:")
        print(f"    {exc}")
    finally:
        if ctx.args.cleanup:
            removed_count, error_count = _cleanup_raw_artifacts(ctx, log)
            if error_count > 0:
                print(
                    "[!] --cleanup ativo: houve erro ao remover alguns artefatos brutos "
                    "(.pcap, p0f.raw.txt); veja o log."
                )
            else:
                print(
                    "[*] --cleanup ativo: artefatos brutos removidos "
                    f"(.pcap, p0f.raw.txt) [{removed_count} arquivo(s)]."
                )
    return fp_hash


def _cleanup_raw_artifacts(ctx: RunContext, log: logging.Logger) -> Tuple[int, int]:
    removed = 0
    errors = 0
    for raw_path in [ctx.pcap_path, ctx.p0f_raw_path]:
        try:
            if raw_path.exists():
                raw_path.unlink()
                removed += 1
                log.info("cleanup removed path=%s", raw_path)
        except Exception as cleanup_err:
            errors += 1
            log.warning("cleanup failed path=%s err=%s", raw_path, cleanup_err)
    return removed, errors


def _pcap_available(pcap_path: Path) -> bool:
    return pcap_path.exists() and pcap_path.stat().st_size > 0


def _print_run_summary(ctx: RunContext, log: logging.Logger, total_elapsed: float) -> None:
    log.info(
        "=== run end total=%s tmarks=%s log_file=%s ===",
        fmt_secs(total_elapsed),
        {key: fmt_secs(value) for key, value in ctx.tmarks.items()},
        ctx.run_dir / "fingerprint_pipeline.log",
    )
    print("\n[OK] Bundle salvo em:")
    print(f" {ctx.run_dir.resolve()}")
    print(f"\n[OK] Log de pipeline: {ctx.run_dir / 'fingerprint_pipeline.log'}")

    print("\n=== TIMING (rodada) ===")
    for key in TIMING_KEYS:
        if key in ctx.tmarks:
            print(f"{key:18s}: {fmt_secs(ctx.tmarks[key])}")
    print(f"{'TOTAL':18s}: {fmt_secs(total_elapsed)}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fingerprint TCP/UPnP: modo target (um IP) ou network (SSDP + um fingerprint por host).",
    )
    parser.add_argument("outroot", help="Pasta raiz de saída, ex: runs")
    parser.add_argument(
        "ip",
        nargs="?",
        default=None,
        help="IP alvo (obrigatório com --mode target), ex: 192.168.1.102",
    )
    parser.add_argument(
        "--mode",
        choices=["target", "network"],
        default="target",
        help="target: apenas o IP indicado; network: M-SEARCH SSDP sem filtro e fingerprint de cada host descoberto.",
    )
    parser.add_argument("--seconds", type=int, default=60, help="Duração da captura PCAP")
    parser.add_argument("--iface", required=True, help="Interface do dumpcap (nome ou índice do dumpcap -D)")
    parser.add_argument("--wsl_distro", default=None, help="Nome da distro WSL (opcional). Ex: Ubuntu-22.04")
    parser.add_argument("--dumpcap_path", default="dumpcap", help="Caminho do dumpcap se não estiver no PATH")
    parser.add_argument("--canon_policy", choices=["stable", "rich"], default="stable", help="stable: nmap só manufacturer+model_name; rich: inclui server e name (mais volátil).")
    parser.add_argument("--probe_count", type=int, default=3, help="Quantidade de SYN probes por porta.")
    parser.add_argument("--probe_delay", type=float, default=2.0, help="Segundos de espera após iniciar dumpcap antes do probe.")
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Apaga artefatos brutos (.pcap e p0f.raw.txt) ao fim da execução (mesmo em falha de hash).",
    )
    parser.add_argument(
        "--log-level",
        default="DEBUG",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Nível mínimo dos logs (ficheiro fingerprint_pipeline.log e consola se --log-console).",
    )
    parser.add_argument(
        "--log-console",
        action="store_true",
        help="Espelha logs no stderr (além do ficheiro).",
    )
    parser.add_argument(
        "--scan-max-hosts",
        type=int,
        default=0,
        help="Modo network: máximo de hosts a fingerprintar (0 = todos os descobertos por SSDP).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    outroot = Path(args.outroot)
    outroot.mkdir(parents=True, exist_ok=True)

    if args.mode == "target":
        if not args.ip:
            parser.error("Modo target: indique o IP alvo, ex: python iot_id_fingerprint.py runs 192.168.1.10 --iface eth0")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = outroot / f"{args.ip}_{ts}"
        run_single_fingerprint(run_dir, args.ip, ts, args)
        return

    _run_network_mode(outroot, args)


def _run_network_mode(outroot: Path, args: argparse.Namespace) -> None:
    if args.ip:
        print("[*] Modo network: o argumento posicional 'ip' é ignorado.")

    batch_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_root = outroot / f"scan_{batch_ts}"
    scan_root.mkdir(parents=True, exist_ok=True)

    print("[*] Modo network: M-SEARCH SSDP (respostas de qualquer IP na LAN) ...")
    ssdp_raw = ssdp_probe(None)
    write_json(scan_root / "ssdp_discovery.json", ssdp_results_to_jsonable(ssdp_raw))

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
    for index, host_ip in enumerate(hosts, 1):
        print(f"\n{'=' * 60}\n[*] [{index}/{len(hosts)}] Fingerprint: {host_ip}\n{'=' * 60}")
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
    write_json(summary_path, {"mode": "network", "batch_ts": batch_ts, "hosts": summary_rows})
    print(f"\n[OK] Scan de rede concluído. Resumo: {summary_path.resolve()}")


def _ip_sort_key(addr: str) -> tuple:
    try:
        return tuple(int(part) for part in addr.split("."))
    except ValueError:
        return (0,)


if __name__ == "__main__":
    main()
