"""
Orquestração de uma rodada completa de fingerprint para um IP.

Sequência: identidade UPnP/nmap -> captura PCAP + sonda nping -> p0f -> tshark
-> bundle JSON -> canonização + hash SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import time
from pathlib import Path

# Canonização vive num módulo separado; mantém-se importação tolerante a falhas
# para que o bundle bruto ainda seja produzido caso o módulo esteja ausente.
try:
    from canonicalize_features import build_canon, dumps_canon
except Exception as e:  # pragma: no cover - caminho defensivo
    build_canon = None
    dumps_canon = None
    _CANON_IMPORT_ERR = e
else:
    _CANON_IMPORT_ERR = None

from .artifacts import fmt_secs, setup_fingerprint_logging, win_to_wsl_path, write_json, write_text
from .discovery import collect_upnp_identity, infer_host_kind, nmap_mobile_scan
from .p0f import extract_p0f_sets, parse_p0f_raw
from .proc import decode_bytes, run
from .tshark import extract_mobile_passive_tshark, extract_tcp_syn_features_tshark


def _cleanup_raw_paths(cleanup_paths: list[Path], log: logging.Logger) -> tuple[int, int]:
    """Remove artefactos brutos (.pcap, p0f.raw.txt). Retorna (removidos, erros)."""
    removed = 0
    errors = 0
    for raw_path in cleanup_paths:
        try:
            if raw_path.exists():
                raw_path.unlink()
                removed += 1
                log.info("cleanup removed path=%s", raw_path)
        except Exception as cleanup_err:
            errors += 1
            log.warning("cleanup failed path=%s err=%s", raw_path, cleanup_err)
    return removed, errors


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
    cleanup_paths: list[Path] = [pcap_path, p0f_raw_path]

    cleanup_removed_count = 0
    cleanup_error_count = 0

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
        print("    Dica: garanta que canonicalize_features.py está na mesma pasta do iot_id_fingerprint.py")
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
        finally:
            if args.cleanup:
                cleanup_removed_count, cleanup_error_count = _cleanup_raw_paths(cleanup_paths, log)
                if cleanup_error_count > 0:
                    print(
                        "[!] --cleanup ativo: houve erro ao remover alguns artefatos brutos "
                        "(.pcap, p0f.raw.txt); veja o log."
                    )
                else:
                    print(
                        "[*] --cleanup ativo: artefatos brutos removidos "
                        f"(.pcap, p0f.raw.txt) [{cleanup_removed_count} arquivo(s)]."
                    )

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
