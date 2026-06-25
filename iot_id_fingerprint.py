#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
iot_id_fingerprint.py

Ponto de entrada (CLI) do pipeline de fingerprinting determinístico.

Modos:
  - target  : faz fingerprint de um único IP.
  - network : descobre hosts via SSDP (M-SEARCH sem filtro) e faz um fingerprint
              por host descoberto.

A lógica está organizada no pacote `iotid` (captura, parsing, descoberta,
canonização e orquestração). Este ficheiro trata apenas dos argumentos e do
despacho entre os modos.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from iotid.artifacts import write_json
from iotid.discovery import ssdp_results_to_jsonable
from iotid.pipeline import run_single_fingerprint
from iotid.upnp import ssdp_probe


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
        "--cleanup",
        action="store_true",
        help="Apaga artefatos brutos (.pcap e p0f.raw.txt) ao fim da execução (mesmo em falha de hash).",
    )
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
            ap.error("Modo target: indique o IP alvo, ex: python iot_id_fingerprint.py runs 192.168.1.10 --iface eth0")
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
