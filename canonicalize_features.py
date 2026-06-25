#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
canonicalize_features.py

Le um bundle JSON (fingerprint.json) e produz um objeto canonico deterministico
e a sua string minificada. Essa string e a entrada do hash SHA-256.

Selecao de features por tipo de host:
  - iot    : nmap (manufacturer, model_name; +server, name em policy "rich")
             + p0f (SYN+ACK do servidor, ou SYN do cliente como fallback)
             + pcap_syn reduzido (ttl, window_size, mss, ws)
  - mobile : p0f (SYN do cliente) + pcap_syn estendido
             (mss, sack_perm, ts_present, ttl, window_size, ws)

Determinismo: chaves ordenadas, espacos colapsados, listas ordenadas sem
duplicatas, e remocao recursiva de campos vazios.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from typing import Any

_WS_RE = re.compile(r"\s+")

# Quais campos entram no canon, por (host_kind, secao).
_PCAP_KEYS = {
    "iot": ("ttl", "window_size", "mss", "ws"),
    "mobile": ("mss", "sack_perm", "ts_present", "ttl", "window_size", "ws"),
}


def norm(value: Any) -> str | None:
    """Normaliza um escalar para string limpa (ou None se vazio/nao-escalar)."""
    if value is None or isinstance(value, (dict, list)):
        return None
    if isinstance(value, bool):
        value = "1" if value else "0"
    text = _WS_RE.sub(" ", str(value)).strip()
    return text or None


def norm_list(items: Any) -> list[str]:
    """Normaliza e ordena uma lista de strings, sem duplicatas nem vazios."""
    return sorted({s for s in (norm(x) for x in items or []) if s})


def prune(obj: Any) -> Any:
    """Remove recursivamente None, dicts vazios e listas vazias."""
    if isinstance(obj, dict):
        return {k: v for k, v in ((k, prune(v)) for k, v in obj.items())
                if v not in (None, {}, [])}
    if isinstance(obj, list):
        return [v for v in (prune(x) for x in obj) if v is not None]
    return obj


def dumps_canon(obj: dict) -> str:
    """Serializa de forma deterministica: chaves ordenadas, sem espacos."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def resolve_host_kind(bundle: dict, nmap: dict) -> str:
    """Usa meta.host_kind se valido; senao infere por presenca de fabricante/modelo."""
    meta = bundle.get("meta") or {}
    if meta.get("host_kind") in ("iot", "mobile"):
        return meta["host_kind"]
    return "iot" if (norm(nmap.get("manufacturer")) or norm(nmap.get("model_name"))) else "mobile"


def build_canon(bundle: dict, policy: str = "stable") -> dict:
    """Constroi o objeto canonico a partir do bundle bruto."""
    policy = policy if policy in ("stable", "rich") else "stable"
    nmap = bundle.get("nmap") or {}
    extracted = (bundle.get("p0f") or {}).get("extracted") or {}
    pcap = bundle.get("pcap_syn") or {}
    kind = resolve_host_kind(bundle, nmap)

    canon: dict = {}

    # nmap: identidade UPnP, apenas para hosts IoT.
    if kind == "iot":
        fields = ["manufacturer", "model_name"] + (["server", "name"] if policy == "rich" else [])
        canon["nmap"] = {k: norm(nmap.get(k)) for k in fields}

    # p0f: SYN+ACK do servidor (IoT) ou SYN do cliente (fallback / mobile).
    client = norm_list(extracted.get("client_syn_raw_sig_set"))
    server = norm_list(extracted.get("server_synack_raw_sig_set"))
    if kind == "iot" and server:
        canon["p0f"] = {"extracted": {"server_synack_raw_sig_set": server}}
    elif client:
        canon["p0f"] = {"extracted": {"client_syn_raw_sig_set": client}}

    # pcap_syn: features TCP extraidas via tshark.
    if pcap and not pcap.get("error"):
        canon["pcap_syn"] = {k: norm(pcap.get(k)) for k in _PCAP_KEYS[kind]}

    canon = prune(canon)
    if not canon:
        raise ValueError("Fingerprint invalido: sem features uteis de p0f, pcap_syn ou nmap.")
    return canon


def main() -> int:
    ap = argparse.ArgumentParser(description="Canoniza um bundle de fingerprint.")
    ap.add_argument("bundle_json", help="Caminho do bundle JSON (ex: fingerprint.json)")
    ap.add_argument("--policy", choices=["stable", "rich"], default="stable",
                    help="stable: nmap so manufacturer+model_name; rich: inclui server e name.")
    ap.add_argument("--outdir", help="Se dado, salva features_canon.json e features_canon.txt.")
    args = ap.parse_args()

    with open(args.bundle_json, encoding="utf-8") as f:
        bundle = json.load(f)

    canon_obj = build_canon(bundle, policy=args.policy)
    canon_str = dumps_canon(canon_obj)

    print("=== CANON_OBJ ===")
    print(json.dumps(canon_obj, ensure_ascii=False, sort_keys=True, indent=2))
    print("\n=== CANON_STRING ===")
    print(canon_str)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        with open(os.path.join(args.outdir, "features_canon.json"), "w", encoding="utf-8") as f:
            json.dump(canon_obj, f, ensure_ascii=False, sort_keys=True, indent=2)
        with open(os.path.join(args.outdir, "features_canon.txt"), "w", encoding="utf-8") as f:
            f.write(canon_str + "\n")
        print(f"\n[OK] Salvo em: {args.outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
