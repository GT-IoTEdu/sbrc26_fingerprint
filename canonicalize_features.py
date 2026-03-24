#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
canonicalize_features.py

Lê um bundle JSON (ex.: fingerprint.json / bundle.json) e gera:
- CANON_OBJ (objeto canônico)
- CANON_STRING (JSON minificado, ordenado e determinístico)

REGRAS ATUAIS:
- Nmap/UPnP é opcional
- p0f raw_sig é preferido, mas NÃO obrigatório
- Se não houver raw_sig, usa pcap_syn como fallback
- A assinatura pode incluir:
    * nmap.server
    * nmap.name
    * nmap.manufacturer
    * nmap.model_name
    * p0f raw_sig
    * pcap_syn
"""

from __future__ import annotations

import argparse
import json
import os
import re
from typing import Any, Dict, List, Optional

# -----------------------------
# Helpers: normalização / ordenação
# -----------------------------

_WS_RE = re.compile(r"\s+")


def norm_ws(s: str) -> str:
    """Normaliza whitespace: trim + colapsa múltiplos espaços."""
    s = s.strip()
    s = _WS_RE.sub(" ", s)
    return s


def stable_list(items: List[Any]) -> List[str]:
    """Normaliza e ordena uma lista de strings de forma determinística."""
    out: List[str] = []
    for x in items or []:
        if isinstance(x, str):
            x2 = norm_ws(x)
            if x2:
                out.append(x2)
    return sorted(set(out))


def stable_str(x: Any) -> Optional[str]:
    """Normaliza string (ou None)."""
    if not isinstance(x, str):
        return None
    x2 = norm_ws(x)
    return x2 if x2 else None


def prune_none(obj: Any) -> Any:
    """Remove chaves None e listas vazias recursivamente."""
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            v2 = prune_none(v)
            if v2 is None:
                continue
            if isinstance(v2, dict) and not v2:
                continue
            if isinstance(v2, list) and not v2:
                continue
            new[k] = v2
        return new

    if isinstance(obj, list):
        new_list = [prune_none(v) for v in obj]
        new_list = [v for v in new_list if v is not None]
        return new_list

    return obj


def dumps_canon(obj: Dict[str, Any]) -> str:
    """
    Serializa com:
    - chaves ordenadas
    - sem espaços
    - unicode preservado
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# -----------------------------
# Canonização por política
# -----------------------------

def build_canon(bundle: Dict[str, Any], policy: str) -> Dict[str, Any]:
    """
    policy:
      - "stable"
      - "rich"

    Nesta versão, a parte Nmap do CANON inclui apenas:
      - server
      - name
      - manufacturer
      - model_name
    """
    policy = (policy or "stable").lower().strip()
    if policy not in ("stable", "rich"):
        policy = "stable"

    # -------- NMAP / UPNP --------
    nmap = bundle.get("nmap", {}) if isinstance(bundle.get("nmap"), dict) else {}

    server = stable_str(nmap.get("server"))
    name = stable_str(nmap.get("name"))
    manufacturer = stable_str(nmap.get("manufacturer"))
    model_name = stable_str(nmap.get("model_name"))

    nmap_canon: Dict[str, Any] = {}

    if server:
        nmap_canon["server"] = server

    if name:
        nmap_canon["name"] = name

    if manufacturer:
        nmap_canon["manufacturer"] = manufacturer

    if model_name:
        nmap_canon["model_name"] = model_name

    # -------- P0F (preferido, mas não obrigatório) --------
    p0f = bundle.get("p0f", {}) if isinstance(bundle.get("p0f"), dict) else {}
    extracted = p0f.get("extracted", {}) if isinstance(p0f.get("extracted"), dict) else {}

    client_sig = stable_list(extracted.get("client_syn_raw_sig_set", []))
    server_sig = stable_list(extracted.get("server_synack_raw_sig_set", []))

    p0f_extracted: Dict[str, Any] = {}
    rawsig_present = False

    if server_sig:
        p0f_extracted["server_synack_raw_sig_set"] = server_sig
        rawsig_present = True
    elif client_sig:
        p0f_extracted["client_syn_raw_sig_set"] = client_sig
        rawsig_present = True

    # -------- PCAP SYN (fallback tshark) --------
    pcap_syn = bundle.get("pcap_syn", {}) if isinstance(bundle.get("pcap_syn"), dict) else {}
    pcap_syn_canon = None

    if pcap_syn and not pcap_syn.get("error"):
        pcap_syn_canon = {
            "ttl": stable_str(pcap_syn.get("ttl")),
            "window_size": stable_str(pcap_syn.get("window_size")),
            "mss": stable_str(pcap_syn.get("mss")),
            "ws": stable_str(pcap_syn.get("ws")),
        }
        pcap_syn_canon = prune_none(pcap_syn_canon)

    # -------- Regras finais --------
    canon: Dict[str, Any] = {}

    if rawsig_present:
        canon["p0f"] = {"extracted": prune_none(p0f_extracted)}

    if pcap_syn_canon:
        canon["pcap_syn"] = pcap_syn_canon

    if nmap_canon:
        canon["nmap"] = nmap_canon

    if not canon:
        raise ValueError(
            "Fingerprint inválido: não foi possível obter features úteis de p0f, pcap_syn ou nmap."
        )

    return prune_none(canon)


# -----------------------------
# CLI
# -----------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle_json", help="Caminho do bundle JSON (ex: fingerprint.json/bundle.json)")
    ap.add_argument(
        "--policy",
        choices=["stable", "rich"],
        default="stable",
        help="stable = conservador; rich = reservado para expansão futura"
    )
    ap.add_argument(
        "--outdir",
        default=None,
        help="Se fornecido, salva features_canon.json e features_canon.txt nesse diretório"
    )
    args = ap.parse_args()

    with open(args.bundle_json, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    canon_obj = build_canon(bundle, policy=args.policy)
    canon_str = dumps_canon(canon_obj)

    print("\n=== CANON_OBJ ===")
    print(json.dumps(canon_obj, ensure_ascii=False, sort_keys=True, indent=2))

    print("\n=== CANON_STRING ===")
    print(canon_str)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        out_json = os.path.join(args.outdir, "features_canon.json")
        out_txt = os.path.join(args.outdir, "features_canon.txt")

        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(canon_obj, f, ensure_ascii=False, sort_keys=True, indent=2)

        with open(out_txt, "w", encoding="utf-8") as f:
            f.write(canon_str + "\n")

        print(f"\n[OK] Saved:\n- {out_json}\n- {out_txt}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
