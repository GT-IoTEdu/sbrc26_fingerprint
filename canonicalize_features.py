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
- host_kind iot: nmap (manufacturer + model_name em stable); p0f (SYN+ACK preferido); pcap_syn (ttl, window, mss, ws)
- host_kind mobile (não-IoT): apenas p0f com client_syn_raw_sig_set e pcap_syn (mss, sack_perm, ts_present, ttl, window_size, ws)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

_LOG = logging.getLogger("fingerprint.canon")

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
    """Normaliza string (ou None). Aceita int/bool para campos numéricos do tshark."""
    if x is None:
        return None
    if isinstance(x, bool):
        s = "1" if x else "0"
    elif isinstance(x, int):
        s = str(x)
    elif isinstance(x, float):
        s = str(x)
    elif isinstance(x, str):
        s = x
    else:
        return None
    x2 = norm_ws(s)
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


def _resolve_host_kind(bundle: Dict[str, Any], nmap: Dict[str, Any]) -> str:
    meta = bundle.get("meta") if isinstance(bundle.get("meta"), dict) else {}
    hk = meta.get("host_kind")
    if hk in ("iot", "mobile"):
        return hk
    m = stable_str(nmap.get("manufacturer"))
    mo = stable_str(nmap.get("model_name"))
    return "iot" if (m or mo) else "mobile"


# -----------------------------
# Canonização por política
# -----------------------------

def build_canon(bundle: Dict[str, Any], policy: str) -> Dict[str, Any]:
    """
    policy:
      - "stable" / "rich": nmap extras só em iot (rich); mobile ignora mobile_passive/mobile_nmap no hash
      - iot: nmap + p0f + pcap_syn reduzido; mobile: só p0f client_syn + pcap_syn estendido
    """
    policy = (policy or "stable").lower().strip()
    if policy not in ("stable", "rich"):
        policy = "stable"

    nmap = bundle.get("nmap", {}) if isinstance(bundle.get("nmap"), dict) else {}
    host_kind = _resolve_host_kind(bundle, nmap)

    _LOG.info(
        "build_canon start policy=%s host_kind=%s top_level_keys=%s",
        policy,
        host_kind,
        sorted(bundle.keys()) if isinstance(bundle, dict) else type(bundle).__name__,
    )

    nmap_canon: Dict[str, Any] = {}

    if host_kind == "iot":
        server = stable_str(nmap.get("server"))
        name = stable_str(nmap.get("name"))
        manufacturer = stable_str(nmap.get("manufacturer"))
        model_name = stable_str(nmap.get("model_name"))

        if policy == "rich" and server:
            nmap_canon["server"] = server

        if policy == "rich" and name:
            nmap_canon["name"] = name

        if manufacturer:
            nmap_canon["manufacturer"] = manufacturer

        if model_name:
            nmap_canon["model_name"] = model_name

        _LOG.debug(
            "build_canon iot nmap fields_present server=%s name=%s mfg=%s model=%s",
            server is not None,
            name is not None,
            manufacturer is not None,
            model_name is not None,
        )

    # -------- P0F (preferido, mas não obrigatório) --------
    p0f = bundle.get("p0f", {}) if isinstance(bundle.get("p0f"), dict) else {}
    extracted = p0f.get("extracted", {}) if isinstance(p0f.get("extracted"), dict) else {}

    client_sig = stable_list(extracted.get("client_syn_raw_sig_set", []))
    server_sig = stable_list(extracted.get("server_synack_raw_sig_set", []))

    p0f_extracted: Dict[str, Any] = {}
    rawsig_present = False

    if host_kind == "mobile":
        if client_sig:
            p0f_extracted["client_syn_raw_sig_set"] = client_sig
            rawsig_present = True
            _LOG.info("build_canon mobile p0f client_syn count=%s", len(client_sig))
        else:
            _LOG.info("build_canon mobile p0f omitido (sem client_syn_raw_sig_set)")
    else:
        if server_sig:
            p0f_extracted["server_synack_raw_sig_set"] = server_sig
            rawsig_present = True
            _LOG.info(
                "build_canon p0f branch=server_synack count=%s",
                len(server_sig),
            )
        elif client_sig:
            p0f_extracted["client_syn_raw_sig_set"] = client_sig
            rawsig_present = True
            _LOG.info(
                "build_canon p0f branch=client_syn (no server_synack) count=%s",
                len(client_sig),
            )
        else:
            _LOG.info("build_canon p0f branch=none (no raw_sig sets)")

    # -------- PCAP SYN (fallback tshark) --------
    pcap_syn = bundle.get("pcap_syn", {}) if isinstance(bundle.get("pcap_syn"), dict) else {}
    pcap_syn_canon = None

    if pcap_syn and not pcap_syn.get("error"):
        if host_kind == "mobile":
            pcap_syn_canon = prune_none(
                {
                    "mss": stable_str(pcap_syn.get("mss")),
                    "sack_perm": stable_str(pcap_syn.get("sack_perm")),
                    "ts_present": stable_str(pcap_syn.get("ts_present")),
                    "ttl": stable_str(pcap_syn.get("ttl")),
                    "window_size": stable_str(pcap_syn.get("window_size")),
                    "ws": stable_str(pcap_syn.get("ws")),
                }
            )
        else:
            pcap_syn_canon = prune_none(
                {
                    "ttl": stable_str(pcap_syn.get("ttl")),
                    "window_size": stable_str(pcap_syn.get("window_size")),
                    "mss": stable_str(pcap_syn.get("mss")),
                    "ws": stable_str(pcap_syn.get("ws")),
                }
            )
        _LOG.info(
            "build_canon pcap_syn host_kind=%s keys=%s",
            host_kind,
            sorted(pcap_syn_canon.keys()) if pcap_syn_canon else [],
        )
    else:
        err = pcap_syn.get("error") if isinstance(pcap_syn, dict) else None
        _LOG.info("build_canon pcap_syn skipped error=%s", err)

    # -------- Regras finais --------
    canon: Dict[str, Any] = {}

    if host_kind != "mobile":
        if nmap_canon:
            canon["nmap"] = nmap_canon

    if rawsig_present:
        canon["p0f"] = {"extracted": prune_none(p0f_extracted)}

    if pcap_syn_canon:
        canon["pcap_syn"] = pcap_syn_canon

    _LOG.info(
        "build_canon result_sections=%s",
        sorted(canon.keys()),
    )
    if _LOG.isEnabledFor(logging.DEBUG):
        for sec, payload in sorted(canon.items()):
            _LOG.debug("build_canon section %s = %s", sec, json.dumps(payload, ensure_ascii=False, sort_keys=True))

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
