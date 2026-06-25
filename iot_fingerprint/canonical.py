#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical feature selection and deterministic serialization."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from typing import Any, Dict, Iterable, List, Optional

_LOG = logging.getLogger("fingerprint.canon")
_WS_RE = re.compile(r"\s+")
VALID_POLICIES = {"stable", "rich"}


def norm_ws(value: str) -> str:
    """Trim a string and collapse repeated whitespace."""
    return _WS_RE.sub(" ", value.strip())


def stable_list(items: Iterable[Any]) -> List[str]:
    """Normalize, de-duplicate and sort a sequence of strings deterministically."""
    normalized = []
    for item in items or []:
        if isinstance(item, str):
            text = norm_ws(item)
            if text:
                normalized.append(text)
    return sorted(set(normalized))


def stable_str(value: Any) -> Optional[str]:
    """Normalize scalar values accepted by the canonical feature set."""
    if value is None:
        return None
    if isinstance(value, bool):
        text = "1" if value else "0"
    elif isinstance(value, (int, float, str)):
        text = str(value)
    else:
        return None

    text = norm_ws(text)
    return text or None


def prune_none(obj: Any) -> Any:
    """Recursively remove None values, empty dicts and empty lists."""
    if isinstance(obj, dict):
        clean = {}
        for key, value in obj.items():
            value = prune_none(value)
            if value is None:
                continue
            if isinstance(value, dict) and not value:
                continue
            if isinstance(value, list) and not value:
                continue
            clean[key] = value
        return clean

    if isinstance(obj, list):
        return [value for value in (prune_none(item) for item in obj) if value is not None]

    return obj


def dumps_canon(obj: Dict[str, Any]) -> str:
    """Serialize the canonical object as compact, sorted UTF-8 JSON."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalize_policy(policy: str) -> str:
    policy = (policy or "stable").lower().strip()
    return policy if policy in VALID_POLICIES else "stable"


def _dict_at(obj: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = obj.get(key)
    return value if isinstance(value, dict) else {}


def _resolve_host_kind(bundle: Dict[str, Any], nmap: Dict[str, Any]) -> str:
    meta = _dict_at(bundle, "meta")
    host_kind = meta.get("host_kind")
    if host_kind in ("iot", "mobile"):
        return host_kind

    manufacturer = stable_str(nmap.get("manufacturer"))
    model_name = stable_str(nmap.get("model_name"))
    return "iot" if (manufacturer or model_name) else "mobile"


def _build_iot_nmap(nmap: Dict[str, Any], policy: str) -> Dict[str, Any]:
    fields = {
        "server": stable_str(nmap.get("server")),
        "name": stable_str(nmap.get("name")),
        "manufacturer": stable_str(nmap.get("manufacturer")),
        "model_name": stable_str(nmap.get("model_name")),
    }

    canon: Dict[str, Any] = {}
    if policy == "rich" and fields["server"]:
        canon["server"] = fields["server"]
    if policy == "rich" and fields["name"]:
        canon["name"] = fields["name"]
    if fields["manufacturer"]:
        canon["manufacturer"] = fields["manufacturer"]
    if fields["model_name"]:
        canon["model_name"] = fields["model_name"]

    _LOG.debug(
        "build_canon iot nmap fields_present server=%s name=%s mfg=%s model=%s",
        fields["server"] is not None,
        fields["name"] is not None,
        fields["manufacturer"] is not None,
        fields["model_name"] is not None,
    )
    return canon


def _build_p0f_extracted(extracted: Dict[str, Any], host_kind: str) -> Dict[str, Any]:
    client_sig = stable_list(extracted.get("client_syn_raw_sig_set", []))
    server_sig = stable_list(extracted.get("server_synack_raw_sig_set", []))

    if host_kind == "mobile":
        if client_sig:
            _LOG.info("build_canon mobile p0f client_syn count=%s", len(client_sig))
            return {"client_syn_raw_sig_set": client_sig}
        _LOG.info("build_canon mobile p0f omitido (sem client_syn_raw_sig_set)")
        return {}

    if server_sig:
        _LOG.info("build_canon p0f branch=server_synack count=%s", len(server_sig))
        return {"server_synack_raw_sig_set": server_sig}
    if client_sig:
        _LOG.info("build_canon p0f branch=client_syn (no server_synack) count=%s", len(client_sig))
        return {"client_syn_raw_sig_set": client_sig}

    _LOG.info("build_canon p0f branch=none (no raw_sig sets)")
    return {}


def _build_pcap_syn(pcap_syn: Dict[str, Any], host_kind: str) -> Optional[Dict[str, Any]]:
    if not pcap_syn or pcap_syn.get("error"):
        _LOG.info("build_canon pcap_syn skipped error=%s", pcap_syn.get("error") if isinstance(pcap_syn, dict) else None)
        return None

    if host_kind == "mobile":
        fields = ["mss", "sack_perm", "ts_present", "ttl", "window_size", "ws"]
    else:
        fields = ["ttl", "window_size", "mss", "ws"]

    canon = prune_none({field: stable_str(pcap_syn.get(field)) for field in fields})
    _LOG.info("build_canon pcap_syn host_kind=%s keys=%s", host_kind, sorted(canon.keys()) if canon else [])
    return canon or None


def build_canon(bundle: Dict[str, Any], policy: str) -> Dict[str, Any]:
    """Build the canonical feature object used as input to the fingerprint hash."""
    policy = normalize_policy(policy)
    nmap = _dict_at(bundle, "nmap")
    host_kind = _resolve_host_kind(bundle, nmap)

    _LOG.info(
        "build_canon start policy=%s host_kind=%s top_level_keys=%s",
        policy,
        host_kind,
        sorted(bundle.keys()) if isinstance(bundle, dict) else type(bundle).__name__,
    )

    canon: Dict[str, Any] = {}

    if host_kind != "mobile":
        nmap_canon = _build_iot_nmap(nmap, policy)
        if nmap_canon:
            canon["nmap"] = nmap_canon

    p0f = _dict_at(bundle, "p0f")
    extracted = _dict_at(p0f, "extracted")
    p0f_extracted = _build_p0f_extracted(extracted, host_kind)
    if p0f_extracted:
        canon["p0f"] = {"extracted": prune_none(p0f_extracted)}

    pcap_syn_canon = _build_pcap_syn(_dict_at(bundle, "pcap_syn"), host_kind)
    if pcap_syn_canon:
        canon["pcap_syn"] = pcap_syn_canon

    _LOG.info("build_canon result_sections=%s", sorted(canon.keys()))
    if _LOG.isEnabledFor(logging.DEBUG):
        for section, payload in sorted(canon.items()):
            _LOG.debug("build_canon section %s = %s", section, json.dumps(payload, ensure_ascii=False, sort_keys=True))

    if not canon:
        raise ValueError(
            "Fingerprint inválido: não foi possível obter features úteis de p0f, pcap_syn ou nmap."
        )

    return prune_none(canon)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_json", help="Caminho do bundle JSON (ex: fingerprint.json/bundle.json)")
    parser.add_argument(
        "--policy",
        choices=["stable", "rich"],
        default="stable",
        help="stable = conservador; rich = reservado para expansão futura",
    )
    parser.add_argument(
        "--outdir",
        default=None,
        help="Se fornecido, salva features_canon.json e features_canon.txt nesse diretório",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    with open(args.bundle_json, "r", encoding="utf-8") as handle:
        bundle = json.load(handle)

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

        with open(out_json, "w", encoding="utf-8") as handle:
            json.dump(canon_obj, handle, ensure_ascii=False, sort_keys=True, indent=2)

        with open(out_txt, "w", encoding="utf-8") as handle:
            handle.write(canon_str + "\n")

        print(f"\n[OK] Saved:\n- {out_json}\n- {out_txt}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
