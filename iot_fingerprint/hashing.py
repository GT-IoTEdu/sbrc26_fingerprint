#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic fingerprint hashing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from .canonical import build_canon, dumps_canon


def compute_hash_from_canon_string(canon_string: str, algo: str = "sha256") -> str:
    """Return the hexadecimal hash of a canonical UTF-8 string."""
    algo = (algo or "sha256").lower().strip()
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"Algoritmo '{algo}' não suportado. Use algo disponível em hashlib.")

    hasher = hashlib.new(algo)
    hasher.update(canon_string.encode("utf-8"))
    return hasher.hexdigest()


def compute_fingerprint(bundle: Dict[str, Any], policy: str = "stable", algo: str = "sha256") -> Dict[str, Any]:
    """Build canonical features and hash them, returning all intermediate values."""
    canon_obj = build_canon(bundle, policy=policy)
    canon_string = dumps_canon(canon_obj)
    return {
        "canon_obj": canon_obj,
        "canon_string": canon_string,
        "fingerprint": compute_hash_from_canon_string(canon_string, algo=algo),
        "algo": algo,
        "policy": policy,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_json", help="Caminho do bundle JSON (ex: bundle.json)")
    parser.add_argument("--policy", choices=["stable", "rich"], default="stable", help="stable = conservador; rich = inclui mais campos")
    parser.add_argument("--algo", default="sha256", help="Algoritmo hashlib (ex: sha256, sha1, blake2b, sha3_256...)")
    parser.add_argument("--outdir", default=None, help="Se fornecido, salva fingerprint.txt e fingerprint.json nesse diretório")
    parser.add_argument("--debug", action="store_true", help="Imprime diagnósticos (repr, tamanhos e hash dos bytes) para confirmar estabilidade")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    with open(args.bundle_json, "r", encoding="utf-8") as handle:
        bundle: Dict[str, Any] = json.load(handle)

    result = compute_fingerprint(bundle, policy=args.policy, algo=args.algo)
    canon_string = result["canon_string"]
    fp_hash = result["fingerprint"]

    print("\n=== CANON_STRING ===")
    print(canon_string)

    if args.debug:
        data = canon_string.encode("utf-8")
        print("\n=== DEBUG ===")
        print("repr:", repr(canon_string))
        print("len(chars):", len(canon_string))
        print("len(bytes):", len(data))
        print("sha256(bytes):", hashlib.sha256(data).hexdigest())

    print("\n=== FINGERPRINT_HASH ===")
    print(fp_hash)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)

        out_txt = os.path.join(args.outdir, "fingerprint.txt")
        out_json = os.path.join(args.outdir, "fingerprint.json")

        with open(out_txt, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(fp_hash + "\n")

        payload = {
            "algo": args.algo,
            "policy": args.policy,
            "fingerprint": fp_hash,
        }
        with open(out_json, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)

        print(f"\n[OK] Saved:\n- {out_txt}\n- {out_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
