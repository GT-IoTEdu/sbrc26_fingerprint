#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fingerprint_hash.py

Gera a assinatura (hash) deterministica de um bundle de fingerprint:

    HASH = sha256( CANON_STRING )

onde CANON_STRING vem de canonicalize_features.build_canon + dumps_canon.

Uso:
  python fingerprint_hash.py bundle.json
  python fingerprint_hash.py bundle.json --outdir runs/.../fp --algo sha256
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os

from canonicalize_features import build_canon, dumps_canon


def compute_hash(canon_string: str, algo: str = "sha256") -> str:
    """Hash hexadecimal deterministico da CANON_STRING (UTF-8)."""
    algo = (algo or "sha256").lower().strip()
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"Algoritmo '{algo}' nao suportado pelo hashlib.")
    return hashlib.new(algo, canon_string.encode("utf-8")).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Hash deterministico de um bundle de fingerprint.")
    ap.add_argument("bundle_json", help="Caminho do bundle JSON (ex: fingerprint.json)")
    ap.add_argument("--policy", choices=["stable", "rich"], default="stable")
    ap.add_argument("--algo", default="sha256", help="Algoritmo hashlib (sha256, sha1, blake2b...)")
    ap.add_argument("--outdir", help="Se dado, salva fingerprint.txt e fingerprint.json.")
    args = ap.parse_args()

    with open(args.bundle_json, encoding="utf-8") as f:
        bundle = json.load(f)

    canon_string = dumps_canon(build_canon(bundle, policy=args.policy))
    fp_hash = compute_hash(canon_string, algo=args.algo)

    print("=== CANON_STRING ===")
    print(canon_string)
    print("\n=== FINGERPRINT_HASH ===")
    print(fp_hash)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        with open(os.path.join(args.outdir, "fingerprint.txt"), "w", encoding="utf-8") as f:
            f.write(fp_hash + "\n")
        with open(os.path.join(args.outdir, "fingerprint.json"), "w", encoding="utf-8") as f:
            json.dump({"algo": args.algo, "policy": args.policy, "fingerprint": fp_hash},
                      f, ensure_ascii=False, indent=2, sort_keys=True)
        print(f"\n[OK] Salvo em: {args.outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
