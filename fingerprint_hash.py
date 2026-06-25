#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compatibility wrapper for deterministic fingerprint hashing."""

from iot_fingerprint.hashing import compute_fingerprint, compute_hash_from_canon_string, main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
