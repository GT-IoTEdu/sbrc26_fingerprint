#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compatibility wrapper for canonical feature generation."""

from iot_fingerprint.canonical import (  # noqa: F401
    build_canon,
    dumps_canon,
    main,
    norm_ws,
    normalize_policy,
    prune_none,
    stable_list,
    stable_str,
)

if __name__ == "__main__":
    raise SystemExit(main())
