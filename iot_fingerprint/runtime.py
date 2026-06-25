#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runtime helpers for filesystem, subprocesses, logging and formatting."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, List, Tuple


def decode_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def run(cmd: List[str], check: bool = True) -> Tuple[str, str]:
    """Run a command and return decoded stdout/stderr."""
    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    text_out = decode_bytes(process.stdout or b"")
    text_err = decode_bytes(process.stderr or b"")

    if check and process.returncode != 0:
        raise RuntimeError(
            f"Command failed ({process.returncode}): {' '.join(cmd)}\n\nSTDOUT:\n{text_out}\n\nSTDERR:\n{text_err}"
        )
    return text_out, text_err


def run_bytes(cmd: List[str]) -> Tuple[int, bytes, bytes]:
    """Run a command and return rc/stdout/stderr bytes."""
    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.returncode, (process.stdout or b""), (process.stderr or b"")


def setup_fingerprint_logging(run_dir: Path, level: str, console: bool) -> logging.Logger:
    """Configure the parent `fingerprint` logger for a pipeline run."""
    root = logging.getLogger("fingerprint")
    root.handlers.clear()
    root.setLevel(logging.DEBUG)
    log_level = getattr(logging, (level or "INFO").upper(), logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    file_handler = logging.FileHandler(run_dir / "fingerprint_pipeline.log", encoding="utf-8")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)

    root.propagate = False
    return root


def win_to_wsl_path(path: Path) -> str:
    """Convert a Windows path to its WSL mount path. Non-Windows paths are unchanged."""
    resolved = path.resolve()
    if os.name != "nt":
        return str(resolved)

    drive = resolved.drive
    if not drive:
        return resolved.as_posix()

    drive_letter = drive[0].lower()
    rest = resolved.as_posix().split(":", 1)[1]
    return f"/mnt/{drive_letter}{rest}"


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
        errors="replace",
    )


def fmt_secs(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    remaining = seconds - (minutes * 60)
    return f"{minutes}m {remaining:05.2f}s"
