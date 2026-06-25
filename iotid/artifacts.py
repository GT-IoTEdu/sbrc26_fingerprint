"""Escrita de artefactos, formatação de tempo, caminhos WSL e logging."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path


def setup_fingerprint_logging(run_dir: Path, level: str, console: bool) -> logging.Logger:
    """
    Configura o logger pai `fingerprint` (pipeline + canon + tshark).
    Escreve em run_dir/fingerprint_pipeline.log.
    """
    root = logging.getLogger("fingerprint")
    root.handlers.clear()
    root.setLevel(logging.DEBUG)
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    fh = logging.FileHandler(run_dir / "fingerprint_pipeline.log", encoding="utf-8")
    fh.setLevel(lvl)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    if console:
        sh = logging.StreamHandler()
        sh.setLevel(lvl)
        sh.setFormatter(fmt)
        root.addHandler(sh)

    root.propagate = False
    return root


def win_to_wsl_path(path: Path) -> str:
    """
    Converte caminho do Windows para WSL:
      C:\\Users\\...\\file.pcap  ->  /mnt/c/Users/.../file.pcap

    Em Linux/macOS: apenas retorna o caminho POSIX normal.
    """
    p = path.resolve()

    if os.name != "nt":
        return str(p)

    drive = p.drive
    if not drive:
        return p.as_posix()

    drive_letter = drive[0].lower()
    rest = p.as_posix().split(":", 1)[1]
    return f"/mnt/{drive_letter}{rest}"


def write_text(path: Path, s: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(s, encoding="utf-8", errors="replace")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
        errors="replace",
    )


def fmt_secs(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds*1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    m = int(seconds // 60)
    s = seconds - (m * 60)
    return f"{m}m {s:05.2f}s"
