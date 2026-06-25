"""Execução de subprocessos e decodificação resiliente de bytes."""

from __future__ import annotations

import subprocess


def decode_bytes(out: bytes) -> str:
    """Decodifica bytes como UTF-8, recorrendo a latin-1 em caso de erro."""
    try:
        return out.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return out.decode("latin-1", errors="replace")


def run(cmd, check=True):
    """
    Executa comando e retorna (stdout_text, stderr_text).
    """
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    text_out = decode_bytes(p.stdout or b"")
    text_err = decode_bytes(p.stderr or b"")

    if check and p.returncode != 0:
        raise RuntimeError(
            f"Command failed ({p.returncode}): {' '.join(cmd)}\n\nSTDOUT:\n{text_out}\n\nSTDERR:\n{text_err}"
        )
    return text_out, text_err


def run_bytes(cmd):
    """Retorna (rc, stdout_bytes, stderr_bytes)."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, (p.stdout or b""), (p.stderr or b"")
