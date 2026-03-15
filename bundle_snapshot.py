#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
import re
import json
import os
import hashlib
import time

# ------------------------------------------------------------
# canonização (separada em canonicalize_features.py)
# ------------------------------------------------------------
try:
    from canonicalize_features import build_canon, dumps_canon 
except Exception as e:
    build_canon = None
    dumps_canon = None
    _CANON_IMPORT_ERR = e
else:
    _CANON_IMPORT_ERR = None


def run(cmd, check=True):
    """
    Executa comando e retorna (stdout_text, stderr_text).
    """
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out = p.stdout or b""
    err = p.stderr or b""

    try:
        text_out = out.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text_out = out.decode("latin-1", errors="replace")

    try:
        text_err = err.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text_err = err.decode("latin-1", errors="replace")

    if check and p.returncode != 0:
        raise RuntimeError(
            f"Command failed ({p.returncode}): {' '.join(cmd)}\n\nSTDOUT:\n{text_out}\n\nSTDERR:\n{text_err}"
        )
    return text_out, text_err


def run_bytes(cmd):
    """Retorna (rc, stdout_bytes, stderr_bytes)."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, (p.stdout or b""), (p.stderr or b"")


def decode_bytes(out: bytes) -> str:
    try:
        return out.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return out.decode("latin-1", errors="replace")


def win_to_wsl_path(path: Path) -> str:
    """
    Converte caminho do Windows para WSL:
      C:\\Users\\...\\file.pcap  ->  /mnt/c/Users/.../file.pcap

    Em Linux/macOS: apenas retorna o caminho POSIX normal.
    """
    p = path.resolve()

    # Se NÃO estamos no Windows, não faz conversão nenhuma.
    if os.name != "nt":
        return str(p)

    drive = p.drive
    if not drive:
        # caso raro: path sem drive no Windows
        return p.as_posix()

    drive_letter = drive[0].lower()          # "C:" -> "c"
    rest = p.as_posix().split(":", 1)[1]     # "/Users/..." (já com /)
    return f"/mnt/{drive_letter}{rest}"


# -------------------------
# Parse do p0f (RAW) -> lista de blocos (sem normalizar)
# -------------------------
P0F_BLOCK_RE = re.compile(r"\.-\[\s*(.*?)\s*\]-\n\|\n(.*?)\n`----", re.S)


def parse_p0f_raw(p0f_text: str):
    warnings = []
    for line in p0f_text.splitlines():
        if "WARNING:" in line:
            warnings.append(line.strip())

    blocks = []
    for header, body in P0F_BLOCK_RE.findall(p0f_text):
        fields = {}
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("|"):
                line = line[1:].strip()
            if " = " in line:
                k, v = line.split(" = ", 1)
                fields[k.strip()] = v.strip()
        blocks.append({"header": header.strip(), "fields": fields})

    processed_packets = None
    m = re.search(r"Processed\s+(\d+)\s+packets", p0f_text)
    if m:
        processed_packets = int(m.group(1))

    return {
        "warnings": warnings,
        "summary": {
            "processed_packets": processed_packets,
            "blocks_count": len(blocks),
        },
        "blocks": blocks,
    }


# -------------------------
# Parse do nmap norm -> extrai campos (sem normalizar)
# + inclui OS lines, MAC, etc (fallback quando stable fields não existe)
# -------------------------
def parse_nmap_norm(norm_text: str):
    """
    Extrai:
      - report_for
      - ports_table_raw
      - service_info
      - network_distance
      - tcpip_stable_fields_raw
      - host_script_results_raw
      - device_type, running, os_cpe, os_details, mac_address
    """
    out = {
        "report_for": None,
        "ports_table_raw": [],
        "service_info": None,
        "network_distance": None,
        "tcpip_stable_fields_raw": [],
        "host_script_results_raw": [],
        "device_type": None,
        "running": None,
        "os_cpe": None,
        "os_details": None,
        "mac_address": None,
    }

    lines = norm_text.splitlines()

    # report_for
    for ln in lines:
        if ln.startswith("Nmap scan report for "):
            out["report_for"] = ln.replace("Nmap scan report for ", "").strip()
            break

    # ports table
    in_ports = False
    for ln in lines:
        if ln.startswith("PORT"):
            in_ports = True
            out["ports_table_raw"].append(ln.rstrip())
            continue
        if in_ports:
            if ln.strip() == "":
                in_ports = False
                continue
            out["ports_table_raw"].append(ln.rstrip())

    # linhas soltas importantes
    for ln in lines:
        if ln.startswith("Service Info:"):
            out["service_info"] = ln.strip()
        elif ln.startswith("Network Distance:"):
            out["network_distance"] = ln.strip()
        elif ln.startswith("Device type:"):
            out["device_type"] = ln.strip()
        elif ln.startswith("Running:"):
            out["running"] = ln.strip()
        elif ln.startswith("OS CPE:"):
            out["os_cpe"] = ln.strip()
        elif ln.startswith("OS details:"):
            out["os_details"] = ln.strip()
        elif ln.startswith("MAC Address:"):
            out["mac_address"] = ln.strip()

    # tcp/ip stable fields raw block
    in_stable = False
    for ln in lines:
        if ln.startswith("TCP/IP fingerprint (stable fields):"):
            in_stable = True
            continue

        if in_stable:
            if (
                ln.startswith("Host script results")
                or ln.startswith("Device type:")
                or ln.startswith("Running:")
                or ln.startswith("OS details:")
                or ln.startswith("OS CPE:")
                or ln.startswith("Service Info:")
                or ln.startswith("Network Distance:")
                or ln.startswith("MAC Address:")
            ):
                in_stable = False
                break

            if ln.strip():
                out["tcpip_stable_fields_raw"].append(ln.rstrip())

    # host script results raw block
    in_hsr = False
    for ln in lines:
        if ln.startswith("Host script results"):
            in_hsr = True
            out["host_script_results_raw"].append(ln.rstrip())
            continue

        if in_hsr:
            if (
                ln.startswith("TCP/IP fingerprint (stable fields):")
                or ln.startswith("Device type:")
                or ln.startswith("Running:")
                or ln.startswith("OS details:")
                or ln.startswith("OS CPE:")
                or ln.startswith("Service Info:")
                or ln.startswith("Network Distance:")
                or ln.startswith("MAC Address:")
                or ln.startswith("PORT")
                or ln.startswith("Nmap scan report for ")
            ):
                in_hsr = False
                break

            out["host_script_results_raw"].append(ln.rstrip())

    return out


def extract_p0f_sets(p0f_parsed: dict, target_ip: str):
    """
    Extrai conjuntos estáveis do p0f para o IP alvo.

    Importante:
    - Quando você usa nping/nmap a partir do seu PC, o alvo geralmente aparece como SERVER
      nos blocos (syn+ack) e (mtu). Então precisamos capturar server_raw_sig e server_mtu.
    - Quando o alvo inicia conexões, ele aparece como CLIENT (syn) e (mtu) como client.
    """
    client_syn_sigs = set()
    client_mtus = set()
    client_oses = set()

    server_synack_sigs = set()
    server_mtus = set()
    server_oses = set()

    for b in p0f_parsed.get("blocks", []):
        header = b.get("header", "")
        fields = b.get("fields", {})

        # CLIENT side (alvo como client)
        if "(syn)" in header and fields.get("client", "").startswith(f"{target_ip}/"):
            rs = fields.get("raw_sig")
            if rs:
                client_syn_sigs.add(rs)
            os_guess = fields.get("os")
            if os_guess:
                client_oses.add(os_guess)

        if "(mtu)" in header and fields.get("client", "").startswith(f"{target_ip}/"):
            mtu = fields.get("raw_mtu")
            if mtu:
                client_mtus.add(mtu)

        # SERVER side (alvo como server)
        if "(syn+ack)" in header and fields.get("server", "").startswith(f"{target_ip}/"):
            rs = fields.get("raw_sig")
            if rs:
                server_synack_sigs.add(rs)
            os_guess = fields.get("os")
            if os_guess:
                server_oses.add(os_guess)

        if "(mtu)" in header and fields.get("server", "").startswith(f"{target_ip}/"):
            mtu = fields.get("raw_mtu")
            if mtu:
                server_mtus.add(mtu)

    return {
        "client_syn_raw_sig_set": sorted(client_syn_sigs),
        "client_mtu_set": sorted(client_mtus),
        "client_os_set": sorted(client_oses),

        "server_synack_raw_sig_set": sorted(server_synack_sigs),
        "server_mtu_set": sorted(server_mtus),
        "server_os_set": sorted(server_oses),
    }


def write_text(path: Path, s: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(s, encoding="utf-8", errors="replace")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True),
                    encoding="utf-8", errors="replace")


def fmt_secs(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds*1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    m = int(seconds // 60)
    s = seconds - (m * 60)
    return f"{m}m {s:05.2f}s"


def parse_open_tcp_ports_from_nmap(nmap_parsed: dict):
    """
    Extrai lista de portas TCP abertas do ports_table_raw.
    Aceita linhas tipo: "49152/tcp open  tcpwrapped"
    """
    open_ports = []
    for row in nmap_parsed.get("ports_table_raw", []):
        row = row.strip()
        m = re.match(r"^(\d+)/tcp\s+open\b", row)
        if m:
            open_ports.append(int(m.group(1)))
    # remove duplicatas mantendo ordem
    seen = set()
    out = []
    for p in open_ports:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def extract_tcp_syn_features_tshark(pcap_path: Path, ip: str):
    """
    Fallback: tenta extrair features do 1º SYN+ACK do alvo (melhor para nping SYN probe).
    Se não achar, tenta o 1º SYN do alvo.
    """
    feats = {
        "source": "tshark_syn_fallback",
        "filters_tried": [],
        "chosen_filter": None,
        "ttl": None,
        "window_size": None,
        "mss": None,
        "ws": None,
        "sack_perm": None,
        "ts_present": None,
        "options_order": None,
    }

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        feats["error"] = "pcap_missing_or_empty"
        return feats

    # 1) SYN+ACK (alvo respondendo aos SYN probes)
    filters = [
        f"ip.src=={ip} && tcp.flags.syn==1 && tcp.flags.ack==1",
        f"ip.src=={ip} && tcp.flags.syn==1 && tcp.flags.ack==0",
    ]

    def try_filter(dfilter: str):
        feats["filters_tried"].append(dfilter)

        cmd1 = [
            "tshark", "-r", str(pcap_path),
            "-Y", dfilter,
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "ip.ttl",
            "-e", "tcp.window_size_value",
            "-e", "tcp.options.mss_val",
            "-e", "tcp.options.wscale.shift",
            "-e", "tcp.options.sack_perm",
            "-e", "tcp.options.timestamp",
        ]
        rc, outb, errb = run_bytes(cmd1)
        txt = decode_bytes(outb).strip()
        err = decode_bytes(errb).strip()

        # log útil (mas não entra no CANON)
        if err:
            feats["tshark_stderr"] = (feats.get("tshark_stderr", "") + "\n" + err).strip()

        if rc != 0 or not txt:
            return None

        first = txt.splitlines()[0]
        cols = first.split("\t")

        def col(i):
            return cols[i] if i < len(cols) and cols[i] != "" else None

        local = {
            "ttl": col(0),
            "window_size": col(1),
            "mss": col(2),
            "ws": col(3),
            "sack_perm": col(4),
            "ts_present": "1" if col(5) is not None else "0",
        }

        # options order
        cmd2 = [
            "tshark", "-r", str(pcap_path),
            "-Y", dfilter,
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "tcp.options"
        ]
        rc2, outb2, errb2 = run_bytes(cmd2)
        txt2 = decode_bytes(outb2).strip()
        err2 = decode_bytes(errb2).strip()

        if err2:
            feats["tshark_stderr"] = (feats.get("tshark_stderr", "") + "\n" + err2).strip()

        if rc2 == 0 and txt2:
            opt_line = txt2.splitlines()[0].lower()

            def pos(key):
                p = opt_line.find(key)
                return p if p >= 0 else 10**9

            keys = [
                ("mss", "mss"),
                ("sack_perm", "sack_perm"),
                ("timestamp", "ts"),
                ("wscale", "ws"),
                ("nop", "nop"),
                ("eol", "eol"),
            ]
            found = []
            for needle, tag in keys:
                p = pos(needle)
                if p < 10**9:
                    found.append((p, tag))
            found.sort(key=lambda x: x[0])
            if found:
                local["options_order"] = ",".join(t for _, t in found)

        return local

    for f in filters:
        chosen = try_filter(f)
        if chosen:
            feats["chosen_filter"] = f
            feats.update(chosen)
            return feats

    feats["error"] = "no_syn_or_synack_found"
    return feats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outroot", help="Pasta raiz de saída, ex: runs")
    ap.add_argument("ip", help="IP alvo, ex: 192.168.1.102")
    ap.add_argument("--seconds", type=int, default=60, help="Duração da captura PCAP")
    ap.add_argument("--iface", default="Wi-Fi", help="Interface do dumpcap (nome ou índice do dumpcap -D)")
    ap.add_argument("--wsl_distro", default=None, help="Nome da distro WSL (opcional). Ex: Ubuntu-22.04")
    ap.add_argument("--nmap_args", nargs="*", default=["-T4", "-sV", "-sC", "-O", "-Pn"],
                    help="Args do nmap (sem o IP)")
    ap.add_argument("--dumpcap_path", default="dumpcap", help="Caminho do dumpcap.exe se não estiver no PATH")

    # Default python: Windows -> python ; Linux/macOS -> python3
    default_python = "python" if os.name == "nt" else "python3"
    ap.add_argument("--python", default=default_python, help="python no Windows (python ou py) / no Linux (python3)")

    ap.add_argument("--canon_policy", choices=["stable", "rich"], default="stable",
                    help="Política de canonização (stable recomendado).")

    ap.add_argument("--probe_count", type=int, default=3,
                    help="Quantidade de SYN probes por porta (nping).")
    ap.add_argument("--probe_max_ports", type=int, default=10,
                    help="Máximo de portas abertas do nmap usadas no probe.")
    ap.add_argument("--probe_delay", type=float, default=2.0,
                    help="Segundos de espera após iniciar dumpcap antes do probe.")

    args = ap.parse_args()

    # TIMING: início total
    t_total0 = time.perf_counter()
    tmarks = {}

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(args.outroot) / f"{args.ip}_{ts}"
    nmap_dir = run_dir / "nmap"
    pcap_dir = run_dir / "pcaps"
    p0f_dir  = run_dir / "p0f"

    for d in (nmap_dir, pcap_dir, p0f_dir):
        d.mkdir(parents=True, exist_ok=True)

    # -------------------------
    # 1) NMAP
    # -------------------------
    print("[*] Running nmap_snapshot.py ...")
    t0 = time.perf_counter()
    nmap_cmd = [args.python, "nmap_snapshot.py", str(nmap_dir), args.ip] + args.nmap_args
    nmap_out, nmap_err = run(nmap_cmd, check=False)
    tmarks["nmap"] = time.perf_counter() - t0
    write_text(nmap_dir / "bundle_nmap_stdout.txt", nmap_out)
    write_text(nmap_dir / "bundle_nmap_stderr.txt", nmap_err)

    norm_files = sorted(nmap_dir.glob("nmap_*.norm.txt"))
    nmap_norm_path = norm_files[-1] if norm_files else None
    nmap_norm_text = ""
    if nmap_norm_path and nmap_norm_path.exists():
        nmap_norm_text = nmap_norm_path.read_text(encoding="utf-8", errors="replace")
        nmap_parsed = parse_nmap_norm(nmap_norm_text)
    else:
        nmap_parsed = {"error": "nmap norm file not found in nmap_dir"}

    open_ports = parse_open_tcp_ports_from_nmap(nmap_parsed)
    if open_ports:
        print(f"[*] Nmap open TCP ports detected: {open_ports[:args.probe_max_ports]}")
    else:
        print("[*] Nmap did not report open TCP ports (or ports table missing).")

    # -------------------------
    # 2) CAPTURA PCAP (dumpcap) + SYN probe (nping)
    # -------------------------
    print("[*] Capturing PCAP with dumpcap (async) ...")
    t0 = time.perf_counter()
    pcap_path = pcap_dir / f"capture_{args.ip}_{ts}.pcap"

    capture_cmd = [
        args.dumpcap_path,
        "-i", args.iface,
        "-w", str(pcap_path),
        "-a", f"duration:{args.seconds}",
        "-f", f"host {args.ip}"
    ]

    cap_p = subprocess.Popen(capture_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(max(0.0, args.probe_delay))

    t_probe0 = time.perf_counter()
    probe_used = False
    probe_ports = open_ports[:max(0, args.probe_max_ports)] if open_ports else []

    if probe_ports:
        ports_csv = ",".join(str(p) for p in probe_ports)
        print(f"[*] Probing target with nping SYN (ports={ports_csv}, count={args.probe_count}) ...")
        nping_cmd = [
            "nping",
            "--tcp",
            "-p", ports_csv,
            "--flags", "syn",
            "--count", str(args.probe_count),
            args.ip
        ]
        np_out, np_err = run(nping_cmd, check=False)
        write_text(run_dir / "nping_stdout.txt", np_out)
        if np_err.strip():
            write_text(run_dir / "nping_stderr.txt", np_err)
        probe_used = True
    else:
        common = [80, 443, 22, 445, 139, 3389, 8080, 8443, 9100, 5357]
        ports_csv = ",".join(str(p) for p in common)
        print(f"[*] Probing common ports with nping SYN (ports={ports_csv}, count=1) ...")
        nping_cmd = [
            "nping",
            "--tcp",
            "-p", ports_csv,
            "--flags", "syn",
            "--count", str(args.probe_count),
            args.ip
        ]
        np_out, np_err = run(nping_cmd, check=False)
        write_text(run_dir / "nping_stdout.txt", np_out)
        if np_err.strip():
            write_text(run_dir / "nping_stderr.txt", np_err)
        probe_used = True
        probe_ports = common

    tmarks["nping_probe"] = time.perf_counter() - t_probe0

    out_b, err_b = cap_p.communicate()
    cap_out = decode_bytes(out_b or b"")
    cap_err = decode_bytes(err_b or b"")

    tmarks["dumpcap_capture"] = time.perf_counter() - t0
    write_text(pcap_dir / "bundle_dumpcap_stdout.txt", cap_out)
    write_text(pcap_dir / "bundle_dumpcap_stderr.txt", cap_err)

    p0f_raw_path = p0f_dir / f"p0f_{args.ip}_{ts}.raw.txt"

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        print("[!] PCAP não foi criado ou está vazio; pulando p0f/tshark.")
        print("    Verifique:")
        print("    - Nome/índice correto da interface (dumpcap -D)")
        print("    - Permissões (tshark/dumpcap pode exigir sudo/capabilities)")
        print("    - Filtro/host correto (IP realmente gerando tráfego)")

        p0f_out, p0f_err = "", "skipped: pcap_missing_or_empty"
        write_text(p0f_raw_path, p0f_out)
        write_text(p0f_dir / f"p0f_{args.ip}_{ts}.stderr.txt", p0f_err)

        p0f_parsed = {
            "error": "pcap_missing_or_empty",
            "warnings": [],
            "summary": {"processed_packets": None, "blocks_count": 0},
            "blocks": [],
            "extracted": {},
        }
        pcap_syn = {"error": "pcap_missing_or_empty"}

    else:
        # -------------------------
        # 3) P0F (Windows via WSL / Linux/macOS nativo)
        # -------------------------
        t0 = time.perf_counter()
        if os.name == "nt":
            print("[*] Running p0f in WSL (offline -r) ...")
            pcap_arg = win_to_wsl_path(pcap_path)

            wsl_prefix = ["wsl", "--"]
            if args.wsl_distro:
                wsl_prefix = ["wsl", "-d", args.wsl_distro, "--"]

            p0f_cmd = wsl_prefix + ["p0f", "-r", pcap_arg]
            p0f_out, p0f_err = run(p0f_cmd, check=False)
            tmarks["p0f_wsl"] = time.perf_counter() - t0
        else:
            print("[*] Running p0f (native) (offline -r) ...")
            pcap_arg = str(pcap_path.resolve())
            p0f_cmd = ["p0f", "-r", pcap_arg]
            p0f_out, p0f_err = run(p0f_cmd, check=False)
            tmarks["p0f_native"] = time.perf_counter() - t0

        write_text(p0f_raw_path, p0f_out)
        write_text(p0f_dir / f"p0f_{args.ip}_{ts}.stderr.txt", p0f_err)

        p0f_parsed = parse_p0f_raw(p0f_out)
        p0f_parsed["extracted"] = extract_p0f_sets(p0f_parsed, args.ip)

        # -------------------------
        # 3b) SYN/SYN+ACK features via tshark
        # -------------------------
        print("[*] Extracting SYN/SYN+ACK TCP features from PCAP via tshark ...")
        t0 = time.perf_counter()
        pcap_syn = extract_tcp_syn_features_tshark(pcap_path, args.ip)
        tmarks["tshark_syn_fallback"] = time.perf_counter() - t0

    # -------------------------
    # 4) Fingerprint JSON (bundle bruto)
    # -------------------------
    fingerprint = {
        "meta": {
            "ts": ts,
            "ip": args.ip,
            "seconds": args.seconds,
            "iface": args.iface,
            "wsl_distro": args.wsl_distro if os.name == "nt" else None,
            "probe_used": bool(probe_used),
            "probe_ports": probe_ports,
            "probe_count": args.probe_count,
        },
        "paths": {
            "run_dir": str(run_dir.resolve()),
            "pcap_path": str(pcap_path),
            "nmap_norm_path": str(nmap_norm_path) if nmap_norm_path else None,
            "p0f_raw_path": str(p0f_raw_path),
        },
        "nmap": nmap_parsed,
        "p0f": p0f_parsed,
        "pcap_syn": pcap_syn,
    }

    fp_json_path = run_dir / "fingerprint.json"
    write_json(fp_json_path, fingerprint)

    # -------------------------
    # 5) Canonização + Hash 
    # -------------------------
    canon_obj = None
    canon_str = None
    fp_hash = None

    if build_canon is None or dumps_canon is None:
        print("\n[!] Canonização/Hash: não foi possível importar canonicalize_features.py")
        print(f"    Erro: {_CANON_IMPORT_ERR}")
        print("    Dica: garanta que canonicalize_features.py está na mesma pasta do bundle_snapshot.py")
    else:
        t0 = time.perf_counter()
        try:
            canon_obj = build_canon(fingerprint, policy=args.canon_policy)
            canon_str = dumps_canon(canon_obj)
            fp_hash = hashlib.sha256(canon_str.encode("utf-8")).hexdigest()

            canon_json_path = run_dir / "features_canon.json"
            canon_txt_path  = run_dir / "features_canon.txt"
            hash_txt_path   = run_dir / "fingerprint_sha256.txt"

            write_json(canon_json_path, canon_obj)
            write_text(canon_txt_path, canon_str + "\n")
            write_text(hash_txt_path, fp_hash + "\n")

            tmarks["canon_plus_hash"] = time.perf_counter() - t0

            print("\n=== CANON_STRING ===")
            print(canon_str)
            print("\n=== FINGERPRINT_HASH ===")
            print(fp_hash)

            print("\n[OK] Saved:")
            print(f"  {canon_json_path}")
            print(f"  {canon_txt_path}")
            print(f"  {hash_txt_path}")

        except Exception as e:
            tmarks["canon_plus_hash"] = time.perf_counter() - t0
            print("\n[!] Canonização/Hash falhou:")
            print(f"    {e}")

    # -------------------------
    # 6) Resumo + TIMING
    # -------------------------
    total_elapsed = time.perf_counter() - t_total0
    print("\n[OK] Bundle salvo em:") 
    print(f" {run_dir.resolve()}")

    print("\n=== TIMING (rodada) ===")
    for key in ["nmap", "dumpcap_capture", "nping_probe", "p0f_wsl", "p0f_native", "tshark_syn_fallback", "canon_plus_hash"]:
        if key in tmarks:
            print(f"{key:18s}: {fmt_secs(tmarks[key])}")
    print(f"{'TOTAL':18s}: {fmt_secs(total_elapsed)}")


if __name__ == "__main__":
    main()
