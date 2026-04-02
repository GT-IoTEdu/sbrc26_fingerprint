#!/usr/bin/env bash
# Descobre hosts ativos na sub-rede do adaptador por defeito (ou indicado)
# e executa iot_id_fingerprint.py para cada IP.
#
# Requisitos: Linux, bash, nmap, ip, python3, sudo (para a ferramenta).
#
# Uso:
#   ./fingerprint_subnet.sh
#   ./fingerprint_subnet.sh -i wlan0 --seconds 90
#   ./fingerprint_subnet.sh -c 192.168.1.0/24 --dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FP_TOOL="${FP_TOOL:-$SCRIPT_DIR/iot_id_fingerprint.py}"
PYTHON="${PYTHON:-python3}"
OUTROOT="runs"
SECONDS_CAP=60
IFACE=""
CIDR=""
DRY_RUN=0
SKIP_SELF=1

die() { echo "fingerprint_subnet.sh: erro: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
fingerprint_subnet.sh — deteta hosts na sub-rede e chama iot_id_fingerprint.py por IP.

Opções:
  -i, --iface IFACE   Interface de captura (omissão: interface da rota por defeito)
  -c, --cidr CIDR     Sub-rede em notação CIDR (omissão: derivada da interface)
  -o, --outroot DIR   Pasta de saída passada à ferramenta (omissão: runs)
  -s, --seconds N     Duração PCAP --seconds (omissão: 60)
  --no-skip-self      Incluir o próprio IP da máquina na lista
  -n, --dry-run       Só listar IPs e o comando; não executar sudo/python
  -h, --help          Esta ajuda

Variáveis de ambiente:
  PYTHON        Interpretador (omissão: python3)
  FP_TOOL       Caminho para iot_id_fingerprint.py
EOF
}

detect_default_iface() {
  ip route get 8.8.8.8 2>/dev/null \
    | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); exit } }' \
    || true
}

cidr_for_iface() {
  local dev="$1"
  [[ -n "$dev" ]] || die "interface vazia"
  ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{ print $4; exit }' \
    || die "sem endereço IPv4 em dev=$dev (use -c CIDR)"
}

local_ip_for_iface() {
  local dev="$1"
  ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{ print $4; exit }' | cut -d/ -f1 \
    || true
}

list_hosts() {
  local net="$1"
  [[ -n "$net" ]] || die "CIDR vazio"
  command -v nmap >/dev/null 2>&1 || die "nmap não encontrado no PATH"
  # Saída grepable: Host: <ip> ()\tStatus: Up
  nmap -sn -n -oG - "$net" 2>/dev/null | awk '/Status: Up/ { print $2 }' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -uV
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--iface) IFACE="${2:?}"; shift 2 ;;
    -c|--cidr) CIDR="${2:?}"; shift 2 ;;
    -o|--outroot) OUTROOT="${2:?}"; shift 2 ;;
    -s|--seconds) SECONDS_CAP="${2:?}"; shift 2 ;;
    --no-skip-self) SKIP_SELF=0; shift ;;
    -n|--dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      die "argumento desconhecido: $1 (use -h)"
  esac
done

[[ -f "$FP_TOOL" ]] || die "ficheiro não encontrado: $FP_TOOL"

if [[ -z "$IFACE" ]]; then
  IFACE="$(detect_default_iface)"
  [[ -n "$IFACE" ]] || die "não foi possível detetar a interface (use -i)"
fi

if [[ -z "$CIDR" ]]; then
  CIDR="$(cidr_for_iface "$IFACE")"
fi

SELF_IP=""
if [[ "$SKIP_SELF" -eq 1 ]]; then
  SELF_IP="$(local_ip_for_iface "$IFACE")"
fi

echo "[*] Interface: $IFACE"
echo "[*] Sub-rede:  $CIDR"
echo "[*] Outroot:   $OUTROOT"
echo "[*] Seconds:   $SECONDS_CAP"
[[ -n "$SELF_IP" ]] && echo "[*] Excluir IP local: $SELF_IP"
echo ""

mapfile -t ALL_HOSTS < <(list_hosts "$CIDR")
[[ ${#ALL_HOSTS[@]} -gt 0 ]] || die "nenhum host Up detetado (nmap -sn $CIDR)"

HOSTS=()
for ip in "${ALL_HOSTS[@]}"; do
  if [[ "$SKIP_SELF" -eq 1 && "$ip" == "$SELF_IP" ]]; then
    echo "[=] Ignorar (este host): $ip"
    continue
  fi
  HOSTS+=("$ip")
done

[[ ${#HOSTS[@]} -gt 0 ]] || die "lista de alvos vazia após exclusões"

echo "[*] Alvos (${#HOSTS[@]}): ${HOSTS[*]}"
echo ""

for ip in "${HOSTS[@]}"; do
  cmd=(sudo "$PYTHON" "$FP_TOOL" "$OUTROOT" "$ip" --seconds "$SECONDS_CAP" --iface "$IFACE")
  echo "================================================================"
  echo "[>] ${cmd[*]}"
  echo "================================================================"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    continue
  fi
  "${cmd[@]}"
done

echo ""
echo "[OK] Concluído para ${#HOSTS[@]} host(s)."
