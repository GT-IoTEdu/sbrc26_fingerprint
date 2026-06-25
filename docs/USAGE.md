# Guia de uso

Referência de linha de comando das ferramentas. Veja `docs/ARCHITECTURE.md` para
o desenho interno e a fórmula do hash.

## Requisitos

- Linux com: `nmap`, `dumpcap`, `nping`, `tshark`, `p0f`, `iproute2`.
- Python 3.8+ e as dependências de `requirements.txt`
  (`pip install -r requirements.txt`).
- Captura e sondas exigem privilégios: rode com `sudo` ou conceda *capabilities*
  a `dumpcap`/`nping`. Tudo também roda em container (veja `Dockerfile` /
  `docker-compose.yml`).

## `iot_id_fingerprint.py` — pipeline principal

```
python3 iot_id_fingerprint.py <outroot> [ip] [opções]
```

`<outroot>` é a pasta raiz de saída (ex.: `runs`). `ip` é obrigatório no modo
`target`.

| Opção | Padrão | Descrição |
|---|---|---|
| `--mode {target,network}` | `target` | `target`: o IP indicado. `network`: descobre hosts por SSDP e roda em cada um. |
| `--iface IFACE` | rota por defeito | Interface de captura. **Auto-detetada** se omitida (`ip route get 8.8.8.8`). |
| `--seconds N` | `60` | Duração da captura PCAP. |
| `--canon-policy {stable,rich}` | `stable` | `stable`: nmap só `manufacturer`+`model_name`. `rich`: inclui `server`+`name`. |
| `--probe-ports LISTA` | `80,443,22,445,139,3389,8080,8443,9100,5357` | Portas da sonda SYN (inteiros separados por vírgula). |
| `--probe-count N` | `3` | SYN probes por porta. |
| `--probe-delay S` | `2.0` | Espera (s) após iniciar o dumpcap antes da sonda. |
| `--dumpcap-path P` | `dumpcap` | Caminho do `dumpcap` se não estiver no PATH. |
| `--cleanup` | desligado | Remove artefatos brutos (`.pcap`, `p0f.raw.txt`) ao fim. |
| `--log-level {DEBUG,INFO,WARNING,ERROR}` | `INFO` | Nível do log de pipeline. |
| `--log-console` | desligado | Espelha o log no stderr além do ficheiro. |
| `--scan-max-hosts N` | `0` | Modo `network`: máximo de hosts (`0` = todos). |

### Exemplos

```bash
# Alvo único (interface auto-detetada)
sudo python3 iot_id_fingerprint.py runs 192.168.1.10

# Interface explícita, captura mais longa, limpeza dos brutos
sudo python3 iot_id_fingerprint.py runs 192.168.1.10 --iface eth0 --seconds 90 --cleanup

# Portas de sonda personalizadas e policy mais discriminante
sudo python3 iot_id_fingerprint.py runs 192.168.1.10 --probe-ports 80,443,8009 --canon-policy rich

# Modo rede: descobre por SSDP e faz fingerprint de cada host
sudo python3 iot_id_fingerprint.py runs --mode network --scan-max-hosts 10
```

## `fingerprint_subnet.sh` — lote por sub-rede

Descobre hosts ativos com `nmap -sn` e chama o pipeline por IP.

```bash
./fingerprint_subnet.sh                       # interface/sub-rede auto-detetadas
./fingerprint_subnet.sh -i wlan0 --seconds 90 # interface e duração
./fingerprint_subnet.sh -c 192.168.1.0/24 -n  # dry-run: só lista IPs e comandos
./fingerprint_subnet.sh -r 1                  # uma passada por host (padrão: 5)
```

Principais flags: `-i/--iface`, `-c/--cidr`, `-o/--outroot`, `-s/--seconds`,
`-r/--repeat`, `--cleanup`, `-n/--dry-run`, `-h/--help`.

## `iot_net_scanner.py` — inventário leve

Lista dispositivos (IP/MAC/identidade UPnP) sem captura de pacotes.

```bash
sudo python3 iot_net_scanner.py            # rede inteira (broadcast UPnP)
sudo python3 iot_net_scanner.py 192.168.1.50   # apenas um alvo
```

## `canonicalize_features.py` e `fingerprint_hash.py` — pós-processamento

Reaproveitam um `fingerprint.json` já gerado (útil para reprocessar dados antigos
ou comparar policies sem recapturar).

```bash
# Ver o objeto canônico e a CANON_STRING
python3 canonicalize_features.py runs/192.168.1.10_*/fingerprint.json --policy rich

# Recalcular o hash de um bundle e salvar
python3 fingerprint_hash.py runs/192.168.1.10_*/fingerprint.json --outdir /tmp/fp
```

## Docker

```bash
docker compose build
# Pipeline (ENTRYPOINT já é iot_id_fingerprint.py); saída vai para ./runs
docker compose run --rm fingerprint runs 192.168.1.10 --seconds 60 --cleanup
```

O serviço usa `network_mode: host` e as capabilities `NET_ADMIN`/`NET_RAW`,
necessárias para captura e sondas.
