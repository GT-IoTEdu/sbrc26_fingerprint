# Arquitetura

Este documento descreve o desenho interno das ferramentas de fingerprint: os
módulos, o fluxo de dados do pipeline e a fórmula do hash. Complementa o
`README.md` (visão geral e instalação) e o `docs/USAGE.md` (linha de comando).

## Visão geral

O objetivo é produzir, para um dispositivo de rede, uma **assinatura SHA-256
determinística** derivada de características de baixo nível (TCP/IP, p0f, UPnP)
que tendem a ser estáveis para o mesmo aparelho. Dois passos garantem o
determinismo: a **canonicalização** (selecionar e normalizar campos) e o
**hash** sobre a string canônica.

```
            captura/análise                  canonicalização          hash
  alvo ──► [ nmap/UPnP + dumpcap + nping ] ─► fingerprint.json ─► CANON_STRING ─► SHA-256
            [ p0f + tshark ]
```

## Módulos

| Arquivo | Responsabilidade |
|---|---|
| `upnp_discovery.py` | Descoberta SSDP/UPnP compartilhada: `ssdp_probe`, `fetch_upnp_description`, `nmap_upnp_scan`, `collect_upnp_identity`. Único ponto que fala UPnP. |
| `iot_id_fingerprint.py` | Orquestrador do pipeline (captura, p0f, tshark, bundle, hash) e CLI. Modos `target` e `network`. |
| `canonicalize_features.py` | `build_canon` (seleção/normalização determinística) + `dumps_canon` (serialização compacta). |
| `fingerprint_hash.py` | CLI que aplica `build_canon` + SHA-256 a um `fingerprint.json` existente. |
| `iot_net_scanner.py` | Inventário leve da LAN (ARP + SSDP + nmap), sem captura de pacotes. |
| `fingerprint_subnet.sh` | Driver em lote: descobre hosts com `nmap -sn` e chama o pipeline por IP. |

A separação segue o princípio de responsabilidade única: a lógica de rede UPnP
vive em um só módulo (`upnp_discovery.py`), importado tanto pelo pipeline quanto
pelo scanner, eliminando a duplicação que existia antes.

## Pipeline (um host)

`run_single_fingerprint()` executa seis estágios e grava todos os artefatos em
`runs/<ip>_<timestamp>/`:

1. **Identidade UPnP/Nmap** — `collect_upnp_identity()` combina `nmap --script
   upnp-info` com respostas SSDP e o XML `device-desc`. Define `host_kind`:
   - `iot` se há fabricante ou modelo;
   - `mobile` caso contrário (telemóvel, tablet, portátil, router sem UPnP).
2. **Captura + sonda** — `dumpcap` grava um PCAP filtrado por `host <ip>` por
   `--seconds` segundos enquanto, em paralelo, `nping` dispara SYNs em portas
   comuns (`--probe-ports`) para provocar respostas SYN+ACK.
3. **p0f** — análise passiva offline (`p0f -r`) sobre o PCAP; extraímos as
   `raw_sig` do SYN (cliente) e do SYN+ACK (servidor) do IP alvo.
4. **tshark** — features do primeiro SYN+ACK (ou SYN) do alvo: `ttl`,
   `window_size`, `mss`, `ws`, `sack_perm`, `ts_present`, ordem das opções. Em
   hosts `mobile`, também coleta pistas passivas (DHCP, HTTP User-Agent, SNI
   TLS, mDNS, NBNS) e um `nmap -sV` leve — usados só para estudo, **fora** do
   hash.
5. **Bundle bruto** — tudo é consolidado em `fingerprint.json`.
6. **Canonicalização + hash** — produz `features_canon.json`,
   `features_canon.txt` (a CANON_STRING) e `fingerprint_sha256.txt`.

Se o PCAP sair vazio (interface errada, falta de permissões, alvo sem tráfego),
os estágios p0f/tshark são pulados com um diagnóstico claro, e o hash usa apenas
o que estiver disponível.

## Fórmula do fingerprint

```
CANON_STRING = json_minificado( build_canon(bundle, policy) )   # chaves ordenadas, sem espaços
FINGERPRINT  = sha256( CANON_STRING em UTF-8 )
```

`build_canon` seleciona campos diferentes por tipo de host. Apenas campos
estáveis entram; campos voláteis (DHCP, banners, User-Agent) ficam de fora.

| Seção | host `iot` | host `mobile` |
|---|---|---|
| `nmap` | `manufacturer`, `model_name` (+ `server`, `name` na policy `rich`) | — (ignorado) |
| `p0f` | `server_synack_raw_sig_set` (ou `client_syn` como fallback) | `client_syn_raw_sig_set` |
| `pcap_syn` | `ttl`, `window_size`, `mss`, `ws` | `mss`, `sack_perm`, `ts_present`, `ttl`, `window_size`, `ws` |

Garantias de determinismo em `build_canon`:

- **chaves ordenadas** e **sem espaços** na serialização (`separators=(",",":")`);
- **normalização** de cada escalar (colapsa whitespace, converte bool/número);
- **listas ordenadas e sem duplicatas**;
- **remoção recursiva** de `None`, dicts e listas vazias.

### Policies

- `stable` (padrão): só `manufacturer` + `model_name` no bloco nmap. Mais robusto
  a mudanças de firmware/nomeação.
- `rich`: adiciona `server` e `name`. Mais discriminante, porém mais volátil.

## Saída em disco

```
runs/<ip>_<ts>/
├── fingerprint.json            # bundle bruto (todas as features)
├── features_canon.json         # objeto canônico (o que entra no hash)
├── features_canon.txt          # CANON_STRING
├── fingerprint_sha256.txt      # o hash
├── fingerprint_pipeline.log    # log do pipeline
├── nmap/                       # stdout e identidade UPnP
├── pcaps/                      # capture_<ip>_<ts>.pcap (removido com --cleanup)
└── p0f/                        # p0f raw + stderr (removido com --cleanup)
```

No modo `network`, tudo fica sob `runs/scan_<ts>/` com um `scan_summary.json`
agregando os hashes de cada host.
