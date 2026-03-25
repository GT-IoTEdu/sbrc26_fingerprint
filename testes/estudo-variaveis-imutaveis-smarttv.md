# Estudo: variáveis estáveis no fingerprint de Smart TVs

Documento de apoio ao pipeline `bundle_snapshot.py` + `canonicalize_features.py` (política **`stable`**).  
Exemplo ancorado numa corrida real contra **TCL Smart TV Pro** (`192.168.59.106`, `20260324_220537`).

**Política `stable` (única, qualquer IP):** não é necessário indicar tipo de dispositivo. O canónico `nmap` usa só **`manufacturer`** e **`model_name`** (não entram `server` nem `name`), para ser aplicável a TVs, telemóveis, routers, etc. Para estudo com banners/nomes completos, usar **`--canon_policy rich`**.

---

## 1. O que entra no hash (SHA-256)

O fingerprint final é `sha256(CANON_STRING)`, onde `CANON_STRING` é JSON minificado com chaves ordenadas.  
Na política `stable`, só entram três secções quando disponíveis:

| Secção | Origem no log | Papel |
|--------|----------------|--------|
| `nmap` | Nmap UPnP + SSDP + fetch XML | Em **`stable`**: `manufacturer`, `model_name` apenas (sem `server` nem `name`) |
| `p0f` | `server_synack_raw_sig_set` (preferido) ou SYN cliente | Assinatura da pilha TCP (SYN+ACK) |
| `pcap_syn` | tshark no primeiro SYN+ACK do alvo | TTL, MSS, janela TCP do SYN+ACK |

**`server`** e **`name`** também ficam de fora do `stable` (banners e nomes amigáveis variam — ex. Xiaomi: Chromecast vs NRDP no mesmo IP). Usar **`--canon_policy rich`** se esses campos fizerem parte do estudo.

**Exemplo de CANON_STRING `stable` (TCL):**

```json
{"nmap":{"manufacturer":"TCL","model_name":"Smart TV Pro"},"p0f":{"extracted":{"server_synack_raw_sig_set":["4:64+0:0:1460:65535,0:mss:df:0"]}},"pcap_syn":{"mss":"1460","ttl":"64","window_size":"65535"}}
```

---

## 2. Variáveis tratadas como “imutáveis” (estáveis) para Smart TVs

São **atributos que tendem a não mudar** enquanto o firmware e a topologia da LAN forem as mesmas. Úteis para **identificar o modelo/pilha**, não para anti-replay criptográfico.

### 2.1 UPnP / DLNA (`nmap` no canónico)

| Campo | Valor (exemplo) | Estabilidade |
|-------|-----------------|--------------|
| `manufacturer` | TCL | Estável até troca de fabricante/firmware que altere o device description |
| `model_name` | Smart TV Pro | Idem |
| `name` | (só em **`rich`**) | Nome amigável (TV, telemóvel, router) — **não** entra em `stable` |
| `server` | (só em **`rich`**) | Banners **instáveis** entre scans |

**Nota:** `name` e `server` ficam no `fingerprint.json` bruto; só **`rich`** os põe no hash. Vários `LOCATION` SSDP: URLs ordenadas por porta para reduzir troca de fabricante no *fetch*.

### 2.2 p0f — SYN+ACK (`server_synack_raw_sig_set`)

| Valor (exemplo) | Significado resumido |
|-----------------|----------------------|
| `4:64+0:0:1460:65535,0:mss:df:0` | Assinatura p0f do segmento SYN+ACK (TTL típico da LAN, MSS 1460, janela inicial, opções TCP) |

**Estabilidade:** alta para o **mesmo SO/pilha TCP** e **mesmo tipo de resposta**. Pode mudar com **atualização de kernel/firmware** ou se o dispositivo usar **pilhas diferentes** por interface/perfil.

**Log bruto (não usado no hash `stable`):** também existem assinaturas de **SYN cliente** e MTUs no extract, por exemplo:

- `client_syn_raw_sig_set`: `4:64+0:0:1460:65535,6:mss,sok,ts,nop,ws:df,id+:0`
- O canónico escolhe **SYN+ACK do servidor** quando presente (`build_canon p0f branch=server_synack`).

### 2.3 tshark — fallback SYN+ACK (`pcap_syn` no canónico)

| Campo | Valor (exemplo) | Estabilidade |
|-------|-----------------|--------------|
| `ttl` | 64 | Muito estável na **mesma sub-rede** (saltos até ao alvo iguais) |
| `mss` | 1460 | Típico Ethernet; estável para a pilha |
| `window_size` | 65535 | Em muitos dispositivos fixo no SYN+ACK; **pode variar** com carga ou outro fluxo capturado primeiro |

**Filtro usado no log:** primeiro pacote SYN+ACK com `ip.src == alvo`, `matching_lines=3`, primeira linha usada para o hash.

Campos **capturados** mas **fora** do canónico `stable` atual (não entram no JSON do hash): `ws`, `options_order`, `sack_perm`, etc. — ver `canonicalize_features.py`.

---

## 3. Variáveis que não são “imutáveis” (podem variar entre corridas)

| Área | Porque pode mudar |
|------|-------------------|
| `window_size` / primeira linha tshark | Ordem dos pacotes no PCAP, outro fluxo TCP, tuning da pilha |
| `ttl` | Mudança de rota entre captura e alvo (menos comum em LAN doméstica) |
| `nmap.server` | Entre scans no mesmo IP: outro serviço responde primeiro (ex. Chromecast vs NRDP na Xiaomi) |
| `name` / friendlyName | Alteração nas definições da TV |
| Conteúdo do PCAP | Tráfego de fundo diferente (tamanho do ficheiro no log: ~28 MB) |

---

## 4. Mapa rápido: linhas do log → decisão do canónico

```
STAGE nmap_upnp END          → preenche nmap (TCL, Smart TV Pro, server string)
STAGE pcap_capture           → ficheiro PCAP filtrado por host
extract_p0f_sets            → client_syn=1, server_synack=1 (canónico usa SYN+ACK)
build_canon p0f branch=server_synack → inclui apenas server_synack_raw_sig_set
build_canon pcap_syn        → inclui mss, ttl, window_size
build_canon result_sections → ['nmap', 'p0f', 'pcap_syn']
```

---

## 5. Conclusão para estudo (Smart TVs)

- Para **fingerprint estável** neste projeto: priorizar **`p0f` SYN+ACK** + **`pcap_syn` (MSS, TTL)** + **identidade UPnP** quando consistente.
- Tratar **`server` UPnP** e **`window_size`** como **sensíveis a firmware** e **ordem de pacotes**, respetivamente.
- Em investigações científicas, documentar sempre: **mesma interface**, **mesmo alvo**, **duração de captura**, e **versão de firmware** da TV.

---

## Referência

- Exemplo TCL (log): `runs/192.168.59.106_20260324_220537/fingerprint_pipeline.log`
- Caso Xiaomi (mesmo IP, hashes diferentes só por `server`): `192.168.59.105` — comparar runs `...222650` vs `...223217`
