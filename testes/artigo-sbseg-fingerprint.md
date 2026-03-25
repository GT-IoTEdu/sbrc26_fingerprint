# Fingerprint determinístico de dispositivos em LAN

**Rascunho para submissão / relatório técnico (formato inspirado em veículos como SBSeg)**  
**Projeto:** ferramenta de fingerprinting IoT e hosts móveis em ambiente de laboratório (`bundle_snapshot`, canonização, SHA-256).

---

## Resumo

Propomos um pipeline que agrega **sonda ativa** (Nmap UPnP, nping), **captura passiva** (PCAP, p0f, tshark) e **canonização determinística** para produzir um **hash SHA-256** estável por dispositivo em LAN. Durante a experimentação surgiram fontes de instabilidade (ordem de URLs SSDP, banners HTTP/UPnP, nomes amigáveis e tráfego de aplicações em smartphones). A solução final **separa classes lógicas** (`iot` vs `mobile`), **restringe campos voláteis** na política `stable` e acrescenta **telemetria estruturada** (logs por fase, manifestos JSON por corrida). Este documento descreve o problema, os experimentos, o desenho final e direções futuras.

**Palavras-chave:** fingerprint de rede; IoT; UPnP; p0f; canonização; SHA-256; smartphone; reproducibilidade.

---

## 1. Introdução e motivação

Identificar dispositivos na rede local sem cooperatividade do terminal é relevante para **inventário**, **segmentação** e **resposta a incidentes**. Assinaturas puramente por **endereço IP** são frágeis (DHCP). Combinar **comportamento da pilha TCP** (SYN/SYN+ACK) com **metadados de serviço** (DLNA/UPnP) aumenta a discriminação, mas introduz **variância entre colheitas** se campos não forem escolhidos com critério.

Objetivos do trabalho:

1. Gerar um **identificador reprodutível** (hash de cadeia canónica UTF-8).
2. **Não exigir** ao operador a classe do dispositivo (TV, telemóvel, router).
3. **Diagnosticar** divergências de hash através de logs e artefactos guardados por corrida.

---

## 2. Arquitetura da solução

### 2.1 Componentes

| Componente | Função |
|------------|--------|
| `bundle_snapshot.py` | Orquestra Nmap UPnP+SSDP, captura `dumpcap`, `nping`, `p0f`, `tshark`; grava `fingerprint.json`, PCAP, logs. |
| `canonicalize_features.py` | Constrói `CANON_OBJ` → `CANON_STRING` (JSON minificado, `sort_keys=True`). |
| `fingerprint_hash.py` | Recalcula hash a partir de um bundle existente (reprodutibilidade). |

O **hash final** é `SHA-256(CANON_STRING)`.

### 2.2 Modos operacionais

- **`--mode target` (padrão):** um IP alvo; pasta `runs/<IP>_<timestamp>/`.
- **`--mode network`:** M-SEARCH SSDP sem filtro de IP; descobre hosts; para cada um aplica o pipeline; índice em `scan_<ts>/scan_summary.json` e `ssdp_discovery.json`.

### 2.3 Classificação automática `host_kind`

- **`iot`:** UPnP/SSDP preenche **fabricante** ou **modelo** no bloco `nmap`.
- **`mobile`:** caso contrário (telefone, tablet, equipamento sem descoberta UPnP útil, etc.).

Esta divisão **não é configurada pelo utilizador**; deriva dos dados colhidos.

---

## 3. Extração de características

### 3.1 IoT (UPnP)

- Nmap com script `upnp-info`, complementado por SSDP e fetch de `device-desc.xml`.
- **Ordenação determinística** das URLs `LOCATION` por **(porta, path, URL)** para evitar alternância entre serviços no **mesmo IP** (ex.: TV em `:8008` vs serviço em `:8443`).

### 3.2 Pilha TCP (todos os tipos)

- **p0f** offline sobre o PCAP; extração de conjuntos `client_syn_raw_sig_set` / `server_synack_raw_sig_set` com correspondência robusta ao IP (formatos de campo, cabeçalhos em maiúsculas).
- **tshark:** preferência por SYN+ACK com `ip.src == alvo`; alternativa SYN cliente; **fallback** de **TTL IPv4** / **hop limit IPv6** quando não há segmentos TCP úteis (comum em telemóveis com pouca resposta aos probes).

### 3.3 Mobile — sondagem e passivo

- **`mobile_passive` (tshark no PCAP):** DHCP (hostname, vendor class), HTTP User-Agent, SNI TLS, mDNS, NBNS.
- **`mobile_nmap`:** `nmap -sV` sobre portas frequentes em telemóveis (SSH, ADB, RTSP, serviços Google/Apple, etc.).

---

## 4. Canonização e políticas

### 4.1 Política `stable` (fingerprint principal)

**IoT — secção `nmap`:** apenas **`manufacturer`** e **`model_name`**.  
Excluem-se **`server`** (banner alterna entre serviços no mesmo host, ex. Chromecast vs NRDP na Xiaomi) e **`name`** (amigável, editável).

**Mobile — `mobile_passive`:** apenas **`dhcp_hostname`**, **`dhcp_vendor`**, **`nbns`**.  
Excluem-se **`tls_sni`**, **`http_user_agent`** e **`mdns`** no `stable`, pois variam com **aplicações e sítios visitados** durante a janela de captura (experimentos mostraram alteração dramática do hash só por listas de SNI diferentes entre corridas consecutivas).

Mantêm-se **`mobile_nmap.service_lines`**, **`p0f`** e **`pcap_syn`** quando disponíveis.

### 4.2 Política `rich`

Inclui campos adicionais (banners `server`, `name` em IoT; passivo completo em mobile) para **análise forense ou estudos** onde a volatilidade é aceitável.

---

## 5. Experimentos realizados (laboratório)

Os ensaios descritos foram executados em ambiente **VirtualBox / Linux**, interface `enp0s3`, capturas ~60 s, salvo indicação contrária.

### 5.1 Smart TV TCL (192.168.59.106)

- UPnP estável; **p0f** e **tshark** coerentes (MSS 1460, TTL 64, janela 65535).
- Após ordenar SSDP e remover `server` do `stable`, **cinco execuções consecutivas** produziram o **mesmo** `CANON_STRING` e SHA-256.

### 5.2 Smart TV Xiaomi (192.168.59.105)

- **Problema:** `CANON_STRING` alternava com o campo **`nmap.server`** (ex.: string Chromecast vs NRDP) com **`p0f`/`pcap_syn` idênticos**.
- **Causa:** múltiplos serviços no mesmo IP; o script UPnP regista banners diferentes entre scans.
- **Mitigação:** exclusão de **`server`** do hash `stable`; ordenação de `LOCATION`.

### 5.3 Smartphone Samsung (192.168.59.100)

- Sem fabricante/modelo UPnP → **`host_kind = mobile`**.
- **Problema inicial:** falha de canonização quando não havia TCP/p0f útil; mitigado com **TTL** a partir de qualquer pacote `ip.src == alvo`.
- **Problema seguinte:** hash instável por **`tls_sni`** (de `play.samsungcloud.com` apenas para longa lista de domínios Google/Instagram/etc. entre corridas).
- **Mitigação:** SNI, User-Agent e mDNS **fora** do `stable` para mobile; permanecem em **`rich`**.

### 5.4 Tempos de execução

- Nmap UPnP pode dominar o tempo quando o alvo não responde depressa (observados ~7–8 min em alguns ensaios vs ~1,5–2,5 min noutros).
- O modo mobile acrescenta **tshark passivo** e **nmap móvel** (limite de tempo configurado no comando).

---

## 6. Evolução até à solução final (resumo cronológico)

1. **Hash instável** → análise mostrou `window_size`/ordem SSDP/banners `server`.
2. **Logs por fase** → `fingerprint_pipeline.log` com STAGEs (nmap, PCAP, p0f, tshark, canon).
3. **Dois modos** → IP único vs varredura SSDP.
4. **Perfil manual smarttv/smartphone** → **abandonado** em favor de **`host_kind` automático** e regras de canónico unificadas.
5. **Mobile sem UPnP** → passivo PCAP + nmap em portas típicas + fallbacks TCP/IP.
6. **Estabilidade do hash mobile** → retirada de SNI/UA/mDNS do `stable`.

---

## 7. Artefactos e reproducibilidade

Cada corrida guarda, entre outros:

- `fingerprint.json` (bundle bruto, inclui `meta.host_kind`),
- `features_canon.json` / `features_canon.txt`,
- `fingerprint_sha256.txt`,
- PCAP, saída p0f, logs.

O hash pode ser **recomputado** com `fingerprint_hash.py` sobre o mesmo bundle após alterações de código (com cautela a versões da canonização).

---

## 8. Limitações

- **Unicidade:** TTL só, ou poucos campos, aumentam colisões entre modelos.
- **Ética e legalidade:** sondagem ativa e captura exigem **autorização** no ambiente alvo.
- **Telemóveis:** fingerprint `stable` depende de **DHCP** (ou NBNS) visível no PCAP e da assinatura TCP; ausência total de tráfego do alvo na janela mantém o problema difícil.
- **Routers / APs sem UPnP** caem em `mobile`; o pipeline tenta extrair o máximo, mas não garante identidade forte.

---

## 9. Próximos passos sugeridos

1. **JA3 / JA4** ou fingerprint de **ClientHello TLS** agregado (menos dependente de SNI individual) para modo `rich` ou sub-política opcional.
2. **Reduzir latência** do Nmap UPnP (timeout agressivo, cache por IP).
3. **Validação em escala:** matriz de dispositivos (fabricantes/OS) com métrica **taxa de colisão** vs **reprodutibilidade** entre $N$ corridas.
4. **IPv6-first:** alargar filtros e meta quando o alvo for só acessível em IPv6.
5. **Integração com inventário:** exportar CSV/JSON Lines com `{ip, host_kind, sha256, timestamp}` para SIEM.
6. **Revisão ética e dados pessoais:** DNI em DHCP hostname, UA; política de retenção de PCAP em estudos com humanos.

---

## 10. Conclusão

A solução final combina **colheita rica** (JSON) com **canonização conservadora** (`stable`) que ignora campos sabidamente voláteis, diferenciando **IoT com UPnP** de **hosts móveis** sem assunções manuais do operador. Os experimentos em TV e smartphone **validaram** tanto a estabilidade em IoT corrigido como a **causa raiz** da instabilidade em mobile (SNI). Os próximos passos focam **métricas formais**, **fingerprints TLS mais estruturados** e **eficiência operacional**.

---

## Referências de implementação (repositório)

- `bundle_snapshot.py` — orquestração, SSDP ordenado, mobile passivo, `nmap` móvel, `infer_host_kind`.
- `canonicalize_features.py` — `build_canon`, políticas `stable`/`rich`, ramos `iot`/`mobile`.
- `fingerprint_hash.py` — hash offline.
- `estudo-variaveis-imutaveis-smarttv.md` — notas sobre campos estáveis em TVs (evoluídas para política unificada).

---

*Documento gerado para apoio à escrita de artigo em formato compatível com comunicações do tipo SBSeg; adaptar seções, autores, afiliações e bibliografia conforme normas oficiais do evento-alvo.*
