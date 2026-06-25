# Relatório técnico de refatoração — `sbrc26_fingerprint`

## 1. Escopo da refatoração

A refatoração foi conduzida com foco nos arquivos principais do pipeline:

- `canonicalize_features.py`
- `fingerprint_hash.py`
- `iot_id_fingerprint.py`
- `iot_net_scanner.py`

O objetivo foi melhorar a estrutura técnica do projeto sem alterar funcionalidades, regras de negócio, entradas, saídas, formato dos arquivos gerados, parâmetros de CLI, política de canonização ou resultado do hash.

A estratégia adotada foi preservar os quatro scripts públicos originais como pontos de entrada compatíveis e mover a implementação real para um pacote interno chamado `iot_fingerprint/`.

---

## 2. Arquitetura original

A estrutura original era funcional e direta, porém concentrava muitas responsabilidades em poucos arquivos:

```text
sbrc26_fingerprint/
├── canonicalize_features.py
├── fingerprint_hash.py
├── iot_id_fingerprint.py
├── iot_net_scanner.py
├── fingerprint_subnet.sh
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── docs/
├── testes/
└── README.md
```

### Responsabilidades observadas

| Arquivo | Responsabilidades principais na versão original |
|---|---|
| `canonicalize_features.py` | Normalização, seleção de features canônicas, política `stable/rich`, serialização determinística e CLI. |
| `fingerprint_hash.py` | Leitura de bundle, chamada da canonização, cálculo de hash, impressão e gravação de arquivos. |
| `iot_id_fingerprint.py` | Orquestração completa do pipeline, execução de comandos externos, logging, Nmap/SSDP/UPnP, dumpcap, nping, p0f, tshark, extrações mobile, geração de bundle, canonização, hash, cleanup e CLI. |
| `iot_net_scanner.py` | Descoberta de dispositivos por SSDP/Nmap/ARP, parsing de XML UPnP e apresentação do inventário. |

---

## 3. Problemas identificados

### 3.1. `iot_id_fingerprint.py` como módulo monolítico

O arquivo possuía mais de mil linhas e acumulava responsabilidades muito diferentes: subprocessos, parsing, rede, PCAP, p0f, tshark, regra de classificação IoT/mobile, montagem de bundle, hash e CLI.

**Impacto:** qualquer manutenção no pipeline exigia navegar por um arquivo grande, com alto custo cognitivo e maior risco de alterar trechos não relacionados.

**Refatoração aplicada:** o pipeline foi dividido em módulos específicos dentro de `iot_fingerprint/`, mantendo `iot_id_fingerprint.py` apenas como wrapper compatível.

---

### 3.2. Duplicação entre `iot_id_fingerprint.py` e `iot_net_scanner.py`

Funções de SSDP, Nmap UPnP, parsing de XML e coleta de identidade apareciam em mais de um lugar, com pequenas diferenças.

**Impacto:** correções futuras em descoberta UPnP/SSDP poderiam ser aplicadas em um arquivo e esquecidas no outro, causando divergência de comportamento.

**Refatoração aplicada:** foi criado o módulo `iot_fingerprint/upnp.py`, centralizando:

- `fetch_upnp_description`
- `nmap_upnp_scan`
- `ssdp_probe`
- ordenação determinística de URLs SSDP
- coleta de identidade UPnP usada pelo pipeline
- conversão de resultados SSDP para JSON
- leitura da tabela ARP

---

### 3.3. Cálculo de hash duplicado

O hash SHA-256 era calculado diretamente em `iot_id_fingerprint.py`, enquanto `fingerprint_hash.py` também possuía uma função própria para hash.

**Impacto:** a regra central do fingerprint ficava espalhada, abrindo espaço para divergência futura caso uma parte fosse alterada e a outra não.

**Refatoração aplicada:** o cálculo de hash foi centralizado em `iot_fingerprint/hashing.py`. O pipeline agora chama a mesma função usada pelo CLI offline.

---

### 3.4. Mistura de CLI com lógica de domínio

Os arquivos principais continham parsing de argumentos, lógica de execução e funções reutilizáveis no mesmo nível.

**Impacto:** isso dificultava testes, reutilização e leitura do fluxo real.

**Refatoração aplicada:** cada script público permanece executável, mas delega para módulos internos. Assim, os comandos antigos continuam válidos, enquanto a implementação fica organizada.

---

### 3.5. Baixa separação entre parsing e orquestração

Parsing de p0f, extração tshark e extrações mobile estavam dentro do pipeline principal.

**Impacto:** cada mudança em uma técnica de extração exigia alterar o arquivo principal.

**Refatoração aplicada:** foram criados módulos dedicados:

- `iot_fingerprint/p0f.py`
- `iot_fingerprint/tshark_features.py`
- `iot_fingerprint/mobile.py`

---

### 3.6. Responsabilidades utilitárias espalhadas

Funções genéricas como execução de comandos, escrita de JSON/texto, logging, formatação de tempo e conversão de caminho Windows/WSL ficavam misturadas ao pipeline.

**Impacto:** aumentava o ruído do arquivo principal e reduzia a clareza do fluxo de alto nível.

**Refatoração aplicada:** essas funções foram consolidadas em `iot_fingerprint/runtime.py`.

---

## 4. Nova arquitetura

A nova estrutura mantém os arquivos públicos originais, mas introduz uma camada interna modular:

```text
sbrc26_fingerprint/
├── canonicalize_features.py      # wrapper compatível
├── fingerprint_hash.py           # wrapper compatível
├── iot_id_fingerprint.py         # wrapper compatível
├── iot_net_scanner.py            # wrapper compatível
├── iot_fingerprint/
│   ├── __init__.py
│   ├── canonical.py
│   ├── hashing.py
│   ├── mobile.py
│   ├── net_scanner.py
│   ├── p0f.py
│   ├── pipeline.py
│   ├── runtime.py
│   ├── tshark_features.py
│   └── upnp.py
├── fingerprint_subnet.sh
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── docs/
├── testes/
├── RELATORIO_REFATORACAO.md
└── README.md
```

---

## 5. Responsabilidades na nova estrutura

| Módulo | Responsabilidade |
|---|---|
| `iot_fingerprint/canonical.py` | Canonização, normalização, política `stable/rich` e serialização determinística. |
| `iot_fingerprint/hashing.py` | Cálculo de hash e fluxo offline de hash a partir de bundle. |
| `iot_fingerprint/pipeline.py` | Orquestração do pipeline completo de fingerprint. |
| `iot_fingerprint/upnp.py` | SSDP, UPnP, Nmap UPnP, ARP e identidade de dispositivo. |
| `iot_fingerprint/p0f.py` | Parsing do p0f e extração dos conjuntos estáveis. |
| `iot_fingerprint/tshark_features.py` | Extração de features TCP SYN/SYN+ACK e fallback por TTL. |
| `iot_fingerprint/mobile.py` | Evidências adicionais para hosts classificados como mobile. |
| `iot_fingerprint/runtime.py` | Subprocessos, logging, escrita de arquivos, formatação e helpers de ambiente. |
| `iot_fingerprint/net_scanner.py` | Fluxo de inventário de rede. |

---

## 6. Alterações relevantes realizadas

### 6.1. Scripts públicos preservados

Os arquivos abaixo continuam existindo e continuam sendo os pontos de entrada esperados:

- `python canonicalize_features.py ...`
- `python fingerprint_hash.py ...`
- `python iot_id_fingerprint.py ...`
- `python iot_net_scanner.py ...`

Eles agora funcionam como wrappers de compatibilidade, importando a implementação dos módulos internos.

**Benefício:** preserva a interface operacional e reduz drasticamente a complexidade dos arquivos de entrada.

---

### 6.2. Canonização reorganizada

A lógica de `build_canon` foi dividida em funções menores:

- normalização de política;
- resolução de `host_kind`;
- construção do bloco Nmap/UPnP para IoT;
- seleção de assinatura p0f;
- construção de `pcap_syn` conforme `host_kind`;
- poda recursiva de valores vazios.

**Benefício:** a regra de fingerprint fica mais legível, mais fácil de auditar e menos propensa a alterações acidentais.

---

### 6.3. Pipeline dividido em estágios explícitos

O pipeline passou a evidenciar melhor suas etapas:

1. Coleta UPnP/Nmap;
2. Classificação `iot`/`mobile`;
3. Captura com `dumpcap`;
4. Probe com `nping`;
5. Parsing p0f;
6. Extração tshark;
7. Evidências mobile, quando aplicável;
8. Montagem do bundle bruto;
9. Canonização e hash;
10. Resumo e timing.

**Benefício:** o fluxo de execução agora é mais claro e as etapas podem ser lidas de forma quase linear em `pipeline.py`.

---

### 6.4. UPnP/SSDP compartilhado

A lógica comum de descoberta foi movida para `upnp.py`, eliminando duplicação entre scanner e pipeline.

**Benefício:** futuras correções na coleta SSDP/UPnP passam a ser feitas em um único lugar.

---

### 6.5. Hash centralizado

O hash usado pelo pipeline e pelo modo offline agora passa por `compute_hash_from_canon_string`.

**Benefício:** a regra `hash = H(CANON_STRING UTF-8)` fica única e explícita.

---

### 6.6. Compatibilidade com imports antigos

Além de manter os CLIs, `iot_id_fingerprint.py` continua reexportando funções importantes usadas anteriormente, como:

- `parse_p0f_raw`
- `extract_p0f_sets`
- `extract_tcp_syn_features_tshark`
- `infer_host_kind`
- `run_single_fingerprint`
- `ssdp_probe`
- `collect_upnp_identity`

**Benefício:** reduz o risco de quebra em notebooks, scripts auxiliares ou usos manuais que importavam diretamente do arquivo antigo.

---

## 7. Comparação antes/depois

### Antes

```text
canonicalize_features.py   -> lógica + CLI
fingerprint_hash.py        -> lógica + CLI
iot_id_fingerprint.py      -> pipeline inteiro + parsers + subprocessos + rede + CLI
iot_net_scanner.py         -> scanner + duplicação UPnP/SSDP + CLI
```

### Depois

```text
canonicalize_features.py   -> wrapper compatível
fingerprint_hash.py        -> wrapper compatível
iot_id_fingerprint.py      -> wrapper compatível
iot_net_scanner.py         -> wrapper compatível

iot_fingerprint/canonical.py        -> canonização
iot_fingerprint/hashing.py          -> hash
iot_fingerprint/pipeline.py         -> orquestração
iot_fingerprint/upnp.py             -> descoberta e identidade
iot_fingerprint/p0f.py              -> p0f
iot_fingerprint/tshark_features.py  -> tshark
iot_fingerprint/mobile.py           -> evidências mobile
iot_fingerprint/runtime.py          -> utilitários técnicos
iot_fingerprint/net_scanner.py      -> inventário de rede
```

---

## 8. Validação executada

Foram executadas validações de sintaxe e regressão funcional sobre os bundles existentes em `testes/**/fingerprint.json`.

### 8.1. Validação sintática

Todos os arquivos Python da raiz e do pacote `iot_fingerprint/` foram parseados com sucesso.

Resultado:

```text
syntax_ok 14
```

### 8.2. Regressão de canonização

A nova implementação de canonização foi comparada contra a implementação original em todos os `fingerprint.json` encontrados no diretório `testes/`.

Foram testadas as políticas:

- `stable`
- `rich`
- política inválida, preservando fallback para `stable`

Resultado:

```text
canonical_regression_ok 22 fixtures
```

### 8.3. Comparação de CLI para canonização e hash

Foi comparada a saída textual dos comandos:

```bash
python canonicalize_features.py <fingerprint.json>
python fingerprint_hash.py <fingerprint.json>
```

A saída da versão refatorada foi idêntica à saída da versão original no caso validado.

### 8.4. Regressão de parsing p0f

A nova implementação de `parse_p0f_raw` e `extract_p0f_sets` foi comparada contra a implementação original usando os arquivos `p0f_*.raw.txt` disponíveis em `testes/`.

Resultado:

```text
raw files 22 fail []
```

---

## 9. Garantias preservadas

Foram preservados:

- nomes dos scripts públicos;
- parâmetros de CLI existentes;
- nomes dos arquivos de saída principais;
- formato do `fingerprint.json`;
- formato do `features_canon.json`;
- formato do `features_canon.txt`;
- formato do `fingerprint_sha256.txt`;
- política `stable`/`rich`;
- regra de classificação `iot`/`mobile`;
- regra de hash sobre o `CANON_STRING` em UTF-8;
- comportamento de fallback quando não há p0f raw signature;
- comportamento de coleta mobile fora do hash canônico;
- compatibilidade dos comandos documentados no README.

---

## 10. Ganhos de legibilidade e manutenção

### Ganhos principais

- Redução do acoplamento entre pipeline, rede, parsing e hash.
- Redução da duplicação entre scanner e pipeline.
- Responsabilidades mais claras por arquivo.
- Fluxo principal mais fácil de acompanhar.
- Canonização mais auditável.
- Menor risco de divergência entre hash online e hash offline.
- Maior facilidade para escrever testes unitários futuros.
- Manutenção do contrato público dos scripts antigos.

---

## 11. Riscos identificados

Mesmo preservando comportamento, há alguns riscos naturais em uma refatoração estrutural:

1. **Dependência de ferramentas externas:** `nmap`, `nping`, `dumpcap`, `p0f` e `tshark` não foram executados em ambiente real nesta validação, pois isso depende de interface de rede, permissões e dispositivos locais.
2. **Rede e SSDP são não determinísticos:** respostas multicast podem chegar em ordens diferentes ou não chegar, dependendo da LAN.
3. **Compatibilidade com imports não documentados:** foram preservadas as funções mais relevantes nos wrappers, mas algum uso externo muito específico de funções internas antigas poderia exigir ajuste.
4. **Mudança estrutural:** embora os comandos sejam os mesmos, agora existe um pacote interno; ambientes que copiem apenas um script isolado precisarão copiar também a pasta `iot_fingerprint/`.

---

## 12. Melhorias futuras recomendadas, não executadas nesta refatoração

Estas melhorias são recomendadas para etapas futuras, mas não foram aplicadas agora para evitar alteração funcional:

1. Criar uma suíte formal de testes automatizados com `pytest` usando os bundles em `testes/` como fixtures de regressão.
2. Adicionar mocks para `subprocess`, `requests` e sockets SSDP, permitindo testar pipeline sem rede real.
3. Criar contratos explícitos para o schema de `fingerprint.json`, `features_canon.json` e `pcap_syn`.
4. Substituir gradualmente `dict` soltos por `dataclasses` ou modelos tipados apenas onde isso reduzir ambiguidade.
5. Padronizar idioma dos comentários e mensagens, hoje misturando português e inglês.
6. Adicionar checagem de presença de binários externos antes da execução do pipeline.
7. Melhorar tratamento de erros de subprocessos com objetos de resultado estruturados.
8. Separar testes/dados históricos de exemplos/documentação para reduzir peso do pacote principal.
9. Atualizar os documentos técnicos em `testes/` caso passem a descrever a arquitetura interna do código.
10. Avaliar empacotamento com `pyproject.toml` e entry points, mantendo os scripts atuais como compatibilidade.

---

## 13. Conclusão

A refatoração transforma o projeto de um conjunto de scripts funcionais, porém concentrados, em uma solução mais modular, coesa e profissional. A interface pública foi preservada, enquanto a implementação interna passou a ter responsabilidades bem definidas.

O ganho mais importante está na manutenibilidade: agora é possível evoluir canonização, hash, parsing p0f, extração tshark, descoberta UPnP e pipeline principal de forma independente, com menor risco de regressão e maior clareza para novos desenvolvedores.
