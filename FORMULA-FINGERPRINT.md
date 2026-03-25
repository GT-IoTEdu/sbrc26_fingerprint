# Fórmula do fingerprint (SHA-256)

## 1. Fórmula principal

```
CANON_OBJ = build_canon(fingerprint.json, policy)
CANON_STRING = dumps_canon(CANON_OBJ)

FINGERPRINT_HASH = SHA-256( bytes_utf8(CANON_STRING) )
```

- **`SHA-256`**: função `hashlib.sha256` sobre a cadeia **exacta** `CANON_STRING` codificada em **UTF-8**.
- **`policy`**: `--canon_policy` do `bundle_snapshot.py` ou `--policy` no `fingerprint_hash.py`: **`stable`** (padrão) ou **`rich`**.

Implementação: `canonicalize_features.build_canon` + `dumps_canon`; hash em `bundle_snapshot.py` / `fingerprint_hash.py`.

---

## 2. Como é construído o `CANON_STRING`

`dumps_canon` faz:

```python
json.dumps(CANON_OBJ, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
```

Ou seja: JSON **minificado** (sem espaços), **chaves ordenadas alfabeticamente** em todos os níveis, Unicode preservado.

Antes disso, `prune_none` remove chaves com valor `None`, dicionários vazios e listas vazias do `CANON_OBJ`.

---

## 3. Classificação `host_kind` (define quais variáveis entram)

| Valor    | Critério |
|----------|----------|
| **`iot`** | Em `bundle["meta"]["host_kind"]` **ou** existe `nmap.manufacturer` **ou** `nmap.model_name` normalizado não vazio (após inferência se `meta` não vier). |
| **`mobile`** | Caso contrário (sem fabricante/modelo UPnP a partir da colheita actual). |

O bundle bruto (`fingerprint.json`) pode ter muitas chaves (`mobile_passive`, `mobile_nmap`, `paths`, etc.); **só as descritas abaixo** entram no `CANON_OBJ`.

---

## 4. Variáveis envolvidas no `CANON_OBJ` (por tipo de host)

### 4.1 IoT (`host_kind == "iot"`)

| Secção   | Campos no canónico | Origem no bundle | `stable` | `rich` |
|----------|-------------------|------------------|----------|--------|
| **`nmap`** | `manufacturer` | `bundle["nmap"]["manufacturer"]` | ✓ | ✓ |
| **`nmap`** | `model_name` | `bundle["nmap"]["model_name"]` | ✓ | ✓ |
| **`nmap`** | `server` | `bundle["nmap"]["server"]` | ✗ | ✓ |
| **`nmap`** | `name` | `bundle["nmap"]["name"]` | ✗ | ✓ |
| **`p0f`** | `extracted.server_synack_raw_sig_set` | `bundle["p0f"]["extracted"]["server_synack_raw_sig_set"]` (lista normalizada e ordenada) | se existir, **prioridade** sobre cliente |
| **`p0f`** | `extracted.client_syn_raw_sig_set` | idem `client_syn_raw_sig_set` | ✓ se **não** houver server SYN+ACK |
| **`pcap_syn`** | `ttl`, `window_size`, `mss`, `ws` | `bundle["pcap_syn"][...]` (tshark) | ✓ | ✓ |

Regra p0f IoT: usa **SYN+ACK** se houver conjunto não vazio; senão usa **SYN cliente**. Nunca ambos no mesmo objeto canónico nessa ramificação.

---

### 4.2 Mobile / não-IoT (`host_kind == "mobile"`)

| Secção   | Campos no canónico | Origem no bundle |
|----------|-------------------|------------------|
| **`p0f`** | `extracted.client_syn_raw_sig_set` **apenas** | `bundle["p0f"]["extracted"]["client_syn_raw_sig_set"]` — **só** se a lista for não vazia após `stable_list` |
| **`pcap_syn`** | `mss`, `sack_perm`, `ts_present`, `ttl`, `window_size`, `ws` | `bundle["pcap_syn"][...]` — omitem-se chaves cujo valor vire `None` após `stable_str` / `prune_none` |

**Não entram** no hash para `mobile`: `nmap`, `mobile_passive`, `mobile_nmap`, `meta`, `paths`, `p0f` com `server_synack`, etc.

---

## 5. Normalização aplicada às variáveis

- **`stable_str(x)`**: converte para string normalizada (trim, espaços colapsados); `bool` → `"0"`/`"1"`; `int`/`float` → texto. `None` ou vazio → removido pelo `prune_none`.
- **`stable_list(lista)`**: cada elemento string → `norm_ws`; remove vazios; **conjunto único**; **ordenado** alfabeticamente.
- **`pcap_syn`**: só entra se **`bundle["pcap_syn"]` existir** e **não** tiver chave `"error"` (captura/tshark válidos para esse bloco).

---

## 6. Resumo em notação matemática

Seja \(B\) o bundle JSON, \(P \in \{\text{stable}, \text{rich}\}\) a política, \(k = \textit{host\_kind}(B) \in \{\text{iot}, \text{mobile}\}\).

\[
\text{CANON\_OBJ} = \mathrm{pruneNone}\bigl(\mathrm{merge}(\mathrm{Nmap}_k(B,P), \mathrm{P0f}_k(B), \mathrm{Pcap}_k(B))\bigr)
\]

\[
\text{CANON\_STRING} = \mathrm{JSON}_{\text{min},\ \text{sort\_keys}}(\text{CANON\_OBJ})
\]

\[
\text{Fingerprint} = \mathrm{SHA256}(\text{UTF8}(\text{CANON\_STRING}))
\]

---

## 7. Onde está cada passo no código

| Passo | Ficheiro / função |
|-------|-------------------|
| `host_kind` | `canonicalize_features._resolve_host_kind` |
| `CANON_OBJ` | `canonicalize_features.build_canon` |
| `CANON_STRING` | `canonicalize_features.dumps_canon` |
| Hash | `hashlib.sha256(canon_str.encode("utf-8")).hexdigest()` em `bundle_snapshot.py` ou `fingerprint_hash.compute_hash_from_canon_string` |

---

## 8. Onde ler o resultado de cada corrida

- Texto exacto do input do SHA-256: `runs/.../features_canon.txt` (conteúdo = `CANON_STRING`).
- Objeto intermédio: `runs/.../features_canon.json`.
- Hash: `runs/.../fingerprint_sha256.txt` (hex minúsculo, uma linha).
