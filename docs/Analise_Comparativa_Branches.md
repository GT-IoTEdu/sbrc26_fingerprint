# Análise comparativa das branches (segurança, superfície de ataque e enxutez)

Repositório: GT-IoTEdu/sbrc26_fingerprint. Objetivo da nova versão: minimizar dependências e código próprio (reduzir superfície de ataque externa e própria), com eficiência computacional e a maior segurança possível. Os dados abaixo foram extraídos diretamente do código de cada branch (`git grep`, contagem de linhas e inspeção de pontos sensíveis), não apenas dos relatórios em PDF.

| Critério | main | gpt_anna | claude_anna | claude_diego |
|---|---|---|---|---|
| LOC Python de produção (medido, testes excluídos) | 1859 | 1862 | 1953 | **1012** |
| Arquivos `.py` de produção | 4 | 14 | 12 | 5 |
| Redução de código próprio vs. main | referência | +0,2% | +5,1% | **-45,6%** |
| Dependências Python declaradas | `requests` | `requests` | `requests` | `requests` + `defusedxml` |
| Superfície de supply chain (nº de pacotes) | **1** | **1** | **1** | 2 (a 2ª é mínima e defensiva) |
| Parsing de XML UPnP não confiável | `ElementTree` stdlib (vulnerável) | `ElementTree` stdlib (vulnerável) | `ElementTree` stdlib (vulnerável) | **`defusedxml`** (protege contra XXE/billion-laughs) |
| `shell=True` / `eval` / `exec` / `os.system` | nenhum | nenhum | nenhum | nenhum |
| Subprocess com argumentos em lista (sem injeção) | sim | sim | sim | sim |
| Timeout em requisições HTTP | sim | sim | sim | sim |
| Timeout no executor genérico de subprocess | não | não | não | **sim** |
| Validação de entrada do usuário | não | não | não | parcial (`--probe-ports`) |
| Superfície operacional (nmap, nping, dumpcap, tshark, p0f, privilégios) | alta | alta | alta | alta |
| Organização do código | scripts na raiz | pacote `iot_fingerprint/` (mais encapsulado) | pacote parcial `iotid/` | scripts na raiz + `upnp_discovery.py` (mais plano) |
| Desempenho do pipeline (~2m39s, dominado por ferramentas externas) | equivalente | equivalente | equivalente | equivalente (permite reduzir portas via `--probe-ports`) |
| Aderência ao objetivo (menos código + mais seguro) | baixa | média (encapsulamento, sem XML defensivo) | baixa | **alta** |

## Veredito

Para o objetivo declarado, **`claude_diego` é a melhor base**: corta cerca de 46% do código próprio (a maior redução de superfície própria) e é a única que trata o XML não confiável de UPnP com `defusedxml`, fechando uma vulnerabilidade real de XXE/expansão de entidades presente nas demais. O custo é apenas uma dependência adicional, `defusedxml`, que é pequena, em Python puro e de finalidade estritamente defensiva: a troca reduz a superfície de ataque líquida.

O ganho de eficiência é marginal em todas as branches, pois o tempo é dominado por `nmap`, `dumpcap` e `nping`. A superfície operacional (uso de ferramentas externas com privilégios elevados) é idêntica e continua sendo o maior risco prático, independente da branch.

Endurecimentos recomendados sobre `claude_diego` antes de promover a versão final:

1. Tornar `defusedxml` obrigatório: remover o fallback silencioso para `xml.etree`, que faz o parser voltar a ficar vulnerável se o pacote não estiver instalado.
2. Validar o IP-alvo e a interface com `ipaddress`/lista de interfaces antes de passá-los às ferramentas externas (evita injeção de argumento, por exemplo valores iniciados por `-`).
3. Aplicar `timeout` a todas as chamadas de subprocess, padronizando o que já existe no executor genérico.

> Metodologia: LOC por `git show <branch>:<arquivo> | wc -l` sobre todos os `.py` de produção (excluídos `testes/`, `test_*` e caches). Verificações de segurança por `git grep` de padrões de risco (`shell=True`, `eval`, `exec`, `os.system`, `pickle`, `yaml.load`, `verify=False`), do parser XML e da construção de comandos subprocess, nas branches `origin/main`, `origin/gpt_anna`, `origin/claude_anna` e `origin/claude_diego`.
