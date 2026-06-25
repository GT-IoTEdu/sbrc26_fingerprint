"""
iotid: pacote interno do pipeline de fingerprinting determinístico.

Organiza por responsabilidade as funções antes concentradas no script
monolítico `iot_id_fingerprint.py`:

- proc      : execução de subprocessos e decodificação de bytes
- artifacts : escrita de ficheiros, formatação de tempo, logging, caminhos WSL
- upnp      : descoberta UPnP/SSDP partilhada (scanner e pipeline)
- p0f       : parsing do output cru do p0f
- tshark    : extração de features TCP e pistas passivas via tshark
- discovery : identidade UPnP/nmap e classificação de host (iot/mobile)
- pipeline  : orquestração de uma rodada completa de fingerprint

Os scripts de topo (`iot_id_fingerprint.py`, `iot_net_scanner.py`,
`fingerprint_hash.py`, `canonicalize_features.py`) permanecem como pontos de
entrada executáveis e apenas importam destes módulos.
"""

from __future__ import annotations
