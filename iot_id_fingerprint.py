#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compatibility wrapper for the IoT-ID fingerprint pipeline."""

from iot_fingerprint.mobile import extract_mobile_passive_tshark, nmap_mobile_scan  # noqa: F401
from iot_fingerprint.p0f import (  # noqa: F401
    P0F_BLOCK_RE,
    extract_p0f_sets,
    p0f_addr_matches_field as _p0f_addr_matches_field,
    parse_p0f_raw,
)
from iot_fingerprint.pipeline import (  # noqa: F401
    PROBE_PORTS,
    build_arg_parser,
    infer_host_kind,
    main,
    run_single_fingerprint,
)
from iot_fingerprint.runtime import (  # noqa: F401
    decode_bytes,
    fmt_secs,
    run,
    run_bytes,
    setup_fingerprint_logging,
    win_to_wsl_path,
    write_json,
    write_text,
)
from iot_fingerprint.tshark_features import (  # noqa: F401
    extract_tcp_syn_features_tshark,
    norm_passive_token as _norm_passive_token,
)
from iot_fingerprint.upnp import (  # noqa: F401
    SSDP_TIMEOUT,
    collect_upnp_identity,
    nmap_upnp_scan as _shared_nmap_upnp_scan,
    sorted_ssdp_locations as _sorted_ssdp_locations,
    ssdp_probe,
    ssdp_results_to_jsonable,
)
from iot_fingerprint.upnp import fetch_upnp_description as _shared_fetch_upnp_description


def fetch_upnp_description(url: str):
    """Legacy iot_id_fingerprint view: UPnP XML identity without UDN."""
    data = _shared_fetch_upnp_description(url)
    if not data:
        return None
    return {
        "friendlyName": data.get("friendlyName"),
        "manufacturer": data.get("manufacturer"),
        "modelName": data.get("modelName"),
    }


def nmap_upnp_scan(target: str):
    """Legacy iot_id_fingerprint behavior: sudo nmap scan for one target."""
    return _shared_nmap_upnp_scan(target=target, sudo=True)


if __name__ == "__main__":
    main()
