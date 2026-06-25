#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compatibility wrapper for the network inventory scanner."""

from iot_fingerprint.net_scanner import main, nmap_upnp_scan  # noqa: F401
from iot_fingerprint.upnp import SSDP_TIMEOUT, fetch_upnp_description, get_arp_table, ssdp_probe  # noqa: F401

if __name__ == "__main__":
    main()
