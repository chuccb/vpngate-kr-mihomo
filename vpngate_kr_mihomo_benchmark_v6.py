#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import io
import ipaddress
import json
import re
import statistics
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlparse

import requests
import yaml

SCRIPT_VERSION = "v7.1"
API_URL = "https://www.vpngate.net/api/iphone/"
HTML_URL = "https://www.vpngate.net/en/"
OPENVPN_DOWNLOAD_URL = "https://www.vpngate.net/common/openvpn_download.aspx"
DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_EXPECTED_STATUS = "204"
MAX_CSV_PING_MS = 40
MAX_PROXIES = 10
MIN_PROXIES = 3
DEFAULT_MIN_SPEED = 0
PUBLIC_SUBSCRIPTION = True
USER_AGENT = "Mozilla/5.0 (compatible; VPNGate-KR-Mihomo/7.1)"

ALLOWED_CIPHERS = {
    "AES-128-GCM",
    "AES-256-GCM",
    "AES-128-CBC",
    "AES-256-CBC",
    "CHACHA20-POLY1305",
    "AES-CBC",
}
ALLOWED_AUTHS = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
ALLOWED_COMP_LZO = {"yes", "no", "adaptive"}
PEM_FIELDS = ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2")


class LiteralString(str):
    pass


def _literal_representer(dumper: yaml.SafeDumper, data: LiteralString):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.SafeDumper.add_representer(LiteralString, _literal_representer)


@dataclass(frozen=True)
class UDPEndpoint:
    ip: str
    fqdn: str
    sid: str
    hid: str
    port: int

    @property
    def url(self) -> str:
        filename = f"vpngate_{self.ip}_udp_{self.port}.ovpn"
        return (
            f"{OPENVPN_DOWNLOAD_URL}"
            f"?sid={quote(self.sid, safe='')}"
            f"&udp=1"
            f"&host={quote(self.ip, safe='')}"
            f"&port={self.port}"
            f"&hid={quote(self.hid, safe='')}"
            f"&/{quote(filename, safe='')}"
        )

