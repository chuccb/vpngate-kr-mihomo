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
DEFAULT_TEST_URL = "https://www.naver.com/"
DEFAULT_EXPECTED_STATUS = "200"
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


@dataclass(frozen=True)
class Candidate:
    hostname: str
    ip: str
    ping: int
    speed_bps: int | None
    score: int | None
    country_long: str
    country_short: str
    ovpn: str
    udp_port: int


class _VPNGateHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[dict[str, Any]]] = []
        self._row: list[dict[str, Any]] | None = None
        self._cell: dict[str, Any] | None = None
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "tr":
            self._row = []
            self._cell = None
            return
        if self._row is None:
            return
        if tag == "td":
            self._cell = {"text": [], "hrefs": []}
            self._row.append(self._cell)
        elif tag == "a" and self._cell is not None:
            href = dict(attrs).get("href")
            if href:
                self._cell["hrefs"].append(href)
        elif tag == "script":
            self._in_script = True
        elif tag == "style":
            self._in_style = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "tr":
            if self._row is not None:
                self.rows.append(self._row)
            self._row = None
            self._cell = None
        elif tag == "td":
            self._cell = None
        elif tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._cell is not None and not self._in_script and not self._in_style:
            self._cell["text"].append(data)


def _cell_text(cell: dict[str, Any]) -> str:
    return re.sub(r"\s+", " ", " ".join(cell["text"])).strip()


def _request(
    session: requests.Session,
    url: str,
    *,
    timeout: tuple[float, float] = (10, 30),
    attempts: int = 3,
    accept: str | None = None,
) -> requests.Response:
    last: Exception | None = None
    headers = {"Accept": accept} if accept else None
    for attempt in range(1, attempts + 1):
        try:
            response = session.get(url, timeout=timeout, headers=headers)
            response.raise_for_status()
            return response
        except (requests.RequestException, OSError) as exc:
            last = exc
            if attempt < attempts:
                time.sleep(min(2.0 * attempt, 5.0))
    raise RuntimeError(f"request failed after {attempts} attempts: {url}") from last


def _int_field(value: str | None, *, default: int | None = None) -> int | None:
    value = (value or "").strip().replace(",", "")
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_official_csv(text: str) -> list[dict[str, str]]:
    lines = text.lstrip("\ufeff").splitlines()
    header_index = next(
        (index for index, line in enumerate(lines) if line.lstrip().startswith("#HostName,")),
        None,
    )
    if header_index is None:
        raise RuntimeError("VPN Gate CSV header not found")

    header = lines[header_index].lstrip()
    if header.startswith("#"):
        header = header[1:]
    reader = csv.DictReader(io.StringIO("\n".join([header, *lines[header_index + 1 :]])))
    if not reader.fieldnames:
        raise RuntimeError("VPN Gate CSV has no fields")

    rows: list[dict[str, str]] = []
    for raw_row in reader:
        row = {
            str(key).strip(): (value or "").strip()
            for key, value in raw_row.items()
            if key is not None
        }
        if not row.get("HostName") and not row.get("IP"):
            continue
        rows.append(row)
    if not rows:
        raise RuntimeError("VPN Gate CSV contains no server rows")
    return rows


def parse_official_udp_endpoints(html: str) -> dict[str, list[UDPEndpoint]]:
    parser = _VPNGateHTMLParser()
    parser.feed(html)
    endpoints: dict[str, list[UDPEndpoint]] = {}

    for row in parser.rows:
        row_text = " ".join(_cell_text(cell) for cell in row)
        if not re.search(r"\bKorea Republic of\b", row_text, re.I):
            continue
        hrefs = [
            href
            for cell in row
            for href in cell["hrefs"]
            if "do_openvpn.aspx?" in href.lower()
        ]
        for href in hrefs:
            try:
                full_href = urljoin(HTML_URL, href)
                query = parse_qs(urlparse(full_href).query)
                ip = query.get("ip", [""])[0].strip()
                fqdn = query.get("fqdn", [""])[0].strip()
                sid = query.get("sid", [""])[0].strip()
                hid = query.get("hid", [""])[0].strip()
                udp_port = _int_field(query.get("udp", [""])[0], default=None)
                if not ip or not sid or not hid or udp_port is None or not 1 <= udp_port <= 65535:
                    continue
                ipaddress.ip_address(ip)
                endpoint = UDPEndpoint(ip=ip, fqdn=fqdn, sid=sid, hid=hid, port=udp_port)
                endpoints.setdefault(ip, []).append(endpoint)
            except (TypeError, ValueError):
                continue

    for ip, values in endpoints.items():
        unique: dict[tuple[str, int, str, str], UDPEndpoint] = {}
        for endpoint in values:
            unique[(endpoint.ip, endpoint.port, endpoint.sid, endpoint.hid)] = endpoint
        endpoints[ip] = list(unique.values())
    return endpoints


def _decode_openvpn_config(encoded: str) -> str:
    cleaned = "".join(encoded.split())
    if not cleaned:
        raise ValueError("OpenVPN_ConfigData_Base64 is empty")
    try:
        raw = base64.b64decode(cleaned, validate=True)
        text = raw.decode("utf-8-sig")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid OpenVPN_ConfigData_Base64") from exc
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) < 32:
        raise ValueError("decoded OpenVPN profile is unexpectedly short")
    return text


def _strip_inline_comment(line: str) -> str:
    return re.split(r"(?<!\\)[#;]", line, maxsplit=1)[0].strip()


def _scalar_directives(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = _strip_inline_comment(raw_line)
        if not line:
            continue
        fields = line.split(None, 1)
        if len(fields) == 2:
            result[fields[0].lower()] = fields[1].strip()
    return result


def _block(text: str, tag: str) -> str | None:
    match = re.search(rf"<{re.escape(tag)}>\s*(.*?)\s*</{re.escape(tag)}>", text, re.I | re.S)
    return match.group(1).strip() if match else None


def _pem_certificate(block: str | None, field: str) -> str | None:
    if not block:
        return None
    matches = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", block, re.S)
    if not matches:
        raise ValueError(f"missing/invalid <{field}>")
    return "\n".join(match.strip() for match in matches)


def _pem_private_key(block: str | None) -> str | None:
    if not block:
        return None
    match = re.search(
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:RSA |EC )?PRIVATE KEY-----",
        block,
        re.S,
    )
    if not match:
        raise ValueError("missing/invalid <key>")
    return match.group(0).strip()


def _normalize_proto(value: str) -> str:
    value = value.strip().lower()
    if value in {"udp", "udp4", "udp6"}:
        return "udp"
    if value in {
        "tcp", "tcp4", "tcp6",
        "tcp-client", "tcp4-client", "tcp6-client",
        "tcp-server", "tcp4-server", "tcp6-server",
    }:
        return "tcp"
    raise ValueError(f"unsupported OpenVPN proto: {value}")


def detect_openvpn_proto(text: str) -> str:
    directives = _scalar_directives(text)
    global_proto = _normalize_proto(directives.get("proto", "udp"))
    remote_protos: list[str] = []
    for raw_line in text.splitlines():
        fields = _strip_inline_comment(raw_line).split()
        if len(fields) >= 4 and fields[0].lower() == "remote":
            remote_protos.append(_normalize_proto(fields[3]))
    return "tcp" if global_proto == "tcp" or "tcp" in remote_protos else "udp"


def parse_ovpn(text: str) -> dict[str, Any]:
    if not re.search(r"(?im)^\s*client\s*$", text):
        raise ValueError("OpenVPN profile is missing the client directive")

    directives = _scalar_directives(text)
    remotes: list[tuple[str, int]] = []
    for raw_line in text.splitlines():
        fields = _strip_inline_comment(raw_line).split()
        if len(fields) >= 2 and fields[0].lower() == "remote":
            port = _int_field(fields[2] if len(fields) >= 3 else "1194", default=1194)
            if port is None or not 1 <= port <= 65535:
                raise ValueError("invalid OpenVPN remote port")
            remotes.append((fields[1], port))
    if not remotes:
        raise ValueError("missing OpenVPN remote")

    ca = _pem_certificate(_block(text, "ca"), "ca")
    if not ca:
        raise ValueError("missing/invalid <ca>")
    cert = _pem_certificate(_block(text, "cert"), "cert")
    key = _pem_private_key(_block(text, "key"))
    if (cert is None) != (key is None):
        raise ValueError("client certificate and private key must be supplied together")

    tls_auth = _block(text, "tls-auth")
    tls_crypt = _block(text, "tls-crypt")
    tls_crypt_v2 = _block(text, "tls-crypt-v2")
    if tls_auth and (tls_crypt or tls_crypt_v2):
        raise ValueError("tls-auth is mutually exclusive with tls-crypt/tls-crypt-v2")
    if tls_crypt and tls_crypt_v2:
        raise ValueError("tls-crypt and tls-crypt-v2 are mutually exclusive")

    key_direction = directives.get("key-direction")
    if tls_auth and key_direction not in {"0", "1"}:
        raise ValueError("tls-auth requires key-direction 0 or 1")

    auth_user_pass = bool(re.search(r"(?im)^\s*auth-user-pass(?:\s|$)", text))
    if _block(text, "auth-user-pass") is not None:
        auth_user_pass = True

    data_ciphers = [
        x for x in re.split(r"[,:\s]+", directives.get("data-ciphers", "")) if x
    ]

    def positive_int(name: str) -> int | None:
        value = _int_field(directives.get(name), default=None)
        return value if value is not None and value > 0 else None

    peer_info: list[str] = []
    for raw_line in text.splitlines():
        fields = _strip_inline_comment(raw_line).split(None, 1)
        if len(fields) == 2 and fields[0].lower() == "peer-info":
            peer_info.append(fields[1].strip())

    return {
        "server": remotes[0][0],
        "port": remotes[0][1],
        "proto": detect_openvpn_proto(text),
        "ca": ca,
        "cert": cert,
        "key": key,
        "tls_auth": tls_auth.strip() if tls_auth else None,
        "tls_crypt": tls_crypt.strip() if tls_crypt else None,
        "tls_crypt_v2": tls_crypt_v2.strip() if tls_crypt_v2 else None,
        "key_direction": key_direction,
        "cipher": directives.get("cipher"),
        "auth": directives.get("auth"),
        "data_ciphers": data_ciphers,
        "data_ciphers_fallback": directives.get("data-ciphers-fallback"),
        "comp_lzo": directives.get("comp-lzo", "").lower() or None,
        "auth_user_pass": auth_user_pass,
        "ping": positive_int("ping"),
        "ping_restart": positive_int("ping-restart"),
        "handshake_timeout": positive_int("handshake-timeout"),
        "peer_info": peer_info,
    }


def _safe_server(server: str) -> str:
    server = server.strip()
    if not server:
        raise ValueError("empty OpenVPN server")
    try:
        ipaddress.ip_address(server)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", server):
            raise ValueError(f"invalid OpenVPN server: {server!r}")
    return server


def _normalize_crypto(value: str | None) -> str | None:
    return value.strip().upper() if value else None


def ovpn_to_mihomo(ovpn: str, name: str) -> dict[str, Any]:
    parsed = parse_ovpn(ovpn)
    node: dict[str, Any] = {
        "name": name,
        "type": "openvpn",
        "server": _safe_server(parsed["server"]),
        "port": parsed["port"],
        "proto": parsed["proto"],
        "ca": LiteralString(parsed["ca"]),
        "udp": parsed["proto"] == "udp",
    }

    # VPN Gate public profiles intentionally may use either vpn/vpn auth or a
    # shared/dummy certificate/key pair. Never combine both authentication modes.
    if parsed["auth_user_pass"]:
        node["username"] = "vpn"
        node["password"] = "vpn"
    elif parsed["cert"] and parsed["key"]:
        node["cert"] = LiteralString(parsed["cert"])
        node["key"] = LiteralString(parsed["key"])
    else:
        raise ValueError("no usable auth-user-pass or cert/key authentication")

    cipher = _normalize_crypto(parsed["cipher"])
    auth = _normalize_crypto(parsed["auth"])
    fallback = _normalize_crypto(parsed["data_ciphers_fallback"])
    if cipher:
        node["cipher"] = cipher
    if auth:
        node["auth"] = auth
    if parsed["data_ciphers"]:
        node["data-ciphers"] = [_normalize_crypto(x) for x in parsed["data_ciphers"]]
    if fallback:
        node["data-ciphers-fallback"] = fallback
    if parsed["comp_lzo"]:
        node["comp-lzo"] = parsed["comp_lzo"]
    if parsed["tls_auth"]:
        node["tls-auth"] = LiteralString(parsed["tls_auth"])
        node["key-direction"] = str(parsed["key_direction"])
    if parsed["tls_crypt"]:
        node["tls-crypt"] = LiteralString(parsed["tls_crypt"])
    if parsed["tls_crypt_v2"]:
        node["tls-crypt-v2"] = LiteralString(parsed["tls_crypt_v2"])
    if parsed["ping"] is not None:
        node["ping"] = parsed["ping"]
    if parsed["ping_restart"] is not None:
        node["ping-restart"] = parsed["ping_restart"]
    if parsed["handshake_timeout"] is not None:
        node["handshake-timeout"] = parsed["handshake_timeout"]
    if parsed["peer_info"]:
        peer_info: dict[str, str] = {}
        for item in parsed["peer_info"]:
            if "=" in item:
                key, value = item.split("=", 1)
                peer_info[key.strip()] = value.strip()
        if peer_info:
            node["peer-info"] = peer_info
    return node


def fetch_udp_profile(
    session: requests.Session,
    row: dict[str, str],
    endpoints: dict[str, list[UDPEndpoint]],
) -> str:
    ip = row.get("IP", "").strip()

    # The API profile is authoritative for the profile material itself. Use it
    # directly when it is already UDP; otherwise obtain the explicitly generated
    # UDP profile from the official download endpoint.
    encoded = row.get("OpenVPN_ConfigData_Base64", "").strip()
    if encoded:
        try:
            ovpn = _decode_openvpn_config(encoded)
            if detect_openvpn_proto(ovpn) == "udp":
                parse_ovpn(ovpn)
                return ovpn
        except (ValueError, UnicodeError):
            pass

    available = endpoints.get(ip, [])
    if not available:
        raise ValueError("CSV profile is not UDP and no UDP endpoint was found on the official server table")

    errors: list[str] = []
    for endpoint in available:
        try:
            response = _request(
                session,
                endpoint.url,
                timeout=(10, 20),
                attempts=2,
                accept="text/plain,*/*;q=0.8",
            )
            ovpn = response.content.decode("utf-8-sig", errors="strict")
            ovpn = ovpn.replace("\r\n", "\n").replace("\r", "\n")
            if detect_openvpn_proto(ovpn) != "udp":
                raise ValueError("official UDP download returned a non-UDP profile")
            parse_ovpn(ovpn)
            return ovpn
        except Exception as exc:
            errors.append(str(exc))
    raise ValueError("all official UDP profile downloads failed: " + " | ".join(errors))


def candidate_from_row(
    row: dict[str, str],
    session: requests.Session,
    endpoints: dict[str, list[UDPEndpoint]],
) -> Candidate:
    hostname = row.get("HostName", "").strip()
    ip = row.get("IP", "").strip()
    country_long = row.get("CountryLong", "").strip()
    country_short = row.get("CountryShort", "").strip().upper()
    ping = _int_field(row.get("Ping"), default=None)
    speed = _int_field(row.get("Speed"), default=None)
    score = _int_field(row.get("Score"), default=None)

    if not ip:
        raise ValueError("missing IP")
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"invalid API IP: {ip}") from exc
    if ping is None or not 0 <= ping < MAX_CSV_PING_MS:
        raise ValueError("API Ping does not satisfy threshold")
    if country_short != "KR" or country_long.lower() != "korea republic of":
        raise ValueError("not a Korea Republic of row")

    ovpn = fetch_udp_profile(session, row, endpoints)
    parsed = parse_ovpn(ovpn)
    if parsed["proto"] != "udp":
        raise ValueError("validated OpenVPN profile is not UDP")

    return Candidate(
        hostname=hostname,
        ip=ip,
        ping=ping,
        speed_bps=speed,
        score=score,
        country_long=country_long,
        country_short=country_short,
        ovpn=ovpn,
        udp_port=parsed["port"],
    )


def validate_config(config: dict[str, Any], *, min_proxies: int = MIN_PROXIES) -> None:
    proxies = config.get("proxies")
    groups = config.get("proxy-groups")
    rules = config.get("rules")
    tun = config.get("tun")

    if not isinstance(proxies, list) or len(proxies) < min_proxies:
        raise RuntimeError(f"generated proxy count below required minimum {min_proxies}")
    if len(proxies) > MAX_PROXIES:
        raise RuntimeError(f"generated proxy count exceeds maximum {MAX_PROXIES}")
    if not isinstance(groups, list) or len(groups) != 1:
        raise RuntimeError("expected exactly one proxy-group")
    if not isinstance(rules, list) or "PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST" not in rules:
        raise RuntimeError("expected FreeStyle Reboot routing rule missing")
    if not isinstance(tun, dict) or tun.get("enable") is not True:
        raise RuntimeError("TUN must be enabled")
    if tun.get("stack") != "system":
        raise RuntimeError("unexpected TUN stack")
    if tun.get("auto-route") is not True or tun.get("auto-detect-interface") is not True:
        raise RuntimeError("unexpected TUN routing settings")

    names = [proxy.get("name") for proxy in proxies if isinstance(proxy, dict)]
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate proxy names")

    for proxy in proxies:
        if not isinstance(proxy, dict) or proxy.get("type") != "openvpn":
            raise RuntimeError("non-OpenVPN proxy in generated config")
        if proxy.get("proto") != "udp" or proxy.get("udp") is not True:
            raise RuntimeError(f"non-UDP proxy emitted: {proxy.get('name')}")
        if not isinstance(proxy.get("server"), str) or not proxy.get("server"):
            raise RuntimeError(f"missing proxy server: {proxy.get('name')}")
        port = proxy.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise RuntimeError(f"invalid proxy port: {proxy.get('name')}")

        has_userpass = "username" in proxy or "password" in proxy
        has_cert = "cert" in proxy
        has_key = "key" in proxy
        if has_cert != has_key:
            raise RuntimeError(f"certificate/key must be paired: {proxy.get('name')}")
        if has_userpass and (has_cert or has_key):
            raise RuntimeError(f"mixed OpenVPN authentication modes: {proxy.get('name')}")
        if not has_userpass and not has_cert:
            raise RuntimeError(f"OpenVPN authentication missing: {proxy.get('name')}")

        if "tls-auth" in proxy and ("tls-crypt" in proxy or "tls-crypt-v2" in proxy):
            raise RuntimeError(f"mutually-exclusive TLS settings: {proxy.get('name')}")
        if "tls-crypt" in proxy and "tls-crypt-v2" in proxy:
            raise RuntimeError(f"mutually-exclusive TLS crypt settings: {proxy.get('name')}")
        if "tls-auth" in proxy and proxy.get("key-direction") not in {"0", "1"}:
            raise RuntimeError(f"invalid key-direction: {proxy.get('name')}")

        cipher = proxy.get("cipher")
        if cipher is not None and str(cipher).upper() not in ALLOWED_CIPHERS:
            raise RuntimeError(f"unsupported cipher: {proxy.get('name')}")
        auth = proxy.get("auth")
        if auth is not None and str(auth).upper() not in ALLOWED_AUTHS:
            raise RuntimeError(f"unsupported auth: {proxy.get('name')}")
        comp = proxy.get("comp-lzo")
        if comp is not None and str(comp).lower() not in ALLOWED_COMP_LZO:
            raise RuntimeError(f"unsupported comp-lzo: {proxy.get('name')}")

        data_ciphers = proxy.get("data-ciphers")
        if data_ciphers is not None:
            if not isinstance(data_ciphers, list) or not data_ciphers:
                raise RuntimeError(f"invalid data-ciphers: {proxy.get('name')}")
            if any(str(x).upper() not in ALLOWED_CIPHERS for x in data_ciphers):
                raise RuntimeError(f"unsupported data-ciphers: {proxy.get('name')}")

        fallback = proxy.get("data-ciphers-fallback")
        if fallback is not None and str(fallback).upper() not in ALLOWED_CIPHERS:
            raise RuntimeError(f"unsupported data-ciphers-fallback: {proxy.get('name')}")

        for field in PEM_FIELDS:
            value = proxy.get(field)
            if isinstance(value, str) and "BEGIN " in value and "\n" not in value:
                raise RuntimeError(f"PEM newline corruption: {proxy.get('name')}:{field}")

    lowest = groups[0]
    if not isinstance(lowest, dict) or lowest.get("name") != "KR-LOWEST" or lowest.get("type") != "url-test":
        raise RuntimeError("KR-LOWEST url-test group missing")
    if lowest.get("proxies") != names:
        raise RuntimeError("KR-LOWEST proxy list mismatch")
    if lowest.get("url") != DEFAULT_TEST_URL:
        raise RuntimeError("unexpected health-check URL")
    if lowest.get("interval") != 60 or lowest.get("timeout") != 3000:
        raise RuntimeError("unexpected health-check timing")
    if lowest.get("tolerance") != 0:
        raise RuntimeError("KR-LOWEST tolerance must remain 0")
    if lowest.get("lazy") is not True:
        raise RuntimeError("KR-LOWEST lazy mode must be enabled")
    if lowest.get("expected-status") != 200:
        raise RuntimeError("unexpected expected-status")
    if lowest.get("disable-udp") is not False:
        raise RuntimeError("KR-LOWEST must keep UDP enabled")


def build_config(candidates: list[Candidate], out_path: Path) -> int:
    proxies: list[dict[str, Any]] = []
    names: list[str] = []
    seen_endpoints: set[tuple[str, int]] = set()

    for candidate in candidates:
        try:
            endpoint = (_safe_server(parse_ovpn(candidate.ovpn)["server"]).lower(), candidate.udp_port)
            if endpoint in seen_endpoints:
                continue
            seen_endpoints.add(endpoint)
            index = len(proxies) + 1
            base = clean_name(candidate.hostname or candidate.ip.replace(".", "-"))
            name = f"KR-{index:02d}-{base}"
            proxy = ovpn_to_mihomo(candidate.ovpn, name)
            proxies.append(proxy)
            names.append(name)
        except Exception as exc:
            print(f"[skip-config] {candidate.hostname or candidate.ip}: {exc}")

    config = {
        "mode": "rule",
        "unified-delay": True,
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "KR-LOWEST",
                "type": "url-test",
                "proxies": names,
                "url": DEFAULT_TEST_URL,
                "interval": 60,
                "timeout": 3000,
                "tolerance": 0,
                "lazy": True,
                "expected-status": 200,
                "disable-udp": False,
            }
        ],
        "rules": ["PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST", "MATCH,DIRECT"],
        "tun": {
            "enable": True,
            "stack": "system",
            "auto-route": True,
            "auto-detect-interface": True,
        },
    }
    validate_config(config, min_proxies=1)
    text = f"# VPN Gate KR Mihomo subscription generated by benchmark {SCRIPT_VERSION}\n" + yaml.safe_dump(
        config,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )
    out_path.write_text(text, encoding="utf-8")
    loaded = yaml.safe_load(text)
    if not isinstance(loaded, dict):
        raise RuntimeError("YAML reload failed")
    validate_config(loaded, min_proxies=1)
    return len(proxies)


def clean_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")[:60] or "node"


def _candidate_sort_key(candidate: Candidate) -> tuple[Any, ...]:
    return (
        candidate.ping,
        -(candidate.speed_bps or 0),
        -(candidate.score or 0),
        candidate.hostname.lower(),
        candidate.ip,
    )


def benchmark(
    names: list[str],
    session: requests.Session,
    controller: str,
    url: str,
    repeat: int,
    timeout_ms: int,
    secret: str | None,
    pause: float,
    expected_status: str | None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    repeat = max(1, repeat)
    for name in names:
        samples: list[int] = []
        endpoint = f"{controller.rstrip('/')}/proxies/{quote(name, safe='')}/delay"
        for index in range(repeat):
            try:
                response = session.get(
                    endpoint,
                    params={
                        "url": url,
                        "timeout": timeout_ms,
                        **({"expected": expected_status} if expected_status else {}),
                    },
                    headers=headers,
                    timeout=timeout_ms / 1000 + 2,
                )
                response.raise_for_status()
                delay = response.json().get("delay")
                if isinstance(delay, int) and delay >= 0:
                    samples.append(delay)
            except (requests.RequestException, ValueError, TypeError):
                pass
            if index + 1 < repeat:
                time.sleep(max(0.0, pause))
        results.append({
            "name": name,
            "samples_ms": samples,
            "min_ms": min(samples) if samples else None,
            "avg_ms": round(statistics.mean(samples), 2) if samples else None,
            "max_ms": max(samples) if samples else None,
            "jitter_ms": round(statistics.pstdev(samples), 2) if len(samples) >= 2 else None,
            "timeouts": repeat - len(samples),
        })
    results.sort(
        key=lambda item: (
            item["avg_ms"] is None,
            item["avg_ms"] if item["avg_ms"] is not None else 10**9,
            item["jitter_ms"] if item["jitter_ms"] is not None else 10**9,
        )
    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=MAX_PROXIES)
    parser.add_argument("--min-speed", type=int, default=DEFAULT_MIN_SPEED, help="minimum VPN Gate API Speed")
    parser.add_argument("--out-dir", default="vpngate_kr_benchmark")
    parser.add_argument("--controller", default="")
    parser.add_argument("--secret", default="")
    parser.add_argument("--url", default=DEFAULT_TEST_URL)
    parser.add_argument("--expected-status", default=DEFAULT_EXPECTED_STATUS)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=5000)
    parser.add_argument("--pause", type=float, default=0.3)
    args = parser.parse_args()

    if not 1 <= args.limit <= MAX_PROXIES:
        raise SystemExit(f"--limit must be between 1 and {MAX_PROXIES}")
    if args.min_speed < 0:
        raise SystemExit("--min-speed must be >= 0")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("[1/4] Downloading VPN Gate official CSV API...")
    csv_response = _request(session, API_URL, accept="text/csv,text/plain;q=0.9,*/*;q=0.8")
    rows = parse_official_csv(csv_response.text)
    print(f"        API rows: {len(rows)}")

    print("[2/4] Discovering official UDP OpenVPN endpoints...")
    html_response = _request(session, HTML_URL, accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
    udp_endpoints = parse_official_udp_endpoints(html_response.text)
    print(f"        Korea IPs with UDP OpenVPN endpoint(s): {len(udp_endpoints)}")

    kr_rows = [
        row
        for row in rows
        if row.get("CountryShort", "").strip().upper() == "KR"
        and row.get("CountryLong", "").strip().lower() == "korea republic of"
    ]
    print(f"        Korea Republic of CSV rows: {len(kr_rows)}")

    eligible_rows = []
    for row in kr_rows:
        ping = _int_field(row.get("Ping"), default=None)
        speed = _int_field(row.get("Speed"), default=None)
        if ping is None or not 0 <= ping < MAX_CSV_PING_MS:
            continue
        if args.min_speed and (speed is None or speed < args.min_speed):
            continue
        if not row.get("OpenVPN_ConfigData_Base64", "").strip():
            continue
        eligible_rows.append(row)

    eligible_rows.sort(
        key=lambda row: (
            _int_field(row.get("Ping"), default=10**9),
            -(_int_field(row.get("Speed"), default=0) or 0),
            -(_int_field(row.get("Score"), default=0) or 0),
            row.get("HostName", "").lower(),
            row.get("IP", ""),
        )
    )
    print(f"        KR + Ping < {MAX_CSV_PING_MS} ms + speed filter: {len(eligible_rows)}")

    candidates: list[Candidate] = []
    seen_endpoints: set[tuple[str, int]] = set()
    invalid_profiles = 0
    direct_udp_profiles = 0
    downloaded_udp_profiles = 0

    for row in eligible_rows:
        if len(candidates) >= args.limit:
            break
        try:
            before = row.get("OpenVPN_ConfigData_Base64", "").strip()
            direct_ovpn = False
            if before:
                try:
                    decoded = _decode_openvpn_config(before)
                    direct_ovpn = detect_openvpn_proto(decoded) == "udp"
                except ValueError:
                    pass

            candidate = candidate_from_row(row, session, udp_endpoints)
            parsed = parse_ovpn(candidate.ovpn)
            endpoint = (_safe_server(parsed["server"]).lower(), candidate.udp_port)
            if endpoint in seen_endpoints:
                print(f"[skip] {candidate.hostname or candidate.ip}: duplicate UDP endpoint")
                continue
            seen_endpoints.add(endpoint)
            candidates.append(candidate)
            if direct_ovpn:
                direct_udp_profiles += 1
            else:
                downloaded_udp_profiles += 1
        except Exception as exc:
            invalid_profiles += 1
            print(f"[skip] {row.get('HostName') or row.get('IP') or 'unknown'}: {exc}")

    if len(candidates) < min(args.limit, MIN_PROXIES):
        raise RuntimeError(
            f"only {len(candidates)} valid UDP OpenVPN candidates remain; required at least {min(args.limit, MIN_PROXIES)}"
        )

    candidates.sort(key=_candidate_sort_key)
    print(f"        valid UDP OpenVPN profiles: {len(candidates)}")
    print(f"        API profile already UDP: {direct_udp_profiles}")
    print(f"        fetched official UDP profile: {downloaded_udp_profiles}")
    print(f"        rejected/invalid profiles: {invalid_profiles}")
    print(f"        selected: {len(candidates)}")

    (out / "source_candidates.json").write_text(
        json.dumps(
            {
                "source_api": API_URL,
                "source_udp_endpoint_discovery": HTML_URL,
                "script_version": SCRIPT_VERSION,
                "ping_threshold_ms_exclusive": MAX_CSV_PING_MS,
                "selected": [
                    {
                        "hostname": c.hostname,
                        "ip": c.ip,
                        "ping": c.ping,
                        "speed_bps": c.speed_bps,
                        "score": c.score,
                        "country_long": c.country_long,
                        "country_short": c.country_short,
                        "udp_port": c.udp_port,
                    }
                    for c in candidates
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    yaml_path = out / "vpngate_kr_mihomo.yaml"
    count = build_config(candidates, yaml_path)
    print(f"        generated: {yaml_path}")
    print(f"        YAML proxies: {count}")

    if args.controller:
        print("[4/4] Benchmarking through Mihomo /delay...")
        cfg = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        names = [proxy["name"] for proxy in cfg["proxies"]]
        results = benchmark(
            names,
            session,
            args.controller,
            args.url,
            args.repeat,
            args.timeout,
            args.secret or None,
            args.pause,
            args.expected_status or None,
        )
        (out / "benchmark_results.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        for index, result in enumerate(results, 1):
            print(
                f"{index:>2}. {result['name']:<42} "
                f"avg={result['avg_ms']} min={result['min_ms']} max={result['max_ms']} "
                f"jitter={result['jitter_ms']} timeout={result['timeouts']}"
            )
    else:
        print("[4/4] Live benchmark not requested.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
