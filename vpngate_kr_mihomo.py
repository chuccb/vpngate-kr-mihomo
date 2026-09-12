#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import io
import ipaddress
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlparse

import requests
import yaml

VERSION = "8.0"
API_URL = "https://www.vpngate.net/api/iphone/"
SERVER_TABLE_URL = "https://www.vpngate.net/en/"
OPENVPN_DOWNLOAD_URL = "https://www.vpngate.net/common/openvpn_download.aspx"
COUNTRY_SHORT = "KR"
COUNTRY_LONG = "Korea Republic of"
MAX_CSV_PING_MS = 40
MAX_PROXIES = 10
MIN_PROXIES = 3
DEFAULT_WORKERS = 4
DEFAULT_BATCH_SIZE = 8
HEALTH_URL = "http://www.gstatic.com/generate_204"
HEALTH_STATUS = 204
HEALTH_INTERVAL = 60
HEALTH_TIMEOUT_MS = 3000
HEALTH_TOLERANCE_MS = 0
HEALTH_LAZY = False
HEALTH_MAX_FAILED_TIMES = 2
USER_AGENT = f"VPNGate-KR-Mihomo/{VERSION}"
ALLOWED_CIPHERS = {"AES-128-GCM", "AES-256-GCM", "AES-128-CBC", "AES-256-CBC", "CHACHA20-POLY1305", "AES-CBC"}
ALLOWED_AUTHS = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
ALLOWED_COMP_LZO = {"yes", "no", "adaptive"}
PEM_FIELDS = ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2")


class LiteralString(str):
    pass


def _literal(dumper: yaml.SafeDumper, data: LiteralString):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.SafeDumper.add_representer(LiteralString, _literal)


@dataclass(frozen=True)
class UdpEndpoint:
    ip: str
    fqdn: str
    sid: str
    hid: str
    port: int

    @property
    def url(self) -> str:
        filename = f"vpngate_{self.ip}_udp_{self.port}.ovpn"
        return f"{OPENVPN_DOWNLOAD_URL}?sid={quote(self.sid, safe='')}&udp=1&host={quote(self.ip, safe='')}&port={self.port}&hid={quote(self.hid, safe='')}&/{quote(filename, safe='')}"


@dataclass(frozen=True)
class Candidate:
    hostname: str
    ip: str
    ping: int
    speed: int | None
    score: int | None
    country_long: str
    country_short: str
    ovpn: str

    @property
    def endpoint(self) -> tuple[str, int]:
        p = parse_openvpn(self.ovpn)
        return p["server"].lower(), p["port"]


class HtmlRows(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[dict[str, Any]]] = []
        self.row: list[dict[str, Any]] | None = None
        self.cell: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "tr":
            self.row = []
            self.cell = None
        elif tag == "td" and self.row is not None:
            self.cell = {"text": [], "hrefs": []}
            self.row.append(self.cell)
        elif tag == "a" and self.cell is not None:
            href = dict(attrs).get("href")
            if href:
                self.cell["hrefs"].append(href)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "tr":
            if self.row is not None:
                self.rows.append(self.row)
            self.row = None
            self.cell = None
        elif tag == "td":
            self.cell = None

    def handle_data(self, data: str) -> None:
        if self.cell is not None:
            self.cell["text"].append(data)


def new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def request(s: requests.Session, url: str, *, timeout: tuple[float, float] = (10, 30), attempts: int = 3, accept: str | None = None) -> requests.Response:
    last: Exception | None = None
    headers = {"Accept": accept} if accept else None
    for n in range(attempts):
        try:
            r = s.get(url, timeout=timeout, headers=headers)
            r.raise_for_status()
            return r
        except (requests.RequestException, OSError) as exc:
            last = exc
            if n + 1 < attempts:
                time.sleep(min(2.0 * (n + 1), 5.0))
    raise RuntimeError(f"request failed: {url}") from last


def pint(value: str | None, default: int | None = None) -> int | None:
    value = (value or "").strip().replace(",", "")
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def clean_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
    return value[:60] or "node"


def normalize_server(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("empty server")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
            raise ValueError(f"invalid server: {value!r}")
    return value.lower()


def parse_csv(text: str) -> list[dict[str, str]]:
    lines = text.lstrip("\ufeff").splitlines()
    i = next((i for i, line in enumerate(lines) if line.lstrip().startswith("#HostName,")), None)
    if i is None:
        raise RuntimeError("VPN Gate CSV header not found")
    header = lines[i].lstrip()[1:]
    reader = csv.DictReader(io.StringIO("\n".join([header, *lines[i + 1:]])))
    if not reader.fieldnames:
        raise RuntimeError("VPN Gate CSV fields missing")
    rows: list[dict[str, str]] = []
    for raw in reader:
        row = {str(k).strip(): (v or "").strip() for k, v in raw.items() if k is not None}
        if row.get("HostName") or row.get("IP"):
            rows.append(row)
    if not rows:
        raise RuntimeError("VPN Gate CSV has no rows")
    return rows


def cell_text(cell: dict[str, Any]) -> str:
    return re.sub(r"\s+", " ", " ".join(cell["text"])).strip()


def parse_udp_links(html: str, *, ip: str | None = None, require_kr: bool = False) -> dict[str, list[UdpEndpoint]]:
    parser = HtmlRows()
    parser.feed(html)
    result: dict[str, list[UdpEndpoint]] = {}
    for row in parser.rows:
        text = " ".join(cell_text(c) for c in row)
        if require_kr and not re.search(r"\bKorea Republic of\b", text, re.I):
            continue
        for href in [h for c in row for h in c["hrefs"] if "do_openvpn.aspx?" in h.lower()]:
            try:
                q = parse_qs(urlparse(urljoin(SERVER_TABLE_URL, href)).query)
                row_ip = q.get("ip", [""])[0].strip()
                if ip and row_ip != ip:
                    continue
                sid = q.get("sid", [""])[0].strip()
                hid = q.get("hid", [""])[0].strip()
                port = pint(q.get("udp", [""])[0])
                if not row_ip or not sid or not hid or port is None or not 1 <= port <= 65535:
                    continue
                ipaddress.ip_address(row_ip)
                result.setdefault(row_ip, []).append(UdpEndpoint(row_ip, q.get("fqdn", [""])[0].strip(), sid, hid, port))
            except (ValueError, TypeError):
                continue
    for key, values in result.items():
        result[key] = list({(x.ip, x.port, x.sid, x.hid): x for x in values}.values())
    return result


def commentless(line: str) -> str:
    return re.split(r"(?<!\\)[#;]", line, maxsplit=1)[0].strip()


def directives(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = commentless(raw)
        f = line.split(None, 1)
        if len(f) == 2:
            out[f[0].lower()] = f[1].strip()
    return out


def block(text: str, tag: str) -> str | None:
    m = re.search(rf"<{re.escape(tag)}>\s*(.*?)\s*</{re.escape(tag)}>", text, re.I | re.S)
    return m.group(1).strip() if m else None


def cert_block(value: str | None) -> str | None:
    if not value:
        return None
    m = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", value, re.S)
    if not m:
        raise ValueError("invalid certificate block")
    return "\n".join(x.strip() for x in m)


def key_block(value: str | None) -> str | None:
    if not value:
        return None
    m = re.search(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", value, re.S)
    if not m:
        raise ValueError("invalid private key block")
    return m.group(0).strip()


def proto(value: str) -> str:
    value = value.lower().strip()
    if value in {"udp", "udp4", "udp6"}:
        return "udp"
    if value in {"tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client", "tcp-server", "tcp4-server", "tcp6-server"}:
        return "tcp"
    raise ValueError(f"unsupported proto: {value}")


def parse_openvpn(text: str) -> dict[str, Any]:
    if not re.search(r"(?im)^\s*client\s*$", text):
        raise ValueError("client directive missing")
    d = directives(text)
    remotes: list[tuple[str, int]] = []
    for raw in text.splitlines():
        f = commentless(raw).split()
        if len(f) >= 2 and f[0].lower() == "remote":
            port = pint(f[2] if len(f) >= 3 else "1194", 1194)
            if port is None or not 1 <= port <= 65535:
                raise ValueError("invalid remote port")
            remotes.append((normalize_server(f[1]), port))
    if not remotes:
        raise ValueError("remote missing")
    ca = cert_block(block(text, "ca"))
    if not ca:
        raise ValueError("ca missing")
    cert = cert_block(block(text, "cert"))
    key = key_block(block(text, "key"))
    if (cert is None) != (key is None):
        raise ValueError("cert/key mismatch")
    tls_auth = block(text, "tls-auth")
    tls_crypt = block(text, "tls-crypt")
    tls_crypt_v2 = block(text, "tls-crypt-v2")
    if tls_auth and (tls_crypt or tls_crypt_v2):
        raise ValueError("TLS mode conflict")
    if tls_crypt and tls_crypt_v2:
        raise ValueError("TLS crypt mode conflict")
    kd = d.get("key-direction")
    if tls_auth and kd not in {"0", "1"}:
        raise ValueError("tls-auth requires key-direction 0 or 1")
    userpass = bool(re.search(r"(?im)^\s*auth-user-pass(?:\s|$)", text)) or block(text, "auth-user-pass") is not None
    cps = [x for x in re.split(r"[,:\s]+", d.get("data-ciphers", "")) if x]
    peers = []
    for raw in text.splitlines():
        f = commentless(raw).split(None, 1)
        if len(f) == 2 and f[0].lower() == "peer-info":
            peers.append(f[1].strip())
    return {
        "server": remotes[0][0], "port": remotes[0][1],
        "proto": proto(d.get("proto", "udp")) if not any(proto(x) == "tcp" for x in [d.get("proto", "udp")]) else "tcp",
        "ca": ca, "cert": cert, "key": key,
        "tls_auth": tls_auth.strip() if tls_auth else None,
        "tls_crypt": tls_crypt.strip() if tls_crypt else None,
        "tls_crypt_v2": tls_crypt_v2.strip() if tls_crypt_v2 else None,
        "key_direction": kd, "cipher": d.get("cipher"), "auth": d.get("auth"),
        "data_ciphers": cps, "data_ciphers_fallback": d.get("data-ciphers-fallback"),
        "comp_lzo": d.get("comp-lzo", "").lower() or None, "auth_user_pass": userpass,
        "ping": pint(d.get("ping")), "ping_restart": pint(d.get("ping-restart")),
        "handshake_timeout": pint(d.get("handshake-timeout")), "peer_info": peers,
    }


def decode_profile(encoded: str) -> str:
    encoded = "".join(encoded.split())
    if not encoded:
        raise ValueError("empty OpenVPN_ConfigData_Base64")
    try:
        text = base64.b64decode(encoded, validate=True).decode("utf-8-sig")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid OpenVPN base64") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n")


def udp_profile(session: requests.Session, row: dict[str, str], homepage: dict[str, list[UdpEndpoint]], detail_cache: dict[str, list[UdpEndpoint]], lock: threading.Lock) -> tuple[str, str]:
    encoded = row.get("OpenVPN_ConfigData_Base64", "").strip()
    if encoded:
        try:
            text = decode_profile(encoded)
            if parse_openvpn(text)["proto"] == "udp":
                return text, "csv"
        except ValueError:
            pass
    ip = row["IP"].strip()
    endpoints = homepage.get(ip, [])
    source = "homepage"
    if not endpoints:
        with lock:
            cached = detail_cache.get(ip)
        if cached is None:
            try:
                detail = request(session, f"{SERVER_TABLE_URL}?ip={quote(ip, safe='')}", timeout=(10, 20), attempts=2, accept="text/html,*/*;q=0.8")
                found = parse_udp_links(detail.text, ip=ip).get(ip, [])
            except Exception:
                found = []
            with lock:
                if ip not in detail_cache:
                    detail_cache[ip] = list(found)
                endpoints = detail_cache[ip]
        else:
            endpoints = cached
        source = "detail"
    if not endpoints:
        raise ValueError("no official UDP endpoint found")
    errors: list[str] = []
    for endpoint in endpoints:
        try:
            r = request(session, endpoint.url, timeout=(10, 20), attempts=2, accept="text/plain,*/*;q=0.8")
            text = r.content.decode("utf-8-sig", errors="strict").replace("\r\n", "\n").replace("\r", "\n")
            if parse_openvpn(text)["proto"] != "udp":
                raise ValueError("download is not UDP")
            return text, source
        except Exception as exc:
            errors.append(str(exc))
    raise ValueError("all official UDP downloads failed: " + " | ".join(errors))


def candidate_task(session: requests.Session, row: dict[str, str], homepage: dict[str, list[UdpEndpoint]], detail_cache: dict[str, list[UdpEndpoint]], lock: threading.Lock) -> tuple[Candidate | None, str | None, str | None]:
    try:
        country_short = row.get("CountryShort", "").strip().upper()
        country_long = row.get("CountryLong", "").strip()
        ip = row.get("IP", "").strip()
        ping = pint(row.get("Ping"))
        if country_short != COUNTRY_SHORT or country_long.lower() != COUNTRY_LONG.lower():
            raise ValueError("not Korea Republic of")
        if not ip:
            raise ValueError("missing IP")
        ipaddress.ip_address(ip)
        if ping is None or not 0 <= ping < MAX_CSV_PING_MS:
            raise ValueError("Ping threshold failed")
        speed = pint(row.get("Speed")); score = pint(row.get("Score"))
        profile, source = udp_profile(session, row, homepage, detail_cache, lock)
        parsed = parse_openvpn(profile)
        if parsed["proto"] != "udp":
            raise ValueError("validated profile is not UDP")
        return Candidate(row.get("HostName", "").strip(), ip, ping, speed, score, country_long, country_short, profile), None, source
    except Exception as exc:
        return None, str(exc), None


def sort_key(c: Candidate) -> tuple[Any, ...]:
    return (c.ping, -(c.speed or 0), -(c.score or 0), c.hostname.lower(), c.ip)


def make_proxy(c: Candidate) -> tuple[dict[str, Any], str]:
    p = parse_openvpn(c.ovpn)
    name = f"KR-{clean_name(p['server'].replace('.', '-'))}-{p['port']}"
    node: dict[str, Any] = {"name": name, "type": "openvpn", "server": p["server"], "port": p["port"], "proto": "udp", "udp": True, "ca": LiteralString(p["ca"])}
    if p["auth_user_pass"]:
        node.update(username="vpn", password="vpn")
    elif p["cert"] and p["key"]:
        node["cert"] = LiteralString(p["cert"]); node["key"] = LiteralString(p["key"])
    else:
        raise ValueError("missing authentication mode")
    if p["cipher"]: node["cipher"] = p["cipher"].strip().upper()
    if p["auth"]: node["auth"] = p["auth"].strip().upper()
    if p["data_ciphers"]: node["data-ciphers"] = [x.strip().upper() for x in p["data_ciphers"]]
    if p["data_ciphers_fallback"]: node["data-ciphers-fallback"] = p["data_ciphers_fallback"].strip().upper()
    if p["comp_lzo"]: node["comp-lzo"] = p["comp_lzo"]
    if p["tls_auth"]:
        if str(p["auth"] or "SHA1").upper() != "SHA1":
            raise ValueError("tls-auth with non-SHA1 auth excluded for stable Mihomo")
        node["tls-auth"] = LiteralString(p["tls_auth"]); node["key-direction"] = str(p["key_direction"])
    if p["tls_crypt"]: node["tls-crypt"] = LiteralString(p["tls_crypt"])
    if p["tls_crypt_v2"]: node["tls-crypt-v2"] = LiteralString(p["tls_crypt_v2"])
    if p["ping"] is not None: node["ping"] = p["ping"]
    if p["ping_restart"] is not None: node["ping-restart"] = p["ping_restart"]
    if p["handshake_timeout"] is not None: node["handshake-timeout"] = p["handshake_timeout"]
    if p["peer_info"]:
        peer = {}
        for item in p["peer_info"]:
            if "=" in item: k, v = item.split("=", 1); peer[k.strip()] = v.strip()
        if peer: node["peer-info"] = peer
    return node, name


def validate_proxy(p: dict[str, Any]) -> None:
    if p.get("type") != "openvpn" or p.get("proto") != "udp" or p.get("udp") is not True:
        raise ValueError(f"invalid OpenVPN UDP proxy: {p.get('name')}")
    if not isinstance(p.get("server"), str) or not p["server"] or not isinstance(p.get("port"), int) or not 1 <= p["port"] <= 65535:
        raise ValueError(f"invalid endpoint: {p.get('name')}")
    up = "username" in p and "password" in p; ck = "cert" in p and "key" in p
    if up == ck:
        raise ValueError(f"invalid auth mode: {p.get('name')}")
    if "tls-auth" in p and p.get("key-direction") not in {"0", "1"}:
        raise ValueError(f"invalid key-direction: {p.get('name')}")
    if "tls-auth" in p and str(p.get("auth", "SHA1")).upper() != "SHA1":
        raise ValueError(f"tls-auth non-SHA1: {p.get('name')}")
    if "tls-auth" in p and ("tls-crypt" in p or "tls-crypt-v2" in p):
        raise ValueError(f"TLS conflict: {p.get('name')}")
    if "tls-crypt" in p and "tls-crypt-v2" in p:
        raise ValueError(f"TLS conflict: {p.get('name')}")
    if p.get("cipher") is not None and str(p["cipher"]).upper() not in ALLOWED_CIPHERS: raise ValueError("unsupported cipher")
    if p.get("auth") is not None and str(p["auth"]).upper() not in ALLOWED_AUTHS: raise ValueError("unsupported auth")
    if p.get("comp-lzo") is not None and str(p["comp-lzo"]).lower() not in ALLOWED_COMP_LZO: raise ValueError("unsupported comp-lzo")
    d = p.get("data-ciphers")
    if d is not None and (not isinstance(d, list) or not d or any(str(x).upper() not in ALLOWED_CIPHERS for x in d)): raise ValueError("unsupported data-ciphers")
    f = p.get("data-ciphers-fallback")
    if f is not None and str(f).upper() not in ALLOWED_CIPHERS: raise ValueError("unsupported fallback cipher")
    for field in PEM_FIELDS:
        v = p.get(field)
        if isinstance(v, str) and "BEGIN " in v and "\n" not in v: raise ValueError(f"PEM corruption: {field}")


def build_config(candidates: list[Candidate]) -> tuple[dict[str, Any], list[Candidate]]:
    proxies: list[dict[str, Any]] = []; emitted: list[Candidate] = []; seen: set[tuple[str, int]] = set(); names: set[str] = set()
    for c in sorted(candidates, key=sort_key):
        try:
            p, name = make_proxy(c); key = (p["server"].lower(), p["port"])
            if key in seen or name in names: continue
            validate_proxy(p); seen.add(key); names.add(name); proxies.append(p); emitted.append(c)
        except Exception as exc:
            print(f"[skip-config] {c.hostname or c.ip}: {exc}")
    if len(proxies) < MIN_PROXIES: raise RuntimeError(f"only {len(proxies)} usable proxies; minimum is {MIN_PROXIES}")
    config = {
        "mode": "rule", "find-process-mode": "strict", "unified-delay": True,
        "profile": {"store-selected": True}, "proxies": proxies,
        "proxy-groups": [{"name": "KR-LOWEST", "type": "url-test", "proxies": [p["name"] for p in proxies], "url": HEALTH_URL, "interval": HEALTH_INTERVAL, "timeout": HEALTH_TIMEOUT_MS, "tolerance": HEALTH_TOLERANCE_MS, "lazy": HEALTH_LAZY, "max-failed-times": HEALTH_MAX_FAILED_TIMES, "expected-status": HEALTH_STATUS, "disable-udp": False}],
        "rules": ["PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST", "MATCH,DIRECT"],
        "tun": {"enable": True, "stack": "system", "auto-route": True, "auto-detect-interface": True},
    }
    validate_config(config); return config, emitted


def validate_config(cfg: dict[str, Any]) -> None:
    if cfg.get("mode") != "rule" or cfg.get("find-process-mode") != "strict": raise ValueError("routing mode mismatch")
    if cfg.get("profile", {}).get("store-selected") is not True: raise ValueError("store-selected mismatch")
    proxies = cfg.get("proxies"); groups = cfg.get("proxy-groups")
    if not isinstance(proxies, list) or not MIN_PROXIES <= len(proxies) <= MAX_PROXIES: raise ValueError("invalid proxy count")
    names: list[str] = []
    for p in proxies: validate_proxy(p); names.append(p["name"])
    if len(names) != len(set(names)): raise ValueError("duplicate proxy names")
    g = groups[0] if isinstance(groups, list) and len(groups) == 1 else None
    if not isinstance(g, dict) or g.get("name") != "KR-LOWEST" or g.get("type") != "url-test": raise ValueError("KR-LOWEST missing")
    if g.get("proxies") != names: raise ValueError("proxy group mismatch")
    expected = {"url": HEALTH_URL, "interval": HEALTH_INTERVAL, "timeout": HEALTH_TIMEOUT_MS, "tolerance": HEALTH_TOLERANCE_MS, "lazy": HEALTH_LAZY, "max-failed-times": HEALTH_MAX_FAILED_TIMES, "expected-status": HEALTH_STATUS, "disable-udp": False}
    for k, v in expected.items():
        if g.get(k) != v: raise ValueError(f"group field mismatch: {k}")
    if cfg.get("rules") != ["PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST", "MATCH,DIRECT"]: raise ValueError("routing rules mismatch")
    tun = cfg.get("tun")
    if not isinstance(tun, dict) or tun.get("enable") is not True or tun.get("stack") != "system" or tun.get("auto-route") is not True or tun.get("auto-detect-interface") is not True: raise ValueError("TUN configuration mismatch")


def write_output(out: Path, cfg: dict[str, Any], selected: list[Candidate], stats: dict[str, Any]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    text = f"# VPN Gate KR Mihomo generated by {VERSION}\n" + yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False, width=120)
    (out / "vpngate_kr_mihomo.yaml").write_text(text, encoding="utf-8")
    loaded = yaml.safe_load(text); validate_config(loaded)
    meta = {"generator_version": VERSION, "source_api": API_URL, "source_server_table": SERVER_TABLE_URL, "country_short": COUNTRY_SHORT, "country_long": COUNTRY_LONG, "ping_threshold_ms_exclusive": MAX_CSV_PING_MS, "health_check": {"url": HEALTH_URL, "expected_status": HEALTH_STATUS, "interval_seconds": HEALTH_INTERVAL, "timeout_ms": HEALTH_TIMEOUT_MS, "tolerance_ms": HEALTH_TOLERANCE_MS, "lazy": HEALTH_LAZY, "max_failed_times": HEALTH_MAX_FAILED_TIMES}, "stats": stats, "selected": []}
    for c in selected:
        p = parse_openvpn(c.ovpn); meta["selected"].append({"hostname": c.hostname, "csv_ip": c.ip, "profile_server": p["server"], "profile_port": p["port"], "ping": c.ping, "speed_bps": c.speed, "score": c.score, "country_short": c.country_short, "country_long": c.country_long, "stable_proxy_name": f"KR-{clean_name(p['server'].replace('.', '-'))}-{p['port']}"})
    (out / "source_candidates.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def generate(limit: int, min_speed: int, workers: int, batch_size: int, out: Path) -> int:
    main = new_session(); detail_cache: dict[str, list[UdpEndpoint]] = {}; cache_lock = threading.Lock(); local = threading.local(); worker_sessions: list[requests.Session] = []; ws_lock = threading.Lock()
    def session() -> requests.Session:
        s = getattr(local, "session", None)
        if s is None:
            s = new_session(); local.session = s
            with ws_lock: worker_sessions.append(s)
        return s
    try:
        print("[1/4] Downloading VPN Gate CSV...")
        rows = parse_csv(request(main, API_URL, accept="text/csv,text/plain;q=0.9,*/*;q=0.8").text)
        kr = [r for r in rows if r.get("CountryShort", "").strip().upper() == COUNTRY_SHORT and r.get("CountryLong", "").strip().lower() == COUNTRY_LONG.lower()]
        eligible = []
        for r in kr:
            p = pint(r.get("Ping")); s = pint(r.get("Speed"))
            if p is not None and 0 <= p < MAX_CSV_PING_MS and (not min_speed or (s is not None and s >= min_speed)): eligible.append(r)
        eligible.sort(key=lambda r: (pint(r.get("Ping"), 10**9), -(pint(r.get("Speed"), 0) or 0), -(pint(r.get("Score"), 0) or 0), r.get("HostName", "").lower(), r.get("IP", "")))
        print(f"        rows={len(rows)} KR={len(kr)} eligible={len(eligible)}")
        print("[2/4] Indexing homepage UDP endpoints...")
        homepage = parse_udp_links(request(main, SERVER_TABLE_URL, accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.8").text, require_kr=True)
        print(f"        homepage UDP IPs={len(homepage)}")
        selected: list[Candidate] = []; seen: set[tuple[str, int]] = set(); rejected = 0; sources = {"csv": 0, "homepage": 0, "detail": 0}; cursor = 0
        print(f"[3/4] Validating UDP profiles: workers={workers}, batch={batch_size}")
        def task(row: dict[str, str]): return candidate_task(session(), row, homepage, detail_cache, cache_lock)
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vpngate") as pool:
            while cursor < len(eligible) and len(selected) < limit:
                batch = eligible[cursor:cursor + min(batch_size, limit - len(selected), len(eligible) - cursor)]; cursor += len(batch)
                futures = [pool.submit(task, r) for r in batch]
                results = []
                for i, f in enumerate(futures):
                    c, err, src = f.result()
                    if c is None: rejected += 1; continue
                    results.append((i, c, src or "unknown"))
                results.sort(key=lambda x: (sort_key(x[1]), x[0]))
                for _, c, src in results:
                    if c.endpoint in seen: continue
                    seen.add(c.endpoint); selected.append(c); sources[src] = sources.get(src, 0) + 1
                    if len(selected) >= limit: break
        selected.sort(key=sort_key)
        if len(selected) < min(limit, MIN_PROXIES): raise RuntimeError(f"only {len(selected)} validated UDP candidates remain")
        print(f"        validated={len(selected)} rejected={rejected} sources={sources}")
        print("[4/4] Building and validating configuration...")
        cfg, emitted = build_config(selected)
        write_output(out, cfg, emitted, {"csv_rows": len(rows), "kr_rows": len(kr), "eligible_rows": len(eligible), "homepage_udp_ips": len(homepage), "validated_candidates": len(selected), "emitted_proxies": len(emitted), "rejected_profiles": rejected, "profile_sources": sources})
        print(f"        generated={out / 'vpngate_kr_mihomo.yaml'} proxies={len(emitted)}")
        return 0
    finally:
        main.close()
        with ws_lock: ss = list(worker_sessions)
        for s in ss: s.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Korea Republic VPN Gate UDP OpenVPN subscription for Mihomo.")
    sub = parser.add_subparsers(dest="command")
    g = sub.add_parser("generate"); g.add_argument("--limit", type=int, default=MAX_PROXIES); g.add_argument("--min-speed", type=int, default=0); g.add_argument("--workers", type=int, default=DEFAULT_WORKERS); g.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE); g.add_argument("--out-dir", type=Path, default=Path("build"))
    v = sub.add_parser("validate"); v.add_argument("path", type=Path, default=Path("build/vpngate_kr_mihomo.yaml"))
    a = parser.parse_args()
    if a.command in (None, "generate"):
        limit = MAX_PROXIES if a.command is None else a.limit; min_speed = 0 if a.command is None else a.min_speed; workers = DEFAULT_WORKERS if a.command is None else a.workers; batch = DEFAULT_BATCH_SIZE if a.command is None else a.batch_size; out = Path("build") if a.command is None else a.out_dir
        if not 1 <= limit <= MAX_PROXIES or min_speed < 0 or not 1 <= workers <= 16 or not 1 <= batch <= 32: raise SystemExit("invalid generation arguments")
        return generate(limit, min_speed, workers, batch, out)
    cfg = yaml.safe_load(a.path.read_text(encoding="utf-8"));
    if not isinstance(cfg, dict): raise SystemExit("YAML root must be mapping")
    validate_config(cfg); print(f"validated {a.path}: proxies={len(cfg['proxies'])}"); return 0


if __name__ == "__main__":
    raise SystemExit(main())
