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


def _safe_server(value: Any) -> str:
    return str(value or "").strip()


def _int_field(value: Any, default: int | None = None) -> int | None:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _request(session: requests.Session, url: str, *, accept: str) -> requests.Response:
    response = session.get(
        url,
        headers={"Accept": accept, "User-Agent": USER_AGENT},
        timeout=20,
    )
    response.raise_for_status()
    return response


def parse_official_csv(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        if not row or not row.get("IP"):
            continue
        rows.append({str(k): str(v or "") for k, v in row.items()})
    return rows


class _ServerTableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_row = False
        self._in_cell = False
        self._row: list[str] = []
        self._cell: list[str] = []
        self.rows: list[list[str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "tr":
            self._in_row = True
            self._row = []
        elif self._in_row and tag.lower() in {"td", "th"}:
            self._in_cell = True
            self._cell = []

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"td", "th"} and self._in_cell:
            self._row.append("".join(self._cell).strip())
            self._cell = []
            self._in_cell = False
        elif tag == "tr" and self._in_row:
            if self._row:
                self.rows.append(self._row)
            self._row = []
            self._in_row = False


def parse_official_udp_endpoints(text: str) -> dict[str, list[UDPEndpoint]]:
    parser = _ServerTableParser()
    parser.feed(text)
    result: dict[str, list[UDPEndpoint]] = {}
    for row in parser.rows:
        if len(row) < 8:
            continue
        ip = row[0].strip()
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if "UDP" not in row[6].upper() or "OPENVPN" not in row[6].upper():
            continue
        sid = row[-3].strip() if len(row) >= 3 else ""
        hid = row[-2].strip() if len(row) >= 2 else ""
        ports = re.findall(r"\b(\d{2,5})\b", row[7]) if len(row) > 7 else []
        if not ports:
            continue
        for port_text in ports:
            port = int(port_text)
            if not 1 <= port <= 65535:
                continue
            endpoint = UDPEndpoint(
                ip=ip,
                fqdn=row[1].strip() if len(row) > 1 else "",
                sid=sid,
                hid=hid,
                port=port,
            )
            result.setdefault(ip, []).append(endpoint)
    return result


def _decode_b64(value: str) -> str:
    return base64.b64decode(value.replace("\n", ""), validate=False).decode("utf-8", "replace")


def _first_remote(ovpn: str) -> tuple[str, int] | None:
    for line in ovpn.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[0].lower() == "remote":
            try:
                return _safe_server(parts[1]), int(parts[2])
            except ValueError:
                return None
    return None


def parse_ovpn(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    remote = _first_remote(text)
    if remote is None:
        raise RuntimeError("OpenVPN profile has no valid remote")
    result["server"], result["port"] = remote
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower == "proto udp":
            result["proto"] = "udp"
        elif lower == "proto tcp":
            result["proto"] = "tcp"
        elif lower.startswith("cipher "):
            result["cipher"] = stripped.split(None, 1)[1].strip()
        elif lower.startswith("auth "):
            result["auth"] = stripped.split(None, 1)[1].strip()
        elif lower.startswith("comp-lzo"):
            parts = stripped.split(None, 1)
            result["comp-lzo"] = parts[1].strip() if len(parts) == 2 else "adaptive"
        elif lower.startswith("data-ciphers "):
            result["data-ciphers"] = [x.strip() for x in stripped.split(None, 1)[1].split(":") if x.strip()]
        elif lower.startswith("data-ciphers-fallback "):
            result["data-ciphers-fallback"] = stripped.split(None, 1)[1].strip()
        elif lower.startswith("key-direction "):
            result["key-direction"] = stripped.split(None, 1)[1].strip()
        elif lower == "auth-user-pass":
            result["auth-user-pass"] = True

    for block in PEM_FIELDS:
        pattern = re.compile(rf"<({re.escape(block)})>(.*?)</\1>", re.IGNORECASE | re.DOTALL)
        match = pattern.search(text)
        if match:
            result[block] = match.group(2).strip() + "\n"

    return result


def _extract_auth_material(parsed: dict[str, Any]) -> dict[str, Any]:
    has_cert = "cert" in parsed
    has_key = "key" in parsed
    has_userpass = bool(parsed.get("auth-user-pass"))
    if has_cert != has_key:
        raise RuntimeError("OpenVPN profile has incomplete certificate authentication material")
    if has_userpass and (has_cert or has_key):
        raise RuntimeError("OpenVPN profile mixes auth-user-pass with client certificate authentication")
    if not has_userpass and not has_cert:
        raise RuntimeError("OpenVPN profile has no supported authentication mode")
    return parsed


def _candidate_sort_key(candidate: "Candidate") -> tuple[Any, ...]:
    return (
        candidate.ping,
        -candidate.speed_bps,
        -candidate.score,
        (candidate.hostname or "").lower(),
        candidate.ip,
        candidate.udp_port,
    )


def clean_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-_")
    return cleaned or "node"


@dataclass(frozen=True)
class Candidate:
    hostname: str
    ip: str
    ping: int
    speed_bps: int
    score: int
    country_long: str
    country_short: str
    ovpn: str
    udp_port: int


def _download_udp_profile(
    session: requests.Session,
    endpoints: list[UDPEndpoint],
) -> str:
    last_error: Exception | None = None
    for endpoint in endpoints:
        try:
            response = _request(
                session,
                endpoint.url,
                accept="application/x-openvpn-profile,text/plain,*/*;q=0.8",
            )
            text = response.text
            parsed = parse_ovpn(text)
            if parsed.get("proto") == "udp":
                return text
            raise RuntimeError("downloaded profile is not UDP")
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"unable to download a valid UDP profile: {last_error}")


def candidate_from_row(
    row: dict[str, str],
    session: requests.Session,
    udp_endpoints: dict[str, list[UDPEndpoint]],
) -> Candidate:
    ip = _safe_server(row.get("IP"))
    if not ip:
        raise RuntimeError("missing IP")
    ping = _int_field(row.get("Ping"), default=None)
    speed = _int_field(row.get("Speed"), default=None)
    score = _int_field(row.get("Score"), default=None)
    if ping is None or speed is None or score is None:
        raise RuntimeError("missing numeric CSV field")

    raw = _decode_b64(row.get("OpenVPN_ConfigData_Base64", ""))
    parsed = parse_ovpn(raw)
    ovpn = raw
    if parsed.get("proto") != "udp":
        endpoints = udp_endpoints.get(ip, [])
        if not endpoints:
            raise RuntimeError("CSV profile is not UDP and no UDP endpoint was found on the official server table")
        ovpn = _download_udp_profile(session, endpoints)
        parsed = parse_ovpn(ovpn)

    if parsed.get("proto") != "udp":
        raise RuntimeError("profile is not UDP")
    _extract_auth_material(parsed)
    actual_server = _safe_server(parsed.get("server"))
    actual_port = _int_field(parsed.get("port"), default=None)
    if not actual_server or actual_port is None or not 1 <= actual_port <= 65535:
        raise RuntimeError("invalid UDP endpoint in OpenVPN profile")

    return Candidate(
        hostname=row.get("HostName", "").strip(),
        ip=ip,
        ping=ping,
        speed_bps=speed,
        score=score,
        country_long=row.get("CountryLong", "").strip(),
        country_short=row.get("CountryShort", "").strip().upper(),
        ovpn=ovpn,
        udp_port=actual_port,
    )


def _pem_or_text(value: str) -> LiteralString:
    return LiteralString(value if value.endswith("\n") else value + "\n")


def ovpn_to_mihomo(ovpn: str, name: str) -> dict[str, Any]:
    parsed = parse_ovpn(ovpn)
    proto = parsed.get("proto")
    if proto != "udp":
        raise RuntimeError("only UDP OpenVPN profiles are supported")
    _extract_auth_material(parsed)
    server = _safe_server(parsed.get("server"))
    port = _int_field(parsed.get("port"), default=None)
    if not server or port is None or not 1 <= port <= 65535:
        raise RuntimeError("invalid OpenVPN server/port")

    proxy: dict[str, Any] = {
        "name": name,
        "type": "openvpn",
        "server": server,
        "port": port,
        "proto": "udp",
        "udp": True,
    }
    if "username" in parsed:
        proxy["username"] = parsed["username"]
    if "password" in parsed:
        proxy["password"] = parsed["password"]
    for field in PEM_FIELDS:
        if field in parsed:
            proxy[field] = _pem_or_text(parsed[field])
    for field in ("cipher", "auth", "comp-lzo", "data-ciphers", "data-ciphers-fallback", "key-direction"):
        if field in parsed:
            proxy[field] = parsed[field]
    return proxy


def validate_config(
    config: dict[str, Any],
    min_proxies: int = 1,
    *,
    expected_test_url: str | None = None,
    expected_status: int | None = None,
) -> None:
    proxies = config.get("proxies")
    groups = config.get("proxy-groups")
    rules = config.get("rules")
    tun = config.get("tun")
    if not isinstance(proxies, list) or len(proxies) < min_proxies:
        raise RuntimeError("insufficient proxies")
    if not isinstance(groups, list) or len(groups) != 1:
        raise RuntimeError("expected exactly one proxy group")
    if not isinstance(tun, dict) or tun.get("enable") is not True:
        raise RuntimeError("TUN configuration missing/disabled")
    if tun.get("stack") != "system" or tun.get("auto-route") is not True or tun.get("auto-detect-interface") is not True:
        raise RuntimeError("unexpected TUN routing settings")
    if not isinstance(rules, list) or "PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST" not in rules:
        raise RuntimeError("FreeStyle Reboot process rule missing")

    names: list[str] = []
    for proxy in proxies:
        if not isinstance(proxy, dict) or proxy.get("type") != "openvpn":
            raise RuntimeError("unexpected proxy type")
        if proxy.get("proto") != "udp" or proxy.get("udp") is not True:
            raise RuntimeError(f"non-UDP proxy: {proxy.get('name')}")
        name = proxy.get("name")
        if not isinstance(name, str) or not name:
            raise RuntimeError("proxy name missing")
        names.append(name)
        server = _safe_server(proxy.get("server"))
        port = _int_field(proxy.get("port"), default=None)
        if not server or port is None or not 1 <= port <= 65535:
            raise RuntimeError(f"invalid OpenVPN endpoint: {name}")

        has_userpass = "username" in proxy or "password" in proxy
        has_cert = "cert" in proxy
        has_key = "key" in proxy
        if has_cert != has_key or (has_userpass and (has_cert or has_key)) or (not has_userpass and not has_cert):
            raise RuntimeError(f"invalid OpenVPN authentication mode: {name}")
        if "tls-auth" in proxy and ("tls-crypt" in proxy or "tls-crypt-v2" in proxy):
            raise RuntimeError(f"mutually-exclusive TLS settings: {name}")
        if "tls-crypt" in proxy and "tls-crypt-v2" in proxy:
            raise RuntimeError(f"mutually-exclusive TLS crypt settings: {name}")
        if "tls-auth" in proxy and proxy.get("key-direction") not in {"0", "1"}:
            raise RuntimeError(f"invalid key-direction: {name}")

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
    test_url = DEFAULT_TEST_URL if expected_test_url is None else expected_test_url
    status = int(DEFAULT_EXPECTED_STATUS) if expected_status is None else int(expected_status)
    if lowest.get("url") != test_url:
        raise RuntimeError("unexpected health-check URL")
    if lowest.get("interval") != 60 or lowest.get("timeout") != 3000:
        raise RuntimeError("unexpected health-check timing")
    if lowest.get("tolerance") != 0:
        raise RuntimeError("KR-LOWEST tolerance must remain 0")
    if lowest.get("lazy") is not True:
        raise RuntimeError("KR-LOWEST lazy mode must be enabled")
    if lowest.get("expected-status") != status:
        raise RuntimeError("unexpected expected-status")
    if lowest.get("disable-udp") is not False:
        raise RuntimeError("KR-LOWEST must keep UDP enabled")


def build_config(candidates: list[Candidate], out_path: Path) -> int:
    proxies: list[dict[str, Any]] = []
    names: list[str] = []
    seen_endpoints: set[tuple[str, int]] = set()

    for candidate in candidates:
        server = _safe_server(candidate.ovpn and parse_ovpn(candidate.ovpn).get("server"))
        endpoint = (server.lower(), candidate.udp_port)
        if endpoint in seen_endpoints:
            continue
        clean = clean_name(candidate.hostname or candidate.ip.replace(".", "-"))
        index = len(proxies) + 1
        name = f"KR-{index:02d}-{clean}"
        proxy = ovpn_to_mihomo(candidate.ovpn, name)
        seen_endpoints.add(endpoint)
        proxies.append(proxy)
        names.append(name)

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
                "expected-status": int(DEFAULT_EXPECTED_STATUS),
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
    text = (
        f"# VPN Gate KR Mihomo subscription generated by benchmark {SCRIPT_VERSION}\n"
        + yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=120)
    )
    out_path.write_text(text, encoding="utf-8")
    return len(proxies)


def benchmark(
    names: list[str],
    session: requests.Session,
    controller: str,
    url: str,
    repeat: int,
    timeout_ms: int,
    secret: str | None,
    pause: float,
    expected_status: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    headers = {"User-Agent": USER_AGENT}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    for name in names:
        samples: list[float] = []
        timeouts = 0
        for _ in range(repeat):
            started = time.perf_counter()
            try:
                response = session.get(
                    f"{controller.rstrip('/')}/proxies/{quote(name, safe='')}/delay",
                    params={"url": url, "timeout": timeout_ms, "expected-status": expected_status},
                    headers=headers,
                    timeout=max(5, timeout_ms / 1000 + 3),
                )
                response.raise_for_status()
                elapsed = (time.perf_counter() - started) * 1000
                samples.append(elapsed)
            except Exception:
                timeouts += 1
            if pause > 0:
                time.sleep(pause)
        if samples:
            results.append(
                {
                    "name": name,
                    "avg_ms": round(statistics.mean(samples), 2),
                    "min_ms": round(min(samples), 2),
                    "max_ms": round(max(samples), 2),
                    "jitter_ms": round(statistics.pstdev(samples), 2) if len(samples) > 1 else 0.0,
                    "timeouts": timeouts,
                }
            )
        else:
            results.append(
                {
                    "name": name,
                    "avg_ms": None,
                    "min_ms": None,
                    "max_ms": None,
                    "jitter_ms": None,
                    "timeouts": timeouts,
                }
            )
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=MAX_PROXIES)
    parser.add_argument("--min-speed", type=int, default=DEFAULT_MIN_SPEED)
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

    try:
        expected_status = int(args.expected_status)
    except ValueError as exc:
        raise SystemExit("--expected-status must be an integer HTTP status") from exc
    if not 100 <= expected_status <= 599:
        raise SystemExit("--expected-status must be between 100 and 599")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    try:
        print("[1/3] Downloading VPN Gate official CSV...")
        csv_response = _request(
            session, API_URL,
            accept="text/csv,text/plain;q=0.9,*/*;q=0.8",
        )
        rows = parse_official_csv(csv_response.text)
        print(f"        total rows: {len(rows)}")

        print("[2/3] Selecting KR + OpenVPN candidates...")
        udp_response = _request(
            session, HTML_URL,
            accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        )
        udp_endpoints = parse_official_udp_endpoints(udp_response.text)

        kr_rows = [
            row for row in rows
            if row.get("CountryShort", "").strip().upper() == "KR"
            and row.get("CountryLong", "").strip().lower() == "korea republic of"
        ]
        candidates: list[Candidate] = []
        for row in kr_rows:
            ping = _int_field(row.get("Ping"), default=None)
            speed = _int_field(row.get("Speed"), default=None)
            if ping is None or not 0 <= ping < MAX_CSV_PING_MS:
                continue
            if args.min_speed and (speed is None or speed < args.min_speed):
                continue
            try:
                candidates.append(candidate_from_row(row, session, udp_endpoints))
            except Exception as exc:
                print(f"[skip] {row.get('HostName') or row.get('IP') or 'unknown'}: {exc}")
            if len(candidates) >= args.limit:
                break

        candidates.sort(key=_candidate_sort_key)
        candidates = candidates[:args.limit]
        if len(candidates) < min(args.limit, MIN_PROXIES):
            raise RuntimeError(
                f"only {len(candidates)} valid UDP OpenVPN candidates remain; "
                f"required at least {min(args.limit, MIN_PROXIES)}"
            )
        print(f"        selected: {len(candidates)}")

        yaml_path = out / "vpngate_kr_mihomo.yaml"
        count = build_config(candidates, yaml_path)
        if count < min(args.limit, MIN_PROXIES):
            raise RuntimeError(
                f"only {count} Mihomo proxies were emitted after final conversion; "
                f"required at least {min(args.limit, MIN_PROXIES)}"
            )
        print(f"        generated: {yaml_path}")
        print(f"        YAML proxies: {count}")

        if args.controller:
            print("[3/3] Benchmarking through Mihomo /delay...")
            cfg = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            names = [proxy["name"] for proxy in cfg["proxies"]]
            results = benchmark(
                names, session, args.controller, args.url, args.repeat,
                args.timeout, args.secret or None, args.pause,
                str(expected_status),
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
            print("[3/3] Live benchmark not requested.")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())