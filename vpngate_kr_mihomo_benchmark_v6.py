#!/usr/bin/env python3
from __future__ import annotations

import argparse
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

SCRIPT_VERSION = "v6.0"
API_URL = "https://www.vpngate.net/api/iphone/"
HTML_URL = "https://www.vpngate.net/en/"
OPENVPN_DOWNLOAD_URL = "https://www.vpngate.net/common/openvpn_download.aspx"
DEFAULT_TEST_URL = "https://www.naver.com/"
DEFAULT_EXPECTED_STATUS = "200"
MAX_CSV_PING_MS = 45
DEFAULT_MIN_SPEED = 0
PUBLIC_SUBSCRIPTION = True
USER_AGENT = "Mozilla/5.0 (compatible; VPNGate-KR-Mihomo/6.0)"


class LiteralString(str):
    pass


def _literal_representer(dumper: yaml.SafeDumper, data: LiteralString):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.SafeDumper.add_representer(LiteralString, _literal_representer)


@dataclass
class Candidate:
    hostname: str
    ip: str
    ping: int
    speed_bps: int | None
    score: int | None
    udp_port: int
    sid: str
    hid: str
    ovpn: str


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
    params: dict[str, Any] | None = None,
    timeout: tuple[float, float] = (10, 30),
    attempts: int = 3,
) -> requests.Response:
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            r = session.get(url, params=params, timeout=timeout)
            r.raise_for_status()
            return r
        except (requests.RequestException, OSError) as exc:
            last = exc
            if attempt < attempts:
                time.sleep(min(2.0 * attempt, 5.0))
    raise RuntimeError(f"request failed after {attempts} attempts: {url}") from last


def parse_official_server_page(html: str) -> list[dict[str, Any]]:
    parser = _VPNGateHTMLParser()
    parser.feed(html)
    result: list[dict[str, Any]] = []
    for row in parser.rows:
        row_text = " ".join(_cell_text(c) for c in row)
        if not re.search(r"\bKorea Republic of\b", row_text, re.I):
            continue
        pm = re.search(r"\bPing:\s*(\d+)\s*ms\b", row_text, re.I)
        if not pm:
            continue
        href = next(
            (h for c in row for h in c["hrefs"] if "do_openvpn.aspx?" in h.lower()),
            None,
        )
        if not href:
            continue
        full_href = urljoin(HTML_URL, href)
        q = parse_qs(urlparse(full_href).query)
        fqdn = q.get("fqdn", [""])[0]
        ip = q.get("ip", [""])[0]
        udp_port = int(q.get("udp", ["0"])[0] or 0)
        sid = q.get("sid", [""])[0]
        hid = q.get("hid", [""])[0]
        if not fqdn or not ip or not sid or not hid or udp_port <= 0:
            continue
        sm = re.search(r"\b([\d.,]+)\s*Mbps\b", row_text, re.I)
        speed_bps = None
        if sm:
            try:
                speed_bps = int(float(sm.group(1).replace(",", "")) * 1_000_000)
            except ValueError:
                pass
        score = None
        score_m = re.search(r"\bScore\s*:?\s*([0-9][0-9,]*)\b", row_text, re.I)
        if score_m:
            score = int(score_m.group(1).replace(",", ""))
        hostname = fqdn[:-len(".opengw.net")] if fqdn.lower().endswith(".opengw.net") else fqdn
        result.append({
            "hostname": hostname,
            "ip": ip,
            "ping": int(pm.group(1)),
            "speed_bps": speed_bps,
            "score": score,
            "udp_port": udp_port,
            "sid": sid,
            "hid": hid,
        })
    return result


def detect_openvpn_proto(text: str) -> str:
    global_proto = "udp"
    remotes: list[str] = []
    for raw in text.splitlines():
        line = re.split(r"[#;]", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        fields = line.split()
        directive = fields[0].lower()
        if directive == "proto" and len(fields) >= 2:
            global_proto = fields[1].lower()
        elif directive == "remote" and len(fields) >= 4:
            remotes.append(fields[3].lower())

    def norm(proto: str) -> str:
        if proto in {"udp", "udp4", "udp6"}:
            return "udp"
        if proto in {
            "tcp", "tcp4", "tcp6",
            "tcp-client", "tcp4-client", "tcp6-client",
            "tcp-server", "tcp4-server", "tcp6-server",
        }:
            return "tcp"
        raise ValueError(f"unsupported OpenVPN proto: {proto}")

    gp = norm(global_proto)
    rp = [norm(x) for x in remotes]
    return "tcp" if gp == "tcp" or "tcp" in rp else "udp"


def parse_ovpn(text: str) -> dict[str, Any]:
    remotes: list[tuple[str, int, str | None]] = []
    for raw in text.splitlines():
        line = re.split(r"[#;]", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if fields and fields[0].lower() == "remote" and len(fields) >= 2:
            port = int(fields[2]) if len(fields) >= 3 and fields[2].isdigit() else 1194
            proto_arg = fields[3] if len(fields) >= 4 else None
            remotes.append((fields[1], port, proto_arg))
    if not remotes:
        raise ValueError("missing OpenVPN remote")

    def scalar(name: str) -> str | None:
        for raw in text.splitlines():
            line = re.split(r"[#;]", raw, maxsplit=1)[0].strip()
            fields = line.split(None, 1)
            if len(fields) >= 2 and fields[0].lower() == name.lower():
                return fields[1].strip()
        return None

    def block(tag: str) -> str | None:
        m = re.search(rf"<{tag}>\s*(.*?)\s*</{tag}>", text, re.I | re.S)
        return m.group(1).strip() if m else None

    ca = block("ca")
    ca_m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", ca or "", re.S)
    if not ca_m:
        raise ValueError("missing/invalid <ca>")

    cert = block("cert")
    cert_m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", cert or "", re.S)

    key = block("key")
    key_m = re.search(
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----",
        key or "",
        re.S,
    )
    if not key_m:
        key_m = re.search(r"-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----", key or "", re.S)

    tls_auth = block("tls-auth")
    tls_crypt = block("tls-crypt")
    tls_crypt_v2 = block("tls-crypt-v2")
    if tls_auth and (tls_crypt or tls_crypt_v2):
        raise ValueError("OpenVPN profile contains mutually-exclusive tls-auth and TLS crypt directives")
    if tls_crypt and tls_crypt_v2:
        raise ValueError("OpenVPN profile contains mutually-exclusive tls-crypt and tls-crypt-v2")

    key_direction = scalar("key-direction")
    if tls_auth and key_direction not in {"0", "1"}:
        raise ValueError(f"tls-auth requires key-direction 0 or 1, got {key_direction!r}")

    return {
        "server": remotes[0][0],
        "port": remotes[0][1],
        "proto": detect_openvpn_proto(text),
        "ca": ca_m.group(0).strip(),
        "cert": cert_m.group(0).strip() if cert_m else None,
        "key": key_m.group(0).strip() if key_m else None,
        "tls_auth": tls_auth,
        "tls_crypt": tls_crypt,
        "tls_crypt_v2": tls_crypt_v2,
        "key_direction": key_direction,
        "cipher": scalar("cipher"),
        "auth": scalar("auth"),
        "data_ciphers": scalar("data-ciphers"),
        "data_ciphers_fallback": scalar("data-ciphers-fallback"),
        "comp_lzo": scalar("comp-lzo"),
        "auth_user_pass": bool(re.search(r"^\s*auth-user-pass(?:\s|$)", text, re.I | re.M)),
    }


def clean_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s.strip()).strip("-")[:60] or "node"


def ovpn_to_mihomo(ovpn: str, name: str) -> dict[str, Any]:
    p = parse_ovpn(ovpn)
    node: dict[str, Any] = {
        "name": name,
        "type": "openvpn",
        "server": p["server"],
        "port": p["port"],
        "proto": p["proto"],
        "ca": LiteralString(p["ca"]),
        "udp": True,
    }
    if p["cert"] and p["key"]:
        if PUBLIC_SUBSCRIPTION:
            raise ValueError("client certificate/private key profile rejected for public subscription")
        node["cert"] = LiteralString(p["cert"])
        node["key"] = LiteralString(p["key"])
    elif p["auth_user_pass"]:
        node["username"] = "vpn"
        node["password"] = "vpn"
    else:
        raise ValueError("no usable cert/key or auth-user-pass")

    if p["cipher"]:
        node["cipher"] = p["cipher"]
    if p["auth"]:
        node["auth"] = p["auth"]
    if p["data_ciphers"]:
        node["data-ciphers"] = [x for x in re.split(r"[,:\s]+", p["data_ciphers"].strip()) if x]
    if p["data_ciphers_fallback"]:
        node["data-ciphers-fallback"] = p["data_ciphers_fallback"]
    if p["comp_lzo"]:
        node["comp-lzo"] = p["comp_lzo"]
    if p["tls_auth"]:
        node["tls-auth"] = LiteralString(p["tls_auth"])
        node["key-direction"] = str(p["key_direction"])
    if p["tls_crypt"]:
        node["tls-crypt"] = LiteralString(p["tls_crypt"])
    if p["tls_crypt_v2"]:
        node["tls-crypt-v2"] = LiteralString(p["tls_crypt_v2"])
    return node


def validate_config(config: dict[str, Any], min_proxies: int) -> None:
    proxies = config.get("proxies")
    groups = config.get("proxy-groups")
    rules = config.get("rules")
    if not isinstance(proxies, list) or len(proxies) < min_proxies:
        raise RuntimeError(
            f"generated proxy count {len(proxies) if isinstance(proxies, list) else 0} < required {min_proxies}"
        )
    if not isinstance(groups, list) or not groups:
        raise RuntimeError("missing proxy-groups")
    if not isinstance(rules, list) or "PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST" not in rules:
        raise RuntimeError("expected FreeStyle Reboot routing rule missing")

    names = [p.get("name") for p in proxies if isinstance(p, dict)]
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate proxy names")

    for p in proxies:
        if not isinstance(p, dict) or p.get("type") != "openvpn":
            raise RuntimeError("non-OpenVPN proxy in generated config")
        if p.get("proto") != "udp" or p.get("udp") is not True:
            raise RuntimeError(f"non-UDP proxy emitted: {p.get('name')}")
        if ("username" in p or "password" in p) and ("cert" in p or "key" in p):
            raise RuntimeError(f"mixed OpenVPN authentication modes: {p.get('name')}")
        if PUBLIC_SUBSCRIPTION and ("cert" in p or "key" in p):
            raise RuntimeError(f"private client key material must not be published: {p.get('name')}")
        if "tls-auth" in p and ("tls-crypt" in p or "tls-crypt-v2" in p):
            raise RuntimeError(f"mutually-exclusive TLS modes: {p.get('name')}")
        if "tls-crypt" in p and "tls-crypt-v2" in p:
            raise RuntimeError(f"mutually-exclusive TLS crypt modes: {p.get('name')}")
        if "tls-auth" in p and p.get("key-direction") not in {"0", "1"}:
            raise RuntimeError(f"invalid key-direction: {p.get('name')}")
        for field in ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"):
            value = p.get(field)
            if isinstance(value, str) and "BEGIN " in value and "\n" not in value:
                raise RuntimeError(f"PEM newline corruption: {p.get('name')}:{field}")


def build_config(candidates: list[Candidate], out_path: Path) -> int:
    proxies: list[dict[str, Any]] = []
    names: list[str] = []
    for idx, candidate in enumerate(candidates, 1):
        name = f"KR-{idx:02d}-{clean_name(candidate.hostname or candidate.ip.replace('.', '-'))}"
        try:
            proxies.append(ovpn_to_mihomo(candidate.ovpn, name))
            names.append(name)
        except Exception as exc:
            print(f"[skip] {candidate.hostname or candidate.ip}: {exc}")

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
                "lazy": False,
                "expected-status": 200,
                "disable-udp": False,
            },
            {"name": "KR-SELECT", "type": "select", "proxies": names + ["KR-LOWEST", "DIRECT"]},
        ],
        "rules": ["PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST", "MATCH,DIRECT"],
        "tun": {
            "enable": True,
            "stack": "system",
            "auto-route": True,
            "auto-detect-interface": True,
        },
    }
    validate_config(config, 1)
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
    validate_config(loaded, 1)
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
    expected_status: str | None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    for name in names:
        samples: list[int] = []
        for sample_index in range(max(1, repeat)):
            endpoint = f"{controller.rstrip('/')}/proxies/{quote(name, safe='')}/delay"
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
                value = response.json().get("delay")
                if isinstance(value, int):
                    samples.append(value)
            except (requests.RequestException, ValueError, TypeError):
                pass
            if sample_index + 1 < max(1, repeat):
                time.sleep(max(0.0, pause))

        results.append({
            "name": name,
            "samples_ms": samples,
            "min_ms": min(samples) if samples else None,
            "avg_ms": round(statistics.mean(samples), 2) if samples else None,
            "max_ms": max(samples) if samples else None,
            "jitter_ms": round(statistics.pstdev(samples), 2) if len(samples) >= 2 else None,
            "timeouts": max(1, repeat) - len(samples),
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
    parser.add_argument("--limit", type=int, default=20)
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

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
    })

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("[1/3] Downloading VPN Gate official server page...")
    response = _request(session, HTML_URL)
    servers = parse_official_server_page(response.text)
    if not servers:
        raise RuntimeError("no Korea Republic server rows found")
    print(f"        Korea server rows: {len(servers)}")

    eligible = [
        server
        for server in servers
        if server["ping"] < MAX_CSV_PING_MS
        and server["udp_port"] > 0
        and (
            not args.min_speed
            or (server["speed_bps"] or 0) >= args.min_speed * 1000
        )
    ]
    eligible.sort(
        key=lambda item: (
            item["ping"],
            -(item["speed_bps"] or 0),
            -(item["score"] or 0),
            item["hostname"].lower(),
            item["ip"],
        )
    )
    print(f"        KR + Ping < {MAX_CSV_PING_MS} ms + UDP + speed filter: {len(eligible)}")

    candidates: list[Candidate] = []
    for server in eligible:
        if len(candidates) >= max(0, args.limit):
            break
        filename = f"vpngate_{server['ip']}_udp_{server['udp_port']}.ovpn"
        url = (
            f"{OPENVPN_DOWNLOAD_URL}"
            f"?sid={quote(server['sid'], safe='')}"
            f"&udp=1"
            f"&host={quote(server['ip'], safe='')}"
            f"&port={server['udp_port']}"
            f"&hid={quote(server['hid'], safe='')}"
            f"&/{quote(filename, safe='')}"
        )
        try:
            rr = _request(session, url)
            ovpn = rr.content.decode("utf-8-sig", errors="strict").replace("\r\n", "\n").replace("\r", "\n")
            if "<ca>" not in ovpn.lower() or not re.search(r"(?im)^\s*client\s*$", ovpn):
                raise ValueError("invalid OpenVPN profile")
            if detect_openvpn_proto(ovpn) != "udp":
                raise ValueError("downloaded profile is not UDP")
            parsed = parse_ovpn(ovpn)
            if PUBLIC_SUBSCRIPTION and parsed["key"]:
                raise ValueError("downloaded profile contains client private key material")
            candidates.append(
                Candidate(
                    server["hostname"],
                    server["ip"],
                    server["ping"],
                    server["speed_bps"],
                    server["score"],
                    server["udp_port"],
                    server["sid"],
                    server["hid"],
                    ovpn,
                )
            )
        except Exception as exc:
            print(f"[skip] {server['hostname'] or server['ip']}: {exc}")

    print(f"        selected: {len(candidates)}")
    (out / "source_candidates.json").write_text(
        json.dumps(
            [candidate.__dict__ | {"ovpn": None} for candidate in candidates],
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    yaml_path = out / "vpngate_kr_mihomo.yaml"
    count = build_config(candidates, yaml_path)
    print(f"        generated: {yaml_path}")
    print(f"        YAML proxies: {count}")

    if args.controller:
        print("[3/3] Benchmarking through Mihomo /delay...")
        yaml_config = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        names = [proxy["name"] for proxy in yaml_config["proxies"]]
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
            json.dumps(results, ensure_ascii=False, indent=2),
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


if __name__ == "__main__":
    raise SystemExit(main())
