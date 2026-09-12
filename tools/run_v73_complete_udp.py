#!/usr/bin/env python3
from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any
from urllib.parse import quote

# When a script under tools/ is executed directly, Python puts tools/ (not the
# repository root) on sys.path. Add the root explicitly so the existing
# top-level generator modules remain importable both locally and in CI.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import vpngate_kr_mihomo_benchmark_v6 as base
import vpngate_kr_mihomo_v7_3 as v73

# VPN Gate explicitly says its public server table is partial. v7.3 already
# uses that table as a fast first-pass UDP endpoint index; this runner adds an
# authoritative per-IP lookup only when that index has no endpoint for a
# candidate. That avoids silently dropping UDP servers that are not present in
# the partial homepage table.
_ORIGINAL_FETCH_UDP_PROFILE = base.fetch_udp_profile
_CACHE_LOCK = threading.Lock()
_IP_ENDPOINT_CACHE: dict[str, list[base.UDPEndpoint]] = {}


def _discover_udp_endpoints_for_ip(
    session: Any,
    ip: str,
) -> list[base.UDPEndpoint]:
    with _CACHE_LOCK:
        cached = _IP_ENDPOINT_CACHE.get(ip)
    if cached is not None:
        return cached

    url = f"{base.HTML_URL}?ip={quote(ip, safe='')}"
    response = base._request(
        session,
        url,
        timeout=(10, 20),
        attempts=2,
        accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    )
    discovered = base.parse_official_udp_endpoints(response.text).get(ip, [])

    with _CACHE_LOCK:
        existing = _IP_ENDPOINT_CACHE.get(ip)
        if existing is None:
            _IP_ENDPOINT_CACHE[ip] = list(discovered)
            return list(discovered)
        return existing


def fetch_udp_profile_complete(
    session: Any,
    row: dict[str, str],
    endpoints: dict[str, list[base.UDPEndpoint]],
) -> str:
    ip = row.get("IP", "").strip()
    if ip and not endpoints.get(ip):
        try:
            extra = _discover_udp_endpoints_for_ip(session, ip)
            if extra:
                merged = dict(endpoints)
                merged[ip] = extra
                return _ORIGINAL_FETCH_UDP_PROFILE(session, row, merged)
        except Exception as exc:
            # Preserve the normal v7.3 error path. A per-IP lookup failure must
            # not hide a valid CSV profile or change the candidate semantics.
            print(f"[udp-fallback] {ip}: {exc}")
    return _ORIGINAL_FETCH_UDP_PROFILE(session, row, endpoints)


def main() -> int:
    original = base.fetch_udp_profile
    base.fetch_udp_profile = fetch_udp_profile_complete
    try:
        return v73.main()
    finally:
        base.fetch_udp_profile = original


if __name__ == "__main__":
    raise SystemExit(main())
