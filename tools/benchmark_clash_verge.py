#!/usr/bin/env python3
from __future__ import annotations

import argparse
import statistics
import sys
import time
from typing import Any
from urllib.parse import quote

import requests

DEFAULT_CONTROLLER = "http://127.0.0.1:9090"
DEFAULT_URL = "http://www.gstatic.com/generate_204"
DEFAULT_EXPECTED_STATUS = "204"
DEFAULT_TIMEOUT_MS = 5000
DEFAULT_REPEAT = 5
DEFAULT_PAUSE = 0.3


def request_json(
    session: requests.Session,
    url: str,
    *,
    timeout_seconds: float,
    headers: dict[str, str],
) -> Any:
    response = session.get(url, timeout=timeout_seconds, headers=headers)
    response.raise_for_status()
    return response.json()


def test_proxy(
    session: requests.Session,
    controller: str,
    name: str,
    url: str,
    expected_status: str,
    timeout_ms: int,
    repeat: int,
    pause: float,
    headers: dict[str, str],
) -> dict[str, Any]:
    samples: list[int] = []
    errors: list[str] = []
    endpoint = f"{controller.rstrip('/')}/proxies/{quote(name, safe='')}/delay"

    for index in range(repeat):
        try:
            response = session.get(
                endpoint,
                params={
                    "url": url,
                    "timeout": timeout_ms,
                    "expected": expected_status,
                },
                headers=headers,
                timeout=timeout_ms / 1000 + 2,
            )
            response.raise_for_status()
            data = response.json()
            delay = data.get("delay") if isinstance(data, dict) else None
            if isinstance(delay, int) and delay >= 0:
                samples.append(delay)
            else:
                errors.append(f"unexpected response: {data!r}")
        except (requests.RequestException, ValueError, TypeError) as exc:
            errors.append(str(exc))

        if index + 1 < repeat:
            time.sleep(max(0.0, pause))

    return {
        "name": name,
        "samples_ms": samples,
        "min_ms": min(samples) if samples else None,
        "avg_ms": round(statistics.mean(samples), 2) if samples else None,
        "max_ms": max(samples) if samples else None,
        "jitter_ms": round(statistics.pstdev(samples), 2) if len(samples) >= 2 else None,
        "failures": repeat - len(samples),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark OpenVPN proxies in the current Mihomo/Clash Verge controller without changing configuration."
    )
    parser.add_argument("--controller", default=DEFAULT_CONTROLLER)
    parser.add_argument("--secret", default="")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--expected-status", default=DEFAULT_EXPECTED_STATUS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT)
    parser.add_argument("--pause", type=float, default=DEFAULT_PAUSE)
    args = parser.parse_args()

    if not 1000 <= args.timeout <= 30000:
        raise SystemExit("--timeout must be between 1000 and 30000 ms")
    if not 1 <= args.repeat <= 20:
        raise SystemExit("--repeat must be between 1 and 20")
    if args.pause < 0:
        raise SystemExit("--pause must be >= 0")
    try:
        expected_status = int(args.expected_status)
    except ValueError as exc:
        raise SystemExit("--expected-status must be an integer HTTP status") from exc
    if not 100 <= expected_status <= 599:
        raise SystemExit("--expected-status must be between 100 and 599")

    headers = {"Authorization": f"Bearer {args.secret}"} if args.secret else {}
    session = requests.Session()
    session.headers.update({"User-Agent": "VPNGate-KR-Mihomo-local-benchmark/1.0"})

    try:
        payload = request_json(
            session,
            f"{args.controller.rstrip('/')}/proxies",
            timeout_seconds=5,
            headers=headers,
        )
    except (requests.RequestException, ValueError) as exc:
        print(f"Failed to query Mihomo controller: {exc}", file=sys.stderr)
        return 1

    proxies = payload.get("proxies") if isinstance(payload, dict) else None
    if not isinstance(proxies, dict):
        print("Mihomo /proxies response does not contain a proxies object.", file=sys.stderr)
        return 1

    names = sorted(
        name
        for name, item in proxies.items()
        if isinstance(item, dict)
        and str(item.get("type", "")).lower() == "openvpn"
        and name.startswith("KR-")
    )
    if not names:
        print("No KR OpenVPN proxies found in the current Mihomo controller.", file=sys.stderr)
        return 1

    print(f"Controller : {args.controller}")
    print(f"Test URL   : {args.url}")
    print(f"Expected   : HTTP {expected_status}")
    print(f"Timeout    : {args.timeout} ms")
    print(f"Repeat     : {args.repeat}")
    print(f"OpenVPN    : {len(names)}")
    print()
    print("Name\t\t\tmin\tavg\tmax\tjitter\tfailures")

    results: list[dict[str, Any]] = []
    for name in names:
        result = test_proxy(
            session,
            args.controller,
            name,
            args.url,
            str(expected_status),
            args.timeout,
            args.repeat,
            args.pause,
            headers,
        )
        results.append(result)
        print(
            f"{name}\t{result['min_ms']}\t{result['avg_ms']}\t{result['max_ms']}\t"
            f"{result['jitter_ms']}\t{result['failures']}"
        )
        for error in result["errors"][:2]:
            print(f"  ERROR: {error}")

    live = [item for item in results if item["avg_ms"] is not None]
    print()
    print(f"Live proxies: {len(live)}/{len(results)}")
    if live:
        best = min(live, key=lambda item: (item["avg_ms"], item["jitter_ms"] or 10**9))
        print(f"Best average delay: {best['name']} = {best['avg_ms']} ms")
    return 0 if live else 2


if __name__ == "__main__":
    raise SystemExit(main())
