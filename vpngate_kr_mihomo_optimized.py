#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests
import yaml

import vpngate_kr_mihomo_benchmark_v6 as base

SCRIPT_VERSION = "v7.2"
DEFAULT_WORKERS = 4
DEFAULT_BATCH_SIZE = 8
DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_EXPECTED_STATUS = "204"
_worker_local = threading.local()
_worker_sessions: list[requests.Session] = []
_worker_sessions_lock = threading.Lock()
_UDP_ENDPOINTS: dict[str, list[base.UDPEndpoint]] = {}


def new_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": base.USER_AGENT})
    return session


def worker_session() -> requests.Session:
    session = getattr(_worker_local, "session", None)
    if session is None:
        session = new_session()
        _worker_local.session = session
        with _worker_sessions_lock:
            _worker_sessions.append(session)
    return session


def close_worker_sessions() -> None:
    with _worker_sessions_lock:
        sessions = list(_worker_sessions)
        _worker_sessions.clear()
    for session in sessions:
        session.close()


def validate_candidate(row: dict[str, str]) -> tuple[base.Candidate | None, str | None]:
    try:
        return base.candidate_from_row(row, worker_session(), _UDP_ENDPOINTS), None
    except Exception as exc:
        return None, str(exc)


def endpoint_key(candidate: base.Candidate) -> tuple[str, int]:
    parsed = base.parse_ovpn(candidate.ovpn)
    return base._safe_server(parsed["server"]).lower(), candidate.udp_port


def candidate_order_key(candidate: base.Candidate) -> tuple[Any, ...]:
    return base._candidate_sort_key(candidate)


def collect_candidates(
    eligible_rows: list[dict[str, str]],
    udp_endpoints: dict[str, list[base.UDPEndpoint]],
    limit: int,
    workers: int,
    batch_size: int,
) -> tuple[list[base.Candidate], int]:
    global _UDP_ENDPOINTS
    _UDP_ENDPOINTS = udp_endpoints

    candidates: list[base.Candidate] = []
    seen_endpoints: set[tuple[str, int]] = set()
    invalid_profiles = 0
    cursor = 0

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vpngate") as pool:
        while cursor < len(eligible_rows) and len(candidates) < limit:
            remaining = limit - len(candidates)
            batch_len = min(batch_size, remaining, len(eligible_rows) - cursor)
            batch = eligible_rows[cursor : cursor + batch_len]
            cursor += batch_len

            futures = {
                pool.submit(validate_candidate, row): (index, row)
                for index, row in enumerate(batch)
            }
            batch_candidates: list[tuple[int, base.Candidate]] = []
            for future in as_completed(futures):
                index, row = futures[future]
                candidate, error = future.result()
                if candidate is None:
                    invalid_profiles += 1
                    print(f"[skip] {row.get('HostName') or row.get('IP') or 'unknown'}: {error}")
                    continue
                batch_candidates.append((index, candidate))

            # Restore source priority before endpoint de-duplication. Completion
            # order must never decide which duplicate endpoint wins.
            batch_candidates.sort(key=lambda item: (candidate_order_key(item[1]), item[0]))
            for _, candidate in batch_candidates:
                endpoint = endpoint_key(candidate)
                if endpoint in seen_endpoints:
                    print(f"[skip] {candidate.hostname or candidate.ip}: duplicate UDP endpoint")
                    continue
                seen_endpoints.add(endpoint)
                candidates.append(candidate)
                if len(candidates) >= limit:
                    break

    candidates.sort(key=candidate_order_key)
    return candidates[:limit], invalid_profiles


def build_config_strict(
    candidates: list[base.Candidate],
    out_path: Path,
) -> tuple[int, list[base.Candidate]]:
    proxies: list[dict[str, Any]] = []
    names: list[str] = []
    emitted: list[base.Candidate] = []
    seen_endpoints: set[tuple[str, int]] = set()

    for candidate in candidates:
        endpoint = endpoint_key(candidate)
        if endpoint in seen_endpoints:
            continue
        index = len(proxies) + 1
        clean = base.clean_name(candidate.hostname or candidate.ip.replace(".", "-"))
        name = f"KR-{index:02d}-{clean}"
        try:
            proxy = base.ovpn_to_mihomo(candidate.ovpn, name)
        except Exception as exc:
            print(f"[skip-config] {candidate.hostname or candidate.ip}: {exc}")
            continue
        seen_endpoints.add(endpoint)
        proxies.append(proxy)
        names.append(name)
        emitted.append(candidate)

    config = {
        "mode": "rule",
        "find-process-mode": "strict",
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
    base.validate_config(config, min_proxies=1)
    text = (
        f"# VPN Gate KR Mihomo subscription generated by benchmark {SCRIPT_VERSION}\n"
        + yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=120)
    )
    out_path.write_text(text, encoding="utf-8")
    loaded = yaml.safe_load(text)
    if not isinstance(loaded, dict):
        raise RuntimeError("YAML reload failed")
    base.validate_config(loaded, min_proxies=1)
    return len(proxies), emitted


def write_metadata(out: Path, candidates: list[base.Candidate]) -> None:
    (out / "source_candidates.json").write_text(
        json.dumps(
            {
                "source_api": base.API_URL,
                "source_udp_endpoint_discovery": base.HTML_URL,
                "script_version": SCRIPT_VERSION,
                "base_parser_version": base.SCRIPT_VERSION,
                "ping_threshold_ms_exclusive": base.MAX_CSV_PING_MS,
                "health_check_url": DEFAULT_TEST_URL,
                "health_check_expected_status": int(DEFAULT_EXPECTED_STATUS),
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=base.MAX_PROXIES)
    parser.add_argument("--min-speed", type=int, default=base.DEFAULT_MIN_SPEED)
    parser.add_argument("--out-dir", default="vpngate_kr_benchmark")
    parser.add_argument("--controller", default="")
    parser.add_argument("--secret", default="")
    parser.add_argument("--url", default=DEFAULT_TEST_URL)
    parser.add_argument("--expected-status", default=DEFAULT_EXPECTED_STATUS)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=5000)
    parser.add_argument("--pause", type=float, default=0.3)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args()

    if not 1 <= args.limit <= base.MAX_PROXIES:
        raise SystemExit(f"--limit must be between 1 and {base.MAX_PROXIES}")
    if args.min_speed < 0:
        raise SystemExit("--min-speed must be >= 0")
    if not 1 <= args.workers <= 16:
        raise SystemExit("--workers must be between 1 and 16")
    if not 1 <= args.batch_size <= 32:
        raise SystemExit("--batch-size must be between 1 and 32")
    try:
        expected_status = int(args.expected_status)
    except ValueError as exc:
        raise SystemExit("--expected-status must be an integer HTTP status") from exc
    if not 100 <= expected_status <= 599:
        raise SystemExit("--expected-status must be between 100 and 599")

    main_session = new_session()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    try:
        print("[1/4] Downloading VPN Gate official CSV API...")
        csv_response = base._request(
            main_session, base.API_URL,
            accept="text/csv,text/plain;q=0.9,*/*;q=0.8",
        )
        rows = base.parse_official_csv(csv_response.text)
        print(f"        API rows: {len(rows)}")

        print("[2/4] Discovering official UDP OpenVPN endpoints...")
        html_response = base._request(
            main_session, base.HTML_URL,
            accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        )
        udp_endpoints = base.parse_official_udp_endpoints(html_response.text)
        print(f"        Korea IPs with UDP OpenVPN endpoint(s): {len(udp_endpoints)}")

        kr_rows = [
            row for row in rows
            if row.get("CountryShort", "").strip().upper() == "KR"
            and row.get("CountryLong", "").strip().lower() == "korea republic of"
        ]
        print(f"        Korea Republic of CSV rows: {len(kr_rows)}")

        eligible_rows: list[dict[str, str]] = []
        for row in kr_rows:
            ping = base._int_field(row.get("Ping"), default=None)
            speed = base._int_field(row.get("Speed"), default=None)
            if ping is None or not 0 <= ping < base.MAX_CSV_PING_MS:
                continue
            if args.min_speed and (speed is None or speed < args.min_speed):
                continue
            eligible_rows.append(row)

        eligible_rows.sort(
            key=lambda row: (
                base._int_field(row.get("Ping"), default=10**9),
                -(base._int_field(row.get("Speed"), default=0) or 0),
                -(base._int_field(row.get("Score"), default=0) or 0),
                row.get("HostName", "").lower(),
                row.get("IP", ""),
            )
        )
        print(f"        KR + Ping < {base.MAX_CSV_PING_MS} ms + speed filter: {len(eligible_rows)}")
        print(f"        parallel UDP validation: workers={args.workers}, batch={args.batch_size}")

        candidates, invalid_profiles = collect_candidates(
            eligible_rows, udp_endpoints, args.limit, args.workers, args.batch_size
        )
        if len(candidates) < min(args.limit, base.MIN_PROXIES):
            raise RuntimeError(
                f"only {len(candidates)} valid UDP OpenVPN candidates remain; "
                f"required at least {min(args.limit, base.MIN_PROXIES)}"
            )

        print(f"        valid UDP OpenVPN profiles: {len(candidates)}")
        print(f"        rejected/invalid profiles: {invalid_profiles}")
        print(f"        selected: {len(candidates)}")

        yaml_path = out / "vpngate_kr_mihomo.yaml"
        count, emitted = build_config_strict(candidates, yaml_path)
        if count < min(args.limit, base.MIN_PROXIES):
            raise RuntimeError(
                f"only {count} Mihomo proxies were emitted after final conversion; "
                f"required at least {min(args.limit, base.MIN_PROXIES)}"
            )
        write_metadata(out, emitted)
        print(f"        generated: {yaml_path}")
        print(f"        YAML proxies: {count}")

        if args.controller:
            print("[4/4] Benchmarking through Mihomo /delay...")
            cfg = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            names = [proxy["name"] for proxy in cfg["proxies"]]
            results = base.benchmark(
                names, main_session, args.controller, args.url, args.repeat,
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
            print("[4/4] Live benchmark not requested.")
        return 0
    finally:
        main_session.close()
        close_worker_sessions()


if __name__ == "__main__":
    raise SystemExit(main())
