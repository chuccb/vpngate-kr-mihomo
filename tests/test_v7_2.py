from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import vpngate_kr_mihomo_benchmark_v6 as base
import vpngate_kr_mihomo_optimized as optimized


PROFILE_TEMPLATE = """client
proto udp
remote {server} {port}
<ca>
-----BEGIN CERTIFICATE-----
CA
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
CERT
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
KEY
-----END PRIVATE KEY-----
</key>
"""


def candidate(name: str, server: str, port: int, ping: int, speed: int) -> base.Candidate:
    return base.Candidate(
        hostname=name,
        ip=server,
        ping=ping,
        speed_bps=speed,
        score=0,
        country_long="Korea Republic of",
        country_short="KR",
        ovpn=PROFILE_TEMPLATE.format(server=server, port=port),
        udp_port=port,
    )


class V72Tests(unittest.TestCase):
    def test_endpoint_key_normalizes_server_case(self) -> None:
        item = candidate("node", "Example.COM", 1194, 5, 10)
        self.assertEqual(optimized.endpoint_key(item), ("example.com", 1194))

    def test_parallel_completion_order_cannot_choose_duplicate_endpoint(self) -> None:
        rows = [
            {"HostName": "preferred", "IP": "1.1.1.1"},
            {"HostName": "same-endpoint", "IP": "2.2.2.2"},
        ]
        preferred = candidate("preferred", "1.1.1.1", 1194, 5, 200)
        duplicate = candidate("same-endpoint", "1.1.1.1", 1194, 5, 100)

        def fake_validate(row: dict[str, str]):
            if row["HostName"] == "preferred":
                time.sleep(0.05)
                return preferred, None
            return duplicate, None

        # The lower-priority duplicate deliberately completes first. Source
        # priority, not worker completion order, must decide which one survives.
        with patch.object(optimized, "validate_candidate", side_effect=fake_validate):
            selected, invalid = optimized.collect_candidates(
                rows,
                {},
                limit=2,
                workers=2,
                batch_size=2,
            )

        self.assertEqual(invalid, 0)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].hostname, "preferred")

    def test_parallel_collection_does_not_process_beyond_limit(self) -> None:
        rows = [{"HostName": f"n{i}", "IP": f"1.1.1.{i}"} for i in range(1, 6)]
        calls: list[str] = []

        def fake_validate(row: dict[str, str]):
            calls.append(row["HostName"])
            return candidate(row["HostName"], row["IP"], 1194 + int(row["IP"].split(".")[-1]), 5, 10), None

        with patch.object(optimized, "validate_candidate", side_effect=fake_validate):
            selected, _ = optimized.collect_candidates(
                rows,
                {},
                limit=2,
                workers=2,
                batch_size=8,
            )

        self.assertEqual(len(selected), 2)
        self.assertEqual(len(calls), 2)

    def test_build_config_contains_v72_health_check_process_and_tun_settings(self) -> None:
        items = [candidate("node", "1.2.3.4", 1194, 5, 100)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            count, emitted = optimized.build_config_strict(items, path)
            self.assertEqual(count, 1)
            self.assertEqual([item.hostname for item in emitted], ["node"])

            config = base.yaml.safe_load(path.read_text(encoding="utf-8"))
            group = config["proxy-groups"][0]
            self.assertEqual(config["find-process-mode"], "strict")
            self.assertEqual(config["rules"][0], "PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST")
            self.assertEqual(config["tun"]["enable"], True)
            self.assertEqual(config["tun"]["stack"], "system")
            self.assertEqual(config["tun"]["auto-route"], True)
            self.assertEqual(group["type"], "url-test")
            self.assertEqual(group["url"], "http://www.gstatic.com/generate_204")
            self.assertEqual(group["expected-status"], 204)
            self.assertEqual(group["interval"], 60)
            self.assertEqual(group["timeout"], 5000)
            self.assertEqual(group["max-failed-times"], 2)
            self.assertEqual(group["lazy"], True)
            self.assertEqual(group["tolerance"], 0)
            self.assertEqual(group["disable-udp"], False)

    def test_v72_validator_requires_health_timeout_and_failure_policy(self) -> None:
        items = [candidate("node", "1.2.3.4", 1194, 5, 100)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            optimized.build_config_strict(items, path)
            config = base.yaml.safe_load(path.read_text(encoding="utf-8"))

            broken = dict(config)
            broken_group = dict(config["proxy-groups"][0])
            broken_group["timeout"] = 3000
            broken["proxy-groups"] = [broken_group]
            with self.assertRaisesRegex(RuntimeError, "health-check timeout"):
                optimized._validate_v72_config(broken)

            broken = dict(config)
            broken_group = dict(config["proxy-groups"][0])
            broken_group["max-failed-times"] = 5
            broken["proxy-groups"] = [broken_group]
            with self.assertRaisesRegex(RuntimeError, "max-failed-times"):
                optimized._validate_v72_config(broken)


if __name__ == "__main__":
    unittest.main()
