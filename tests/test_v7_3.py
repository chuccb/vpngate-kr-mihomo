from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import vpngate_kr_mihomo_benchmark_v6 as base
import vpngate_kr_mihomo_v7_3 as v73


PROFILE_TEMPLATE = """client
proto udp
remote {server} {port}
{tls_auth}
cipher AES-128-CBC
auth {auth}
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


def candidate(name: str, auth: str = "SHA1", tls_auth: bool = False) -> base.Candidate:
    block = ""
    if tls_auth:
        block = "key-direction 1\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\nKEY\n-----END OpenVPN Static key V1-----\n</tls-auth>"
    return base.Candidate(
        hostname=name,
        ip="1.2.3.4",
        ping=5,
        speed_bps=100,
        score=1,
        country_long="Korea Republic of",
        country_short="KR",
        ovpn=PROFILE_TEMPLATE.format(server="1.2.3.4", port=1194, tls_auth=block, auth=auth),
        udp_port=1194,
    )


class V73Tests(unittest.TestCase):
    def test_tls_auth_non_sha1_is_rejected_for_stable_core(self) -> None:
        with self.assertRaisesRegex(ValueError, "tls-auth with non-SHA1"):
            v73._validate_stable_openvpn_compat(candidate("bad", auth="SHA512", tls_auth=True))

    def test_tls_auth_sha1_is_allowed(self) -> None:
        v73._validate_stable_openvpn_compat(candidate("good", auth="SHA1", tls_auth=True))

    def test_low_latency_group_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            count, emitted = v73.build_config_strict_v73([candidate("node")], path)
            self.assertEqual(count, 1)
            self.assertEqual([x.hostname for x in emitted], ["node"])

            cfg = base.yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(cfg["profile"]["store-selected"], True)
            self.assertEqual(cfg["proxy-groups"][0]["timeout"], 3000)
            self.assertEqual(cfg["proxy-groups"][0]["tolerance"], 5)
            self.assertEqual(cfg["proxy-groups"][0]["lazy"], False)
            self.assertEqual(cfg["proxy-groups"][0]["disable-udp"], False)


if __name__ == "__main__":
    unittest.main()
