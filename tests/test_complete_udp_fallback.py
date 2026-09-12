from __future__ import annotations

import unittest
from unittest.mock import patch

import vpngate_kr_mihomo_benchmark_v6 as base
from tools import run_v73_complete_udp as runner


HTML = """
<table>
<tr>
  <td>Korea Republic of</td>
  <td><a href="/en/do_openvpn.aspx?ip=1.2.3.4&fqdn=vpn.example.com&sid=sid1&hid=hid1&udp=1194">OpenVPN</a></td>
</tr>
</table>
"""

PROFILE = """client
proto udp
remote 1.2.3.4 1194 udp
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


class FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.content = text.encode("utf-8")


class CompleteUDPFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        with runner._CACHE_LOCK:
            runner._IP_ENDPOINT_CACHE.clear()

    def test_per_ip_lookup_fills_partial_homepage_index(self) -> None:
        row = {
            "IP": "1.2.3.4",
            "HostName": "vpn.example.com",
            "OpenVPN_ConfigData_Base64": "",
        }
        calls: list[str] = []

        def fake_request(_session, url, **_kwargs):
            calls.append(url)
            if "?ip=1.2.3.4" in url:
                return FakeResponse(HTML)
            if "/common/openvpn_download.aspx?" in url:
                return FakeResponse(PROFILE)
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(base, "_request", side_effect=fake_request):
            result = runner.fetch_udp_profile_complete(object(), row, {})

        self.assertIn("proto udp", result)
        self.assertEqual(result, PROFILE)
        self.assertEqual(sum("?ip=1.2.3.4" in url for url in calls), 1)
        self.assertEqual(sum("/common/openvpn_download.aspx?" in url for url in calls), 1)

    def test_per_ip_lookup_is_cached(self) -> None:
        row = {
            "IP": "1.2.3.4",
            "HostName": "vpn.example.com",
            "OpenVPN_ConfigData_Base64": "",
        }
        lookup_calls = 0

        def fake_request(_session, url, **_kwargs):
            nonlocal lookup_calls
            if "?ip=1.2.3.4" in url:
                lookup_calls += 1
                return FakeResponse(HTML)
            return FakeResponse(PROFILE)

        with patch.object(base, "_request", side_effect=fake_request):
            runner.fetch_udp_profile_complete(object(), row, {})
            runner.fetch_udp_profile_complete(object(), row, {})

        self.assertEqual(lookup_calls, 1)


if __name__ == "__main__":
    unittest.main()
