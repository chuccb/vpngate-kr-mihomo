import base64
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import vpngate_kr_mihomo as m

PROFILE = '''client\nproto udp\nremote 1.2.3.4 1194\n<ca>\n-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n</ca>\n<cert>\n-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n</cert>\n<key>\n-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n</key>\n'''


def row(profile=PROFILE, **extra):
    data = {
        "HostName": "node",
        "IP": "1.2.3.4",
        "Ping": "5",
        "Speed": "1000",
        "Score": "10",
        "CountryShort": "KR",
        "CountryLong": "Korea Republic of",
        "OpenVPN_ConfigData_Base64": base64.b64encode(profile.encode()).decode(),
    }
    data.update(extra)
    return data


class CoreTests(unittest.TestCase):
    def test_udp_csv_profile_is_used_without_endpoint_lookup(self):
        session = Mock()
        candidate, error, source = m.candidate_task(session, row(), {}, {}, m.threading.Lock())
        self.assertIsNone(error)
        self.assertEqual(source, "csv")
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.endpoint, ("1.2.3.4", 1194))
        session.get.assert_not_called()

    def test_partial_homepage_falls_back_to_per_ip_lookup(self):
        endpoint = m.UdpEndpoint("1.2.3.4", "node.example", "sid", "hid", 1195)
        html = f'''<table><tr><td>Korea Republic of</td><td><a href="/do_openvpn.aspx?ip=1.2.3.4&fqdn=node.example&sid=sid&hid=hid&udp=1195">OpenVPN</a></td></tr></table>'''
        session = Mock()
        response = Mock()
        response.content = PROFILE.replace("1194", "1195").encode()
        response.text = html

        # First call is the per-IP HTML lookup; second is the generated UDP profile.
        session.get.side_effect = [response, response]
        profile, source = m.udp_profile(session, {"IP": "1.2.3.4", "OpenVPN_ConfigData_Base64": ""}, {}, {}, m.threading.Lock())
        self.assertEqual(source, "detail")
        self.assertEqual(m.parse_openvpn(profile)["port"], 1195)
        self.assertEqual(session.get.call_count, 2)
        _ = endpoint

    def test_endpoint_parser_accepts_udp_link_and_deduplicates(self):
        html = '''<table><tr><td>Korea Republic of</td><td><a href="/do_openvpn.aspx?ip=1.2.3.4&fqdn=n&sid=s&hid=h&udp=1194">A</a><a href="/do_openvpn.aspx?ip=1.2.3.4&fqdn=n&sid=s&hid=h&udp=1194">B</a></td></tr></table>'''
        result = m.parse_udp_links(html, require_kr=True)
        self.assertEqual(len(result["1.2.3.4"]), 1)
        self.assertEqual(result["1.2.3.4"][0].port, 1194)

    def test_config_targets_only_game_process_and_keeps_udp(self):
        candidates = [m.Candidate(f"n{i}", f"1.2.3.{i}", i, 1000, 10, "Korea Republic of", "KR", PROFILE.replace("1.2.3.4", f"1.2.3.{i}")) for i in range(1, 4)]
        cfg, emitted = m.build_config(candidates)
        self.assertEqual(len(emitted), 3)
        self.assertEqual(cfg["rules"], ["PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST", "MATCH,DIRECT"])
        self.assertEqual(cfg["tun"]["stack"], "system")
        group = cfg["proxy-groups"][0]
        self.assertEqual(group["timeout"], 3000)
        self.assertEqual(group["tolerance"], 0)
        self.assertFalse(group["lazy"])
        self.assertFalse(group["disable-udp"])

    def test_tls_auth_non_sha1_is_rejected(self):
        profile = PROFILE.replace("</key>", "</key>\nkey-direction 1\n auth SHA512\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\nKEY\n-----END OpenVPN Static key V1-----\n</tls-auth>")
        c = m.Candidate("n", "1.2.3.4", 5, 1000, 1, "Korea Republic of", "KR", profile)
        with self.assertRaises(ValueError):
            m.make_proxy(c)


if __name__ == "__main__":
    unittest.main()
