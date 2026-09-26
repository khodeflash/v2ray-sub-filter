import base64
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import xray_geo_verify as geo


UUID = "11111111-1111-1111-1111-111111111111"


class GeoVerifierTests(unittest.TestCase):
    def test_vless_fingerprint_ignores_remark(self):
        first = f"vless://{UUID}@example.com:443?security=tls&type=ws#ONE"
        second = f"vless://{UUID}@example.com:443?security=tls&type=ws#TWO"

        self.assertEqual(
            geo.config_fingerprint(first),
            geo.config_fingerprint(second),
        )

    def test_vmess_fingerprint_ignores_ps(self):
        base = {
            "v": "2",
            "add": "example.com",
            "port": "443",
            "id": UUID,
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "example.com",
            "path": "/",
            "tls": "tls",
        }

        first = dict(base, ps="ONE")
        second = dict(base, ps="TWO")

        link_first = "vmess://" + base64.b64encode(
            json.dumps(first).encode()
        ).decode()

        link_second = "vmess://" + base64.b64encode(
            json.dumps(second).encode()
        ).decode()

        self.assertEqual(
            geo.config_fingerprint(link_first),
            geo.config_fingerprint(link_second),
        )

    def test_vless_ws_tls_with_ech(self):
        link = (
            f"vless://{UUID}@1.2.3.4:443"
            "?security=tls&type=ws&host=example.com"
            "&sni=example.com&path=%2Fws&fp=chrome"
            "&ech=example.com%2Budp%3A%2F%2F8.8.8.8"
        )

        outbound = geo.build_vless_outbound(link)
        tls = outbound["streamSettings"]["tlsSettings"]

        self.assertEqual(
            outbound["streamSettings"]["method"],
            "websocket",
        )
        self.assertEqual(tls["serverName"], "example.com")
        self.assertEqual(
            tls["echConfigList"],
            "example.com+udp://8.8.8.8",
        )

    def test_vless_ws_path_preserves_early_data_query(self):
        link = (
            f"vless://{UUID}@1.2.3.4:443"
            "?security=tls&type=ws&host=example.com"
            "&sni=example.com&path=%2Fws%3Fed%3D2560"
        )

        outbound = geo.build_vless_outbound(link)

        self.assertEqual(
            outbound["streamSettings"]["wsSettings"]["path"],
            "/ws?ed=2560",
        )

    def test_build_vless_raw_reality(self):
        link = (
            f"vless://{UUID}@1.2.3.4:443"
            "?security=reality&type=tcp&headerType=none"
            "&sni=www.example.com&fp=chrome"
            "&pbk=PUBLICKEY&sid=0123456789abcdef"
        )

        outbound = geo.build_vless_outbound(link)
        reality = outbound["streamSettings"]["realitySettings"]

        self.assertEqual(
            outbound["streamSettings"]["method"],
            "raw",
        )
        self.assertEqual(reality["password"], "PUBLICKEY")
        self.assertEqual(
            reality["shortId"],
            "0123456789abcdef",
        )

    def test_build_vless_xhttp(self):
        link = (
            f"vless://{UUID}@example.com:443"
            "?security=tls&type=xhttp&sni=example.com"
            "&path=%2Fabc&mode=stream-up"
            "&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"
        )

        outbound = geo.build_vless_outbound(link)
        xhttp = outbound["streamSettings"]["xhttpSettings"]

        self.assertEqual(
            outbound["streamSettings"]["method"],
            "xhttp",
        )
        self.assertEqual(xhttp["path"], "/abc")
        self.assertEqual(xhttp["mode"], "stream-up")
        self.assertEqual(
            xhttp["extra"]["xPaddingBytes"],
            "100-1000",
        )

    def test_build_vmess_tls(self):
        data = {
            "v": "2",
            "ps": "US-VMESS-001",
            "add": "1.2.3.4",
            "port": "443",
            "id": UUID,
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "example.com",
            "path": "/ws",
            "tls": "tls",
            "sni": "example.com",
        }

        link = "vmess://" + base64.b64encode(
            json.dumps(data).encode()
        ).decode()

        outbound = geo.build_vmess_outbound(link)

        self.assertEqual(outbound["protocol"], "vmess")
        self.assertEqual(
            outbound["streamSettings"]["method"],
            "websocket",
        )
        self.assertEqual(
            outbound["streamSettings"]["tlsSettings"]["serverName"],
            "example.com",
        )

    def test_raw_http_requires_host(self):
        with self.assertRaises(ValueError):
            geo.raw_settings("http", "", "/")

    def test_trace_parser(self):
        ip, country = geo.parse_trace(
            "fl=1\nh=www.cloudflare.com\n"
            "ip=203.0.113.5\nloc=GB\n"
        )

        self.assertEqual(ip, "203.0.113.5")
        self.assertEqual(country, "GB")


    def test_country_slug_uses_friendly_name(self):
        self.assertEqual(
            geo.country_file_slug("DE"),
            "Germany",
        )
        self.assertEqual(
            geo.country_file_slug("GB"),
            "United_Kingdom",
        )

    def test_resolved_geo_is_country_agnostic(self):
        result = geo.make_result(
            status="geo_resolved",
            stage="geo",
            name="UK-VLESS-001",
            expected="GB",
            detected="DE",
            exit_ip="203.0.113.1",
            latency_ms=100,
            reason="geo_resolved",
            checked_at="2026-09-26T00:00:00Z",
        )

        self.assertEqual(
            result["status"],
            "geo_resolved",
        )
        self.assertEqual(
            result["detected_country"],
            "DE",
        )
        self.assertEqual(
            result["expected_country"],
            "GB",
        )

    def test_cache_version_is_incremented(self):
        self.assertEqual(geo.CACHE_VERSION, 2)


if __name__ == "__main__":
    unittest.main()
