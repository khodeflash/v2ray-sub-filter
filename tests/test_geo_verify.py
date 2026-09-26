import base64
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


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
        a = dict(base, ps="ONE")
        b = dict(base, ps="TWO")
        link_a = "vmess://" + base64.b64encode(
            json.dumps(a).encode()
        ).decode()
        link_b = "vmess://" + base64.b64encode(
            json.dumps(b).encode()
        ).decode()
        self.assertEqual(
            geo.config_fingerprint(link_a),
            geo.config_fingerprint(link_b),
        )

    def test_build_vless_ws_tls(self):
        link = (
            f"vless://{UUID}@1.2.3.4:443"
            "?security=tls&type=ws&host=example.com"
            "&sni=example.com&path=%2Fws&fp=chrome"
        )
        out = geo.build_vless_outbound(link)
        self.assertEqual(out["protocol"], "vless")
        self.assertEqual(out["streamSettings"]["method"], "websocket")
        self.assertEqual(
            out["streamSettings"]["wsSettings"]["host"],
            "example.com",
        )
        self.assertEqual(
            out["streamSettings"]["tlsSettings"]["serverName"],
            "example.com",
        )

    def test_build_vless_raw_reality_uses_password(self):
        link = (
            f"vless://{UUID}@1.2.3.4:443"
            "?security=reality&type=tcp&headerType=none"
            "&sni=www.example.com&fp=chrome"
            "&pbk=PUBLICKEY&sid=0123456789abcdef"
        )
        out = geo.build_vless_outbound(link)
        reality = out["streamSettings"]["realitySettings"]
        self.assertEqual(out["streamSettings"]["method"], "raw")
        self.assertEqual(reality["password"], "PUBLICKEY")
        self.assertEqual(reality["shortId"], "0123456789abcdef")

    def test_build_vless_xhttp(self):
        link = (
            f"vless://{UUID}@example.com:443"
            "?security=tls&type=xhttp&sni=example.com"
            "&path=%2Fabc&mode=stream-up"
            "&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"
        )
        out = geo.build_vless_outbound(link)
        xhttp = out["streamSettings"]["xhttpSettings"]
        self.assertEqual(out["streamSettings"]["method"], "xhttp")
        self.assertEqual(xhttp["path"], "/abc")
        self.assertEqual(xhttp["mode"], "stream-up")
        self.assertEqual(xhttp["extra"]["xPaddingBytes"], "100-1000")

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
        out = geo.build_vmess_outbound(link)
        self.assertEqual(out["protocol"], "vmess")
        self.assertEqual(out["streamSettings"]["method"], "websocket")
        self.assertEqual(
            out["streamSettings"]["tlsSettings"]["serverName"],
            "example.com",
        )

    def test_raw_http_requires_host(self):
        with self.assertRaises(ValueError):
            geo.raw_settings("http", "", "/")

    def test_trace_parser(self):
        ip, country = geo.parse_trace(
            "fl=1\nh=www.cloudflare.com\nip=203.0.113.5\nloc=GB\n"
        )
        self.assertEqual(ip, "203.0.113.5")
        self.assertEqual(country, "GB")


if __name__ == "__main__":
    unittest.main()
