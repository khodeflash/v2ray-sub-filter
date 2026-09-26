import base64
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_subscriptions as app


VALID_UUID = "11111111-1111-1111-1111-111111111111"


class FilterTests(unittest.TestCase):
    def test_vless_tls_is_accepted(self):
        keep, reason, protocol, canonical, _ = app.evaluate_link(
            f"vless://{VALID_UUID}@example.com:443?security=tls&type=ws#OldName"
        )
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")
        self.assertEqual(protocol, "vless")
        self.assertNotIn("#OldName", canonical)

    def test_vless_reality_is_accepted_when_complete(self):
        link = (
            f"vless://{VALID_UUID}@example.com:443"
            "?security=reality&type=tcp&headerType=none"
            "&sni=www.example.com&fp=chrome"
            "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "&sid=0123456789abcdef#OldName"
        )
        keep, reason, protocol, _, _ = app.evaluate_link(link)
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")
        self.assertEqual(protocol, "vless")

    def test_vless_reality_missing_public_key_is_rejected(self):
        link = (
            f"vless://{VALID_UUID}@example.com:443"
            "?security=reality&type=tcp&sni=www.example.com&fp=chrome"
        )
        keep, reason, _, _, _ = app.evaluate_link(link)
        self.assertFalse(keep)
        self.assertEqual(reason, "invalid_reality_missing_public_key")

    def test_vless_reality_odd_short_id_is_rejected(self):
        link = (
            f"vless://{VALID_UUID}@example.com:443"
            "?security=reality&type=tcp&sni=www.example.com&fp=chrome"
            "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abc"
        )
        keep, reason, _, _, _ = app.evaluate_link(link)
        self.assertFalse(keep)
        self.assertEqual(reason, "invalid_reality_short_id")

    def test_vless_tcp_http_without_host_is_rejected(self):
        link = (
            f"vless://{VALID_UUID}@example.com:443"
            "?security=tls&type=tcp&headerType=http&path=%2F"
        )
        keep, reason, _, _, _ = app.evaluate_link(link)
        self.assertFalse(keep)
        self.assertEqual(reason, "invalid_http_header_host")

    def test_vless_raw_http_with_host_is_accepted(self):
        link = (
            f"vless://{VALID_UUID}@example.com:443"
            "?security=tls&type=raw&headerType=http"
            "&host=www.example.com&path=%2F"
        )
        keep, reason, _, _, _ = app.evaluate_link(link)
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")

    def test_vless_vision_over_ws_is_rejected(self):
        link = (
            f"vless://{VALID_UUID}@example.com:443"
            "?security=tls&type=ws&flow=xtls-rprx-vision"
        )
        keep, reason, _, _, _ = app.evaluate_link(link)
        self.assertFalse(keep)
        self.assertEqual(reason, "invalid_vision_transport")

    def test_invalid_vless_uuid_is_rejected(self):
        link = "vless://not-a-uuid@example.com:443?security=tls&type=ws"
        keep, reason, _, _, _ = app.evaluate_link(link)
        self.assertFalse(keep)
        self.assertEqual(reason, "invalid_vless_uuid")


    def test_malformed_fragment_metadata_is_rejected(self):
        link = (
            f"vless://{VALID_UUID}@example.com:443"
            "?security=tls&type=ws&host=example.com"
            "&fm={\\\"tcp\\\":[{\\\"type\\\":\\\"fragment\\\""
        )
        keep, reason, _, _, _ = app.evaluate_link(link)
        self.assertFalse(keep)
        self.assertEqual(reason, "invalid_fragment_metadata")

    def test_trojan_is_rejected_from_filtered(self):
        keep, reason, protocol, _, _ = app.evaluate_link(
            "trojan://password@example.com:443?security=tls&type=ws"
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "trojan")
        self.assertEqual(protocol, "trojan")

    def test_shadowsocks_is_rejected_from_filtered(self):
        keep, reason, protocol, _, _ = app.evaluate_link(
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443"
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "shadowsocks")
        self.assertEqual(protocol, "ss")

    def test_vmess_tls_is_accepted(self):
        data = {
            "v": "2",
            "ps": "OldName",
            "add": "example.com",
            "port": "443",
            "id": VALID_UUID,
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "",
            "path": "/",
            "tls": "tls",
        }
        payload = base64.b64encode(json.dumps(data).encode()).decode().rstrip("=")
        keep, reason, protocol, canonical, parsed = app.evaluate_link(
            f"vmess://{payload}"
        )
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")
        self.assertEqual(protocol, "vmess")
        self.assertEqual(parsed["ps"], "OldName")
        self.assertIn('"ps":""', canonical)

    def test_vmess_tcp_http_without_host_is_rejected(self):
        data = {
            "v": "2",
            "ps": "OldName",
            "add": "example.com",
            "port": "443",
            "id": VALID_UUID,
            "aid": "0",
            "net": "tcp",
            "type": "http",
            "host": "",
            "path": "/",
            "tls": "tls",
        }
        payload = base64.b64encode(json.dumps(data).encode()).decode().rstrip("=")
        keep, reason, _, _, _ = app.evaluate_link(f"vmess://{payload}")
        self.assertFalse(keep)
        self.assertEqual(reason, "invalid_http_header_host")

    def test_vmess_without_tls_is_rejected(self):
        data = {
            "v": "2",
            "ps": "OldName",
            "add": "example.com",
            "port": "80",
            "id": VALID_UUID,
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "",
            "path": "/",
            "tls": "",
        }
        payload = base64.b64encode(json.dumps(data).encode()).decode().rstrip("=")
        keep, reason, _, _, _ = app.evaluate_link(f"vmess://{payload}")
        self.assertFalse(keep)
        self.assertEqual(reason, "not_tls")

    def test_generic_uri_remark_rewrite(self):
        original = (
            "trojan://humanity@8.47.69.0:443"
            "?security=tls&type=tcp#OldRemark"
        )
        renamed, success = app.rename_any_config(
            original,
            "US-TROJAN-001",
        )
        self.assertTrue(success)
        self.assertEqual(
            renamed,
            "trojan://humanity@8.47.69.0:443"
            "?security=tls&type=tcp#US-TROJAN-001",
        )

    def test_unfiltered_preserves_invalid_filtered_config(self):
        original = (
            f"vless://{VALID_UUID}@example.com:443"
            "?security=tls&type=tcp&headerType=http#BadForXray"
        )
        output, _, failures = app.build_unfiltered_output([original], "US")
        self.assertEqual(len(output), 1)
        self.assertEqual(failures, 0)
        self.assertTrue(output[0].endswith("#US-VLESS-001"))


if __name__ == "__main__":
    unittest.main()
