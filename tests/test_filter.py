import base64
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_subscriptions as app


class FilterTests(unittest.TestCase):
    def test_vless_tls_is_accepted(self):
        keep, reason, protocol, canonical, _ = app.evaluate_link(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws#OldName"
        )
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")
        self.assertEqual(protocol, "vless")
        self.assertNotIn("#OldName", canonical)

    def test_vless_reality_is_rejected(self):
        keep, reason, _, _, _ = app.evaluate_link(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp"
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "not_tls")

    def test_vless_none_is_rejected(self):
        keep, reason, _, _, _ = app.evaluate_link(
            "vless://11111111-1111-1111-1111-111111111111@example.com:80?security=none&type=ws"
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "not_tls")

    def test_trojan_is_rejected(self):
        keep, reason, protocol, _, _ = app.evaluate_link(
            "trojan://password@example.com:443?security=tls&type=ws"
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "trojan")
        self.assertEqual(protocol, "trojan")

    def test_shadowsocks_is_rejected(self):
        keep, reason, protocol, _, _ = app.evaluate_link(
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443"
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "shadowsocks")
        self.assertEqual(protocol, "shadowsocks")

    def test_vmess_tls_is_accepted(self):
        data = {
            "v": "2",
            "ps": "OldName",
            "add": "example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "example.com",
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

    def test_vmess_without_tls_is_rejected(self):
        data = {
            "v": "2",
            "ps": "OldName",
            "add": "example.com",
            "port": "80",
            "id": "11111111-1111-1111-1111-111111111111",
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

    def test_vless_rename_changes_only_fragment(self):
        link = (
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?security=tls&type=ws#OldName"
        )
        renamed = app.rename_vless(link, "US-VLESS-001")
        self.assertTrue(renamed.endswith("#US-VLESS-001"))
        self.assertIn("?security=tls&type=ws", renamed)

    def test_vmess_rename_changes_ps(self):
        config = {
            "v": "2",
            "ps": "OldName",
            "add": "example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "example.com",
            "path": "/",
            "tls": "tls",
        }
        renamed = app.rename_vmess(config, "US-VMESS-001")
        decoded = app.decode_vmess_payload(renamed)
        self.assertEqual(decoded["ps"], "US-VMESS-001")
        self.assertEqual(decoded["add"], "example.com")


if __name__ == "__main__":
    unittest.main()
