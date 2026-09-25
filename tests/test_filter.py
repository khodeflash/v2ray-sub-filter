import base64
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_subscriptions as app


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.settings = {
            "allow_reality": True,
            "allowed_protocols": ["vless", "trojan", "vmess"],
        }

    def test_shadowsocks_is_rejected(self):
        keep, reason = app.evaluate_link(
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443",
            self.settings,
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "shadowsocks")

    def test_vless_tls_is_accepted(self):
        keep, reason = app.evaluate_link(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws",
            self.settings,
        )
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")

    def test_vless_reality_is_accepted(self):
        keep, reason = app.evaluate_link(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp",
            self.settings,
        )
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")

    def test_vless_none_is_rejected(self):
        keep, reason = app.evaluate_link(
            "vless://11111111-1111-1111-1111-111111111111@example.com:80?security=none&type=ws",
            self.settings,
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "no_allowed_security")

    def test_trojan_tls_is_accepted(self):
        keep, reason = app.evaluate_link(
            "trojan://password@example.com:443?security=tls&type=ws",
            self.settings,
        )
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")

    def test_trojan_without_explicit_security_is_rejected(self):
        keep, reason = app.evaluate_link(
            "trojan://password@example.com:443?type=ws",
            self.settings,
        )
        self.assertFalse(keep)
        self.assertEqual(reason, "no_allowed_security")

    def test_vmess_tls_is_accepted(self):
        data = {
            "v": "2",
            "ps": "test",
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
        keep, reason = app.evaluate_link(f"vmess://{payload}", self.settings)
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")

    def test_vmess_without_tls_is_rejected(self):
        data = {
            "v": "2",
            "ps": "test",
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
        keep, reason = app.evaluate_link(f"vmess://{payload}", self.settings)
        self.assertFalse(keep)
        self.assertEqual(reason, "no_allowed_security")

    def test_duplicate_removal_preserves_order(self):
        values = ["a", "b", "a", "c", "b"]
        self.assertEqual(app.unique_preserving_order(values), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
