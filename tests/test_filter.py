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

    def test_vless_reality_is_accepted_in_filtered(self):
        keep, reason, protocol, canonical, _ = app.evaluate_link(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp#OldName"
        )
        self.assertTrue(keep)
        self.assertEqual(reason, "accepted")
        self.assertEqual(protocol, "vless")
        self.assertNotIn("#OldName", canonical)

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

    def test_ss_remark_is_added_without_filtering(self):
        original = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443"
        renamed, success = app.rename_any_config(original, "US-SS-001")
        self.assertTrue(success)
        self.assertTrue(renamed.endswith("#US-SS-001"))

    def test_vmess_unfiltered_rename_changes_only_ps(self):
        config = {
            "v": "2",
            "ps": "Advertising Name",
            "add": "example.com",
            "port": "80",
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "example.com",
            "path": "/",
            "tls": "",
        }
        link = "vmess://" + base64.b64encode(
            json.dumps(config).encode()
        ).decode()

        renamed, success = app.rename_any_config(
            link,
            "US-VMESS-001",
        )
        self.assertTrue(success)

        decoded = app.decode_vmess_payload(renamed)
        self.assertEqual(decoded["ps"], "US-VMESS-001")
        self.assertEqual(decoded["tls"], "")
        self.assertEqual(decoded["add"], "example.com")

    def test_unfiltered_output_preserves_count_order_and_duplicates(self):
        lines = [
            "trojan://a@example.com:443?security=tls#one",
            "trojan://a@example.com:443?security=tls#two",
            "vless://id@example.com:443?security=reality#three",
        ]
        output, by_protocol, failures = app.build_unfiltered_output(
            lines,
            "US",
        )

        self.assertEqual(len(output), 3)
        self.assertEqual(failures, 0)
        self.assertTrue(output[0].endswith("#US-TROJAN-001"))
        self.assertTrue(output[1].endswith("#US-TROJAN-002"))
        self.assertTrue(output[2].endswith("#US-VLESS-001"))
        self.assertEqual(by_protocol["trojan"], 2)
        self.assertEqual(by_protocol["vless"], 1)


if __name__ == "__main__":
    unittest.main()
