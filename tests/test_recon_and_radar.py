from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from ct_radar import extract_candidate_domains_from_crt  # noqa: E402
from recon_target import (  # noqa: E402
    _build_curl_cmd,
    _build_dig_cmd,
    _filter_valid_ips,
    _parse_der_cert_with_openssl,
    build_evidence_manifest,
    extract_storefront_fingerprints,
    parse_whois_summary,
    refresh_case_manifest,
    run_recon,
    trigger_wayback_save,
)


class TestReconAndRadar(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_extract_storefront_fingerprints_shopify_stripe_paypal_and_pixels(self) -> None:
        sample_html = """
        <html><head>
        <script>
          Shopify.shop = "scam-outlet-9921.myshopify.com";
          window.ShopifyAnalytics = {"meta":{"page":{"customerId":null},"shopId":78123456789}};
          var stripe = Stripe('pk_live_51NabcDEF1234567890xyz');
          gtag('config', 'G-9X8Y7Z6W5V');
          fbq('init', '123456789012345');
        </script>
        <script src="https://www.paypal.com/sdk/js?client-id=AbCdEfGhIjKlMnOp123&merchant-id=ZXCVBNM987654"></script>
        </head><body>
          <a href="mailto:support@acmesports.com">Contact</a>
          <a href="https://wa.me/15551234567">WhatsApp</a>
        </body></html>
        """
        headers = "HTTP/2 200\r\nx-shopid: 78123456789\r\nserver: cloudflare\r\n"
        fp = extract_storefront_fingerprints(sample_html, headers)
        self.assertEqual(fp["platform"], "shopify")
        self.assertEqual(fp["shopify_domain"], "scam-outlet-9921.myshopify.com")
        self.assertEqual(fp["shopify_shop_id"], "78123456789")
        self.assertIn("pk_live_51NabcDEF1234567890xyz", fp["stripe_publishable_keys"])
        self.assertIn("ZXCVBNM987654", fp["paypal_identifiers"])
        self.assertIn("G-9X8Y7Z6W5V", fp["ga_ids"])
        self.assertIn("123456789012345", fp["meta_pixel_ids"])

    def test_filter_valid_ips_excludes_cname_strings_and_dig_errors(self) -> None:
        raw_lines = [
            "shop.myshopify.com",
            ";; connection timed out; no servers could be reached",
            "23.227.38.65",
            "2620:127:f00f:5::",
        ]
        self.assertEqual(_filter_valid_ips(raw_lines), ["23.227.38.65", "2620:127:f00f:5::"])

    def test_curl_command_enforces_proto_globoff_suppress_connect_and_noproxy(self) -> None:
        head_cmd = _build_curl_cmd("https://acmesports.com/", head_only=True, proxy=None, referer=None)
        self.assertIn("--proto", head_cmd)
        self.assertIn("=http,https", head_cmd)
        self.assertIn("--globoff", head_cmd)
        self.assertIn("--suppress-connect-headers", head_cmd)
        self.assertIn("--noproxy", head_cmd)
        self.assertEqual(head_cmd[-2:], ["--", "https://acmesports.com/"])

    def test_macos_dig_command_has_no_unsupported_double_dash_and_executes_cleanly(self) -> None:
        import subprocess

        cmd = _build_dig_cmd("example.com", "A")
        self.assertNotIn("--", cmd)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        self.assertNotIn("Invalid option", proc.stdout + proc.stderr)

    def test_macos_libressl_parses_der_certificate_metadata_including_san(self) -> None:
        import subprocess

        key_path = self.base / "key.pem"
        der_path = self.base / "cert.der"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key_path),
                "-out",
                str(der_path),
                "-outform",
                "DER",
                "-days",
                "1",
                "-subj",
                "/CN=acmesports.com",
            ],
            capture_output=True,
            check=True,
        )
        meta = _parse_der_cert_with_openssl(der_path.read_bytes())
        self.assertIn("acmesports.com", meta.get("subject", ""))
        self.assertTrue(bool(meta.get("issuer")))
        self.assertTrue(bool(meta.get("not_before")))
        self.assertTrue(bool(meta.get("not_after")))
        self.assertTrue(bool(meta.get("serial")))

    def test_manifest_excludes_recon_report_and_refresh_syncs_report(self) -> None:
        case_dir = self.base / "case_sync"
        ev_dir = case_dir / "evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        (ev_dir / "raw.html").write_bytes(b"<html>fake</html>")
        (ev_dir / "recon-report.json").write_text('{"evidence_manifest": {}}', encoding="utf-8")

        m1 = build_evidence_manifest(ev_dir, "https://acmesports.com/", ["23.227.38.65"], False)
        names1 = [f["filename"] for f in m1["files"]]
        self.assertIn("raw.html", names1)
        self.assertNotIn("recon-report.json", names1)

        shot = ev_dir / "screenshot.png"
        shot_bytes = b"\x89PNG\r\n\x1a\nshot"
        shot.write_bytes(shot_bytes)
        m2 = refresh_case_manifest(case_dir)
        names2 = [f["filename"] for f in m2["files"]]
        self.assertIn("screenshot.png", names2)
        report_after = json.loads((ev_dir / "recon-report.json").read_text(encoding="utf-8"))
        self.assertEqual(report_after["evidence_manifest"]["files"], m2["files"])
        shot_entry = [f for f in m2["files"] if f["filename"] == "screenshot.png"][0]
        self.assertEqual(shot_entry["sha256"], hashlib.sha256(shot_bytes).hexdigest())

    def test_run_recon_and_wayback_abort_on_allowlist_and_file_scheme(self) -> None:
        with self.assertRaises(ValueError):
            run_recon("https://www.acmesport.com/x1", self.base / "c1", ["acmesport.com"])
        with self.assertRaises(ValueError):
            run_recon("file://localhost/etc/passwd", self.base / "c2", ["acmesport.com"])
        with self.assertRaises(ValueError):
            trigger_wayback_save("https://shop.acmesport.com/", allowlist_domains=["acmesport.com"])

    def test_parse_whois_summary_extracts_registrar_abuse_and_status(self) -> None:
        raw_whois = """
        Registrar: NameCheap, Inc.
        Registrar IANA ID: 1068
        Registrar Abuse Contact Email: abuse@namecheap.com
        Domain Status: clientTransferProhibited
        Name Server: NS1.CLOUDFLARE.COM
        """
        summary = parse_whois_summary(raw_whois)
        self.assertEqual(summary["registrar"], "NameCheap, Inc.")
        self.assertEqual(summary["registrar_iana_id"], "1068")
        self.assertIn("abuse@namecheap.com", summary["abuse_emails"])

    def test_crt_wildcard_and_multiline_dedup_with_allowlist(self) -> None:
        rows = [
            {"name_value": "*.acmesports.com\nacmesports.com"},
            {"name_value": "shop.acmesport.com\nACMEX1.COM"},
            {"name_value": "-invalid.com"},
        ]
        found = extract_candidate_domains_from_crt(rows, ["acmesport.com"], set())
        self.assertEqual(found, ["acmesports.com", "acmex1.com"])


if __name__ == "__main__":
    unittest.main()
