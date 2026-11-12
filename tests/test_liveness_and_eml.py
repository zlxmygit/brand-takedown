from __future__ import annotations

import email
import email.policy
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from build_eml import create_eml_file  # noqa: E402
from check_liveness import classify_liveness  # noqa: E402


class TestLivenessAndEml(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_dns_clienthold_or_verified_empty_dns_is_confirmed_down(self) -> None:
        res_hold = classify_liveness(
            http_status=0,
            html="",
            dns_ips=[],
            whois_statuses=["clientHold"],
            brand_keywords=["acme"],
            baseline_ips=["104.21.10.2"],
            dns_query_ok=True,
        )
        self.assertEqual(res_hold["verdict"], "CONFIRMED_DOWN_DNS")

    def test_transient_dns_failure_is_not_falsely_marked_down(self) -> None:
        res_net_err = classify_liveness(
            http_status=0,
            html="",
            dns_ips=[],
            whois_statuses=[],
            brand_keywords=["acme"],
            baseline_ips=["104.21.10.2"],
            dns_query_ok=False,
        )
        self.assertEqual(res_net_err["verdict"], "HTTP_ERROR_NEEDS_CROSSCHECK")

    def test_active_store_with_dmca_footer_or_i18n_json_is_not_falsely_down(self) -> None:
        live_fake_html = """
        <html><body>
          <h1>Acme X1 Flagship Edition — 70% OFF</h1>
          <script>window.i18n = {"unavailable": "Sorry, this shop is currently unavailable."};</script>
          <footer><a href="/pages/dmca">DMCA Takedown Policy</a></footer>
        </body></html>
        """
        res = classify_liveness(
            http_status=200,
            html=live_fake_html,
            dns_ips=["23.227.38.65"],
            whois_statuses=["clienttransferprohibited"],
            brand_keywords=["acme", "x1"],
            baseline_ips=["23.227.38.65"],
        )
        self.assertEqual(res["verdict"], "STILL_ACTIVE")

    def test_shopify_unavailable_banner_on_404_is_confirmed_down_platform(self) -> None:
        res = classify_liveness(
            http_status=404,
            html="<html><body><h1>Sorry, this shop is currently unavailable.</h1></body></html>",
            dns_ips=["23.227.38.65"],
            whois_statuses=["clienttransferprohibited"],
            brand_keywords=["acme"],
            baseline_ips=["23.227.38.65"],
        )
        self.assertEqual(res["verdict"], "CONFIRMED_DOWN_PLATFORM")

    def test_http_200_without_brand_keywords_flagged_as_suspected_cloaking(self) -> None:
        res = classify_liveness(
            http_status=200,
            html="<html><body><h1>Classic Cotton T-Shirt Boutique</h1><p>Summer Linen</p></body></html>",
            dns_ips=["104.21.10.2"],
            whois_statuses=["ok"],
            brand_keywords=["acme", "x1"],
            baseline_ips=["104.21.10.2"],
        )
        self.assertEqual(res["verdict"], "SUSPECTED_CLOAKING")

    def test_active_site_with_completely_new_ips_flags_escaped_infra(self) -> None:
        res = classify_liveness(
            http_status=200,
            html="<html><body><h1>Acme X1 Flagship Sale</h1></body></html>",
            dns_ips=["185.199.108.153"],
            whois_statuses=["ok"],
            brand_keywords=["acme", "x1"],
            baseline_ips=["104.21.10.2", "172.67.150.10"],
        )
        self.assertEqual(res["verdict"], "ACTIVE_ESCAPED_INFRA")

    def test_eml_preserves_utf8_chinese_attachment_and_headers(self) -> None:
        pdf_path = self.tmp_path / "外观设计证书(X1)--六视图.pdf"
        png_path = self.tmp_path / "fullpage_evidence.png"
        pdf_bytes = b"%PDF-1.4 mock patent drawing payload"
        png_bytes = b"\x89PNG\r\n\x1a\nmock screenshot"
        pdf_path.write_bytes(pdf_bytes)
        png_path.write_bytes(png_bytes)

        eml_path = self.tmp_path / "notice.eml"
        create_eml_file(
            output_path=eml_path,
            from_addr="legal@acmesport.com",
            to_addrs=["abuse@namecheap.com", "legal@shopify.com"],
            subject="[URGENT] Trademark & Counterfeit Takedown Notice - acmesports.com",
            markdown_or_text_body="Dear Abuse Team,\n\nPlease suspend the infringing domain immediately.",
            attachment_paths=[pdf_path, png_path],
            cc_addrs=["ip@acmesport.com"],
            reply_to="legal@acmesport.com",
        )

        parsed = email.message_from_bytes(eml_path.read_bytes(), policy=email.policy.default)
        self.assertEqual(parsed["From"], "legal@acmesport.com")
        attachments = list(parsed.iter_attachments())
        self.assertEqual(len(attachments), 2)
        self.assertEqual(attachments[0].get_filename(), "外观设计证书(X1)--六视图.pdf")
        self.assertEqual(attachments[0].get_payload(decode=True), pdf_bytes)


if __name__ == "__main__":
    unittest.main()
