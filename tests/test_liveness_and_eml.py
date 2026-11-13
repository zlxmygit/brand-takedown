import email
import email.policy
from unittest.mock import patch

from common import Fixture, br, cm
import check_liveness as lv
from build_eml import create_eml_file
from safe_http import FetchResult


class TestLiveness(Fixture):
    def classify(self, code=200, html="<h1>examplebrand</h1>", ips=None, dns_ok=True, statuses=None):
        return lv.classify_liveness(code, html, ips if ips is not None else ["93.184.216.34"], statuses or [], ["examplebrand"], [], dns_ok)

    def test_dns_empty_does_not_confirm_down_even_with_200(self):
        self.assertEqual(self.classify(ips=[])["verdict"], "UNKNOWN_REQUIRES_REVIEW")

    def test_partial_dns_is_unknown(self):
        self.assertEqual(self.classify(dns_ok=False)["verdict"], "UNKNOWN_REQUIRES_REVIEW")

    def test_hidden_banner_not_down(self):
        result = self.classify(html='<h1>examplebrand shop</h1><div hidden>This store is unavailable</div>')
        self.assertEqual(result["verdict"], "CONTENT_PRESENT")

    def test_visible_banner_only_review_candidate(self):
        self.assertEqual(self.classify(404, "This store is unavailable")["verdict"], "DOWN_CANDIDATE_REVIEW")

    def test_clienthold_not_automatic_case_close(self):
        self.assertEqual(self.classify(statuses=["clientHold"])["verdict"], "DOWN_CANDIDATE_REVIEW")
        self.assertEqual(self.classify(statuses=["client Hold"])["verdict"], "DOWN_CANDIDATE_REVIEW")

    def test_probe_case_with_check_rdap_caches_and_surfaces_hold(self):
        cm.create_case(self.brand, "https://suspect.example/second", ["COPYRIGHT_CLONE"])
        with patch.object(lv, "query_direct_dns", return_value={"A": ["93.184.216.34"], "dns_query_ok": True}), \
             patch.object(lv, "query_rdap", return_value={"ok": True, "queried_domain": "suspect.example",
                                                          "summary": {"status_codes": ["clienthold"]}}) as qrdap, \
             patch.object(lv, "fetch", return_value=FetchResult("https://suspect.example/product", 200, {}, b"examplebrand", "93.184.216.34", ())):
            result = lv.probe_case(self.case, ["examplebrand"], check_rdap=True)
        qrdap.assert_called_once_with("suspect.example")
        self.assertEqual(result["case_status_after_probe"], "DISCOVERED")
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")
        for target in result["targets"]:
            self.assertEqual(target["verdict"], "DOWN_CANDIDATE_REVIEW")
            self.assertEqual(target["rdap_statuses"], ["clienthold"])

    def test_probe_case_with_check_rdap_surfaces_rdap_error_without_blocking(self):
        with patch.object(lv, "query_direct_dns", return_value={"A": ["93.184.216.34"], "dns_query_ok": True}), \
             patch.object(lv, "query_rdap", return_value={"ok": False, "error": "RDAP unavailable"}), \
             patch.object(lv, "fetch", return_value=FetchResult("https://suspect.example/product", 200, {}, b"examplebrand", "93.184.216.34", ())):
            result = lv.probe_case(self.case, ["examplebrand"], check_rdap=True)
        self.assertEqual(result["targets"][0]["verdict"], "CONTENT_PRESENT")
        self.assertEqual(result["targets"][0]["rdap_error"], "RDAP unavailable")

    def test_keywords_in_attributes_not_visible(self):
        self.assertEqual(self.classify(html='<div data-tag="examplebrand">Other</div>')["verdict"], "CONTENT_CHANGED_REVIEW")

    def test_all_urls_and_linked_domains_are_probed(self):
        cm.create_case(self.brand, "https://suspect.example/second", ["COPYRIGHT_CLONE"])
        cm.add_linked_cloak_domain(self.case, "checkout.other.example")
        seen = []
        def fetch(url, *a):
            seen.append(url); return FetchResult(url, 200, {}, b"examplebrand", "93.184.216.34", ())
        with patch.object(lv, "query_direct_dns", return_value={"A": ["93.184.216.34"], "dns_query_ok": True}), patch.object(lv, "fetch", side_effect=fetch):
            result = lv.probe_case(self.case, ["examplebrand"])
        self.assertEqual(len(seen), 3); self.assertEqual(len(result["targets"]), 3)

    def test_counter_notice_never_overwritten(self):
        self.channel(); cm.record_counter_notice(self.case, "host", br.utc_now(), "Review", source_ref="test-message")
        with patch.object(lv, "query_direct_dns", return_value={"A": [], "dns_query_ok": False}), patch.object(lv, "fetch", side_effect=OSError("offline")):
            result = lv.probe_case(self.case, ["examplebrand"])
        self.assertEqual(result["case_status_after_probe"], "COUNTER_NOTICE_ALERT")
        self.assertEqual(cm.scan_due_escalations(self.brand)[0]["kind"], "LEGAL_REVIEW")

    def test_allowlist_added_after_creation_blocks_network(self):
        p = dict(self.profile); p["allowlist_domains"] = ["suspect.example"]
        br.register_brand("example-brand", self.brand, p, self.registry)
        with patch.object(lv, "fetch") as fetch:
            result = lv.probe_case(self.case, ["examplebrand"])
        fetch.assert_not_called(); self.assertIn("error", result["targets"][0])

    def test_corrupt_case_does_not_block_rest_of_patrol(self):
        second, _ = cm.create_case(self.brand, "https://other.example/", ["COPYRIGHT_CLONE"])
        (second / "case.json").write_text("{")
        with patch.object(lv, "query_direct_dns", return_value={"A": [], "dns_query_ok": False}), patch.object(lv, "fetch", side_effect=OSError("offline")):
            result = lv.patrol(self.brand, ["examplebrand"])
        self.assertEqual(result["probed_count"], 1); self.assertEqual(len(result["errors"]), 1)


class TestEml(Fixture):
    def build(self, **changes):
        kwargs = dict(output_path=self.root / "notice.eml", from_addr="legal@brand.example", to_addrs=["abuse@provider.example"], subject="Review notice", markdown_or_text_body="Factual review request", attachment_paths=[])
        kwargs.update(changes); return create_eml_file(**kwargs)

    def test_empty_recipient_rejected(self):
        for recipients in ([], [""], [" "], ["not-mail"]):
            with self.subTest(recipients=recipients), self.assertRaises(ValueError): self.build(to_addrs=recipients)

    def test_header_injection_rejected(self):
        with self.assertRaises(ValueError): self.build(subject="Subject\r\nBcc: other@example.com")
        with self.assertRaises(ValueError): self.build(to_addrs=["abuse@provider.example\nBcc: other@example.com"])

    def test_unfilled_placeholder_rejected(self):
        with self.assertRaises(ValueError): self.build(markdown_or_text_body="Hello {{SIGNATORY_NAME}}")

    def test_unicode_attachments_and_smtp_line_endings(self):
        path = self.root / "测试证据.txt"; path.write_text("合成证据", encoding="utf-8")
        out = self.build(attachment_paths=[path]); raw = out.read_bytes()
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        message = email.message_from_bytes(raw, policy=email.policy.default)
        self.assertEqual(next(message.iter_attachments()).get_filename(), "测试证据.txt")
        self.assertEqual(message["X-Unsent"], "1")

    def test_output_cannot_overwrite_attachment(self):
        path = self.root / "notice.eml"; path.write_bytes(b"original")
        with self.assertRaises(ValueError): self.build(attachment_paths=[path])
        self.assertEqual(path.read_bytes(), b"original")
