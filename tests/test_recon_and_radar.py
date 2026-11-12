import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from common import Fixture, br, cm, recon
import ct_radar as ct
from safe_http import FetchResult


class TestRecon(Fixture):
    def test_cross_target_recon_rejected_without_network(self):
        with patch.object(recon, "fetch") as fetch, self.assertRaises(ValueError):
            recon.run_recon("https://unrelated.example/", self.case)
        fetch.assert_not_called()

    def test_empty_or_failed_fetch_does_not_lock(self):
        with patch.object(recon, "query_direct_dns", return_value={"A": [], "AAAA": []}), patch.object(recon, "query_rdap", return_value={"ok": False}), patch.object(recon, "fetch", side_effect=OSError("offline")):
            report = recon.run_recon("https://suspect.example/product", self.case)
        self.assertEqual(report["capture_status"], "FAILED")
        self.assertEqual(cm.load_case(self.case)["status"], "DISCOVERED")
        self.assertTrue(recon.refresh_case_manifest(self.case)["verified"])

    def test_empty_success_not_usable_evidence(self):
        self.assertEqual(self.capture(b"")["capture_status"], "PARTIAL")
        self.assertEqual(cm.load_case(self.case)["status"], "DISCOVERED")

    def test_raw_non_utf8_preserved(self):
        raw = b"\xff\xfe\x00\x80"; report = self.capture(raw)
        self.assertEqual((self.case / "evidence" / report["capture_id"] / "raw.bin").read_bytes(), raw)

    def test_repeated_capture_preserves_original(self):
        first = self.capture(b"first"); second = self.capture(b"second")
        self.assertNotEqual(first["capture_id"], second["capture_id"])
        self.assertEqual((self.case / "evidence" / first["capture_id"] / "raw.bin").read_bytes(), b"first")
        self.assertEqual(len(cm.load_case(self.case)["captures"]), 2)

    def test_tampering_cannot_be_resealed(self):
        report = self.capture(); directory = self.case / "evidence" / report["capture_id"]
        original = (directory / "evidence-manifest.json").read_bytes()
        (directory / "raw.bin").write_bytes(b"tampered")
        with self.assertRaises(ValueError): recon.refresh_case_manifest(self.case)
        self.assertEqual((directory / "evidence-manifest.json").read_bytes(), original)

    def test_manifest_itself_is_bound_to_case(self):
        report = self.capture(); p = self.case / "evidence" / report["capture_id"] / "evidence-manifest.json"
        p.write_text(p.read_text() + " ")
        with self.assertRaises(ValueError): recon.verify_capture(self.case, report["capture_id"])

    def test_nested_evidence_included(self):
        directory = self.root / "capture"; (directory / "screenshots").mkdir(parents=True)
        (directory / "screenshots" / "page.png").write_bytes(b"image")
        result = recon.build_evidence_manifest(directory, "https://suspect.example/", [], False)
        self.assertEqual(result["files"][0]["filename"], "screenshots/page.png")

    def test_external_symlink_rejected(self):
        directory = self.root / "capture"; directory.mkdir()
        outside = self.root / "secret.txt"; outside.write_text("test")
        (directory / "linked.txt").symlink_to(outside)
        with self.assertRaises(ValueError): recon.build_evidence_manifest(directory, "https://suspect.example/", [], False)

    def test_capture_metadata_hashed(self):
        report = self.capture(); manifest = recon.verify_capture(self.case, report["capture_id"])
        self.assertIn("recon-report.json", [f["filename"] for f in manifest["files"]])

    def test_refresh_preserves_original_time(self):
        report = self.capture(); first = recon.verify_capture(self.case, report["capture_id"])
        result = recon.refresh_case_manifest(self.case)
        self.assertEqual(result["captures"][0]["captured_at_utc"], first["captured_at_utc"])

    def test_no_stale_platform_files_shared(self):
        one = self.capture(b"cdn.shopify.com"); two = self.capture(b"custom site")
        self.assertEqual(one["fingerprints"]["platform_hint"], "shopify")
        self.assertEqual(two["fingerprints"]["platform_hint"], "unknown")

    def test_fingerprints_are_untrusted_leads(self):
        result = recon.extract_storefront_fingerprints("Stripe('pk_live_abcdefghijklmnopqrst'); G-12345678")
        self.assertEqual(result["confidence"], "UNVERIFIED_PAGE_CONTROLLED_LEADS")
        self.assertEqual(len(result["stripe_publishable_keys"]), 1)

    def test_dns_failure_not_authoritative_negative(self):
        with patch.object(recon, "resolve_addresses", side_effect=OSError("timeout")):
            result = recon.query_direct_dns("suspect.example")
        self.assertFalse(result["dns_query_ok"]); self.assertFalse(result["negative_result_verified"])

    def test_rdap_bootstrap_success(self):
        bootstrap = FetchResult("https://data.iana.org/rdap/dns.json", 200, {}, json.dumps({"services": [[["example"], ["https://rdap.provider.example/"]]]}).encode(), "93.184.216.34", ())
        response = FetchResult("https://rdap.provider.example/domain/suspect.example", 200, {}, b'{"objectClassName":"domain","ldhName":"suspect.example"}', "93.184.216.34", ())
        with patch.object(recon, "fetch", side_effect=[bootstrap, response]):
            self.assertTrue(recon.query_rdap("suspect.example")["ok"])

    def test_rdap_failure_explicit(self):
        with patch.object(recon, "fetch", side_effect=OSError("offline")):
            result = recon.query_rdap("suspect.example")
        self.assertFalse(result["ok"]); self.assertTrue(result["manual_lookup_required"])

    def test_wayback_no_false_success(self):
        with self.assertRaises(ValueError): recon.trigger_wayback_save("https://suspect.example/", [])

    def test_user_evidence_appends(self):
        original = self.capture(); source = self.root / "reviewed-image.png"; source.write_bytes(b"image")
        recon.add_evidence(self.case, "https://suspect.example/product", source)
        self.assertEqual(len(cm.load_case(self.case)["captures"]), 2)
        recon.verify_capture(self.case, original["capture_id"])


    def test_reserved_user_evidence_names_rejected(self):
        for name in ("evidence-manifest.json", ".evidence.lock", "recon-report.json", "headers.json"):
            source = self.root / name; source.write_text("synthetic")
            with self.subTest(name=name), self.assertRaises(ValueError):
                recon.add_evidence(self.case, "https://suspect.example/product", source)

    def test_empty_user_evidence_rejected(self):
        source = self.root / "empty.txt"; source.write_bytes(b"")
        with self.assertRaises(ValueError): recon.add_evidence(self.case, "https://suspect.example/product", source)

    def test_malformed_rdap_shape_reports_error(self):
        result = FetchResult("https://data.iana.org/rdap/dns.json", 200, {}, b'{"services":null}', "93.184.216.34", ())
        with patch.object(recon, "fetch", return_value=result):
            self.assertFalse(recon.query_rdap("suspect.example")["ok"])


class TestRadar(Fixture):
    def test_failure_not_successful_empty_scan(self):
        with patch.object(ct, "_fetch_crt_json", side_effect=ValueError("bad JSON")):
            result = ct.run_radar_scan(self.brand, self.profile)
        self.assertEqual(result["status"], "FAILED"); self.assertTrue(result["errors"])

    def test_pending_survives_second_scan(self):
        with patch.object(ct, "_fetch_crt_json", return_value=[{"name_value": "examplebrand-suspect.example"}]):
            first = ct.run_radar_scan(self.brand, self.profile); second = ct.run_radar_scan(self.brand, self.profile)
        self.assertEqual(first["pending_domains"], second["pending_domains"])
        self.assertEqual(second["pending_count"], 1)

    def test_triage_is_explicit(self):
        with patch.object(ct, "_fetch_crt_json", return_value=[{"name_value": "examplebrand-suspect.example"}]):
            ct.run_radar_scan(self.brand, self.profile)
            ct.triage(self.brand, "examplebrand-suspect.example", "REJECTED", "Human Reviewer", "Independent review found unrelated use")
            self.assertEqual(ct.run_radar_scan(self.brand, self.profile)["pending_count"], 0)

    def test_corrupt_seen_state_not_reset(self):
        path = self.brand / "radar_seen.json"; path.write_text("{")
        with patch.object(ct, "_fetch_crt_json", return_value=[]), self.assertRaises(ValueError): ct.run_radar_scan(self.brand, self.profile)
        self.assertEqual(path.read_text(), "{")

    def test_wildcard_allowlist_dedup(self):
        result = ct.extract_candidate_domains_from_crt([{"name_value": "*.bad.example\nbad.example\nshop.brand.example"}], ["brand.example"], set())
        self.assertEqual(result, ["bad.example"])

    def test_cross_brand_profile_rejected(self):
        p = copy.deepcopy(self.profile); p["brand_id"] = "another"
        with self.assertRaises(ValueError): ct.run_radar_scan(self.brand, p)
