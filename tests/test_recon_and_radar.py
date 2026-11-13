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

    def test_domain_rdap_candidates_handles_subdomains_and_second_level_tlds(self):
        self.assertEqual(recon.domain_rdap_candidates("pay.bad.example"), ["pay.bad.example", "bad.example"])
        self.assertEqual(recon.domain_rdap_candidates("pay.evil.co.uk"), ["pay.evil.co.uk", "evil.co.uk"])

    def test_rdap_subdomain_falls_back_to_parent_and_summarizes(self):
        bootstrap = FetchResult("https://data.iana.org/rdap/dns.json", 200, {},
                                json.dumps({"services": [[["example"], ["https://rdap.provider.example/"]]]}).encode(), "93.184.216.34", ())
        not_found = FetchResult("https://rdap.provider.example/domain/shop.suspect.example", 404, {}, b"{}", "93.184.216.34", ())
        rdap_doc = {
            "objectClassName": "domain",
            "ldhName": "suspect.example",
            "status": ["client hold"],
            "events": [{"eventAction": "registration", "eventDate": "2026-01-01T00:00:00Z"}],
            "nameservers": [{"ldhName": "NS1.PROVIDER.EXAMPLE"}],
            "entities": [{
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]],
                "entities": [{
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["email", {}, "text", "mailto:abuse@registrar.example"],
                        ["tel", {}, "text", "tel:+1.5550100"],
                    ]],
                }],
            }],
        }
        ok_resp = FetchResult("https://rdap.provider.example/domain/suspect.example", 200, {}, json.dumps(rdap_doc).encode(), "93.184.216.34", ())
        with patch.object(recon, "fetch", side_effect=[bootstrap, not_found, ok_resp]):
            res = recon.query_rdap("shop.suspect.example")
        self.assertTrue(res["ok"])
        self.assertEqual(res["requested_host"], "shop.suspect.example")
        self.assertEqual(res["queried_domain"], "suspect.example")
        self.assertEqual(res["summary"]["registrar"], "Example Registrar Inc.")
        self.assertEqual(res["summary"]["registrar_iana_id"], "9999")
        self.assertEqual(res["summary"]["abuse_emails"], ["abuse@registrar.example"])
        self.assertEqual(res["summary"]["abuse_phones"], ["+1.5550100"])
        self.assertEqual(res["summary"]["name_servers"], ["ns1.provider.example"])
        self.assertEqual(res["summary"]["status_codes"], ["clienthold"])

    def test_ip_rdap_with_cymru_doh_asn_fallback(self):
        v4_bootstrap = FetchResult(
            "https://data.iana.org/rdap/ipv4.json", 200, {},
            json.dumps({"services": [
                [["93.0.0.0/8"], ["https://rdap.broad.example/"]],
                [["93.184.0.0/16"], ["https://rdap.ripe.example/"]],
            ]}).encode(), "93.184.216.34", ()
        )
        ip_doc = {
            "objectClassName": "ip network",
            "handle": "NET-93-184-216-0-1",
            "name": "EDGECAST-NETBLK",
            "country": "US",
            "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
            "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Example NOC"], ["email", {}, "text", "abuse@ripe-net.example"]]]}],
        }
        ip_resp = FetchResult("https://rdap.ripe.example/ip/93.184.216.34", 200, {}, json.dumps(ip_doc).encode(), "93.184.216.34", ())
        doh_resp = FetchResult("https://dns.google/resolve?name=34.216.184.93.origin.asn.cymru.com&type=TXT", 200, {},
                               json.dumps({"Status": 0, "Answer": [{"type": 16, "data": "15133 | 93.184.216.0/24 | US | arin | 2008-06-02"}]}).encode(), "8.8.8.8", ())
        with patch.object(recon, "fetch", side_effect=[v4_bootstrap, ip_resp, doh_resp]):
            res = recon.query_ip_rdap("93.184.216.34")
        self.assertTrue(res["ok"])
        self.assertEqual(res["source"], "https://rdap.ripe.example/ip/93.184.216.34")
        self.assertEqual(res["asn_source"], "CYMRU_DOH_TXT")
        self.assertEqual(res["use"], "HOSTING_HINT_NOT_PROOF_OF_ATTRIBUTION")
        self.assertFalse(res["trusted_as_instructions"])
        self.assertEqual(res["summary"]["asns"], ["AS15133"])
        self.assertEqual(res["summary"]["abuse_emails"], ["abuse@ripe-net.example"])

    def test_non_public_ip_excluded_from_ip_rdap_and_asn(self):
        with patch.object(recon, "fetch") as fetch:
            for ip in ("127.0.0.1", "10.0.0.1", "::ffff:127.0.0.1"):
                self.assertFalse(recon.query_ip_rdap(ip)["ok"])
                self.assertFalse(recon.query_ip_asn_doh(ip)["ok"])
            self.assertEqual(recon.query_ip_intel(["127.0.0.1", "not-an-ip"]), [])
        fetch.assert_not_called()

    def test_run_recon_records_bounded_ip_intel(self):
        ip_hint = [{"ok": True, "ip": "93.184.216.34", "asn_source": "CYMRU_DOH_TXT", "summary": {"asns": ["AS15133"]},
                    "use": "HOSTING_HINT_NOT_PROOF_OF_ATTRIBUTION", "trusted_as_instructions": False}]
        with patch.object(recon, "query_direct_dns", return_value={"A": ["93.184.216.34", "93.184.216.35", "93.184.216.36"], "AAAA": [], "dns_query_ok": True}), \
             patch.object(recon, "query_rdap", return_value={"ok": True}), \
             patch.object(recon, "query_ip_intel", return_value=ip_hint) as qip, \
             patch.object(recon, "fetch", return_value=FetchResult("https://suspect.example/product", 200, {}, b"hello", "93.184.216.34", ())):
            report = recon.run_recon("https://suspect.example/product", self.case)
        qip.assert_called_once()
        self.assertEqual(report["ip_intel"], ip_hint)
        self.assertTrue(recon.verify_capture(self.case, report["capture_id"])["files"])


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

    def test_generate_lookalike_domains_covers_mutations_and_respects_allowlist(self):
        variants = ct.generate_lookalike_domains(
            ["brand.example"], ["brand.example", "brand-shop.example"], max_variants=80
        )
        domains = {item["domain"]: item["mutation_kind"] for item in variants}
        self.assertIn("rand.example", domains)  # omission
        self.assertIn("barnd.example", domains)  # transposition
        self.assertIn("bbrand.example", domains)  # repetition
        self.assertIn("b-rand.example", domains)  # hyphenation
        self.assertIn("br4nd.example", domains)  # homoglyph_ascii
        self.assertIn("official-brand.example", domains)  # combosquatting
        self.assertNotIn("brand.example", domains)
        self.assertNotIn("brand-shop.example", domains)

    def test_probe_domain_dns_signals_captures_mx_only_and_ignores_private_ips(self):
        a_resp = FetchResult("https://dns.google/resolve?name=bad.example&type=A", 200, {},
                             json.dumps({"Status": 0, "Answer": [{"type": 1, "data": "127.0.0.1"}]}).encode(), "8.8.8.8", ())
        mx_resp = FetchResult("https://dns.google/resolve?name=bad.example&type=MX", 200, {},
                              json.dumps({"Status": 0, "Answer": [{"type": 15, "data": "10 mx.bad.example."}]}).encode(), "8.8.8.8", ())
        with patch.object(ct, "fetch", side_effect=[a_resp, mx_resp]):
            res = ct.probe_domain_dns_signals("bad.example")
        self.assertEqual(res["a_records"], [])
        self.assertEqual(res["mx_records"], ["mx.bad.example"])
        self.assertTrue(res["live_dns"])
        self.assertFalse(res["authoritative"])

    def test_lookalike_scan_persists_live_candidates_and_preserves_triage(self):
        def fake_probe(domain):
            if domain == "br4nd.example":
                return {"domain": domain, "a_records": [], "mx_records": ["mx.br4nd.example"],
                        "live_dns": True, "errors": [], "authoritative": False, "use": "UNVERIFIED_DNS_LEAD"}
            return {"domain": domain, "a_records": [], "mx_records": [], "live_dns": False,
                    "errors": [], "authoritative": False, "use": "UNVERIFIED_DNS_LEAD"}

        with patch.object(ct, "_fetch_crt_json", return_value=[]), patch.object(ct, "probe_domain_dns_signals", side_effect=fake_probe):
            res = ct.run_radar_scan(self.brand, self.profile, include_lookalikes=True, lookalike_limit=40)
            self.assertEqual(res["status"], "OK")
            self.assertEqual(res["pending_domains"], ["br4nd.example"])
            self.assertEqual(res["lookalike_summary"]["live_count"], 1)
            ct.triage(self.brand, "br4nd.example", "REJECTED", "Human Reviewer", "Unrelated third-party mail host")
            res2 = ct.run_radar_scan(self.brand, self.profile, include_lookalikes=True, lookalike_limit=40)
            self.assertEqual(res2["pending_count"], 0)
