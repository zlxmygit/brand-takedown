import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from unittest.mock import patch

from common import Fixture, br, cm, packets, recon
from build_eml import build_approved_eml


class TestPackets(Fixture):
    def setUp(self):
        super().setUp(); self.channel(); self.cap = self.capture()
        self.req = self.request(self.cap["capture_id"])

    def prepare(self):
        return packets.prepare_packet(self.case, self.req)

    def approve(self):
        draft = self.prepare()
        packets.approve_packet(self.case, draft["packet_id"], "Human Reviewer", draft["packet_sha256"], True)
        return draft

    def test_empty_claims_rejected(self):
        self.req["claims"] = []
        with self.assertRaises(ValueError): self.prepare()

    def test_route_mismatch_rejected(self):
        self.req["route"] = "TRADEMARK_NOTICE"
        with self.assertRaises(ValueError): self.prepare()

    def test_missing_evidence_rejected(self):
        self.req["claims"][0]["evidence"] = []
        with self.assertRaises(ValueError): self.prepare()

    def test_metadata_cannot_substitute_for_evidence(self):
        self.req["claims"][0]["evidence"][0]["filename"] = "recon-report.json"
        with self.assertRaises(ValueError): self.prepare()

    def test_failed_capture_cannot_support_claim(self):
        cm.mutate_case(self.case, "test_fixture", lambda d: d["captures"][0].update(status="FAILED"))
        with self.assertRaises(ValueError): self.prepare()

    def test_claim_target_mismatch_rejected(self):
        self.req["claims"][0]["target_url"] = "https://different.example/"
        with self.assertRaises(ValueError): self.prepare()

    def test_missing_right_index_rejected(self):
        self.req["claims"][0].pop("right_index")
        with self.assertRaises(ValueError): self.prepare()

    def test_pending_registered_right_rejected(self):
        p = copy.deepcopy(self.profile)
        p["trademarks"] = [{"jurisdiction": "US", "mark_text": "Example", "status": "pending", "reg_number": "application-test"}]
        br.register_brand("example-brand", self.brand, p, self.registry)
        self.req["route"] = "TRADEMARK_NOTICE"; self.req["claims"][0]["kind"] = "TRADEMARK"
        with self.assertRaises(ValueError): self.prepare()

    def test_expired_right_rejected(self):
        p = copy.deepcopy(self.profile)
        p["trademarks"] = [{"jurisdiction": "US", "mark_text": "Example", "status": "registered", "reg_number": "test", "expiry_date": "2000-01-01"}]
        br.register_brand("example-brand", self.brand, p, self.registry)
        self.req["route"] = "TRADEMARK_NOTICE"; self.req["claims"][0]["kind"] = "TRADEMARK"
        with self.assertRaises(ValueError): self.prepare()

    def test_uk_does_not_implicitly_activate_dsa(self):
        self.req.update(route="DSA_NOTICE", jurisdiction="UK")
        with self.assertRaises(ValueError): self.prepare()

    def test_dsa_payment_role_rejected(self):
        p = copy.deepcopy(self.profile); p["target_markets"].append("EU")
        br.register_brand("example-brand", self.brand, p, self.registry)
        self.req.update(route="DSA_NOTICE", jurisdiction="EU", provider_role="payment")
        with self.assertRaises(ValueError): self.prepare()

    def test_safety_category_does_not_add_hazard_allegations(self):
        p = copy.deepcopy(self.profile); p["product_risk_profile"] = {"category": "electronics_battery", "hazard_statement_en": "UNVERIFIED_DANGER_MARKER"}
        br.register_brand("example-brand", self.brand, p, self.registry)
        draft = self.prepare(); body = (Path(draft["packet_dir"]) / "notice.txt").read_text(encoding="utf-8")
        self.assertNotIn("UNVERIFIED_DANGER_MARKER", body)

    def test_stale_provider_endpoint_rejected(self):
        self.req["endpoint_verified_at"] = "2000-01-01T00:00:00Z"
        with self.assertRaises(ValueError): self.prepare()

    def test_target_page_is_not_endpoint_provenance(self):
        self.req["endpoint_source_url"] = "https://suspect.example/abuse"
        with self.assertRaises(ValueError): self.prepare()

    def test_placeholders_rejected(self):
        self.req["subject"] = "Hello {{NAME}}"
        with self.assertRaises(ValueError): self.prepare()

    def test_explicit_human_confirmation_required(self):
        draft = self.prepare()
        with self.assertRaises(ValueError): packets.approve_packet(self.case, draft["packet_id"], "Human", draft["packet_sha256"], False)

    def test_reviewed_digest_required(self):
        draft = self.prepare()
        with self.assertRaises(ValueError): packets.approve_packet(self.case, draft["packet_id"], "Human", "0" * 64, True)

    def test_unapproved_draft_cannot_build_cli_eml(self):
        draft = self.prepare()
        with self.assertRaises(OSError): build_approved_eml(self.case, draft["packet_id"], Path(draft["packet_dir"]) / "notice.eml")

    def test_body_change_invalidates_approval(self):
        draft = self.approve(); (Path(draft["packet_dir"]) / "notice.txt").write_text("changed", encoding="utf-8")
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, draft["packet_id"])

    def test_attachment_change_invalidates_approval(self):
        draft = self.approve(); directory = Path(draft["packet_dir"])
        packet = json.loads((directory / "packet.json").read_text(encoding="utf-8")); (directory / packet["attachments"][0]["filename"]).write_bytes(b"changed")
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, draft["packet_id"])

    def test_original_evidence_change_invalidates_approval(self):
        draft = self.approve(); (self.case / "evidence" / self.cap["capture_id"] / "raw.bin").write_bytes(b"changed")
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, draft["packet_id"])

    def test_profile_change_invalidates_approval(self):
        draft = self.approve(); p = copy.deepcopy(self.profile); p["entity_address"] = "Changed address"
        br.register_brand("example-brand", self.brand, p, self.registry)
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, draft["packet_id"])

    def test_approved_eml_preserves_exact_body(self):
        import email, email.policy
        draft = self.approve(); directory = Path(draft["packet_dir"])
        output = build_approved_eml(self.case, draft["packet_id"], directory / "notice.eml")
        message = email.message_from_bytes(output.read_bytes(), policy=email.policy.default)
        self.assertEqual(message.get_body().get_content().replace("\r\n", "\n"), (directory / "notice.txt").read_text(encoding="utf-8"))
        self.assertEqual(message["To"], "abuse@provider.example")

    def test_path_traversal_packet_id_rejected(self):
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, "../../other")

    def test_public_archive_requires_agent_or_explicit_override(self):
        self.req["public_archive_expected"] = True
        with self.assertRaises(ValueError):
            self.prepare()
        self.req["allow_primary_signatory_in_public_archive"] = True
        draft = self.prepare()
        packet = json.loads((Path(draft["packet_dir"]) / "packet.json").read_text(encoding="utf-8"))
        self.assertEqual(packet["signatory_mode"], "PRIMARY_SIGNATORY")
        self.assertTrue(packet["public_archive_expected"])
        self.assertIn("Lumen Database", packet["disclosure_advisory"])

    def test_public_filing_agent_shields_primary_signatory(self):
        p = copy.deepcopy(self.profile)
        p["public_filing_agent"] = {
            "name": "Shielded Compliance Agent",
            "title": "Authorized Enforcement Agent",
            "legal_email": "enforcement-proxy@agent.example",
            "entity_address": "PO Box 900, Agent Suite",
            "phone": "+1-202-555-0199",
        }
        br.register_brand("example-brand", self.brand, p, self.registry)
        self.req["public_archive_expected"] = True
        draft = self.prepare()
        directory = Path(draft["packet_dir"])
        body = (directory / "notice.txt").read_text(encoding="utf-8")
        packet = json.loads((directory / "packet.json").read_text(encoding="utf-8"))
        self.assertEqual(packet["signatory_mode"], "PUBLIC_FILING_AGENT")
        self.assertEqual(packet["from_addr"], "enforcement-proxy@agent.example")
        self.assertIn("Shielded Compliance Agent", body)
        self.assertIn("PO Box 900, Agent Suite", body)
        self.assertNotIn("Example Reviewer", body)
        self.assertNotIn("legal@brand.example", body)
        self.assertNotIn("Fictional address", body)

    def test_use_public_filing_agent_without_profile_config_rejected(self):
        self.req["use_public_filing_agent"] = True
        with self.assertRaises(ValueError):
            self.prepare()
