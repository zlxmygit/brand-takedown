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
        draft = self.prepare(); body = (Path(draft["packet_dir"]) / "notice.txt").read_text()
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
        draft = self.approve(); (Path(draft["packet_dir"]) / "notice.txt").write_text("changed")
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, draft["packet_id"])

    def test_attachment_change_invalidates_approval(self):
        draft = self.approve(); directory = Path(draft["packet_dir"])
        packet = json.loads((directory / "packet.json").read_text()); (directory / packet["attachments"][0]["filename"]).write_bytes(b"changed")
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
        self.assertEqual(message.get_body().get_content().replace("\r\n", "\n"), (directory / "notice.txt").read_text())
        self.assertEqual(message["To"], "abuse@provider.example")

    def test_path_traversal_packet_id_rejected(self):
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, "../../other")
