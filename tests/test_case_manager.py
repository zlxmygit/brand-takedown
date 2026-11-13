from datetime import datetime, timedelta, timezone
import json
from unittest.mock import patch

from common import Fixture, br, cm, packets
from storage import ConflictError


class TestCaseManager(Fixture):
    def test_domain_collision_preserves_channels(self):
        first, _ = cm.create_case(self.brand, "https://a.b.example/", ["COPYRIGHT_CLONE"])
        cm.upsert_channel(first, "a", "ENFORCEMENT_SLA", "hosting", "Provider", "abuse@provider.example")
        second, _ = cm.create_case(self.brand, "https://a-b.example/", ["COPYRIGHT_CLONE"])
        self.assertNotEqual(first, second); self.assertEqual(len(cm.load_case(first)["channels"]), 1)

    def test_same_host_merge(self):
        same, data = cm.create_case(self.brand, "https://suspect.example/second", ["COPYRIGHT_CLONE"])
        self.assertEqual(same, self.case); self.assertEqual(len(data["target_urls"]), 2)

    def test_unknown_type_rejected(self):
        with self.assertRaises(ValueError): cm.create_case(self.brand, "https://other.example/", ["MISTYPED"])

    def test_allowlist_enforced_even_empty_argument(self):
        with self.assertRaises(ValueError): cm.create_case(self.brand, "https://brand.example/", ["COPYRIGHT_CLONE"], [])

    def test_cloak_allowlist_enforced_without_slug(self):
        with self.assertRaises(ValueError): cm.add_linked_cloak_domain(self.case, "checkout.brand.example")

    def test_cross_brand_case_path_rejected(self):
        with self.assertRaises(ConflictError): cm.assert_case_brand(self.case, self.root / "other")

    def test_submission_cannot_be_claimed_in_upsert(self):
        with self.assertRaises(ValueError): cm.upsert_channel(self.case, "a", "ENFORCEMENT_SLA", "hosting", "Provider", "abuse@provider.example", status="SUBMITTED")

    def test_unsubmitted_cannot_escalate(self):
        self.channel()
        with self.assertRaises(ConflictError): cm.advance_escalation_tier(self.case, "host")

    def test_submitted_requires_reviewed_packet_and_receipt(self):
        self.channel()
        with self.assertRaises(ValueError): cm.confirm_submission(self.case, "host", "PKT-" + "0"*32, "", br.utc_now())

    def test_real_submission_sets_due(self):
        self.submitted(); channel = cm.load_case(self.case)["channels"][0]
        self.assertTrue(channel["submitted_at"]); self.assertTrue(channel["next_action_due_at"])

    def test_double_submission_rejected(self):
        draft = self.submitted()
        with self.assertRaises(ConflictError): cm.confirm_submission(self.case, "host", draft["packet_id"], "duplicate", br.utc_now())

    def test_early_escalation_rejected(self):
        self.submitted()
        with self.assertRaises(ConflictError): cm.advance_escalation_tier(self.case, "host")

    def test_escalation_only_plans_not_sends(self):
        self.submitted(); old = cm.load_case(self.case)["channels"][0]
        future = cm._format_iso_utc(datetime.now(timezone.utc) + timedelta(days=7))
        new = cm.advance_escalation_tier(self.case, "host", future)["channels"][0]
        self.assertEqual(new["status"], "SUBMITTED"); self.assertEqual(new["next_action_due_at"], old["next_action_due_at"])
        self.assertEqual(new["pending_tier"], 2)

    def test_resolved_cannot_escalate(self):
        self.submitted(); cm.update_channel_fields(self.case, "host", "RESOLVED")
        with self.assertRaises(ConflictError): cm.advance_escalation_tier(self.case, "host", "2030-01-01T00:00:00Z")

    def test_need_more_info_stays_due(self):
        self.submitted(); cm.update_channel_fields(self.case, "host", "NEED_MORE_INFO")
        due = cm.scan_due_escalations(self.brand, "2030-01-01T00:00:00Z")
        self.assertEqual(due[0]["kind"], "SUPPLEMENT_REVIEW")

    def test_tier3_stays_in_review_queue(self):
        self.submitted()
        cm.mutate_case(self.case, "test_fixture", lambda d: d["channels"][0].update(status="ESCALATED_TIER3", escalation_tier=3))
        due = cm.scan_due_escalations(self.brand, "2030-01-01T00:00:00Z")
        self.assertEqual(due[0]["kind"], "TIER3_REVIEW")
        with self.assertRaises(ConflictError): cm.advance_escalation_tier(self.case, "host", "2030-01-01T00:00:00Z")

    def test_regulatory_channel_never_gets_commercial_due(self):
        self.channel(channel_class="REGULATORY_FILING")
        self.assertEqual(cm.scan_due_escalations(self.brand, "2030-01-01T00:00:00Z"), [])
        with self.assertRaises(ConflictError): cm.advance_escalation_tier(self.case, "host")

    def test_counter_notice_unknown_provider_date_no_fake_deadline(self):
        self.channel(); d = cm.record_counter_notice(self.case, "host", br.utc_now(), "Review counter notice", source_ref="test-message")
        task = d["counter_notices"][0]
        self.assertNotIn("legal_action_deadline_iso", task); self.assertNotIn("earliest_restore_estimate", task)
        self.assertEqual(d["status"], "COUNTER_NOTICE_ALERT")

    def test_counter_notice_window_is_labeled_estimate(self):
        self.channel(); d = cm.record_counter_notice(self.case, "host", "2026-11-14T10:00:00Z", "Review", "2026-11-13T10:00:00Z", "America/New_York", "test-message")
        task = d["counter_notices"][0]
        self.assertTrue(task["earliest_restore_estimate"].startswith("2026-11-27"))
        self.assertTrue(task["latest_restore_estimate"].startswith("2026-12-03"))
        self.assertTrue(task["requires_counsel_confirmation"])

    def test_counter_notice_deduplicates_message(self):
        self.channel()
        for _ in range(2): cm.record_counter_notice(self.case, "host", br.utc_now(), "Review", source_ref="test-message")
        self.assertEqual(len(cm.load_case(self.case)["counter_notices"]), 1)

    def test_legal_task_has_separate_due_queue(self):
        self.channel(); d = cm.record_counter_notice(self.case, "host", br.utc_now(), "Review", source_ref="test-message")
        self.assertEqual(cm.scan_due_escalations(self.brand)[0]["kind"], "LEGAL_REVIEW")
        cm.resolve_legal_task(self.case, d["counter_notices"][0]["task_id"], "Human Counsel", "Reviewed procedural status; documented disposition")
        self.assertEqual(cm.scan_due_escalations(self.brand), [])

    def test_naive_timestamps_rejected(self):
        with self.assertRaises(ValueError): cm._parse_iso_utc("2026-11-12T12:00:00")

    def test_corrupt_case_is_visible_not_silent(self):
        (self.case / "case.json").write_text("{", encoding="utf-8")
        self.assertEqual(cm.scan_due_escalations(self.brand)[0]["kind"], "CASE_ERROR")
