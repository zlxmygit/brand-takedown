from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from case_manager import (  # noqa: E402
    _main as case_cli_main,
    add_linked_cloak_domain,
    advance_escalation_tier,
    create_case,
    record_counter_notice,
    scan_due_escalations,
    update_channel_fields,
    upsert_channel,
)


class TestCaseManager(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.brand_dir = Path(self.temp_dir.name) / "acme"
        (self.brand_dir / "cases").mkdir(parents=True, exist_ok=True)
        self.allowlist = ["acmesport.com"]
        self.case_dir, self.case_data = create_case(
            brand_dir=self.brand_dir,
            target_url="https://acmesports.com/products/x1",
            infringement_types=["COPYRIGHT_CLONE", "TRADEMARK_IMPERSONATION", "COUNTERFEIT_GOODS"],
            allowlist_domains=self.allowlist,
            now_iso="2026-11-01T00:00:00Z",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_create_case_blocks_allowlisted_domain_and_malformed_url(self) -> None:
        with self.assertRaises(ValueError):
            create_case(
                brand_dir=self.brand_dir,
                target_url="https://shop.acmesport.com/item",
                infringement_types=["COPYRIGHT_CLONE"],
                allowlist_domains=self.allowlist,
            )
        with self.assertRaises(ValueError):
            create_case(
                brand_dir=self.brand_dir,
                target_url="file://localhost/etc/passwd",
                infringement_types=["COPYRIGHT_CLONE"],
                allowlist_domains=self.allowlist,
            )

    def test_submitted_without_explicit_timestamp_auto_populates_sla_deadline(self) -> None:
        updated = upsert_channel(
            self.case_dir,
            channel_id="stripe_abuse",
            channel_class="ENFORCEMENT_SLA",
            category="payment",
            provider_name="Stripe",
            target_endpoint="heretohelp@stripe.com",
            status="SUBMITTED",
        )
        ch = updated["channels"][0]
        self.assertTrue(bool(ch["submitted_at"]))
        self.assertTrue(bool(ch["next_action_due_at"]))

    def test_update_channel_cli_and_preserve_tier2_deadline_on_ticket_ack(self) -> None:
        upsert_channel(
            self.case_dir,
            channel_id="registrar_abuse",
            channel_class="ENFORCEMENT_SLA",
            category="registrar",
            provider_name="Namecheap",
            target_endpoint="abuse@namecheap.com",
            status="SUBMITTED",
            sla_hours=72,
            submitted_at="2026-11-01T00:00:00.123456789z",
        )
        advance_escalation_tier(
            self.case_dir,
            channel_id="registrar_abuse",
            now_iso="2026-11-04T02:00:00+0000",
            next_sla_hours=48,
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = case_cli_main(
                [
                    "update-channel",
                    "--case-dir",
                    str(self.case_dir),
                    "--channel-id",
                    "registrar_abuse",
                    "--ticket-ref",
                    "NC-998877",
                    "--status",
                    "ACKNOWLEDGED",
                ]
            )
        self.assertEqual(rc, 0)
        cli_payload = json.loads(buf.getvalue())
        self.assertEqual(cli_payload["channels"][0]["ticket_ref"], "NC-998877")
        after_ack = update_channel_fields(self.case_dir, "registrar_abuse")
        ch = after_ack["channels"][0]
        self.assertEqual(ch["ticket_ref"], "NC-998877")
        self.assertEqual(ch["escalation_tier"], 2)
        self.assertEqual(ch["status"], "ESCALATED_TIER2")
        self.assertEqual(ch["next_action_due_at"], "2026-11-06T02:00:00Z")

        due = scan_due_escalations(self.brand_dir, now_iso="2026-11-06T03:00:00Z")
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0]["submitted_at"], "2026-11-01T00:00:00Z")
        self.assertEqual(due[0]["tier2_escalated_at"], "2026-11-04T02:00:00Z")

    def test_regulatory_filing_never_triggers_sla_escalation(self) -> None:
        upsert_channel(
            self.case_dir,
            channel_id="cbp_allegation",
            channel_class="REGULATORY_FILING",
            category="customs",
            provider_name="US CBP",
            target_endpoint="https://eallegations.cbp.gov/",
            status="SUBMITTED",
            submitted_at="2026-11-01T00:00:00Z",
        )
        upsert_channel(
            self.case_dir,
            channel_id="registrar_abuse",
            channel_class="ENFORCEMENT_SLA",
            category="registrar",
            provider_name="Namecheap",
            target_endpoint="abuse@namecheap.com",
            status="SUBMITTED",
            sla_hours=72,
            submitted_at="2026-11-01T00:00:00Z",
        )
        due = scan_due_escalations(self.brand_dir, now_iso="2026-11-05T01:00:00Z")
        self.assertEqual([item["channel_id"] for item in due], ["registrar_abuse"])

    def test_counter_notice_ten_business_days_skips_weekends(self) -> None:
        updated = record_counter_notice(
            self.case_dir,
            channel_id="shopify_dmca",
            received_at_iso="2026-11-13T10:00:00.987654321Z",
            summary="Infringer submitted counter-notice with suspected freight-forwarder address",
        )
        self.assertEqual(updated["status"], "COUNTER_NOTICE_ALERT")
        self.assertTrue(
            updated["counter_notices"][0]["legal_action_deadline_iso"].startswith("2026-11-27T10:00:00Z")
        )

    def test_add_linked_cloak_domain_enforces_allowlist_and_deduplicates(self) -> None:
        with self.assertRaises(ValueError):
            add_linked_cloak_domain(
                self.case_dir,
                "https://checkout.acmesport.com/pay",
                role="payment_b_site",
                allowlist_domains=self.allowlist,
            )
        add_linked_cloak_domain(
            self.case_dir,
            "https://Pay-Safe-Checkout.shop/pay",
            role="payment_b_site",
            allowlist_domains=self.allowlist,
        )
        updated = add_linked_cloak_domain(
            self.case_dir,
            "pay-safe-checkout.shop",
            role="payment_b_site",
            allowlist_domains=self.allowlist,
        )
        self.assertEqual(len(updated["linked_payment_cloak_domains"]), 1)
        self.assertEqual(updated["linked_payment_cloak_domains"][0]["domain"], "pay-safe-checkout.shop")


if __name__ == "__main__":
    unittest.main()
