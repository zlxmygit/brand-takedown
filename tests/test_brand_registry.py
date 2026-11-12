from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from brand_registry import (  # noqa: E402
    is_allowlisted_url,
    load_brand_profile,
    normalize_hostname,
    register_brand,
    sanitize_http_url,
    validate_profile,
)


class TestBrandRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)
        self.registry_path = self.base / "registry.json"
        self.brand_data_dir = self.base / "brands" / "acme"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _valid_sample_profile(self) -> dict:
        return {
            "brand_slug": "acme",
            "brand_name": "Acme Mobility",
            "legal_entity_name_en": "Acme Mobility Innovation Co., Ltd.",
            "legal_entity_name_local": "艾克米创新科技有限公司",
            "entity_address": "100 Innovation Way, Suite 200, Austin, TX 78701, USA",
            "authorized_signatory": {
                "name": "Legal Counsel",
                "title": "IP Enforcement Lead",
                "legal_email": "legal@acmesport.com",
                "phone": "+1-512-555-0199",
            },
            "official_domains": ["acmesport.com"],
            "allowlist_domains": ["authorized-dealer.eu"],
            "official_product_urls": ["https://acmesport.com/products/x1"],
            "counterfeit_warning_url": "https://acmesport.com/pages/counterfeit-alert",
            "target_markets": ["US", "CA", "EU", "UK", "AU", "CN_EXPORT"],
            "product_risk_profile": {
                "category": "electronics_battery",
                "safety_standards": ["UL", "CE", "UN38.3", "EU GPSR"],
                "hazard_statement_en": "Counterfeit uncertified lithium-ion consumer hardware poses severe fire and safety hazards.",
            },
            "trademarks": [
                {
                    "jurisdiction": "US",
                    "mark_text": "ACME",
                    "reg_number": "US-CLASS12-SAMPLE",
                    "status": "registered",
                    "nice_classes": [12],
                    "expiry_date": "2036-01-01",
                    "cert_file_path": "",
                }
            ],
            "patents_and_designs": [],
            "copyright_originals": [
                {
                    "asset_name": "Acme Flagship Official Product Gallery",
                    "official_source_url": "https://acmesport.com/products/x1",
                    "first_published_date": "2025-01-15",
                    "description": "Original studio photos and copywriting.",
                }
            ],
            "keyword_watch_patterns": ["acme", "acmetrack"],
        }

    def test_normalize_hostname_strips_scheme_port_path_and_trailing_dot(self) -> None:
        self.assertEqual(
            normalize_hostname("HTTPS://Shop.AcmeSport.com:443/products/x1?v=1"),
            "shop.acmesport.com",
        )
        self.assertEqual(normalize_hostname("acmesports.com."), "acmesports.com")
        self.assertEqual(normalize_hostname("-o/tmp/x"), "")
        self.assertEqual(normalize_hostname("localhost"), "")

    def test_allowlist_defeats_backslash_userinfo_and_missing_slash_tricks(self) -> None:
        allowlist = ["acmesport.com", "authorized-dealer.eu"]
        self.assertTrue(is_allowlisted_url("https://acmesport.com/products/x1", allowlist))
        self.assertTrue(is_allowlisted_url("https://Shop.AcmeSport.com:443/cart", allowlist))
        self.assertTrue(is_allowlisted_url("https://acmesport.com\\foo", allowlist))
        self.assertTrue(is_allowlisted_url("https://acmesport.com\\@evil.com", allowlist))
        self.assertTrue(is_allowlisted_url("https:acmesport.com/foo", allowlist))
        self.assertFalse(is_allowlisted_url("https://theacmesport.com/", allowlist))
        self.assertFalse(is_allowlisted_url("https://acmesport.com.scam.shop/", allowlist))
        self.assertFalse(is_allowlisted_url("https://acmesports.com/", allowlist))

    def test_sanitize_http_url_blocks_file_scheme_cli_flags_and_backslashes(self) -> None:
        self.assertEqual(sanitize_http_url("https://acmesports.com/item?v=1"), "https://acmesports.com/item?v=1")
        for malicious in (
            "file://localhost/etc/passwd",
            "ftp://acmesports.com/a",
            "-o/tmp/pwn",
            "https://-badhost.com/a",
            "https://acmesport.com\\@evil.com",
            "https://user:pass@acmesports.com/",
        ):
            with self.assertRaises(ValueError, msg=f"Should reject {malicious!r}"):
                sanitize_http_url(malicious)

    def test_validate_profile_catches_missing_entity_address_and_subfields(self) -> None:
        valid = self._valid_sample_profile()
        self.assertEqual(validate_profile(valid), [])

        broken = dict(valid)
        broken["entity_address"] = ""
        broken["target_markets"] = ["US", "MARS"]
        broken["official_domains"] = []
        broken["trademarks"] = [{"jurisdiction": "US"}]
        errors = validate_profile(broken)
        self.assertTrue(any("entity_address" in err for err in errors))
        self.assertTrue(any("official_domains" in err for err in errors))
        self.assertTrue(any("MARS" in err for err in errors))
        self.assertTrue(any("trademarks[0]" in err for err in errors))

    def test_register_and_load_brand_merges_official_into_allowlist(self) -> None:
        profile = self._valid_sample_profile()
        saved_path = register_brand(
            brand_slug="acme",
            data_dir=self.brand_data_dir,
            profile=profile,
            registry_path=self.registry_path,
        )
        self.assertTrue(saved_path.exists())
        loaded_dir, loaded_profile = load_brand_profile("acme", registry_path=self.registry_path)
        self.assertEqual(loaded_dir, self.brand_data_dir.resolve())
        self.assertIn("acmesport.com", loaded_profile["allowlist_domains"])
        self.assertIn("authorized-dealer.eu", loaded_profile["allowlist_domains"])
        registry_data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertIn("acme", registry_data["brands"])


if __name__ == "__main__":
    unittest.main()
