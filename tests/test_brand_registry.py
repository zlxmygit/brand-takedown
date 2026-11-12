import copy
import json
from pathlib import Path
from unittest.mock import patch

from common import Fixture, ROOT, br
from storage import ConflictError


class TestBrandRegistry(Fixture):
    def test_valid_sample(self):
        self.assertEqual(br.validate_profile(self.profile), [])

    def test_null_required_identity(self):
        for key in ("brand_name", "legal_entity_name_en", "entity_address"):
            with self.subTest(key=key):
                p = copy.deepcopy(self.profile); p[key] = None
                self.assertTrue(br.validate_profile(p))

    def test_null_signer(self):
        p = copy.deepcopy(self.profile); p["authorized_signatory"]["name"] = None
        self.assertTrue(br.validate_profile(p))

    def test_invalid_enum(self):
        p = copy.deepcopy(self.profile); p["product_risk_profile"] = {"category": "unknown"}
        self.assertTrue(br.validate_profile(p))

    def test_invalid_mark_status(self):
        p = copy.deepcopy(self.profile); p["trademarks"] = [{"jurisdiction": "US", "mark_text": "Example", "status": "revoked"}]
        self.assertTrue(br.validate_profile(p))

    def test_common_law_does_not_require_fake_registration(self):
        p = copy.deepcopy(self.profile); p["trademarks"] = [{"jurisdiction": "US", "mark_text": "Example", "status": "common_law"}]
        self.assertEqual(br.validate_profile(p), [])

    def test_class_range(self):
        p = copy.deepcopy(self.profile); p["trademarks"] = [{"jurisdiction": "US", "mark_text": "Example", "status": "registered", "reg_number": "test", "nice_classes": [99]}]
        self.assertTrue(br.validate_profile(p))

    def test_official_source_must_match_brand(self):
        p = copy.deepcopy(self.profile); p["copyright_originals"][0]["official_source_url"] = "https://unrelated.example/"
        self.assertTrue(br.validate_profile(p))

    def test_same_directory_cannot_hold_two_brands(self):
        p = copy.deepcopy(self.profile); p["brand_slug"] = "second-brand"; p.pop("brand_id")
        with self.assertRaises(ConflictError):
            br.register_brand("second-brand", self.brand, p, self.registry)
        self.assertEqual(br.load_brand_profile("example-brand", self.registry)[1]["brand_slug"], "example-brand")

    def test_corrupt_registry_preserved(self):
        self.registry.write_text('{"brands":')
        before = self.registry.read_bytes()
        with self.assertRaises(ValueError):
            br.register_brand("example-brand", self.brand, self.profile, self.registry)
        self.assertEqual(self.registry.read_bytes(), before)

    def test_profile_slug_tampering_rejected(self):
        path = self.brand / "profile.json"; p = json.loads(path.read_text()); p["brand_slug"] = "another"; path.write_text(json.dumps(p))
        with self.assertRaises(ConflictError):
            br.load_brand_profile("example-brand", self.registry)

    def test_repo_private_data_rejected(self):
        with self.assertRaises(ValueError):
            br.register_brand("example-brand", ROOT / "private-data", self.profile, self.registry)

    def test_normalization(self):
        self.assertEqual(br.normalize_hostname("HTTPS://Shop.Brand.Example:443/path"), "shop.brand.example")
        self.assertEqual(br.sanitize_http_url("https://BRAND.example.:443"), "https://brand.example/")

    def test_url_attack_matrix(self):
        for url in ("file:///etc/passwd", "https://user:pass@host.example/", "https://brand.example\\@bad.example", "https://*.example/", "http://127.0.0.1/", "http://[::1]/", "https://host.example:9000/", "https://host.example:bad/", "https://host.example:65536/", "-o/tmp/a", "https://host.example/\nfoo"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                br.sanitize_http_url(url)

    def test_allowlist_parser_tricks(self):
        for value in ("https://brand.example/", "https:brand.example/x", "https://brand.example\\@bad.example", "https://brand.example@bad.example/", "https://sub.brand.example/"):
            with self.subTest(value=value):
                self.assertTrue(br.is_allowlisted_url(value, ["brand.example"]))
        self.assertFalse(br.is_allowlisted_url("https://brand.example.bad.example/", ["brand.example"]))

    def test_certificate_directory_not_file(self):
        p = copy.deepcopy(self.profile); p["trademarks"] = [{"jurisdiction": "US", "mark_text": "Example", "status": "registered", "reg_number": "TEST", "cert_file_path": str(self.root)}]
        self.assertTrue(br.validate_profile(p))

    def test_private_permissions(self):
        self.assertEqual((self.brand / "profile.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.brand.stat().st_mode & 0o777, 0o700)
