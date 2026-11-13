from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import brand_registry as br
import case_manager as cm
import packets
import recon_target as recon
from safe_http import FetchResult


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry = self.root / "registry.json"
        self.brand = self.root / "brand"
        self.profile = json.loads((ROOT / "examples/sample-profile.json").read_text(encoding="utf-8"))
        self.profile["copyright_originals"] = [{"asset_name": "Original photo", "official_source_url": "https://brand.example/product"}]
        self.profile["keyword_watch_patterns"] = ["examplebrand"]
        br.register_brand(self.profile["brand_slug"], self.brand, self.profile, self.registry)
        self.profile = br.profile_from_dir(self.brand)
        self.case, _ = cm.create_case(self.brand, "https://suspect.example/product", ["COPYRIGHT_CLONE"])


    def assertPrivatePath(self, path, directory=False):
        import os
        if os.name == "nt":
            import re
            from windows_security import current_user_sid, read_dacl
            dacl = read_dacl(path)
            self.assertTrue(dacl.startswith("D:P"), dacl)
            aces = re.findall(r"\(([^)]+)\)", dacl)
            self.assertEqual(len(aces), 3, dacl)
            self.assertEqual({a.split(";")[-1] for a in aces}, {current_user_sid(), "SY", "BA"})
            for ace in aces:
                fields = ace.split(";")
                self.assertEqual(fields[0], "A")
                self.assertEqual(fields[2], "FA")
                self.assertNotIn("ID", fields[1])
                if directory:
                    self.assertIn("OI", fields[1]); self.assertIn("CI", fields[1])
        else:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if directory else 0o600)

    def capture(self, body=b"<h1>examplebrand copied image</h1>", url=None):
        url = url or "https://suspect.example/product"
        response = FetchResult(url, 200, {}, body, "93.184.216.34", ())
        with patch.object(recon, "query_direct_dns", return_value={"A": ["93.184.216.34"], "AAAA": [], "dns_query_ok": True}), \
             patch.object(recon, "query_rdap", return_value={"ok": True}), \
             patch.object(recon, "fetch", return_value=response):
            return recon.run_recon(url, self.case)

    def channel(self, identifier="host", category="hosting", channel_class="ENFORCEMENT_SLA"):
        return cm.upsert_channel(self.case, identifier, channel_class, category, "Example Hosting", "abuse@provider.example")

    def request(self, capture_id, channel_id="host"):
        return {"channel_id": channel_id, "route": "COPYRIGHT_NOTICE", "jurisdiction": "US",
                "subject": "Request to review copied original material", "provider_role": "hosting",
                "scope_reason": "US copyright claim at a provider accepting DMCA notices",
                "endpoint_source_url": "https://provider.example/legal", "endpoint_verified_by": "Human Test Reviewer",
                "endpoint_verified_at": br.utc_now(), "rights_verified_by": "Human Test Reviewer", "rights_verified_at": br.utc_now(),
                "authorization_fair_use_review": "Reviewer checked authority, license, resale and fair use for this synthetic fixture",
                "claims": [{"kind": "COPYRIGHT", "target_url": "https://suspect.example/product", "right_index": 0,
                            "statement": "The specified product image appears copied from our original",
                            "legal_basis": "17 U.S.C. 512(c)(3)", "comparison_or_observed_facts": "Reviewer compared the original and copied image",
                            "evidence": [{"capture_id": capture_id, "filename": "raw.bin"}]}]}

    def approved(self):
        self.channel()
        cap = self.capture()
        request = self.request(cap["capture_id"])
        draft = packets.prepare_packet(self.case, request)
        packets.approve_packet(self.case, draft["packet_id"], "Human Test Reviewer", draft["packet_sha256"], confirmed=True)
        return draft

    def submitted(self):
        draft = self.approved()
        cm.confirm_submission(self.case, "host", draft["packet_id"], "synthetic-receipt-1", br.utc_now())
        return draft
