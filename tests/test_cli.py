"""Subprocess tests of documented CLIs, using synthetic local data only."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

from common import Fixture, ROOT, br, cm


class TestCLI(Fixture):
    def cli(self, script, *args, expected=0, extra_env=None):
        env = dict(os.environ, BRAND_TAKEDOWN_REGISTRY=str(self.registry), PYTHONDONTWRITEBYTECODE="1")
        if extra_env:
            env.update(extra_env)
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, args)],
            capture_output=True, text=True, timeout=15, env=env, cwd=str(self.root), encoding="utf-8")
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return json.loads(result.stdout if expected == 0 or result.stdout else result.stderr)

    def test_doctor_has_no_unimplemented_adapter_claim(self):
        result = self.cli("doctor.py")
        self.assertTrue(result["ok"])
        for capability in ("gmail_send", "gmail_sync", "browser_checkout", "proxy", "public_archival", "scheduler"):
            self.assertFalse(result["capabilities"][capability])

    def test_all_public_clis_have_help(self):
        for name in ("brand_registry", "case_manager", "recon_target", "check_liveness", "ct_radar", "packets", "build_eml", "package_skill"):
            with self.subTest(name=name):
                result = subprocess.run([sys.executable, str(ROOT / "scripts" / (name + ".py")), "--help"], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_profile_validation(self):
        result = self.cli("brand_registry.py", "validate", "--profile-file", ROOT / "examples/sample-profile.json")
        self.assertTrue(result["valid"])

    def test_cli_registration_and_list(self):
        sample = json.loads((ROOT / "examples/sample-profile.json").read_text(encoding="utf-8"))
        sample["brand_slug"] = "second-brand"
        path = self.root / "input.json"; path.write_text(json.dumps(sample), encoding="utf-8")
        self.cli("brand_registry.py", "init", "--slug", "second-brand", "--data-dir", self.root / "second", "--profile-file", path)
        result = self.cli("brand_registry.py", "list")
        self.assertIn("second-brand", result["brands"])

    def test_cli_case_creation_collision_resistance(self):
        cases = []
        for host in ("a.b.example", "a-b.example"):
            result = self.cli("case_manager.py", "create", "--slug", "example-brand", "--url", "https://" + host + "/", "--types", "COPYRIGHT_CLONE")
            cases.append(result["case_dir"])
        self.assertNotEqual(*cases)

    def test_cli_official_target_fails_closed(self):
        result = self.cli("case_manager.py", "create", "--slug", "example-brand", "--url", "https://brand.example/", "--types", "COPYRIGHT_CLONE", expected=2)
        self.assertIn("error", result)

    def test_cli_legacy_state_requires_review(self):
        legacy = self.brand / "cases" / "CASE-legacy"; legacy.mkdir()
        (legacy / "case.json").write_text('{"primary_domain":"suspect.example"}', encoding="utf-8")
        result = self.cli("case_manager.py", "due", "--slug", "example-brand", expected=1)
        self.assertTrue(any(item["kind"] == "CASE_ERROR" for item in result["items"]))

    def test_cli_cross_brand_case_rejected(self):
        sample = json.loads((ROOT / "examples/sample-profile.json").read_text(encoding="utf-8")); sample["brand_slug"] = "second-brand"
        br.register_brand("second-brand", self.root / "second", sample, self.registry)
        result = self.cli("case_manager.py", "add-channel", "--slug", "second-brand", "--case-dir", self.case,
            "--channel-id", "host", "--channel-class", "ENFORCEMENT_SLA", "--category", "hosting", "--provider", "Synthetic", "--endpoint", "abuse@provider.example", expected=2)
        self.assertIn("error", result)

    def test_cli_proxy_fails_before_network(self):
        result = self.cli("recon_target.py", "run", "--slug", "example-brand", "--case-dir", self.case,
            "--url", "https://suspect.example/product", "--proxy", "http://127.0.0.1:8080", expected=2)
        self.assertIn("disabled", result["error"])

    def test_cli_wayback_is_explicitly_disabled(self):
        result = self.cli("recon_target.py", "archive-wayback", "--slug", "example-brand", "--case-dir", self.case,
            "--url", "https://suspect.example/product", expected=2)
        self.assertIn("disabled", result["error"])

    def test_cli_end_to_end_reviewed_draft_and_receipt(self):
        source = self.root / "comparison.txt"
        source.write_text("Synthetic local comparison, not a real allegation.", encoding="utf-8")
        capture = self.cli("recon_target.py", "add-evidence", "--slug", "example-brand", "--case-dir", self.case,
            "--url", "https://suspect.example/product", "--source", source)
        verified = self.cli("recon_target.py", "refresh-manifest", "--slug", "example-brand", "--case-dir", self.case)
        self.assertTrue(verified["verified"])
        self.cli("case_manager.py", "add-channel", "--slug", "example-brand", "--case-dir", self.case,
            "--channel-id", "host", "--channel-class", "ENFORCEMENT_SLA", "--category", "hosting", "--provider", "Synthetic Hosting", "--endpoint", "abuse@provider.example")
        req = self.request(capture["capture_id"])
        req["claims"][0]["evidence"][0]["filename"] = "comparison.txt"
        request_file = self.root / "request.json"; request_file.write_text(json.dumps(req), encoding="utf-8")
        draft = self.cli("packets.py", "--slug", "example-brand", "--case-dir", self.case, "prepare", "--request-file", request_file)
        packet_id = draft["packet_id"]
        self.cli("build_eml.py", "--slug", "example-brand", "--case-dir", self.case, "--packet-id", packet_id, expected=2)
        self.cli("packets.py", "--slug", "example-brand", "--case-dir", self.case, "approve", "--packet-id", packet_id,
            "--reviewer", "Synthetic Human Reviewer", "--reviewed-digest", draft["packet_sha256"], "--confirm-human-review")
        eml = self.cli("build_eml.py", "--slug", "example-brand", "--case-dir", self.case, "--packet-id", packet_id)
        self.assertFalse(eml["sent"]); self.assertTrue(Path(eml["eml_path"]).is_file())
        state = self.cli("case_manager.py", "submit", "--slug", "example-brand", "--case-dir", self.case, "--channel-id", "host",
            "--packet-id", packet_id, "--submission-ref", "synthetic-manual-receipt", "--sent-at", br.utc_now())
        self.assertEqual(state["channels"][0]["status"], "SUBMITTED")
        self.cli("case_manager.py", "update-channel", "--slug", "example-brand", "--case-dir", self.case, "--channel-id", "host", "--status", "NEED_MORE_INFO")
        due = self.cli("case_manager.py", "due", "--slug", "example-brand")
        self.assertEqual(due["items"][0]["kind"], "SUPPLEMENT_REVIEW")
        state = self.cli("case_manager.py", "counter-notice", "--slug", "example-brand", "--case-dir", self.case, "--channel-id", "host",
            "--received-at", br.utc_now(), "--summary", "Synthetic counter-notice requiring review", "--source-ref", "synthetic-message")
        task = state["counter_notices"][0]
        self.assertEqual(state["status"], "COUNTER_NOTICE_ALERT")
        self.cli("case_manager.py", "resolve-legal", "--slug", "example-brand", "--case-dir", self.case, "--task-id", task["task_id"],
            "--reviewer", "Synthetic Counsel", "--disposition", "Local fixture reviewed, no real legal action")

    def test_cli_compare_images_and_hmac_manifest(self):
        import struct

        def write_bmp(path: Path, width: int, height: int) -> None:
            stride = ((width * 3 + 3) // 4) * 4
            pad = stride - width * 3
            rows = bytearray()
            for y in range(height - 1, -1, -1):
                for x in range(width):
                    v = int(255 * x / max(1, width - 1))
                    rows.extend((v, v, int(180 * y / max(1, height - 1))))
                rows.extend(b"\x00" * pad)
            hdr = b"BM" + struct.pack("<IHHI", 54 + len(rows), 0, 0, 54)
            dib = struct.pack("<IIIHHIIIIII", 40, width, height, 1, 24, 0, len(rows), 0, 0, 0, 0)
            path.write_bytes(hdr + dib + bytes(rows))

        orig = self.root / "orig.bmp"
        suspect = self.root / "suspect.bmp"
        write_bmp(orig, 36, 24)
        write_bmp(suspect, 54, 36)
        cmp_res = self.cli("recon_target.py", "compare-images", "--slug", "example-brand", "--case-dir", self.case,
            "--original", orig, "--suspect", suspect, "--threshold", "10")
        self.assertEqual(cmp_res["algorithm"], "dhash-64")
        self.assertLessEqual(cmp_res["hamming_distance"], 2)
        self.assertTrue(cmp_res["candidate_similar"])
        self.assertEqual(cmp_res["use"], "VISUAL_SIMILARITY_HINT_NOT_PROOF_OF_INFRINGEMENT")
        self.assertFalse(cmp_res["trusted_as_instructions"])

        note = self.root / "unsigned.txt"
        note.write_text("unsigned cli payload", encoding="utf-8")
        self.cli("recon_target.py", "add-evidence", "--slug", "example-brand", "--case-dir", self.case,
            "--url", "https://suspect.example/product", "--source", note)
        err_unsigned = self.cli("recon_target.py", "refresh-manifest", "--slug", "example-brand", "--case-dir", self.case,
            "--require-hmac", expected=2)
        self.assertIn("hmac", err_unsigned["error"].lower())

        created = self.cli("case_manager.py", "create", "--slug", "example-brand",
            "--url", "https://signed.example/product", "--types", "COPYRIGHT_CLONE")
        signed_case = Path(created["case_dir"])
        signed_file = self.root / "signed.txt"
        signed_file.write_text("signed cli payload", encoding="utf-8")
        self.cli("recon_target.py", "add-evidence", "--slug", "example-brand", "--case-dir", signed_case,
            "--url", "https://signed.example/product", "--source", signed_file,
            extra_env={"BRAND_TAKEDOWN_HMAC_KEY": "cli-test-secret"})
        self.cli("recon_target.py", "refresh-manifest", "--slug", "example-brand", "--case-dir", signed_case,
            "--require-hmac", expected=2)
        self.cli("recon_target.py", "refresh-manifest", "--slug", "example-brand", "--case-dir", signed_case,
            "--require-hmac", expected=2, extra_env={"BRAND_TAKEDOWN_HMAC_KEY": "wrong-secret"})
        verified = self.cli("recon_target.py", "refresh-manifest", "--slug", "example-brand", "--case-dir", signed_case,
            "--require-hmac", extra_env={"BRAND_TAKEDOWN_HMAC_KEY": "cli-test-secret"})
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["captures"][0]["hmac_algorithm"], "HMAC-SHA256")
