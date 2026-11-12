from __future__ import annotations

import re
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent


class TestSkillIntegrity(unittest.TestCase):
    def test_non_test_assets_are_100_percent_brand_and_host_agnostic(self) -> None:
        host_path_re = re.compile(
            r"(?:^|[\s\"'`=(]|file://)(?:/users/|/home/|c:\\users\\)[a-z0-9._-]+",
            re.IGNORECASE,
        )
        for subdir in ("scripts", "references", "templates"):
            for path in (SKILL_ROOT / subdir).iterdir():
                if path.is_file():
                    text = path.read_text(encoding="utf-8")
                    self.assertIsNone(
                        host_path_re.search(text),
                        f"Host-specific filesystem path leaked in {path}",
                    )

        for doc_name in ("SKILL.md", "README.md"):
            doc_path = SKILL_ROOT / doc_name
            if doc_path.is_file():
                doc_text = doc_path.read_text(encoding="utf-8")
                self.assertIsNone(
                    host_path_re.search(doc_text),
                    f"Host-specific filesystem path leaked in {doc_name}",
                )

    def test_references_exist_and_cover_core_jurisdictions_and_customs(self) -> None:
        expected_refs = {
            "channel-playbook.md": ["Shopify", "Stripe", "PayPal", "Safe Browsing", "ClientHold", "Cloudflare"],
            "legal-jurisdictions.md": [
                "17 U.S.C. § 512",
                "15 U.S.C. § 1114",
                "15 U.S.C. § 1125(a)",
                "Regulation (EU) 2022/2065",
                "Article 16",
                "Passing Off",
            ],
            "customs-and-safety.md": [
                "CBP",
                "e-Allegations",
                "EUIPO",
                "HMRC",
                "GACC",
                "Regulation (EU) 2023/988",
                "CPSC",
            ],
            "escalation-and-counter-notice.md": [
                "ICANN",
                "NIS2",
                "UDRP",
                "URS",
                "Counter-Notice",
            ],
        }

        for filename, required_terms in expected_refs.items():
            path = SKILL_ROOT / "references" / filename
            self.assertTrue(path.is_file(), f"Missing reference file: {path}")
            content = path.read_text(encoding="utf-8")
            self.assertGreater(len(content), 600, f"Reference file unexpectedly short: {filename}")
            self.assertNotIn("TODO:", content)
            for term in required_terms:
                self.assertIn(term, content, f"Missing term {term!r} in {filename}")
            for block in re.findall(r"```text\n(.*?)```", content, flags=re.DOTALL):
                self.assertIsNone(
                    re.search(r"[\u4e00-\u9fff]", block),
                    f"Non-English CJK characters leaked inside English legal code block in {filename}",
                )

    def test_notice_templates_exist_and_have_no_typos_or_forced_dmca(self) -> None:
        expected_templates = {
            "notices-saas-payment-phishing.md": [
                "Stripe",
                "PayPal",
                "Shopify",
                "perjury",
                "Safe Browsing",
                "COPYRIGHT_CLONE",
            ],
            "notices-registrar-hosting-cdn.md": [
                "17 U.S.C. § 512",
                "Regulation (EU) 2022/2065",
                "Article 16",
                "NIS2",
                "clientHold",
                "telephone",
                "COPYRIGHT_CLONE",
            ],
            "notices-escalation-chaser.md": [
                "Safe Harbor",
                "ICANN",
                "RAA",
                "Digital Services Coordinator",
            ],
        }

        for filename, required_terms in expected_templates.items():
            path = SKILL_ROOT / "templates" / filename
            self.assertTrue(path.is_file(), f"Missing template file: {path}")
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("teléfono", content, f"Spanish typo found in {filename}")
            self.assertNotIn("TODO:", content)
            for term in required_terms:
                self.assertIn(term, content, f"Missing term {term!r} in {filename}")
            for block in re.findall(r"```text\n(.*?)```", content, flags=re.DOTALL):
                self.assertIsNone(
                    re.search(r"[\u4e00-\u9fff]", block),
                    f"Non-English CJK characters leaked inside English legal code block in {filename}",
                )

    def test_skill_md_frontmatter_line_budget_and_relative_links(self) -> None:
        skill_md = SKILL_ROOT / "SKILL.md"
        self.assertTrue(skill_md.is_file(), "Missing top-level SKILL.md")
        text = skill_md.read_text(encoding="utf-8")
        lines = text.splitlines()
        self.assertLessEqual(len(lines), 250, f"SKILL.md exceeds 250-line budget ({len(lines)} lines)")
        self.assertTrue(text.startswith("---\n"), "SKILL.md must begin with YAML frontmatter")
        self.assertIn("name: brand-takedown", text[:400])
        self.assertIn("update-channel", text)

        rel_links = re.findall(r"\]\((\./[^)#]+)\)", text)
        self.assertGreaterEqual(len(rel_links), 10, "SKILL.md should link to scripts, references, and templates")
        for rel in rel_links:
            resolved = (SKILL_ROOT / rel).resolve()
            self.assertTrue(resolved.exists(), f"Broken relative link in SKILL.md: {rel} -> {resolved}")


if __name__ == "__main__":
    unittest.main()
