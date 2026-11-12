"""Artifact and documentation invariants, not word-count-based legal validation."""
import ast
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
import zipfile
import uuid

from common import ROOT, br
from package_skill import FILES, build_package
from doctor import diagnose


class TestSkillIntegrity(unittest.TestCase):
    def test_package_files_exist_and_are_unique(self):
        self.assertEqual(len(FILES), len(set(FILES)))
        for name in FILES:
            self.assertTrue((ROOT / name).is_file(), name)

    def test_skill_budget_and_links(self):
        text = (ROOT / "SKILL.md").read_text()
        self.assertTrue(text.startswith("---\nname: brand-takedown\n"))
        self.assertLessEqual(len(text.splitlines()), 250)
        for link in re.findall(r"\]\(([^)#]+)\)", text):
            if "://" not in link:
                self.assertTrue((ROOT / link).is_file(), link)

    def test_all_local_markdown_links_resolve(self):
        for path in ROOT.rglob("*.md"):
            for link in re.findall(r"\]\(([^)#]+)\)", path.read_text()):
                if "://" not in link and not link.startswith("mailto:"):
                    self.assertTrue((path.parent / link).exists(), (path, link))

    def test_schema_keywords_are_implemented(self):
        schema = json.loads((ROOT / "templates/profile.schema.json").read_text())
        supported = {"$schema", "title", "description", "type", "required", "properties", "additionalProperties", "items",
                     "enum", "minLength", "maxLength", "minItems", "uniqueItems", "pattern", "format", "minimum", "maximum"}
        def visit(node):
            self.assertFalse(set(node) - supported, set(node) - supported)
            for item in node.get("properties", {}).values(): visit(item)
            if "items" in node: visit(node["items"])
        visit(schema)

    def test_generic_example_matches_runtime_schema(self):
        value = json.loads((ROOT / "examples/sample-profile.json").read_text())
        self.assertEqual(br.validate_profile(value), [])
        for domain in value["official_domains"] + value.get("allowlist_domains", []):
            self.assertTrue(domain.endswith(".example"))

    def test_all_audit_ids_have_unique_ledger_rows(self):
        text = (ROOT / "docs/audit-remediation.md").read_text()
        ids = re.findall(r"^\|(BT-\d\d)\|", text, re.M)
        self.assertEqual(ids, [f"BT-{i:02d}" for i in range(1, 40)])
        self.assertIn("Partial", text); self.assertIn("Restricted", text)

    def test_unsafe_guarantees_removed_from_active_guidance(self):
        for relative in ("SKILL.md", "references/channel-playbook.md", "references/escalation-and-counter-notice.md", "templates/notices-escalation-chaser.md"):
            text = (ROOT / relative).read_text()
            for phrase in ("permanently welded", "indisputable actual knowledge", "95%", "100% 缺失", "永久焊死", "直接触发共同侵权"):
                self.assertNotIn(phrase, text)

    def test_runtime_python_imports_are_standard_library_or_local(self):
        import sys
        local = {p.stem for p in (ROOT / "scripts").glob("*.py")}
        for path in (ROOT / "scripts").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
                for name in names:
                    self.assertIn(name.split(".")[0], sys.stdlib_module_names | local, (path, name))

    def test_no_shell_true_or_embedded_sender_credentials(self):
        for path in (ROOT / "scripts").glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg == "shell":
                    self.assertFalse(isinstance(node.value, ast.Constant) and node.value.value is True)
            self.assertNotIn("SMTP_PASSWORD", path.read_text())

    def test_reproducible_package_excludes_unlisted_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary); copy = temporary / "skill"
            for name in FILES:
                target = copy / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(ROOT / name, target)
            marker = uuid.uuid4().hex
            (copy / "profile.json").write_text(json.dumps({"private": marker}))
            (copy / ".env").write_text(marker)
            (copy / "cases").mkdir(); (copy / "cases" / "notice.eml").write_text(marker)
            one, two = temporary / "one.zip", temporary / "two.zip"
            self.assertEqual(build_package(one, copy), build_package(two, copy))
            with zipfile.ZipFile(one) as archive:
                self.assertEqual(set(archive.namelist()), {"brand-takedown/" + p for p in FILES} | {"brand-takedown/SHA256SUMS.txt"})
                for name in archive.namelist(): self.assertNotIn(marker.encode(), archive.read(name))
                for line in archive.read("brand-takedown/SHA256SUMS.txt").decode().splitlines():
                    digest, name = line.split("  ", 1)
                    self.assertEqual(digest, hashlib.sha256(archive.read("brand-takedown/" + name)).hexdigest())

    def test_package_refuses_output_inside_source(self):
        with self.assertRaises(ValueError): build_package(ROOT / "unsafe.zip")

    def test_policy_sources_have_scope_and_provenance(self):
        data = json.loads((ROOT / "references/policy-sources.json").read_text())
        self.assertIn("2026-11-12", json.dumps(data))
        self.assertGreaterEqual(len(data["sources"]), 8)
