"""Walking directories, and the bookkeeping that goes with it.

Fixture secrets are assembled at runtime so the repository itself passes
GitHub's push protection; see the note in ``test_rules.py``.
"""

import tempfile
import unittest
from pathlib import Path

from leakhound.scanner import scan, scan_text


def _j(*parts):
    return "".join(parts)


AWS_KEY = _j("AKIA", "Q3EGRT7XYZ2LMNOP")
AWS_KEY_2 = _j("AKIA", "5XYZW7ABCDEFGHIJ")
GOOGLE_KEY = _j("AIza", "SyD4kLm9QpRt2VwXyZ3aBcDeFgHiJkLmNoP")


class ScanTextTest(unittest.TestCase):
    def test_line_and_column(self):
        text = 'line one\n\nkey = "%s"\n' % AWS_KEY
        finding = scan_text(text, "app.py")[0]
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.column, 8)

    def test_two_secrets_on_one_line(self):
        text = 'a = "%s"; b = "%s"\n' % (AWS_KEY, GOOGLE_KEY)
        self.assertEqual(len(scan_text(text, "x.py")), 2)

    def test_same_secret_twice_is_reported_once(self):
        text = 'k = "%s"  # again "%s"\n' % (AWS_KEY, AWS_KEY)
        self.assertEqual(len(scan_text(text, "x.py")), 1)

    def test_findings_are_capped(self):
        text = "\n".join(
            'k = "%s"' % _j("AKIA", "Q3EGRT7XYZ2LM%03d" % index) for index in range(5)
        )
        self.assertEqual(len(scan_text(text, "x.py", max_findings=3)), 3)

    def test_ignore_marker(self):
        text = 'key = "%s"  # leakhound:ignore\n' % AWS_KEY
        self.assertEqual(scan_text(text, "x.py"), [])

    def test_snippet_is_masked(self):
        finding = scan_text('key = "%s"' % AWS_KEY, "x.py")[0]
        self.assertNotIn(AWS_KEY, finding.snippet)
        self.assertIn("*", finding.snippet)

    def test_empty_text(self):
        self.assertEqual(scan_text("", "x.py"), [])


class ScanFilesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / "app.py").write_text('AWS_KEY = "%s"\n' % AWS_KEY, encoding="utf-8")
        (self.root / ".env").write_text(
            'DATABASE_URL="%s"\n' % _j("postgres://admin:", "S3cr3tP4ssw0rd", "@db/app"),
            encoding="utf-8",
        )
        (self.root / "README.md").write_text(
            'Use `api_key = "your-api-key-here"`.\n', encoding="utf-8"
        )
        nested = self.root / "node_modules" / "left-pad"
        nested.mkdir(parents=True)
        (nested / "index.js").write_text(
            'const k = "%s";\n' % AWS_KEY_2, encoding="utf-8"
        )
        (self.root / "blob.bin").write_bytes(b"\x00\x01\x02" + AWS_KEY.encode())
        (self.root / "big.txt").write_text("x" * 4000, encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_finds_the_real_ones(self):
        result = scan([str(self.root)])
        rules = {finding.rule_id for finding in result.findings}
        self.assertIn("aws-access-key-id", rules)
        self.assertIn("database-url", rules)

    def test_readme_placeholder_is_quiet(self):
        result = scan([str(self.root)])
        self.assertFalse([f for f in result.findings if f.path.endswith("README.md")])

    def test_node_modules_are_skipped(self):
        result = scan([str(self.root)])
        self.assertFalse([f for f in result.findings if "node_modules" in f.path])

    def test_all_flag_descends_anyway(self):
        result = scan([str(self.root)], include_ignored=True)
        self.assertTrue([f for f in result.findings if "node_modules" in f.path])

    def test_binary_is_skipped(self):
        result = scan([str(self.root)])
        self.assertFalse([f for f in result.findings if f.path.endswith(".bin")])
        self.assertTrue(any(name.endswith(".bin") for name, _ in result.skipped))

    def test_size_limit(self):
        result = scan([str(self.root)], max_bytes=1000)
        self.assertFalse([f for f in result.findings if f.path.endswith("big.txt")])

    def test_ignore_globs(self):
        result = scan([str(self.root)], ignore_globs=("*.env",))
        self.assertFalse([f for f in result.findings if f.path.endswith(".env")])

    def test_results_are_sorted(self):
        result = scan([str(self.root)])
        keys = [(f.path, f.line, f.column) for f in result.findings]
        self.assertEqual(keys, sorted(keys))

    def test_single_file(self):
        result = scan([str(self.root / "app.py")])
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(result.count, 1)

    def test_missing_path_is_not_fatal(self):
        result = scan([str(self.root / "nope.py")])
        self.assertEqual(result.count, 0)
        self.assertEqual(result.files_scanned, 0)


if __name__ == "__main__":
    unittest.main()
