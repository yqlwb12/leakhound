"""Report formats, and the promise that they never print a live secret."""

import json
import unittest

from leakhound.report import render, to_json, to_markdown, to_sarif, to_text
from leakhound.scanner import ScanResult, scan_text

SECRET = "".join(("AKIA", "Q3EGRT7XYZ2LMNOP"))
TEXT = 'AWS_KEY = "%s"\n' % SECRET


def sample() -> ScanResult:
    result = ScanResult()
    result.files_scanned = 4
    result.findings = scan_text(TEXT, "src/app.py")
    return result


class JsonTest(unittest.TestCase):
    def test_shape(self):
        payload = json.loads(to_json(sample()))
        self.assertEqual(payload["tool"], "leakhound")
        self.assertEqual(payload["summary"]["findings"], 1)
        finding = payload["findings"][0]
        self.assertEqual(finding["rule"], "aws-access-key-id")
        self.assertEqual(finding["path"], "src/app.py")
        self.assertEqual(finding["line"], 1)
        self.assertIn("fingerprint", finding)

    def test_never_contains_the_raw_secret(self):
        self.assertNotIn(SECRET, to_json(sample()))

    def test_clean_result(self):
        payload = json.loads(to_json(ScanResult()))
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["summary"]["findings"], 0)


class SarifTest(unittest.TestCase):
    def test_minimum_sarif(self):
        document = json.loads(to_sarif(sample()))
        self.assertEqual(document["version"], "2.1.0")
        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "leakhound")
        self.assertTrue(run["tool"]["driver"]["rules"])
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "aws-access-key-id")
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "src/app.py")
        self.assertEqual(location["region"]["startLine"], 1)
        self.assertGreaterEqual(location["region"]["startColumn"], 1)

    def test_no_secret_in_sarif(self):
        self.assertNotIn(SECRET, to_sarif(sample()))


class TextTest(unittest.TestCase):
    def test_findings_are_listed(self):
        text = to_text(sample())
        self.assertIn("src/app.py", text)
        self.assertIn("aws-access-key-id", text)
        self.assertIn("1 finding", text)

    def test_clean_message(self):
        self.assertIn("no secrets found", to_text(ScanResult(files_scanned=2)))

    def test_no_ansi_when_disabled(self):
        self.assertNotIn("\x1b", to_text(sample(), colour=False))


class MarkdownTest(unittest.TestCase):
    def test_table(self):
        text = to_markdown(sample())
        self.assertIn("| File | Line | Rule | Value |", text)
        self.assertIn("aws-access-key-id", text)
        self.assertNotIn(SECRET, text)

    def test_clean(self):
        self.assertIn("no secrets found", to_markdown(ScanResult(files_scanned=3)))


class DispatchTest(unittest.TestCase):
    def test_render_dispatches(self):
        result = sample()
        self.assertTrue(render(result, format="markdown").startswith("**leakhound"))
        self.assertEqual(json.loads(render(result, format="sarif"))["version"], "2.1.0")
        self.assertIn("aws-access-key-id", render(result, format="json"))

    def test_text_is_the_default(self):
        self.assertIn("src/app.py", render(sample()))


if __name__ == "__main__":
    unittest.main()
