"""The command line contract: exit codes, formats, and --staged."""

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path

from leakhound import cli

SECRET = "".join(("AKIA", "Q3EGRT7XYZ2LMNOP"))
LOOSE = "".join(("AKIA", "5XYZW7ABCDEFGHIJ"))


def call(*argv):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli.main(list(argv))
    return code, buffer.getvalue()


@contextmanager
def inside(path):
    previous = os.getcwd()
    os.chdir(str(path))
    try:
        yield
    finally:
        os.chdir(previous)


class ProjectTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / "app.py").write_text('AWS_KEY = "%s"\n' % SECRET, encoding="utf-8")
        (self.root / "clean.py").write_text("print('hello')\n", encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_findings_exit_one(self):
        with inside(self.root):
            code, out = call(".")
        self.assertEqual(code, cli.EXIT_FOUND)
        self.assertIn("aws-access-key-id", out)

    def test_clean_exits_zero(self):
        with inside(self.root):
            code, out = call("clean.py")
        self.assertEqual(code, cli.EXIT_CLEAN)
        self.assertIn("no secrets", out)

    def test_json_format(self):
        with inside(self.root):
            code, out = call(".", "--format", "json")
        payload = json.loads(out)
        self.assertEqual(code, cli.EXIT_FOUND)
        self.assertEqual(payload["findings"][0]["path"], "app.py")
        self.assertNotIn(SECRET, out)

    def test_sarif_format(self):
        with inside(self.root):
            code, out = call(".", "-f", "sarif")
        self.assertEqual(json.loads(out)["version"], "2.1.0")
        self.assertEqual(code, cli.EXIT_FOUND)

    def test_markdown_format(self):
        with inside(self.root):
            _, out = call(".", "-f", "markdown")
        self.assertIn("| File | Line | Rule | Value |", out)

    def test_quiet(self):
        with inside(self.root):
            code, out = call(".", "--quiet")
        self.assertEqual((code, out), (cli.EXIT_FOUND, ""))

    def test_ignore_flag(self):
        with inside(self.root):
            code, out = call(".", "--ignore", "app.py")
        self.assertEqual(code, cli.EXIT_CLEAN)
        self.assertIn("no secrets", out)

    def test_missing_path(self):
        with inside(self.root):
            with self.assertRaises(SystemExit) as caught:
                call("nope.txt")
        self.assertEqual(caught.exception.code, 2)

    def test_bad_max_bytes(self):
        with inside(self.root):
            with self.assertRaises(SystemExit) as caught:
                call(".", "--max-bytes", "0")
        self.assertEqual(caught.exception.code, 2)

    def test_version(self):
        with self.assertRaises(SystemExit) as caught:
            call("--version")
        self.assertEqual(caught.exception.code, 0)


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class StagedTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.git("init", "-b", "main")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")

    def tearDown(self):
        self.directory.cleanup()

    def git(self, *args):
        subprocess.run(
            ["git"] + list(args), cwd=str(self.root), check=True, capture_output=True
        )

    def test_only_staged_files(self):
        (self.root / "staged.py").write_text('K = "%s"\n' % SECRET, encoding="utf-8")
        (self.root / "loose.py").write_text(
            'K = "%s"\n' % LOOSE, encoding="utf-8"
        )
        self.git("add", "staged.py")
        with inside(self.root):
            code, out = call("--staged", "--format", "json")
        payload = json.loads(out)
        self.assertEqual(code, cli.EXIT_FOUND)
        self.assertEqual([f["path"] for f in payload["findings"]], ["staged.py"])

    def test_nothing_staged(self):
        with inside(self.root):
            code, out = call("--staged")
        self.assertEqual((code, out.strip()), (cli.EXIT_CLEAN, "nothing staged to scan"))


if __name__ == "__main__":
    unittest.main()
