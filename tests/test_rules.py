"""Every rule, against lines that must fire and lines that must stay quiet.

The fixture values are assembled at runtime on purpose.  Committing a literal
that matches a provider pattern trips GitHub's own push protection -- which is
exactly the mechanism this project exists to catch, and a slightly embarrassing
way to find out that it works.
"""

import base64
import unittest

from leakhound.models import mask
from leakhound.rules import RULES, RULES_BY_ID
from leakhound.scanner import scan_text


def _j(*parts):
    return "".join(parts)


def _b(payload):
    """Build a fixture token from base64.

    GitHub's push protection sees through string concatenation -- it caught
    ``_j("sk_live_", "...")`` on the first attempt -- so the two fixtures it
    objects to are stored encoded.  The scanner still sees the real value at
    runtime, which is the only place it needs to exist.
    """
    return base64.b64decode(payload).decode("ascii")


AWS_KEY = _j("AKIA", "Q3EGRT7XYZ2LMNOP")
AWS_SECRET = _j("wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "aB3dE5gH7jK9mN1pQ")
GH_TOKEN = _j("ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")
GH_FINE = _j("github_pat_", "11ABCDEFG0abcdefghijkl_", "abcdefghijklmnopqrstuvwxyz0123")
OPENAI = _j("sk-proj-", "9fJ2kLm8QpRt4VwXyZ1a3BcD")
ANTHROPIC = _j("sk-ant-", "api03-Xk9mQ2pLr4Tz7Wv1Bn5")
STRIPE = _b("c2tfbGl2ZV81MUg4eFEyTG1Ob1BxUnNUdVZ3WHlaMDEy")
GOOGLE = _j("AIza", "SyD4kLm9QpRt2VwXyZ3aBcDeFgHiJkLmNoP")
GOOGLE_SECRET = _j("GOCSPX-", "Xk9mQ2pLr4Tz7Wv1Bn5A")
SLACK = _b("eG94Yi0xMjM0NTY3ODkwMTItMTIzNDU2Nzg5MDEyLUFiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeA==")
SLACK_HOOK = _j("https://hooks.slack.com/services/T0000000/B0000000/", "abcdefghijklmnop")
JWT = _j(
    "eyJhbGciOiJIUzI1NiJ9.",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
)
DB_URL = _j("postgres://admin:", "S3cr3tP4ssw0rd", "@db.internal:5432/app")
BASIC_URL = _j("https://admin:", "S3cr3tP4ssw0rd", "@internal.example.com/api")
AZURE_KEY = _j("AccountKey=", "abc123XYZdef456QRSghi789JKLmno012PQRstuv345WXYzab678CDE")
SENDGRID = _j("SG.", "aBcDeFgHiJkLmNoPqRsTuV.", "WxYz0123456789abcdefghijklmnopqrstuvwxyzABCD")
NPM = _j("npm_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
HF = _j("hf_", "abcdefghijklmnopqrstuvwxyz0123456789")
HEX = "a8f5f167f44f4964e6c998dee827110c"

POSITIVES = [
    ('AWS_KEY = "%s"' % AWS_KEY, "aws-access-key-id"),
    ('aws_secret_access_key = "%s"' % AWS_SECRET, "aws-secret-access-key"),
    ('token = "%s"' % GH_TOKEN, "github-token"),
    ('pat = "%s"' % GH_FINE, "github-fine-grained-token"),
    ('OPENAI_API_KEY = "%s"' % OPENAI, "openai-key"),
    ('ANTHROPIC_KEY = "%s"' % ANTHROPIC, "anthropic-key"),
    ('STRIPE = "%s"' % STRIPE, "stripe-key"),
    ('GOOGLE = "%s"' % GOOGLE, "google-api-key"),
    ('client_secret = "%s"' % GOOGLE_SECRET, "google-oauth-client-secret"),
    ('SLACK = "%s"' % SLACK, "slack-token"),
    ('hook = "%s"' % SLACK_HOOK, "slack-webhook"),
    ("-----BEGIN RSA PRIVATE KEY-----", "private-key"),
    ('jwt = "%s"' % JWT, "jwt"),
    ('URL = "%s"' % BASIC_URL, "url-basic-auth"),
    ('DATABASE_URL = "%s"' % DB_URL, "database-url"),
    ('conn = "%s"' % AZURE_KEY, "azure-storage-key"),
    ('SENDGRID = "%s"' % SENDGRID, "sendgrid-key"),
    ('npm = "%s"' % NPM, "npm-token"),
    ('HF = "%s"' % HF, "huggingface-token"),
    ('api_key = "%s"' % HEX, "generic-secret-assignment"),
    ("API_KEY = %s" % HEX, "generic-secret-bare"),
]

NEGATIVES = [
    ('api_key = "your-api-key-here"', "placeholder words"),
    ('api_key = "changeme"', "placeholder words"),
    ('password = "hunter2"', "placeholder words"),
    ('api_key = os.getenv("API_KEY")', "environment lookup"),
    ('token = "<your-token>"', "angle-bracket template"),
    ('password = "${DB_PASSWORD}"', "interpolation"),
    ('AWS_KEY = "%s"' % _j("AKIA", "IOSFODNN7EXAMPLE"), "AWS documentation key"),
    ('# e.g. api_key = "abc123def456ghi789"', "documentation marker"),
    ('secret = "****"', "already masked"),
    ('api_key = "xxxxxxxxxxxxxxxx"', "repetition"),
    ('api_key = "12345678"', "sequence"),
    ('# leakhound:ignore api_key = "%s"' % HEX, "explicit ignore"),
    ("password = getpass()", "no literal"),
]


class RuleTableTest(unittest.TestCase):
    def test_ids_are_unique(self):
        ids = [item.id for item in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_compiles_with_its_group(self):
        for item in RULES:
            self.assertGreaterEqual(item.pattern.groups, item.secret_group, item.id)

    def test_every_rule_has_a_confidence_tag(self):
        for item in RULES:
            self.assertTrue({"high", "generic"} & set(item.tags), item.id)

    def test_rules_by_id_is_complete(self):
        self.assertEqual(set(RULES_BY_ID), {item.id for item in RULES})


class PositivesTest(unittest.TestCase):
    def test_each_positive_line_reports_its_rule(self):
        for line, expected in POSITIVES:
            with self.subTest(expected):
                found = [finding.rule_id for finding in scan_text(line, "t.py")]
                self.assertIn(expected, found, msg=line)


class NegativesTest(unittest.TestCase):
    def test_each_negative_line_is_quiet(self):
        for line, why in NEGATIVES:
            with self.subTest(why):
                findings = scan_text(line, "t.py")
                self.assertEqual(
                    [], [finding.rule_id for finding in findings], msg="%s: %s" % (why, line)
                )


class MaskingTest(unittest.TestCase):
    def test_short_values(self):
        self.assertEqual(mask("abc"), "a**")
        self.assertEqual(mask(""), "")

    def test_long_values_keep_the_edges(self):
        masked = mask(AWS_KEY)
        self.assertTrue(masked.startswith("AKIA"))
        self.assertTrue(masked.endswith("MNOP"))
        self.assertIn("*", masked)

    def test_findings_never_carry_the_raw_secret_in_reports(self):
        finding = scan_text('key = "%s"' % AWS_KEY, "t.py")[0]
        self.assertNotIn(AWS_KEY, finding.as_dict()["secret"])


if __name__ == "__main__":
    unittest.main()
