"""The placeholder heuristics, which are what make this usable on AI code."""

import unittest

from leakhound.placeholders import (
    KNOWN_FAKE,
    is_environment_lookup,
    is_placeholder,
    looks_like_template,
)

#: Assembled at runtime so the repository never contains a credential-shaped
#: literal; see the note in ``test_rules.py``.
AWS_KEY = "AKIA" + "Q3EGRT7XYZ2LMNOP"


class TemplateTest(unittest.TestCase):
    def test_angle_brackets(self):
        for value in ("<TOKEN>", "<your-key>", "${KEY}", "{{ token }}", "%(key)s"):
            self.assertTrue(looks_like_template(value), value)

    def test_plain_values_are_not_templates(self):
        for value in ("a8f5f167f44f", "ghp_abc", AWS_KEY):
            self.assertFalse(looks_like_template(value), value)

    def test_empty_is_a_template(self):
        self.assertTrue(looks_like_template(""))


class PlaceholderTest(unittest.TestCase):
    def test_known_fake_aws_pair(self):
        for value in KNOWN_FAKE:
            self.assertTrue(is_placeholder(value, strict=True), value)

    def test_words_that_only_mean_placeholder(self):
        for value in (
            "your-api-key-here",
            "changeme",
            "REPLACE_ME",
            "sk-dummy-key",
            "TODO_FILL_THIS_IN",
            "not-a-real-token",
        ):
            self.assertTrue(is_placeholder(value), value)

    def test_repetitive_and_sequential(self):
        for value in ("xxxxxxxx", "12345678", "abababab", "aaaaaaaa"):
            self.assertTrue(is_placeholder(value), value)

    def test_real_looking_token_survives(self):
        for value in ("a8f5f167f44f4964e6c998dee827110c", AWS_KEY):
            self.assertFalse(is_placeholder(value), value)

    def test_strict_ignores_context(self):
        line = '# for example, put the key here: "ghp_' + "a" * 36 + '"'
        self.assertFalse(is_placeholder("ghp_" + "a" * 36, line, strict=True))

    def test_generic_trusts_context(self):
        self.assertTrue(is_placeholder("a8f5f167f44f4964e6c998dee827110c",
                                       "e.g. api_key = ...", strict=False))

    def test_masked_values(self):
        for value in ("****", "abc...", "sk-***"):
            self.assertTrue(is_placeholder(value), value)


class EnvironmentTest(unittest.TestCase):
    def test_references(self):
        for line in (
            'key = os.getenv("OPENAI_API_KEY")',
            "token = os.environ['TOKEN']",
            "const key = process.env.API_KEY",
            'pwd = "${DB_PASSWORD}"',
            'value = config.get("api_key")',
        ):
            self.assertTrue(is_environment_lookup(line), line)

    def test_literals_are_not_references(self):
        for line in ('key = "a8f5f167f44f"', "password = 'hunter2'"):
            self.assertFalse(is_environment_lookup(line), line)


if __name__ == "__main__":
    unittest.main()
