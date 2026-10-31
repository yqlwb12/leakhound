"""Entropy, which is the difference between a key and a sentence."""

import unittest

from leakhound.entropy import classes, entropy, is_repetitive, is_sequential


class EntropyTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(entropy(""), 0.0)

    def test_single_character_repeated(self):
        self.assertEqual(entropy("aaaaaaaa"), 0.0)

    def test_two_symbols(self):
        self.assertAlmostEqual(entropy("ab" * 8), 1.0, places=6)

    def test_uniform_alphabet(self):
        # 4 symbols used equally: 2 bits each.
        self.assertAlmostEqual(entropy("abcd" * 4), 2.0, places=6)

    def test_random_token_clears_the_bar(self):
        self.assertGreater(entropy("a8f5f167f44f4964e6c998dee827110c"), 3.5)

    def test_real_word_is_low(self):
        self.assertLess(entropy("password"), 3.0)

    def test_bounds(self):
        for value in ("", "a", "abc", "a1B2c3D4!@#$"):
            self.assertGreaterEqual(entropy(value), 0.0)
            self.assertLessEqual(entropy(value), 8.0)


class ClassesTest(unittest.TestCase):
    def test_counting(self):
        self.assertEqual(classes("abc"), 1)
        self.assertEqual(classes("aB"), 2)
        self.assertEqual(classes("aB1"), 3)
        self.assertEqual(classes("aB1!"), 4)

    def test_empty(self):
        self.assertEqual(classes(""), 0)


class ShapeTest(unittest.TestCase):
    def test_repetitive(self):
        for value in ("aaaa", "xxxxxx", "ababab", "abcabcabc"):
            self.assertTrue(is_repetitive(value), value)

    def test_not_repetitive(self):
        for value in ("a8f5f167", "ghp_abc123", "x9Y2z7Q4"):
            self.assertFalse(is_repetitive(value), value)

    def test_sequential(self):
        # Descending counts too: "zyxwvut" is the alphabet backwards.
        for value in ("12345678", "abcdef", "abcdefgh", "87654321", "zyxwvut"):
            self.assertTrue(is_sequential(value), value)

    def test_not_sequential(self):
        for value in ("a8f5f167", "1a2b3c4d", "qwertyui"):
            self.assertFalse(is_sequential(value), value)


if __name__ == "__main__":
    unittest.main()
