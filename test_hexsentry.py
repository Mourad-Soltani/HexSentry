"""
HexSentry health tests.
Built by Mourad.Soltani
"""

import unittest
import tempfile
import os
from pathlib import Path
from hexsentry import shannon_entropy, is_high_entropy, scan_text, scan_path

class TestHexSentry(unittest.TestCase):
    def test_entropy_low(self):
        self.assertLess(shannon_entropy("aaaaaaa"), 1.0)

    def test_entropy_high(self):
        # High entropy random-like string
        self.assertGreater(shannon_entropy("aB3$kL9mN2pQ7xY"), 3.5)

    def test_high_entropy_detection(self):
        secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        self.assertTrue(is_high_entropy(secret, threshold=4.0))

    def test_scan_openai_key(self):
        text = 'API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"'
        findings = scan_text(text)
        self.assertTrue(any("OpenAI" in f["type"] for f in findings))

    def test_scan_github_token(self):
        text = 'token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890abcd"'
        findings = scan_text(text)
        self.assertTrue(any("GitHub" in f["type"] for f in findings))

    def test_no_false_positive_short(self):
        text = "password = 'short'"
        findings = scan_text(text)
        self.assertEqual(len(findings), 0)

    def test_scan_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write('SECRET=sk-abcdefghijklmnopqrstuvwxyz1234567890\n')
            fname = f.name
        try:
            findings = scan_path(Path(fname))
            self.assertGreater(len(findings), 0)
        finally:
            os.unlink(fname)

    def test_health_basic(self):
        # Basic health: tool imports and core functions work
        self.assertGreater(shannon_entropy("teststring123"), 2.0)
        self.assertIsInstance(scan_text("hello"), list)

if __name__ == "__main__":
    unittest.main()
