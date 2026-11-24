
# Import unittest for automated testing.
import unittest

# Import Path to work with file paths.
from pathlib import Path

# Import our detection functions.
from scanner import (
    calculate_hash,
    check_double_extension,
    check_hash_blocklist,
    check_suspicious_content
)


# Locate the project folder.
PROJECT_DIR = Path(__file__).resolve().parent.parent

# Locate the test samples.
SAMPLES_DIR = PROJECT_DIR / "samples"


class TestTrojanScanner(unittest.TestCase):
    """
    Test the three static detection methods using
    harmless sample files.
    """

    def test_normal_file(self):
        # A normal file should not trigger any detection rule.
        path = SAMPLES_DIR / "test.txt"

        self.assertFalse(check_double_extension(path))
        self.assertFalse(
            check_hash_blocklist(calculate_hash(path))
        )
        self.assertEqual(check_suspicious_content(path), [])

    def test_double_extension(self):
        # A misleading filename should trigger the extension rule.
        path = SAMPLES_DIR / "invoice.pdf.exe"

        self.assertTrue(check_double_extension(path))

    def test_hash_blocklist(self):
        # Our blocklisted test file should produce a hash match.
        path = SAMPLES_DIR / "blocklist_test.txt"

        file_hash = calculate_hash(path)

        self.assertTrue(check_hash_blocklist(file_hash))

    def test_suspicious_content(self):
        # The test file contains two simulated indicators.
        path = SAMPLES_DIR / "content_test.txt"

        matches = check_suspicious_content(path)

        self.assertIn("SIMULATED_CREDENTIAL_ACCESS", matches)
        self.assertIn("SIMULATED_REMOTE_CONTROL", matches)


# Run the tests when this file is executed directly.
if __name__ == "__main__":
    unittest.main()
