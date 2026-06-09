from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from revbot.static_analysis import StaticAnalyzer, categorize_strings, extract_strings, shannon_entropy


class StaticAnalysisTests(unittest.TestCase):
    def test_extracts_ascii_and_utf16_strings(self) -> None:
        data = b"\x00flag{demo}\x00" + "password".encode("utf-16le") + b"\x00" + "serial".encode("utf-16be")
        strings = extract_strings(data)
        self.assertIn("flag{demo}", strings)
        self.assertIn("password", strings)
        self.assertIn("serial", strings)

    def test_categorizes_ctf_strings(self) -> None:
        categories = categorize_strings(["wrong password", "https://example.com/a", "flag{demo}"])
        self.assertIn("https://example.com/a", categories["urls"])
        self.assertTrue(any("flag" in item for item in categories["ctf"]))

    def test_entropy_bounds(self) -> None:
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertLess(shannon_entropy(b"A" * 128), 0.1)

    def test_analyze_unknown_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.bin"
            sample.write_bytes(b"hello\x00wrong password\x00flag{demo}\x00")
            result = StaticAnalyzer().analyze(sample)
            self.assertEqual(result["identity"]["format"], "unknown")
            self.assertTrue(result["strings"]["categories"]["ctf"])

    def test_analyze_zip_or_apk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "demo.apk"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                archive.writestr("classes.dex", b"dex\n035\x00wrong password\x00DH{inside_apk}\x00")
            result = StaticAnalyzer().analyze(sample)
            self.assertEqual(result["identity"]["format"], "zip_or_apk")
            self.assertTrue(result["zip"]["is_apk"])
            self.assertIn("DH{inside_apk}", result["zip"]["embedded_strings"])

    def test_detects_common_image_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            samples = {
                "sample.png": b"\x89PNG\r\n\x1a\n",
                "sample.gif": b"GIF89a",
                "sample.jpg": b"\xff\xd8\xff\xe0",
                "sample.bmp": b"BM\x00\x00",
            }
            expected = {
                "sample.png": "png",
                "sample.gif": "gif",
                "sample.jpg": "jpeg",
                "sample.bmp": "bmp",
            }
            for name, data in samples.items():
                path = Path(tmp) / name
                path.write_bytes(data)
                self.assertEqual(StaticAnalyzer().analyze(path)["identity"]["format"], expected[name])

    def test_analyze_nested_zip_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "outer.zip"
            nested = Path(tmp) / "inner.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("Demo.class", b"\xca\xfe\xba\xbe\x00DH{nested_jar}\x00")
            with zipfile.ZipFile(sample, "w") as archive:
                archive.write(nested, "libs/inner.jar")
            result = StaticAnalyzer().analyze(sample)
            self.assertIn("DH{nested_jar}", result["zip"]["embedded_strings"])


if __name__ == "__main__":
    unittest.main()
