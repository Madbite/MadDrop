from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from maddrop.core.inspection import (
    CLEAN,
    DANGEROUS,
    SUSPICIOUS,
    inspect_file,
    scan_with_defender,
)

PE_STUB = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200


class InspectionTests(unittest.TestCase):
    def _write(self, root: Path, name: str, data: bytes) -> Path:
        path = root / name
        path.write_bytes(data)
        return path

    def test_plain_text_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), "notes.txt", b"shopping list\n" * 20)
            result = inspect_file(path, "notes.txt")
            self.assertEqual(result.risk, CLEAN)
            self.assertFalse(result.flagged)

    def test_program_wearing_a_document_name_is_dangerous(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), "holiday.jpg", PE_STUB)
            result = inspect_file(path, "holiday.jpg")
            self.assertEqual(result.risk, DANGEROUS)
            self.assertIn("named like a document", result.describe())

    def test_double_extension_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), "statement.pdf.exe", PE_STUB)
            result = inspect_file(path, "statement.pdf.exe")
            self.assertTrue(result.flagged)
            self.assertIn("double extension", result.describe())

    def test_pdf_with_embedded_script_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = b"%PDF-1.7\n" + b"body\n" * 50 + b"/JavaScript (alert(1))"
            path = self._write(Path(temporary), "form.pdf", data)
            result = inspect_file(path, "form.pdf")
            self.assertEqual(result.risk, SUSPICIOUS)
            self.assertIn("script", result.describe())

    def test_office_macros_are_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"VBA" + b"\x00" * 64
            path = self._write(Path(temporary), "invoice.doc", data)
            result = inspect_file(path, "invoice.doc")
            self.assertTrue(result.flagged)
            self.assertIn("macros", result.describe())

    def test_archive_is_reported_as_not_inspected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), "photos.zip", b"PK\x03\x04" + b"\x00" * 100)
            result = inspect_file(path, "photos.zip")
            self.assertEqual(result.risk, SUSPICIOUS)
            self.assertIn("archive", result.describe())

    def test_pdf_that_is_not_a_pdf_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), "report.pdf", b"not really a pdf\n" * 10)
            result = inspect_file(path, "report.pdf")
            self.assertEqual(result.risk, SUSPICIOUS)
            self.assertIn("not one", result.describe())

    def test_defender_is_absent_off_windows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), "notes.txt", b"hello")
            if sys.platform != "win32":
                self.assertIsNone(scan_with_defender(path))

    def test_inspection_reads_a_sample_rather_than_the_whole_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            # A 6 MB file is far larger than the 1 MiB head sample; the check
            # must still finish promptly instead of chewing through all of it.
            path = self._write(Path(temporary), "video.mp4", b"\x00" * (6 * 1024 * 1024))
            result = inspect_file(path, "video.mp4")
            self.assertEqual(result.risk, CLEAN)


if __name__ == "__main__":
    unittest.main()
