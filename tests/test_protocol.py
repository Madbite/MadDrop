from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from maddrop.core.protocol import (
    MAX_FILE_BYTES,
    PROTOCOL_VERSION,
    sanitize_filename,
    unique_destination,
    validate_offer,
)


class ProtocolTests(unittest.TestCase):
    def test_filename_cannot_escape_receive_folder(self) -> None:
        self.assertEqual(sanitize_filename(r"..\..\private\photo.png"), "photo.png")
        self.assertEqual(sanitize_filename("../../CON.txt"), "_CON.txt")
        self.assertNotIn("/", sanitize_filename("folder/name.txt"))
        self.assertNotIn("\\", sanitize_filename(r"folder\name.txt"))

    def test_offer_rejects_oversized_files_and_bad_sizes(self) -> None:
        base = {
            "version": PROTOCOL_VERSION,
            "sender_name": "  Laptop  ",
            "sender_device_id": "device-1",
            "files": [{"name": "notes.txt", "size": 10}],
        }
        sender, device_id, files = validate_offer(base)
        self.assertEqual(sender, "Laptop")
        self.assertEqual(device_id, "device-1")
        self.assertEqual(files[0].name, "notes.txt")

        base["files"] = [{"name": "huge.bin", "size": MAX_FILE_BYTES + 1}]
        with self.assertRaises(ValueError):
            validate_offer(base)

        base["files"] = [{"name": "bad.bin", "size": True}]
        with self.assertRaises(ValueError):
            validate_offer(base)

    def test_destination_is_unique_and_stays_in_receive_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "report.txt").write_text("existing")
            result = unique_destination(root, "../report.txt")
            self.assertEqual(result.parent, root.resolve())
            self.assertEqual(result.name, "report (2).txt")


if __name__ == "__main__":
    unittest.main()
