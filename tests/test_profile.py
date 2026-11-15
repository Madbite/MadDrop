from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from maddrop.core.profile import (
    FREE_TRANSFER_BYTES,
    PLAN_FREE,
    PLAN_PREMIUM,
    Profile,
    ProfileStore,
    available_space,
    build_profile,
    capacity_warning,
    downgrade,
    transfer_limit,
    upgrade,
)
from maddrop.core.protocol import MAX_TRANSFER_BYTES


class RegistrationTests(unittest.TestCase):
    def test_a_valid_username_and_email_create_a_free_profile(self) -> None:
        profile = build_profile("  ruksana_99 ", " ruksana@example.com ")
        self.assertEqual(profile.username, "ruksana_99")
        self.assertEqual(profile.email, "ruksana@example.com")
        self.assertEqual(profile.plan, PLAN_FREE)
        self.assertFalse(profile.is_premium)

    def test_bad_usernames_are_rejected(self) -> None:
        for username in ("ab", "", "space name", "bad!char", "x" * 25):
            with self.assertRaises(ValueError, msg=username):
                build_profile(username, "user@example.com")

    def test_bad_emails_are_rejected(self) -> None:
        for email in ("", "nope", "no@domain", "two@@at.com", "spaces in@mail.com"):
            with self.assertRaises(ValueError, msg=email):
                build_profile("ruksana", email)


class PlanTests(unittest.TestCase):
    def test_free_accounts_are_capped_and_premium_lifts_the_cap(self) -> None:
        free = Profile("ruksana", "r@example.com")
        premium = upgrade(free)

        self.assertEqual(transfer_limit(free), FREE_TRANSFER_BYTES)
        self.assertEqual(transfer_limit(premium), MAX_TRANSFER_BYTES)
        self.assertEqual(transfer_limit(None), FREE_TRANSFER_BYTES)
        self.assertEqual(premium.plan, PLAN_PREMIUM)
        self.assertEqual(downgrade(premium).plan, PLAN_FREE)


class ProfileStoreTests(unittest.TestCase):
    def test_a_profile_survives_a_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            store = ProfileStore(path)
            self.assertIsNone(store.current())

            store.save(upgrade(build_profile("ruksana", "r@example.com")))

            reopened = ProfileStore(path)
            current = reopened.current()
            self.assertIsNotNone(current)
            self.assertEqual(current.username, "ruksana")
            self.assertTrue(current.is_premium)

    def test_signing_out_removes_the_stored_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            store = ProfileStore(path)
            store.save(build_profile("ruksana", "r@example.com"))
            store.sign_out()
            self.assertIsNone(store.current())
            self.assertIsNone(ProfileStore(path).current())

    def test_a_corrupted_file_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text("{not json", encoding="utf-8")
            self.assertIsNone(ProfileStore(path).current())


class CapacityTests(unittest.TestCase):
    def test_a_transfer_that_fits_raises_no_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(capacity_warning(1024, Path(temporary)), "")

    def test_a_transfer_larger_than_the_disk_is_explained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            free = shutil.disk_usage(temporary).free
            message = capacity_warning(free + 1024, Path(temporary))
            self.assertIn("does not have room", message)

    def test_available_space_walks_up_to_an_existing_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "not" / "created" / "yet"
            self.assertGreater(available_space(missing), 0)


if __name__ == "__main__":
    unittest.main()
