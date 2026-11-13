from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from maddrop.core.identity import (
    certificate_der,
    certificate_fingerprint,
    ensure_tls_identity,
    load_private_key,
)
from dataclasses import replace

from maddrop.core.network import LanTransferService
from maddrop.core.pairing import (
    PAIR_CODE_DIGITS,
    TrustStore,
    pairing_code,
    sign_pairing_proof,
    verify_pairing_proof,
)
from maddrop.core.protocol import PeerDevice

LEFT = "1a" * 32
RIGHT = "b7" * 32


class PairingCodeTests(unittest.TestCase):
    def test_code_is_three_digits_and_identical_on_both_devices(self) -> None:
        code = pairing_code(LEFT, RIGHT)
        self.assertEqual(len(code), PAIR_CODE_DIGITS)
        self.assertTrue(code.isdigit())
        self.assertEqual(code, pairing_code(RIGHT, LEFT))

    def test_code_changes_with_the_device_pair(self) -> None:
        other = "c4" * 32
        self.assertNotEqual(pairing_code(LEFT, RIGHT), pairing_code(LEFT, other))


class PairingProofTests(unittest.TestCase):
    def test_proof_only_verifies_against_the_certificate_that_signed_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, key_path, fingerprint = ensure_tls_identity(root / "a")
            _, _, other_fingerprint = ensure_tls_identity(root / "b")

            proof = sign_pairing_proof(load_private_key(key_path), fingerprint, other_fingerprint, "nonce-1")
            der = certificate_der(certificate)

            self.assertTrue(
                verify_pairing_proof(der, fingerprint, other_fingerprint, "nonce-1", proof)
            )
            # A nonce signed for another device must not be reused here.
            self.assertFalse(
                verify_pairing_proof(der, fingerprint, other_fingerprint, "nonce-2", proof)
            )
            # Claiming someone else's identity cannot work without their key.
            self.assertFalse(
                verify_pairing_proof(der, other_fingerprint, other_fingerprint, "nonce-1", proof)
            )

    def test_proof_from_a_different_certificate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert_a, key_a, fingerprint_a = ensure_tls_identity(root / "a")
            cert_b, _, fingerprint_b = ensure_tls_identity(root / "b")

            proof = sign_pairing_proof(load_private_key(key_a), fingerprint_a, fingerprint_b, "n")
            self.assertFalse(
                verify_pairing_proof(
                    certificate_der(cert_b), fingerprint_a, fingerprint_b, "n", proof
                )
            )


class TrustStoreTests(unittest.TestCase):
    def test_pairs_persist_and_must_match_the_paired_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "trusted-devices.json"
            store = TrustStore(path)
            store.add("device-1", "Laptop", LEFT)

            reloaded = TrustStore(path)
            self.assertTrue(reloaded.matches("device-1", LEFT))
            self.assertTrue(reloaded.matches("device-1", LEFT.upper()))
            self.assertFalse(reloaded.matches("device-1", RIGHT))
            self.assertFalse(reloaded.matches("device-2", LEFT))
            self.assertEqual(reloaded.get("device-1").name, "Laptop")

    def test_forgetting_a_device_removes_it_from_disk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "trusted-devices.json"
            store = TrustStore(path)
            store.add("device-1", "Laptop", LEFT)
            store.forget("device-1")
            self.assertFalse(TrustStore(path).matches("device-1", LEFT))

    def test_a_device_whose_identity_changed_is_flagged_not_trusted_silently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = LanTransferService(
                device_id="me",
                display_name="Me",
                identity_directory=root / "identity",
                download_directory=root / "downloads",
            )
            service.trust_store.add("peer", "Peer", LEFT)
            peer = PeerDevice(
                device_id="peer",
                name="Peer",
                platform="Test",
                address="192.0.2.10",
                port=1234,
                fingerprint=RIGHT,
            )
            changed = service._with_trust(peer)
            self.assertTrue(changed.paired)
            self.assertTrue(changed.identity_changed)

            same = service._with_trust(replace(peer, fingerprint=LEFT))
            self.assertTrue(same.paired)
            self.assertFalse(same.identity_changed)

    def test_certificate_fingerprint_helper_matches_the_der_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            certificate, _, fingerprint = ensure_tls_identity(Path(temporary) / "identity")
            self.assertEqual(certificate_fingerprint(certificate_der(certificate)), fingerprint)


if __name__ == "__main__":
    unittest.main()
