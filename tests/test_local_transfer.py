from __future__ import annotations

import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from PySide6.QtCore import QCoreApplication, QObject, Slot

from maddrop.core.identity import (
    certificate_der,
    ensure_tls_identity,
    load_private_key,
    server_tls_context,
)
from maddrop.core.network import LanTransferService, _ThreadingHTTPServer
from maddrop.core.pairing import pairing_code
from maddrop.core.protocol import PeerDevice
from maddrop.core.sender import PairWorker, SendWorker


class _AcceptEveryOffer(QObject):
    def __init__(self, service: LanTransferService) -> None:
        super().__init__()
        self.service = service

    @Slot(object)
    def accept(self, offer) -> None:
        self.service.decide_offer(offer.transfer_id, True)


class _AcceptEveryPair(QObject):
    def __init__(self, service: LanTransferService, accepted: bool = True) -> None:
        super().__init__()
        self.service = service
        self.accepted = accepted

    @Slot(object)
    def respond(self, request) -> None:
        self.service.decide_pair(request.request_id, self.accepted)


class LocalTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QCoreApplication.instance() or QCoreApplication([])

    def test_files_are_sent_over_tls_only_after_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "received"
            identity = root / "identity"
            source = root / "source"
            source.mkdir()
            contents = b"MadDrop local transfer test\n" * 2000
            (source / "sample.txt").write_bytes(contents)
            (source / "image.bin").write_bytes(b"\x00\x01\x02")
            output.mkdir()
            (output / "sample.txt").write_bytes(b"keep this existing file")

            service = LanTransferService(
                device_id="receiver-device",
                display_name="Receiver",
                identity_directory=identity,
                download_directory=output,
            )
            acceptor = _AcceptEveryOffer(service)
            service.offer_received.connect(acceptor.accept)

            server = _ThreadingHTTPServer(("127.0.0.1", 0), service)
            certificate, key, fingerprint = ensure_tls_identity(identity)
            server.socket = server_tls_context(certificate, key).wrap_socket(
                server.socket, server_side=True
            )
            service._server = server
            service._server_thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )
            service._server_thread.start()

            peer = PeerDevice(
                device_id=service.device_id,
                name=service.display_name,
                platform="Test",
                address="127.0.0.1",
                port=server.server_address[1],
                fingerprint=fingerprint,
            )
            worker = SendWorker(
                peer,
                [source / "sample.txt", source / "image.bin"],
                "Sender",
                str(uuid.uuid4()),
            )
            finished: list[tuple[str, bool, str]] = []
            worker.transfer_done.connect(
                lambda transfer_id, success, message: finished.append(
                    (transfer_id, success, message)
                )
            )
            worker.start()
            deadline = time.monotonic() + 30
            while worker.isRunning() and time.monotonic() < deadline:
                self.application.processEvents()
                time.sleep(0.01)
            worker.wait(1000)
            self.application.processEvents()
            service.stop()

            self.assertTrue(finished, "The sender did not complete.")
            self.assertTrue(finished[0][1], finished[0][2])
            self.assertEqual((output / "sample.txt").read_bytes(), b"keep this existing file")
            self.assertEqual((output / "sample (2).txt").read_bytes(), contents)
            self.assertEqual((output / "image.bin").read_bytes(), b"\x00\x01\x02")

    def test_start_and_stop_stay_responsive_without_a_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = LanTransferService(
                device_id="offline-device",
                display_name="Offline",
                identity_directory=root / "identity",
                download_directory=root / "received",
            )

            with mock.patch(
                "maddrop.core.network.local_ipv4_address",
                side_effect=OSError("no network"),
            ):
                started = time.monotonic()
                with self.assertRaises(OSError):
                    service.start()
                elapsed = time.monotonic() - started

            # No half-open server may be left behind, and neither starting nor
            # shutting down may block the interface.
            self.assertIsNone(service._server)
            self.assertLess(elapsed, 5.0)

            started = time.monotonic()
            service.stop()
            self.assertLess(time.monotonic() - started, 5.0)

    def test_pairing_proves_identity_and_remembers_the_device(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = LanTransferService(
                device_id="receiver-device",
                display_name="Receiver",
                identity_directory=root / "receiver-identity",
                download_directory=root / "received",
            )
            acceptor = _AcceptEveryPair(service)
            service.pair_requested.connect(acceptor.respond)

            certificate, key, fingerprint = ensure_tls_identity(root / "receiver-identity")
            server = _ThreadingHTTPServer(("127.0.0.1", 0), service)
            server.socket = server_tls_context(certificate, key).wrap_socket(
                server.socket, server_side=True
            )
            service._server = server
            service._server_thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )
            service._server_thread.start()

            sender_certificate, sender_key, sender_fingerprint = ensure_tls_identity(
                root / "sender-identity"
            )
            peer = PeerDevice(
                device_id="sender-device",
                name="Sender",
                platform="Test",
                address="127.0.0.1",
                port=server.server_address[1],
                fingerprint=fingerprint,
            )
            worker = PairWorker(
                peer=peer,
                device_id="sender-device",
                display_name="Sender",
                fingerprint=sender_fingerprint,
                certificate_der=certificate_der(sender_certificate),
                private_key=load_private_key(sender_key),
            )
            results: list[tuple[bool, str, str]] = []
            worker.pairing_done.connect(
                lambda success, message, code: results.append((success, message, code))
            )
            worker.start()
            deadline = time.monotonic() + 30
            while worker.isRunning() and time.monotonic() < deadline:
                self.application.processEvents()
                time.sleep(0.01)
            worker.wait(1000)
            self.application.processEvents()
            service.stop()

            self.assertTrue(results, "The pairing request did not finish.")
            self.assertTrue(results[0][0], results[0][1])
            self.assertEqual(
                results[0][2], pairing_code(fingerprint, sender_fingerprint)
            )
            self.assertTrue(
                service.trust_store.matches("sender-device", sender_fingerprint)
            )

    def test_declining_a_pairing_request_trusts_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = LanTransferService(
                device_id="receiver-device",
                display_name="Receiver",
                identity_directory=root / "receiver-identity",
                download_directory=root / "received",
            )
            acceptor = _AcceptEveryPair(service, accepted=False)
            service.pair_requested.connect(acceptor.respond)

            certificate, key, fingerprint = ensure_tls_identity(root / "receiver-identity")
            server = _ThreadingHTTPServer(("127.0.0.1", 0), service)
            server.socket = server_tls_context(certificate, key).wrap_socket(
                server.socket, server_side=True
            )
            service._server = server
            service._server_thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )
            service._server_thread.start()

            sender_certificate, sender_key, sender_fingerprint = ensure_tls_identity(
                root / "sender-identity"
            )
            peer = PeerDevice(
                device_id="sender-device",
                name="Sender",
                platform="Test",
                address="127.0.0.1",
                port=server.server_address[1],
                fingerprint=fingerprint,
            )
            worker = PairWorker(
                peer=peer,
                device_id="sender-device",
                display_name="Sender",
                fingerprint=sender_fingerprint,
                certificate_der=certificate_der(sender_certificate),
                private_key=load_private_key(sender_key),
            )
            results: list[tuple[bool, str, str]] = []
            worker.pairing_done.connect(
                lambda success, message, code: results.append((success, message, code))
            )
            worker.start()
            deadline = time.monotonic() + 30
            while worker.isRunning() and time.monotonic() < deadline:
                self.application.processEvents()
                time.sleep(0.01)
            worker.wait(1000)
            self.application.processEvents()
            service.stop()

            self.assertTrue(results, "The pairing request did not finish.")
            self.assertFalse(results[0][0])
            self.assertIn("declined", results[0][1].lower())
            self.assertIsNone(service.trust_store.get("sender-device"))

    def test_declining_an_offer_sends_no_file_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "received"
            source = root / "private.txt"
            source.write_text("this should not be transferred")
            service = LanTransferService(
                device_id="receiver-device",
                display_name="Receiver",
                identity_directory=root / "identity",
                download_directory=output,
            )
            acceptor = _AcceptEveryOffer(service)
            service.offer_received.connect(
                lambda offer: service.decide_offer(offer.transfer_id, False)
            )

            server = _ThreadingHTTPServer(("127.0.0.1", 0), service)
            certificate, key, fingerprint = ensure_tls_identity(root / "identity")
            server.socket = server_tls_context(certificate, key).wrap_socket(
                server.socket, server_side=True
            )
            service._server = server
            service._server_thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )
            service._server_thread.start()
            peer = PeerDevice(
                device_id=service.device_id,
                name=service.display_name,
                platform="Test",
                address="127.0.0.1",
                port=server.server_address[1],
                fingerprint=fingerprint,
            )
            worker = SendWorker(peer, [source], "Sender", str(uuid.uuid4()))
            finished: list[tuple[str, bool, str]] = []
            worker.transfer_done.connect(
                lambda transfer_id, success, message: finished.append(
                    (transfer_id, success, message)
                )
            )
            worker.start()
            deadline = time.monotonic() + 30
            while worker.isRunning() and time.monotonic() < deadline:
                self.application.processEvents()
                time.sleep(0.01)
            worker.wait(1000)
            self.application.processEvents()
            service.stop()

            self.assertTrue(finished, "The sender did not complete.")
            self.assertFalse(finished[0][1])
            self.assertIn("declined", finished[0][2].lower())
            self.assertFalse(output.exists() and any(output.iterdir()))


if __name__ == "__main__":
    unittest.main()
