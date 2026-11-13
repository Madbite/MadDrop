from __future__ import annotations

import base64
import http.client
import json
import os
import ssl
import time
import uuid
from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, Signal

from .identity import certificate_fingerprint
from .pairing import PAIR_CODE_DIGITS, sign_pairing_proof
from .protocol import MAX_FILE_BYTES, MAX_TRANSFER_BYTES, PROTOCOL_VERSION, PeerDevice

CHUNK_SIZE = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024


def pinned_connection(
    peer: PeerDevice, timeout: float = 180
) -> http.client.HTTPSConnection:
    """Open TLS to the peer and refuse it unless its certificate is the pinned one."""
    if len(peer.fingerprint) != 64:
        raise ValueError("The selected device has an invalid security identity.")
    context = ssl._create_unverified_context()
    connection = http.client.HTTPSConnection(
        peer.address, peer.port, timeout=timeout, context=context
    )
    connection.connect()
    if connection.sock is None:
        connection.close()
        raise ConnectionError("The device closed the connection.")
    certificate = connection.sock.getpeercert(binary_form=True)
    if not certificate:
        connection.close()
        raise ConnectionError("The device closed the connection.")
    if certificate_fingerprint(certificate) != peer.fingerprint.lower():
        connection.close()
        raise ConnectionError(
            "The device identity changed. Refresh nearby devices before sending."
        )
    return connection


def read_json_response(response: http.client.HTTPResponse) -> dict:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("The receiving device returned an oversized response.")
    try:
        value = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The receiving device returned an invalid response.") from exc
    if not isinstance(value, dict):
        raise ValueError("The receiving device returned an invalid response.")
    return value


class SendWorker(QThread):
    status_changed = Signal(str, str)
    progress_changed = Signal(str, str, int, int, float, int)
    transfer_done = Signal(str, bool, str)

    def __init__(
        self,
        peer: PeerDevice,
        paths: list[Path],
        sender_name: str,
        sender_device_id: str,
        transfer_id: str | None = None,
    ) -> None:
        super().__init__()
        self.peer = peer
        self.paths = paths
        self.sender_name = sender_name
        self.sender_device_id = sender_device_id
        self.transfer_id = transfer_id or str(uuid.uuid4())

    def _connection(self) -> http.client.HTTPSConnection:
        return pinned_connection(self.peer)

    @staticmethod
    def _response_json(response: http.client.HTTPResponse) -> dict:
        return read_json_response(response)

    def _check_cancelled(self) -> None:
        if self.isInterruptionRequested():
            raise InterruptedError("Transfer cancelled.")

    def run(self) -> None:
        total_bytes = 0
        sent_bytes = 0
        try:
            files: list[tuple[Path, str, int]] = []
            for path in self.paths:
                self._check_cancelled()
                if not path.is_file():
                    raise ValueError(f"{path.name} is no longer available.")
                size = path.stat().st_size
                if size > MAX_FILE_BYTES:
                    raise ValueError(f"{path.name} is larger than the 30 GB file limit.")
                total_bytes += size
                if total_bytes > MAX_TRANSFER_BYTES:
                    raise ValueError("This selection exceeds the 50 GB transfer limit.")
                files.append((path, path.name, size))
            if not files:
                raise ValueError("Choose at least one file to send.")

            self.status_changed.emit(self.transfer_id, "Waiting for acceptance")
            offer = {
                "version": PROTOCOL_VERSION,
                "sender_name": self.sender_name,
                "sender_device_id": self.sender_device_id,
                "files": [{"name": name, "size": size} for _, name, size in files],
            }
            connection = self._connection()
            try:
                connection.request(
                    "POST",
                    "/v1/offers",
                    body=json.dumps(offer, ensure_ascii=False).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                payload = self._response_json(response)
                if response.status == 403:
                    raise PermissionError("The transfer was declined.")
                if response.status != 202:
                    raise ConnectionError(
                        payload.get("error", "The receiving device could not accept this transfer.")
                    )
            finally:
                connection.close()

            session_id = payload.get("session_id")
            token = payload.get("token")
            if not isinstance(session_id, str) or not isinstance(token, str):
                raise ConnectionError("The receiving device returned an invalid transfer session.")

            started = time.monotonic()
            for index, (path, name, size) in enumerate(files):
                self._check_cancelled()
                self.status_changed.emit(self.transfer_id, f"Sending {name}")
                connection = self._connection()
                file_sent = 0
                try:
                    connection.putrequest("PUT", f"/v1/transfers/{session_id}/{index}")
                    connection.putheader("Content-Type", "application/octet-stream")
                    connection.putheader("Content-Length", str(size))
                    connection.putheader("X-MadDrop-Token", token)
                    connection.putheader("Connection", "close")
                    connection.endheaders()

                    with path.open("rb") as source:
                        while file_sent < size:
                            self._check_cancelled()
                            chunk = source.read(min(CHUNK_SIZE, size - file_sent))
                            if not chunk:
                                raise OSError(f"{name} changed while it was being sent.")
                            connection.send(chunk)
                            file_sent += len(chunk)
                            current = sent_bytes + file_sent
                            elapsed = max(time.monotonic() - started, 0.001)
                            speed = current / elapsed
                            eta = int((total_bytes - current) / speed) if speed > 0 else 0
                            self.progress_changed.emit(
                                self.transfer_id,
                                name,
                                current,
                                total_bytes,
                                speed,
                                eta,
                            )

                    response = connection.getresponse()
                    payload = self._response_json(response)
                    if response.status != 201:
                        raise ConnectionError(
                            payload.get("error", f"Could not send {name}.")
                        )
                finally:
                    connection.close()

                sent_bytes += size
                elapsed = max(time.monotonic() - started, 0.001)
                speed = sent_bytes / elapsed
                eta = int((total_bytes - sent_bytes) / speed) if speed > 0 else 0
                self.progress_changed.emit(
                    self.transfer_id,
                    name,
                    sent_bytes,
                    total_bytes,
                    speed,
                    eta,
                )

            self.transfer_done.emit(
                self.transfer_id, True, f"Sent to {self.peer.name}"
            )
        except InterruptedError as exc:
            self.transfer_done.emit(self.transfer_id, False, str(exc))
        except PermissionError as exc:
            self.transfer_done.emit(self.transfer_id, False, str(exc))
        except Exception as exc:
            self.transfer_done.emit(self.transfer_id, False, str(exc))


class PairWorker(QThread):
    """Asks another device to pair, proving we hold the key behind our fingerprint."""

    pairing_done = Signal(bool, str, str)

    def __init__(
        self,
        peer: PeerDevice,
        device_id: str,
        display_name: str,
        fingerprint: str,
        certificate_der: bytes,
        private_key: Any,
    ) -> None:
        super().__init__()
        self.peer = peer
        self.device_id = device_id
        self.display_name = display_name
        self.fingerprint = fingerprint
        self.certificate_der = certificate_der
        self.private_key = private_key

    def run(self) -> None:
        try:
            nonce = base64.b64encode(os.urandom(32)).decode("ascii")
            payload = {
                "version": PROTOCOL_VERSION,
                "device_id": self.device_id,
                "name": self.display_name,
                "fingerprint": self.fingerprint,
                "certificate": base64.b64encode(self.certificate_der).decode("ascii"),
                "nonce": nonce,
                "signature": sign_pairing_proof(
                    self.private_key,
                    self.fingerprint,
                    self.peer.fingerprint,
                    nonce,
                ),
            }
            connection = pinned_connection(self.peer)
            try:
                connection.request(
                    "POST",
                    "/v1/pair",
                    body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Connection": "close"},
                )
                response = connection.getresponse()
                body = read_json_response(response)
                if response.status == 403:
                    raise PermissionError(
                        body.get("error", "The pairing request was declined.")
                    )
                if response.status != 202:
                    raise ConnectionError(
                        body.get("error", "The other device could not pair.")
                    )
            finally:
                connection.close()

            code = body.get("code")
            if (
                not isinstance(code, str)
                or len(code) != PAIR_CODE_DIGITS
                or not code.isdigit()
            ):
                raise ConnectionError("The other device returned an invalid pairing code.")
            self.pairing_done.emit(True, f"Paired with {self.peer.name}", code)
        except PermissionError as exc:
            self.pairing_done.emit(False, str(exc), "")
        except Exception as exc:
            self.pairing_done.emit(False, str(exc), "")
