"""Pairing codes and the local list of devices the user has verified."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .identity import certificate_fingerprint

PAIR_CODE_DIGITS = 3
PAIR_PROOF_PREFIX = "maddrop-pair"


def pairing_code(fingerprint_a: str, fingerprint_b: str) -> str:
    """The 3-digit code both devices show; it is derived from both identities.

    The code is not a secret. It exists so two people can compare what is on
    their screens before they trust each other's device for good.
    """
    left, right = sorted((fingerprint_a.lower(), fingerprint_b.lower()))
    digest = hashlib.sha256(f"{left}:{right}".encode("ascii")).digest()
    span = 10**PAIR_CODE_DIGITS
    return f"{int.from_bytes(digest[:8], 'big') % span:0{PAIR_CODE_DIGITS}d}"


def pairing_payload(
    sender_fingerprint: str, receiver_fingerprint: str, nonce: str
) -> bytes:
    """The exact bytes a device signs to prove it owns its certificate key."""
    return (
        f"{PAIR_PROOF_PREFIX}|{sender_fingerprint.lower()}|"
        f"{receiver_fingerprint.lower()}|{nonce}"
    ).encode("ascii")


def sign_pairing_proof(
    private_key: Any, sender_fingerprint: str, receiver_fingerprint: str, nonce: str
) -> str:
    signature = private_key.sign(
        pairing_payload(sender_fingerprint, receiver_fingerprint, nonce),
        ec.ECDSA(hashes.SHA256()),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_pairing_proof(
    certificate_der: bytes,
    sender_fingerprint: str,
    receiver_fingerprint: str,
    nonce: str,
    signature: str,
) -> bool:
    """Check that the sender holds the key behind the fingerprint it claims."""
    try:
        if certificate_fingerprint(certificate_der) != sender_fingerprint.lower():
            return False
        public_key = x509.load_der_x509_certificate(certificate_der).public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        public_key.verify(
            base64.b64decode(signature, validate=True),
            pairing_payload(sender_fingerprint, receiver_fingerprint, nonce),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass(frozen=True)
class TrustedDevice:
    device_id: str
    name: str
    fingerprint: str
    paired_at: float


class TrustStore:
    """Devices the user has paired with, persisted next to the identity."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._devices: dict[str, TrustedDevice] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for device_id, entry in raw.items():
            if not isinstance(entry, dict):
                continue
            fingerprint = entry.get("fingerprint")
            if not isinstance(device_id, str) or not isinstance(fingerprint, str):
                continue
            if len(fingerprint) != 64:
                continue
            try:
                paired_at = float(entry.get("paired_at", 0.0))
            except (TypeError, ValueError):
                paired_at = 0.0
            self._devices[device_id] = TrustedDevice(
                device_id=device_id,
                name=str(entry.get("name", "Paired device"))[:48],
                fingerprint=fingerprint.lower(),
                paired_at=paired_at,
            )

    def _save(self) -> None:
        payload = {
            device.device_id: {
                "name": device.name,
                "fingerprint": device.fingerprint,
                "paired_at": device.paired_at,
            }
            for device in self._devices.values()
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.path)

    def add(self, device_id: str, name: str, fingerprint: str) -> TrustedDevice:
        with self._lock:
            device = TrustedDevice(
                device_id=device_id,
                name=name[:48] or "Paired device",
                fingerprint=fingerprint.lower(),
                paired_at=time.time(),
            )
            self._devices[device_id] = device
            self._save()
            return device

    def forget(self, device_id: str) -> None:
        with self._lock:
            if self._devices.pop(device_id, None) is not None:
                self._save()

    def get(self, device_id: str) -> TrustedDevice | None:
        with self._lock:
            return self._devices.get(device_id)

    def devices(self) -> list[TrustedDevice]:
        with self._lock:
            return sorted(self._devices.values(), key=lambda item: item.name.casefold())

    def matches(self, device_id: str, fingerprint: str) -> bool:
        device = self.get(device_id)
        return device is not None and device.fingerprint == fingerprint.lower()
