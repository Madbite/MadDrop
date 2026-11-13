from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any

from .identity import certificate_fingerprint

PROTOCOL_VERSION = 1
MAX_OFFER_BYTES = 1024 * 1024
PAIR_REQUEST_BYTES = 16 * 1024
MAX_FILES_PER_TRANSFER = 100
MAX_FILE_BYTES = 30 * 1024**3
MAX_TRANSFER_BYTES = 50 * 1024**3

_INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_RESERVED_NAME = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE
)


@dataclass(frozen=True)
class FileOffer:
    name: str
    size: int


@dataclass(frozen=True)
class PeerDevice:
    device_id: str
    name: str
    platform: str
    address: str
    port: int
    fingerprint: str
    paired: bool = False
    identity_changed: bool = False


@dataclass
class IncomingOffer:
    transfer_id: str
    sender_name: str
    sender_device_id: str
    files: tuple[FileOffer, ...]
    remote_address: str
    decision_event: Event = field(default_factory=Event, repr=False)
    accepted: bool = False
    session_id: str | None = None
    token: str | None = field(default=None, repr=False)

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.files)


@dataclass(frozen=True)
class PairClaim:
    """What another device says about itself when it asks to be paired."""

    device_id: str
    name: str
    fingerprint: str
    certificate: bytes
    nonce: str
    signature: str


@dataclass
class PairingRequest:
    request_id: str
    device_id: str
    name: str
    fingerprint: str
    code: str
    remote_address: str
    decision_event: Event = field(default_factory=Event, repr=False)
    accepted: bool = False


def clean_device_name(value: Any, fallback: str = "Nearby device") -> str:
    if not isinstance(value, str):
        return fallback
    name = " ".join(value.replace("\x00", "").split()).strip()
    return name[:48] or fallback


def sanitize_filename(value: Any) -> str:
    if not isinstance(value, str):
        return "Shared file"

    # Treat either platform's separator as a path boundary before sanitizing.
    name = value.replace("\\", "/").rsplit("/", 1)[-1]
    name = _INVALID_FILENAME_CHARS.sub("_", name).strip().rstrip(". ")
    if not name or name in {".", ".."}:
        name = "Shared file"
    if _WINDOWS_RESERVED_NAME.match(name):
        name = f"_{name}"

    if len(name) > 180:
        suffix = Path(name).suffix[:24]
        stem = name[: 180 - len(suffix)].rstrip(". ")
        name = f"{stem}{suffix}" or "Shared file"
    return name


def validate_offer(payload: Any) -> tuple[str, str, tuple[FileOffer, ...]]:
    if not isinstance(payload, dict):
        raise ValueError("The transfer request is invalid.")
    if payload.get("version") != PROTOCOL_VERSION:
        raise ValueError("This device uses an unsupported MadDrop version.")

    sender_name = clean_device_name(payload.get("sender_name"))
    sender_device_id = payload.get("sender_device_id")
    if (
        not isinstance(sender_device_id, str)
        or len(sender_device_id) > 64
        or not sender_device_id
    ):
        raise ValueError("The sending device could not be identified.")

    raw_files = payload.get("files")
    if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= MAX_FILES_PER_TRANSFER:
        raise ValueError(f"Choose between 1 and {MAX_FILES_PER_TRANSFER} files.")

    files: list[FileOffer] = []
    total = 0
    for raw in raw_files:
        if not isinstance(raw, dict):
            raise ValueError("The file list is invalid.")
        name = sanitize_filename(raw.get("name"))
        size = raw.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("A file has an invalid size.")
        if size > MAX_FILE_BYTES:
            raise ValueError(f"{name} is larger than the 30 GB per-file limit.")
        total += size
        if total > MAX_TRANSFER_BYTES:
            raise ValueError("This transfer exceeds the 50 GB total limit.")
        files.append(FileOffer(name=name, size=size))

    return sender_name, sender_device_id, tuple(files)


def unique_destination(directory: Path, requested_name: str) -> Path:
    """Choose a non-existing destination without trusting a remote path."""
    directory = directory.resolve()
    name = sanitize_filename(requested_name)
    candidate = directory / name
    if not candidate.exists() and not candidate.is_symlink():
        return candidate

    original = Path(name)
    stem, suffix = original.stem, original.suffix
    for number in range(2, 100_000):
        candidate = directory / f"{stem} ({number}){suffix}"
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise OSError("Could not choose a unique filename in the receive folder.")


def _decode_pairing_bytes(value: Any, label: str, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"The pairing {label} is invalid.")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"The pairing {label} is invalid.") from exc
    if not raw or len(raw) > maximum:
        raise ValueError(f"The pairing {label} is invalid.")
    return raw


def validate_pair_request(payload: Any) -> PairClaim:
    if not isinstance(payload, dict):
        raise ValueError("The pairing request is invalid.")
    if payload.get("version") != PROTOCOL_VERSION:
        raise ValueError("This device uses an unsupported MadDrop version.")

    device_id = payload.get("device_id")
    if not isinstance(device_id, str) or not device_id or len(device_id) > 64:
        raise ValueError("The pairing device could not be identified.")

    fingerprint = payload.get("fingerprint")
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError("The pairing device has an invalid identity.")
    try:
        int(fingerprint, 16)
    except ValueError as exc:
        raise ValueError("The pairing device has an invalid identity.") from exc

    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not 16 <= len(nonce) <= 128:
        raise ValueError("The pairing request is missing its challenge.")

    signature = payload.get("signature")
    if not isinstance(signature, str) or not 16 <= len(signature) <= 256:
        raise ValueError("The pairing request is missing its proof.")

    return PairClaim(
        device_id=device_id,
        name=clean_device_name(payload.get("name")),
        fingerprint=fingerprint.lower(),
        certificate=_decode_pairing_bytes(payload.get("certificate"), "certificate", 4096),
        nonce=nonce,
        signature=signature,
    )
