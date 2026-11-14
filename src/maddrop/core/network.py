from __future__ import annotations

import hmac
import http.server
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QObject, Signal
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

from .identity import ensure_tls_identity, local_ipv4_address, server_tls_context
from .pairing import TrustStore, pairing_code, verify_pairing_proof
from .protocol import (
    MAX_OFFER_BYTES,
    PAIR_REQUEST_BYTES,
    FileOffer,
    IncomingOffer,
    PairClaim,
    PairingRequest,
    PeerDevice,
    clean_device_name,
    sanitize_filename,
    unique_destination,
    validate_offer,
    validate_pair_request,
)

SERVICE_TYPE = "_maddrop._tcp.local."
CHUNK_SIZE = 256 * 1024
UPLOAD_ROUTE = re.compile(r"^/v1/transfers/([0-9a-fA-F-]{36})/(\d+)$")
SHUTDOWN_TIMEOUT = 2.0


def _run_bounded(step: Callable[[], None], timeout: float = SHUTDOWN_TIMEOUT) -> None:
    """Run a teardown step on a daemon thread so a stuck stack cannot freeze the app."""

    def guarded() -> None:
        try:
            step()
        except Exception:
            pass

    worker = threading.Thread(target=guarded, daemon=True)
    worker.start()
    worker.join(timeout)


@dataclass
class TransferSession:
    session_id: str
    token: str = field(repr=False)
    files: tuple[FileOffer, ...]
    completed: set[int] = field(default_factory=set)
    active: set[int] = field(default_factory=set)
    received_paths: dict[int, str] = field(default_factory=dict)
    started_at: float = field(default_factory=time.monotonic)


class _RequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MadDrop"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(180)

    @property
    def controller(self) -> LanTransferService:
        return self.server.controller  # type: ignore[attr-defined, no-any-return]

    def log_message(self, _format: str, *_args: Any) -> None:
        # Avoid logging filenames, addresses, and transfer tokens.
        return

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        self.close_connection = True

    def _content_length(self, maximum: int) -> int:
        raw = self.headers.get("Content-Length")
        if raw is None:
            raise ValueError("Content-Length is required.")
        try:
            length = int(raw)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length.") from exc
        if length < 0 or length > maximum:
            raise ValueError("Request size is outside the allowed limit.")
        return length

    def do_POST(self) -> None:
        if self.path == "/v1/offers":
            self._handle_offer()
        elif self.path == "/v1/pair":
            self._handle_pair()
        else:
            self._respond(404, {"error": "Not found."})

    def _handle_offer(self) -> None:
        try:
            length = self._content_length(MAX_OFFER_BYTES)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("The transfer request was incomplete.")
            payload = json.loads(raw.decode("utf-8"))
            sender, sender_id, files = validate_offer(payload)
            result = self.controller.request_acceptance(
                sender, sender_id, files, self.client_address[0]
            )
            if result is None:
                self._respond(403, {"error": "The transfer was declined."})
                return
            session_id, token = result
            self._respond(
                202,
                {"session_id": session_id, "token": token, "accepted": True},
            )
        except TimeoutError as exc:
            self._respond(408, {"error": str(exc)})
        except ValueError as exc:
            self._respond(400, {"error": str(exc)})
        except PermissionError as exc:
            self._respond(429, {"error": str(exc)})
        except Exception:
            self._respond(500, {"error": "The transfer request could not be processed."})

    def _handle_pair(self) -> None:
        try:
            length = self._content_length(PAIR_REQUEST_BYTES)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("The pairing request was incomplete.")
            claim = validate_pair_request(json.loads(raw.decode("utf-8")))
            if not verify_pairing_proof(
                claim.certificate,
                claim.fingerprint,
                self.controller.fingerprint,
                claim.nonce,
                claim.signature,
            ):
                self._respond(
                    403, {"error": "The pairing request could not be verified."}
                )
                return
            code = self.controller.request_pairing(claim, self.client_address[0])
            if code is None:
                self._respond(403, {"error": "The pairing request was declined."})
                return
            self._respond(202, {"paired": True, "code": code})
        except TimeoutError as exc:
            self._respond(408, {"error": str(exc)})
        except ValueError as exc:
            self._respond(400, {"error": str(exc)})
        except PermissionError as exc:
            self._respond(429, {"error": str(exc)})
        except Exception:
            self._respond(500, {"error": "The pairing request could not be processed."})

    def do_PUT(self) -> None:
        match = UPLOAD_ROUTE.fullmatch(self.path)
        if match is None:
            self._respond(404, {"error": "Not found."})
            return
        session_id = ""
        index = -1
        try:
            session_id, raw_index = match.groups()
            index = int(raw_index)
            session, item = self.controller.begin_upload(
                session_id, index, self.headers.get("X-MadDrop-Token", "")
            )
            length = self._content_length(item.size)
            if length != item.size:
                self.controller.abort_upload(session_id, index)
                raise ValueError("The file size does not match the accepted offer.")
            saved_path = self.controller.receive_file(
                self.rfile, session, index, item, length
            )
            self._respond(201, {"saved": True, "name": Path(saved_path).name})
        except PermissionError as exc:
            self._respond(403, {"error": str(exc)})
        except (ValueError, OSError, TimeoutError) as exc:
            if session_id and index >= 0:
                self.controller.abort_upload(session_id, index)
                self.controller.incoming_failed.emit(
                    session_id, f"Transfer failed: {exc}"
                )
            self._respond(400, {"error": str(exc)})
        except Exception:
            self._respond(500, {"error": "The file could not be saved."})


class _ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], controller: LanTransferService):
        self.controller = controller
        super().__init__(address, _RequestHandler)


class _DiscoveryListener(ServiceListener):
    def __init__(self, service: LanTransferService):
        self.service = service

    def add_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self.service._resolve_device(zeroconf, service_type, name)

    def update_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self.service._resolve_device(zeroconf, service_type, name)

    def remove_service(self, _zeroconf: Zeroconf, _service_type: str, name: str) -> None:
        self.service._remove_device(name)


class LanTransferService(QObject):
    devices_changed = Signal(object)
    status_changed = Signal(str)
    offer_received = Signal(object)
    pair_requested = Signal(object)
    incoming_progress = Signal(str, str, int, int, int, int, float, int)
    incoming_complete = Signal(str, object, str)
    incoming_failed = Signal(str, str)

    def __init__(
        self,
        device_id: str,
        display_name: str,
        identity_directory: Path,
        download_directory: Path,
        trust_store: TrustStore | None = None,
    ) -> None:
        super().__init__()
        self.device_id = device_id
        self.display_name = clean_device_name(display_name, platform.node() or "This device")
        self.identity_directory = identity_directory
        self.download_directory = download_directory.expanduser().resolve()
        self.trust_store = trust_store or TrustStore(
            identity_directory.parent / "trusted-devices.json"
        )
        (
            self.certificate_path,
            self.private_key_path,
            self.fingerprint,
        ) = ensure_tls_identity(identity_directory)
        self._lock = threading.RLock()
        self._devices_by_service: dict[str, PeerDevice] = {}
        self._pending: dict[str, IncomingOffer] = {}
        self._pending_pairs: dict[str, PairingRequest] = {}
        self._sessions: dict[str, TransferSession] = {}
        self._offer_times: dict[str, list[float]] = {}
        self._pair_times: dict[str, list[float]] = {}
        self._server: _ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._zeroconf: Zeroconf | None = None
        self._browser: ServiceBrowser | None = None
        self._service_info: ServiceInfo | None = None
        self._stopping = False

    def start(self) -> None:
        if self._server is not None:
            return
        self._stopping = False
        try:
            # Resolve the address first: with no network this must fail before a
            # listening server is left behind to tear down.
            address = local_ipv4_address()
            self.download_directory.mkdir(parents=True, exist_ok=True)
            self._server = _ThreadingHTTPServer(("0.0.0.0", 0), self)
            self._server.socket = server_tls_context(
                self.certificate_path, self.private_key_path
            ).wrap_socket(self._server.socket, server_side=True)
            self._server_thread = threading.Thread(
                target=self._server.serve_forever,
                name="MadDrop transfer server",
                daemon=True,
            )
            self._server_thread.start()

            self._zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
            self._service_info = self._make_service_info(address)
            self._zeroconf.register_service(self._service_info)
            self._browser = ServiceBrowser(
                self._zeroconf,
                SERVICE_TYPE,
                listener=_DiscoveryListener(self),
            )
            self.status_changed.emit("Visible on this local network")
        except Exception:
            self.stop()
            raise

    def _make_service_info(self, address: str) -> ServiceInfo:
        service_name = f"MadDrop-{self.device_id}._maddrop._tcp.local."
        host = re.sub(r"[^A-Za-z0-9-]", "-", socket.gethostname()).strip("-") or "maddrop"
        return ServiceInfo(
            SERVICE_TYPE,
            service_name,
            addresses=[socket.inet_aton(address)],
            port=self._server.server_address[1] if self._server else 0,
            properties={
                b"id": self.device_id.encode("utf-8"),
                b"name": self.display_name.encode("utf-8"),
                b"platform": platform.system().encode("utf-8"),
                b"fingerprint": self.fingerprint.encode("ascii"),
                b"version": b"1",
            },
            server=f"{host}.local.",
        )

    def set_display_name(self, name: str) -> None:
        name = clean_device_name(name, self.display_name)
        if name == self.display_name:
            return
        self.display_name = name
        if self._zeroconf is not None and self._service_info is not None:
            try:
                address = local_ipv4_address()
            except OSError:
                return
            old = self._service_info
            self._service_info = self._make_service_info(address)
            try:
                self._zeroconf.unregister_service(old)
            except OSError:
                pass
            self._zeroconf.register_service(self._service_info)

    def set_download_directory(self, directory: Path) -> None:
        directory = directory.expanduser().resolve()
        directory.mkdir(parents=True, exist_ok=True)
        if not directory.is_dir():
            raise OSError("The selected receive location is not a folder.")
        self.download_directory = directory

    def _resolve_device(
        self, zeroconf: Zeroconf, service_type: str, name: str
    ) -> None:
        info = zeroconf.get_service_info(service_type, name, timeout=1800)
        if info is None:
            return
        props = info.properties

        def prop(key: bytes, fallback: str = "") -> str:
            value = props.get(key, fallback.encode("utf-8"))
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value)

        device_id = prop(b"id")
        fingerprint = prop(b"fingerprint")
        if not device_id or device_id == self.device_id or len(fingerprint) != 64:
            return
        address = next(
            (
                str(ipaddress.ip_address(raw))
                for raw in info.addresses
                if ipaddress.ip_address(raw).version == 4
            ),
            "",
        )
        if not address or not info.port:
            return
        try:
            int(fingerprint, 16)
        except ValueError:
            return
        peer = PeerDevice(
            device_id=device_id[:64],
            name=clean_device_name(prop(b"name")),
            platform=prop(b"platform", "Device")[:24],
            address=address,
            port=info.port,
            fingerprint=fingerprint.lower(),
        )
        with self._lock:
            self._devices_by_service[name] = peer
        self.refresh_devices()

    def _remove_device(self, name: str) -> None:
        with self._lock:
            self._devices_by_service.pop(name, None)
        self.refresh_devices()

    def refresh_devices(self) -> None:
        with self._lock:
            devices = [
                self._with_trust(peer) for peer in self._devices_by_service.values()
            ]
        self.devices_changed.emit(devices)

    def _with_trust(self, peer: PeerDevice) -> PeerDevice:
        paired = self.trust_store.get(peer.device_id)
        if paired is None:
            return replace(peer, paired=False, identity_changed=False)
        return replace(
            peer,
            paired=True,
            identity_changed=paired.fingerprint != peer.fingerprint,
        )

    def request_acceptance(
        self,
        sender_name: str,
        sender_id: str,
        files: tuple[FileOffer, ...],
        remote_address: str,
    ) -> tuple[str, str] | None:
        now = time.monotonic()
        with self._lock:
            self._purge_expired_sessions(now)
            history = [
                stamp
                for stamp in self._offer_times.get(remote_address, [])
                if now - stamp < 60
            ]
            if len(history) >= 5:
                raise PermissionError("Too many requests from this device. Try again in a minute.")
            if len(self._pending) >= 8 or len(self._sessions) >= 20:
                raise PermissionError("MadDrop is busy. Try again in a moment.")
            history.append(now)
            self._offer_times[remote_address] = history

            offer = IncomingOffer(
                transfer_id=str(uuid.uuid4()),
                sender_name=clean_device_name(sender_name),
                sender_device_id=sender_id,
                files=files,
                remote_address=remote_address,
            )
            self._pending[offer.transfer_id] = offer

        self.offer_received.emit(offer)
        if not offer.decision_event.wait(120):
            with self._lock:
                self._pending.pop(offer.transfer_id, None)
            raise TimeoutError("This request expired because it was not answered.")

        with self._lock:
            self._pending.pop(offer.transfer_id, None)
            if not offer.accepted or not offer.session_id or not offer.token:
                return None
            return offer.session_id, offer.token

    def decide_offer(self, transfer_id: str, accepted: bool) -> None:
        with self._lock:
            offer = self._pending.get(transfer_id)
            if offer is None or offer.decision_event.is_set():
                return
            if accepted:
                try:
                    self.download_directory.mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    self.incoming_failed.emit(transfer_id, str(exc))
                    accepted = False
            offer.accepted = accepted
            if accepted:
                session_id = str(uuid.uuid4())
                token = secrets.token_urlsafe(32)
                offer.session_id = session_id
                offer.token = token
                self._sessions[session_id] = TransferSession(
                    session_id=session_id,
                    token=token,
                    files=offer.files,
                )
            offer.decision_event.set()

    def request_pairing(self, claim: PairClaim, remote_address: str) -> str | None:
        """Ask the user to confirm the pairing code, then remember the device."""
        now = time.monotonic()
        with self._lock:
            history = [
                stamp
                for stamp in self._pair_times.get(remote_address, [])
                if now - stamp < 60
            ]
            if len(history) >= 5:
                raise PermissionError(
                    "Too many pairing requests from this device. Try again in a minute."
                )
            if len(self._pending_pairs) >= 4:
                raise PermissionError("MadDrop is busy. Try again in a moment.")
            history.append(now)
            self._pair_times[remote_address] = history

            request = PairingRequest(
                request_id=str(uuid.uuid4()),
                device_id=claim.device_id,
                name=clean_device_name(claim.name),
                fingerprint=claim.fingerprint,
                code=pairing_code(self.fingerprint, claim.fingerprint),
                remote_address=remote_address,
            )
            self._pending_pairs[request.request_id] = request

        self.pair_requested.emit(request)
        if not request.decision_event.wait(120):
            with self._lock:
                self._pending_pairs.pop(request.request_id, None)
            raise TimeoutError("This pairing request expired because it was not answered.")

        with self._lock:
            self._pending_pairs.pop(request.request_id, None)
        if not request.accepted:
            return None

        self.trust_store.add(request.device_id, request.name, request.fingerprint)
        self.refresh_devices()
        return request.code

    def decide_pair(self, request_id: str, accepted: bool) -> None:
        with self._lock:
            request = self._pending_pairs.get(request_id)
            if request is None or request.decision_event.is_set():
                return
            request.accepted = accepted
            request.decision_event.set()

    def begin_upload(
        self, session_id: str, index: int, token: str
    ) -> tuple[TransferSession, FileOffer]:
        with self._lock:
            self._purge_expired_sessions(time.monotonic())
            session = self._sessions.get(session_id)
            if session is None:
                raise PermissionError("This transfer request has expired.")
            if not hmac.compare_digest(session.token, token):
                raise PermissionError("The transfer token is invalid.")
            if index < 0 or index >= len(session.files):
                raise ValueError("The file index is invalid.")
            if index in session.completed or index in session.active:
                raise PermissionError("This file was already received.")
            session.active.add(index)
            return session, session.files[index]

    def abort_upload(self, session_id: str, index: int) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                session.active.discard(index)

    def receive_file(
        self,
        body: Any,
        session: TransferSession,
        index: int,
        item: FileOffer,
        content_length: int,
    ) -> str:
        self.download_directory.mkdir(parents=True, exist_ok=True)
        download_dir = self.download_directory.resolve()
        temp_path = download_dir / f".maddrop-{uuid.uuid4().hex}.part"
        started = time.monotonic()
        received = 0
        try:
            with temp_path.open("xb") as destination:
                while received < content_length:
                    chunk = body.read(min(CHUNK_SIZE, content_length - received))
                    if not chunk:
                        raise OSError("The connection ended before the file was complete.")
                    destination.write(chunk)
                    received += len(chunk)
                    elapsed = max(time.monotonic() - started, 0.001)
                    speed = received / elapsed
                    eta = (
                        int((content_length - received) / speed)
                        if speed > 0
                        else 0
                    )
                    self.incoming_progress.emit(
                        session.session_id,
                        item.name,
                        received,
                        content_length,
                        index + 1,
                        len(session.files),
                        speed,
                        eta,
                    )
                destination.flush()
                os.fsync(destination.fileno())

            final_path = self._commit_without_overwrite(temp_path, item.name, download_dir)
            with self._lock:
                active_session = self._sessions.get(session.session_id)
                if active_session is None:
                    raise OSError("This transfer expired before the file was saved.")
                active_session.active.discard(index)
                active_session.completed.add(index)
                active_session.received_paths[index] = str(final_path)
                is_complete = len(active_session.completed) == len(active_session.files)
                received_paths = [
                    active_session.received_paths[key]
                    for key in sorted(active_session.received_paths)
                ]
                if is_complete:
                    self._sessions.pop(session.session_id, None)

            if is_complete:
                self.incoming_complete.emit(
                    session.session_id, received_paths, str(download_dir)
                )
            return str(final_path)
        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            self.abort_upload(session.session_id, index)
            self.incoming_failed.emit(
                session.session_id, f"Could not receive {sanitize_filename(item.name)}."
            )
            raise

    @staticmethod
    def _commit_without_overwrite(temp_path: Path, name: str, directory: Path) -> Path:
        base = sanitize_filename(name)
        original = Path(base)
        for number in range(1, 100_000):
            if number == 1:
                candidate = directory / base
            else:
                candidate = directory / f"{original.stem} ({number}){original.suffix}"
            try:
                os.link(temp_path, candidate)
                temp_path.unlink()
                return candidate
            except FileExistsError:
                continue
            except OSError:
                # Exclusive creation is the safe fallback on filesystems without hard links.
                try:
                    descriptor = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                except FileExistsError:
                    continue
                try:
                    with os.fdopen(descriptor, "wb") as output, temp_path.open("rb") as source:
                        while chunk := source.read(CHUNK_SIZE):
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    temp_path.unlink()
                    return candidate
                except Exception:
                    candidate.unlink(missing_ok=True)
                    raise
        raise OSError("Could not create a unique destination filename.")

    def _purge_expired_sessions(self, now: float) -> None:
        expired = [
            key
            for key, value in self._sessions.items()
            if not value.active and now - value.started_at > 20 * 60
        ]
        for key in expired:
            self._sessions.pop(key, None)

    def stop(self) -> None:
        with self._lock:
            if self._stopping:
                return
            self._stopping = True
            for offer in self._pending.values():
                offer.accepted = False
                offer.decision_event.set()
            for request in self._pending_pairs.values():
                request.accepted = False
                request.decision_event.set()

        browser, self._browser = self._browser, None
        zeroconf, self._zeroconf = self._zeroconf, None
        service_info, self._service_info = self._service_info, None
        server, self._server = self._server, None
        server_thread, self._server_thread = self._server_thread, None

        if browser is not None:
            _run_bounded(browser.cancel)
        if zeroconf is not None:
            if service_info is not None:
                _run_bounded(lambda: zeroconf.unregister_service(service_info))
            _run_bounded(zeroconf.close)
        if server is not None:
            if server_thread is not None and server_thread.is_alive():
                _run_bounded(server.shutdown)
            _run_bounded(server.server_close)
