from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import sys
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def app_data_directory() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    path = root / "MadDrop"
    path.mkdir(parents=True, exist_ok=True)
    return path


def local_ipv4_address() -> str:
    """Ask the OS which interface it would use for a route; no packets are sent."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
        if address and not address.startswith("127."):
            return address
    except OSError:
        pass
    finally:
        probe.close()

    try:
        for result in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = result[4][0]
            if not address.startswith("127."):
                return address
    except OSError:
        pass
    raise OSError("MadDrop could not find an active IPv4 network connection.")


def ensure_tls_identity(directory: Path) -> tuple[Path, Path, str]:
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "device-key.pem"
    certificate_path = directory / "device-certificate.pem"

    try:
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
        cert_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_public != key_public:
            raise ValueError("The saved MadDrop identity does not match.")
        return certificate_path, key_path, certificate.fingerprint(hashes.SHA256()).hex()
    except (OSError, ValueError, TypeError):
        pass

    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MadDrop local device")]
    )
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

    key_temp = key_path.with_suffix(".tmp")
    cert_temp = certificate_path.with_suffix(".tmp")
    key_temp.write_bytes(key_bytes)
    cert_temp.write_bytes(certificate_bytes)
    try:
        os.chmod(key_temp, 0o600)
    except OSError:
        pass
    os.replace(key_temp, key_path)
    os.replace(cert_temp, certificate_path)
    return certificate_path, key_path, certificate.fingerprint(hashes.SHA256()).hex()


def server_tls_context(certificate_path: Path, key_path: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate_path), str(key_path))
    return context


def certificate_fingerprint(certificate_der: bytes) -> str:
    return sha256(certificate_der).hexdigest()


def load_private_key(key_path: Path):
    return serialization.load_pem_private_key(key_path.read_bytes(), password=None)


def certificate_der(certificate_path: Path) -> bytes:
    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    return certificate.public_bytes(serialization.Encoding.DER)
