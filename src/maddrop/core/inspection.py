"""Offline inspection of incoming files.

Everything here runs on this device. Nothing is uploaded, no telemetry is
recorded, and only a sample of the file is read (the first megabyte and the
last 64 KiB), so a 30 GB transfer is not re-read end to end.

On Windows the check also asks the already-installed Microsoft Defender to
scan the finished file, since that engine is local and keeps its own
signature database up to date. When Defender is not present the built-in
structural checks still run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

CLEAN = "clean"
SUSPICIOUS = "suspicious"
DANGEROUS = "dangerous"

HEAD_BYTES = 1024 * 1024
TAIL_BYTES = 64 * 1024
DEFENDER_TIMEOUT = 120

RISK_ORDER = {CLEAN: 0, SUSPICIOUS: 1, DANGEROUS: 2}

EXECUTABLE_SUFFIXES = {
    ".exe", ".scr", ".com", ".pif", ".msi", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk", ".reg",
}

DOCUMENT_SUFFIXES = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip",
}

ARCHIVE_MAGIC = (
    (b"PK\x03\x04", "zip archive"),
    (b"Rar!\x1a\x07", "rar archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
)

EXECUTABLE_MAGIC = (
    (b"MZ", "Windows executable"),
    (b"\x7fELF", "Linux executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O or Java binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
)


@dataclass(frozen=True)
class InspectionResult:
    risk: str = CLEAN
    reasons: tuple[str, ...] = ()
    scanner: str = "built-in"

    @property
    def flagged(self) -> bool:
        return self.risk != CLEAN

    def describe(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "No problems found"


def _worst(current: str, candidate: str) -> str:
    return candidate if RISK_ORDER[candidate] > RISK_ORDER[current] else current


def _read_sample(path: Path) -> tuple[bytes, bytes]:
    head = b""
    tail = b""
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            head = handle.read(HEAD_BYTES)
            if size <= HEAD_BYTES:
                # Small files are already fully in hand; keep the tail in sync
                # so checks that look at the end of the file still see content.
                tail = head[-TAIL_BYTES:]
            else:
                handle.seek(size - TAIL_BYTES)
                tail = handle.read(TAIL_BYTES)
    except OSError:
        return head, tail
    return head, tail


def _structure_reasons(head: bytes, tail: bytes, declared_name: str) -> list[str]:
    reasons: list[str] = []
    suffix = Path(declared_name).suffix.lower()

    executable = next((label for magic, label in EXECUTABLE_MAGIC if head.startswith(magic)), None)
    if executable and suffix not in EXECUTABLE_SUFFIXES:
        # A program wearing a document's name is the classic trick.
        reasons.append(f"named like a document but is a {executable}")
    elif executable and suffix in EXECUTABLE_SUFFIXES:
        reasons.append(f"is a {executable}")

    inner = Path(declared_name).stem
    if suffix in EXECUTABLE_SUFFIXES and inner:
        inner_suffix = Path(inner).suffix.lower()
        if inner_suffix in DOCUMENT_SUFFIXES or inner_suffix in EXECUTABLE_SUFFIXES:
            reasons.append(f"uses a hidden double extension ({inner_suffix}{suffix})")

    if suffix in DOCUMENT_SUFFIXES and suffix not in {".zip", ".doc", ".xls", ".ppt"}:
        if not head.startswith(b"%PDF") and suffix == ".pdf":
            reasons.append("claims to be a PDF but is not one")
        if head.startswith(b"MZ"):
            reasons.append("claims to be a document but contains a program")

    if head.startswith(b"\xd0\xcf\x11\xe0") and (b"VBA" in head or b"vbaProject" in head):
        reasons.append("contains Office macros")

    if head.startswith(b"%PDF") and (b"/JavaScript" in tail or b"/JS" in tail or b"/Launch" in tail or b"/OpenAction" in tail):
        reasons.append("PDF runs embedded script or launches an action")

    for magic, label in ARCHIVE_MAGIC:
        if head.startswith(magic):
            reasons.append(f"is an archive ({label}); its contents are not inspected")
            break

    if head.startswith(b"#!") or head.startswith(b"#!python"):
        reasons.append("is a script")

    return reasons


def _defender_executable() -> Path | None:
    if sys.platform != "win32":
        return None
    root = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    if not root.is_dir():
        return None
    for version in sorted(root.iterdir(), reverse=True):
        candidate = version / "MpCmdRun.exe"
        if candidate.is_file():
            return candidate
    return None


def scan_with_defender(path: Path, timeout: float = DEFENDER_TIMEOUT) -> InspectionResult | None:
    """Ask the installed Windows Defender to scan the file. Returns None when unavailable."""
    executable = _defender_executable()
    if executable is None:
        return None
    flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
    try:
        completed = subprocess.run(
            [
                str(executable),
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                str(path),
                "-DisableRemediation",
            ],
            capture_output=True,
            timeout=timeout,
            creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode == 2:
        return InspectionResult(DANGEROUS, ("Windows Defender reported a threat",), "Windows Defender")
    if completed.returncode == 0:
        return InspectionResult(CLEAN, (), "Windows Defender")
    return None


def inspect_file(path: Path, declared_name: str = "") -> InspectionResult:
    """Check a finished file before it is handed to the user."""
    name = declared_name or path.name
    head, tail = _read_sample(path)
    reasons = _structure_reasons(head, tail, name)

    risk = CLEAN
    for _reason in reasons:
        risk = _worst(risk, SUSPICIOUS)
    if any("named like a document but" in reason for reason in reasons):
        risk = DANGEROUS

    result = InspectionResult(risk, tuple(reasons), "built-in")

    defender = scan_with_defender(path)
    if defender is not None:
        merged_risk = _worst(result.risk, defender.risk)
        reasons_out = result.reasons + defender.reasons
        result = InspectionResult(merged_risk, reasons_out, defender.scanner)

    return result
