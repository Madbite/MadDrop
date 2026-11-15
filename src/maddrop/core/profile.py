"""Local account profile and the limits that come with a plan.

MadDrop has no servers: the account is stored on this device next to the
identity file, and nothing is uploaded or verified remotely.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from .protocol import MAX_TRANSFER_BYTES

PLAN_FREE = "free"
PLAN_PREMIUM = "premium"

FREE_TRANSFER_BYTES = 4 * 1024**3

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,24}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


@dataclass(frozen=True)
class Profile:
    username: str
    email: str
    plan: str = PLAN_FREE
    created_at: float = 0.0

    @property
    def is_premium(self) -> bool:
        return self.plan == PLAN_PREMIUM


def build_profile(username: str, email: str) -> Profile:
    """Validate what the user typed and return a fresh free-plan profile."""
    cleaned_username = username.strip()
    cleaned_email = email.strip()

    if not USERNAME_PATTERN.match(cleaned_username):
        raise ValueError(
            "Usernames are 3-24 characters: letters, numbers, dot, dash or underscore."
        )
    if not EMAIL_PATTERN.match(cleaned_email) or len(cleaned_email) > 254:
        raise ValueError("Enter a valid email address.")
    return Profile(
        username=cleaned_username,
        email=cleaned_email,
        plan=PLAN_FREE,
        created_at=time.time(),
    )


def transfer_limit(profile: Profile | None) -> int:
    """The largest batch a plan may send."""
    if profile is not None and profile.is_premium:
        return MAX_TRANSFER_BYTES
    return FREE_TRANSFER_BYTES


def upgrade(profile: Profile) -> Profile:
    return replace(profile, plan=PLAN_PREMIUM)


def downgrade(profile: Profile) -> Profile:
    return replace(profile, plan=PLAN_FREE)


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def available_space(path: Path) -> int:
    """Free bytes on the volume holding `path`, walking up until it exists."""
    probe = path
    while True:
        try:
            return shutil.disk_usage(probe).free
        except OSError:
            if probe.parent == probe:
                return 0
            probe = probe.parent


def capacity_warning(total_bytes: int, download_directory: Path) -> str:
    """Explain why a transfer will not fit, or return an empty string."""
    free = available_space(download_directory)
    if free <= 0:
        return ""
    if total_bytes > free:
        return (
            "This device does not have room for this transfer: it needs "
            f"{format_size(total_bytes)} but only {format_size(free)} is free."
        )
    if total_bytes > free * 0.9:
        return (
            "This transfer will leave very little free space "
            f"({format_size(free)} free before it starts)."
        )
    return ""


class ProfileStore:
    """Keeps the signed-in account on disk, atomically."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._profile: Profile | None = None
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        username = raw.get("username")
        email = raw.get("email")
        if not isinstance(username, str) or not isinstance(email, str):
            return
        plan = raw.get("plan", PLAN_FREE)
        if plan not in {PLAN_FREE, PLAN_PREMIUM}:
            plan = PLAN_FREE
        try:
            created_at = float(raw.get("created_at", 0.0))
        except (TypeError, ValueError):
            created_at = 0.0
        self._profile = Profile(username, email, plan, created_at)

    def _save(self) -> None:
        if self._profile is None:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
            return
        payload = {
            "username": self._profile.username,
            "email": self._profile.email,
            "plan": self._profile.plan,
            "created_at": self._profile.created_at,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.path)

    def current(self) -> Profile | None:
        with self._lock:
            return self._profile

    def save(self, profile: Profile) -> Profile:
        with self._lock:
            self._profile = profile
            self._save()
            return profile

    def sign_out(self) -> None:
        with self._lock:
            self._profile = None
            self._save()
