"""Account, premium prompt, and device capacity helpers."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from maddrop.core.profile import Profile, build_profile

class AccountDialog(QDialog):
    """Create the local account: a username and an email address."""

    def __init__(self, parent: QWidget | None = None, current: Profile | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("MadDrop account")
        self.setMinimumWidth(440)
        self.setModal(True)
        self.profile: Profile | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(10)

        title = QLabel("Create your account" if current is None else f"Signed in as {current.username}")
        title.setStyleSheet("font-size: 15pt; font-weight: 700;")
        layout.addWidget(title)

        note = QLabel(
            "Your account is stored on this device only. MadDrop has no servers "
            "and never uploads your profile."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.username_field = QLineEdit(current.username if current else "")
        self.username_field.setPlaceholderText("Username")
        layout.addWidget(self.username_field)

        self.email_field = QLineEdit(current.email if current else "")
        self.email_field.setPlaceholderText("Email address")
        layout.addWidget(self.email_field)

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #ff8a80; font-size: 9pt;")
        self.error_label.hide()
        layout.addWidget(self.error_label)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Not now")
        cancel.setObjectName("quietButton")
        cancel.clicked.connect(self.reject)
        primary = QPushButton("Save account" if current else "Create account")
        primary.setObjectName("primaryButton")
        primary.clicked.connect(self.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(primary)
        layout.addLayout(buttons)

    def accept(self) -> None:
        try:
            self.profile = build_profile(
                self.username_field.text(), self.email_field.text()
            )
        except ValueError as exc:
            self.error_label.setText(str(exc))
            self.error_label.show()
            return
        super().accept()


class UpsellDialog(QDialog):
    """The 'Support MadDrop' prompt shown after registering."""

    def __init__(
        self,
        parent: QWidget | None = None,
        reason: str = "",
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Support MadDrop")
        self.setMinimumWidth(470)
        self.setModal(True)
        self.premium_enabled = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 22)
        layout.setSpacing(12)

        title = QLabel("Support MadDrop")
        title.setStyleSheet("font-size: 20pt; font-weight: 750; color: #f8faff;")
        layout.addWidget(title)

        if reason:
            reason_label = QLabel(reason)
            reason_label.setWordWrap(True)
            reason_label.setStyleSheet("color: #ffb454; font-weight: 600;")
            layout.addWidget(reason_label)

        price = QLabel(
            "Premium is <b>$3.99 / month</b> — your <b>first month is $1</b>."
        )
        price.setWordWrap(True)
        price.setStyleSheet("font-size: 11pt;")
        layout.addWidget(price)

        perks = QFrame()
        perks.setObjectName("panel")
        perk_layout = QVBoxLayout(perks)
        perk_layout.setContentsMargins(16, 14, 16, 14)
        perk_layout.setSpacing(7)
        for text in (
            "No 4 GB cap — send up to the 50 GB maximum",
            "No premium prompts interrupting a transfer",
            "Early access to new features",
            "Support a small app with no ads and no trackers",
        ):
            label = QLabel(f"✓  {text}")
            label.setWordWrap(True)
            perk_layout.addWidget(label)
        layout.addWidget(perks)

        self.status_label = QLabel("")
        self.status_label.setObjectName("muted")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        buttons.addStretch()
        self.later_button = QPushButton("Maybe later")
        self.later_button.setObjectName("quietButton")
        self.later_button.clicked.connect(self.reject)
        self.get_button = QPushButton("Get Premium")
        self.get_button.setObjectName("primaryButton")
        self.get_button.clicked.connect(self._activate)
        buttons.addWidget(self.later_button)
        buttons.addWidget(self.get_button)
        layout.addLayout(buttons)

    def _activate(self) -> None:
        if self.premium_enabled:
            self.accept()
            return
        # No payment provider is connected in this build, so be explicit
        # rather than pretending a charge happened.
        self.premium_enabled = True
        self.status_label.setText(
            "Billing is not connected in this build, so Premium is switched on "
            "for this device only. Nothing was charged."
        )
        self.get_button.setText("Done")


