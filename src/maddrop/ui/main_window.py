from __future__ import annotations

import uuid
from functools import partial
from pathlib import Path

from PySide6.QtCore import QPoint, QSettings, QSize, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QDragEnterEvent, QDropEvent, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from maddrop.core.identity import certificate_der, load_private_key
from maddrop.core.network import LanTransferService
from maddrop.core.pairing import pairing_code
from maddrop.core.protocol import IncomingOffer, PairingRequest, PeerDevice
from maddrop.core.sender import PairWorker, SendWorker
from maddrop.resources import asset_path
from maddrop.ui.animation import fade_in, flash, slide_in
from maddrop.ui.swipe import FlyingChip, SwipeToSend

APP_STYLE = """
QMainWindow, QWidget#root {
    background: #080a10;
    color: #f4f7fc;
}
QWidget {
    color: #f4f7fc;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 10pt;
}
QLabel#eyebrow {
    color: #8290a5;
    font-size: 9pt;
    font-weight: 600;
}
QLabel#muted {
    color: #97a6bb;
}
QLabel#headline {
    font-size: 26pt;
    font-weight: 650;
    color: #f8faff;
}
QLabel#sectionTitle {
    font-size: 13pt;
    font-weight: 650;
    color: #f5f8fd;
}
QLabel#brand {
    font-size: 15pt;
    font-weight: 750;
    letter-spacing: 0.3px;
}
QLabel#brandLogo {
    background: #0c111b;
    border: 1px solid #203858;
    border-radius: 10px;
}
QFrame#panel {
    background: #10151e;
    border: 1px solid #202a38;
    border-radius: 16px;
}
QFrame#dropZone {
    background: #0b1018;
    border: 1px dashed #29405e;
    border-radius: 14px;
}
QFrame#dropZone[dragging="true"] {
    border: 1px solid #006fff;
    background: #101d31;
}
QFrame#deviceRow, QFrame#transferRow {
    background: #141b27;
    border: 1px solid #222e40;
    border-radius: 12px;
}
QFrame#deviceRow[selected="true"] {
    border: 1px solid #006fff;
    background: #10203a;
}
QFrame#deviceRow[paired="true"] {
    border: 1px solid #1f4a73;
}
QFrame#deviceRow[receiving="true"] {
    border: 1px solid #4da3ff;
    background: #12253c;
}
QLabel#deviceIcon {
    background: #17243a;
    border-radius: 14px;
}
QPushButton#statusPill {
    color: #d6e6ff;
    background: #101b2d;
    border: 1px solid #254b7c;
    border-radius: 11px;
    padding: 6px 10px;
    font-size: 9pt;
    font-weight: 600;
}
QPushButton {
    background: #192333;
    border: 1px solid #2a394e;
    border-radius: 9px;
    padding: 9px 13px;
    color: #f0f4fa;
    font-weight: 600;
}
QPushButton:hover {
    background: #202f44;
    border-color: #3d587b;
}
QPushButton:pressed {
    background: #121a27;
}
QPushButton:disabled {
    color: #6e7b8e;
    background: #141b26;
    border-color: #202938;
}
QPushButton#primaryButton {
    background: #006fff;
    color: #ffffff;
    border: 1px solid #006fff;
    padding: 11px 16px;
}
QPushButton#primaryButton:hover {
    background: #2182ff;
    border-color: #2182ff;
}
QPushButton#primaryButton:disabled {
    color: #8d9db4;
    background: #1a2b43;
    border-color: #1a2b43;
}
QPushButton#quietButton {
    background: transparent;
    border-color: transparent;
    color: #bdc9d9;
}
QPushButton#quietButton:hover {
    background: #151e2b;
    border-color: #26364c;
}
QListWidget {
    background: transparent;
    border: none;
    outline: none;
}
QListWidget::item {
    background: #141b27;
    border: 1px solid #222e40;
    border-radius: 8px;
    padding: 9px 10px;
    margin: 3px 0;
}
QListWidget::item:selected {
    background: #10203a;
    border-color: #006fff;
}
QProgressBar {
    background: #263247;
    border: none;
    border-radius: 4px;
    height: 7px;
    text-align: center;
}
QProgressBar::chunk {
    background: #006fff;
    border-radius: 4px;
}
QScrollArea {
    background: transparent;
    border: none;
}
QScrollBar:vertical {
    width: 8px;
    background: transparent;
}
QScrollBar::handle:vertical {
    background: #30415b;
    border-radius: 4px;
    min-height: 24px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QLineEdit {
    background: #0c111a;
    border: 1px solid #2a394e;
    border-radius: 8px;
    padding: 9px 10px;
    selection-background-color: #006fff;
}
QMenu {
    background: #10151e;
    border: 1px solid #26364b;
    border-radius: 8px;
    padding: 5px;
}
QMenu::item {
    padding: 8px 26px 8px 12px;
    border-radius: 5px;
}
QMenu::item:selected {
    background: #14294a;
}
QDialog {
    background: #10151e;
}
"""


def format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    value = float(size)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
    return f"{size} B"


def format_duration(seconds: int) -> str:
    if seconds <= 0:
        return "under a second"
    minutes, remaining = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} hr {minutes:02} min"
    if minutes:
        return f"{minutes} min {remaining:02} sec"
    return f"{remaining} sec"


class DropZone(QFrame):
    files_dropped = Signal(list)

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(165)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(7)
        layout.addStretch()
        self.title = QLabel("Drop files here")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setStyleSheet("font-size: 14pt; font-weight: 650;")
        layout.addWidget(self.title)
        subtitle = QLabel("or choose files from your device")
        subtitle.setObjectName("muted")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        layout.addStretch()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            self.setProperty("dragging", True)
            self.style().unpolish(self)
            self.style().polish(self)
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:
        self.setProperty("dragging", False)
        self.style().unpolish(self)
        self.style().polish(self)
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        self.setProperty("dragging", False)
        self.style().unpolish(self)
        self.style().polish(self)
        paths = [
            Path(url.toLocalFile())
            for url in event.mimeData().urls()
            if url.isLocalFile()
        ]
        if paths:
            self.files_dropped.emit(paths)
        event.acceptProposedAction()


class DeviceRow(QFrame):
    selected = Signal(str)
    pair_requested = Signal(str)

    def __init__(self, peer: PeerDevice, is_selected: bool = False) -> None:
        super().__init__()
        self.peer = peer
        self.setObjectName("deviceRow")
        self.setProperty("selected", is_selected)
        self.setProperty("paired", peer.paired)
        self.setMinimumHeight(78)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(10)

        icon = QLabel()
        icon.setObjectName("deviceIcon")
        icon.setFixedSize(42, 42)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pixmap = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon).pixmap(22, 22)
        icon.setPixmap(pixmap)
        layout.addWidget(icon)

        details = QVBoxLayout()
        details.setSpacing(3)
        name = QLabel(peer.name)
        name.setStyleSheet("font-weight: 650;")
        subtitle = QLabel(f"{peer.platform}  ·  {self._status_text()}")
        subtitle.setObjectName("muted")
        subtitle.setStyleSheet("font-size: 9pt;")
        details.addWidget(name)
        details.addWidget(subtitle)
        layout.addLayout(details, 1)

        if not peer.paired or peer.identity_changed:
            pair_button = QPushButton("Pair")
            pair_button.setObjectName("quietButton")
            pair_button.setMinimumWidth(56)
            pair_button.clicked.connect(
                lambda: self.pair_requested.emit(peer.device_id)
            )
            layout.addWidget(pair_button)

        button = QPushButton("Selected" if is_selected else "Select")
        button.setObjectName("quietButton")
        button.setMinimumWidth(82)
        button.clicked.connect(lambda: self.selected.emit(peer.device_id))
        layout.addWidget(button)

    def _status_text(self) -> str:
        if self.peer.identity_changed:
            return "Identity changed — pair again"
        return "Paired" if self.peer.paired else "Not paired"

    def set_selected(self, selected: bool) -> None:
        self.setProperty("selected", selected)
        self.style().unpolish(self)
        self.style().polish(self)

    def pulse(self) -> None:
        self.setProperty("receiving", True)
        self.style().unpolish(self)
        self.style().polish(self)
        QTimer.singleShot(700, self._end_pulse)

    def _end_pulse(self) -> None:
        self.setProperty("receiving", False)
        self.style().unpolish(self)
        self.style().polish(self)


class TransferRow(QFrame):
    def __init__(self, title: str, direction: str) -> None:
        super().__init__()
        self.setObjectName("transferRow")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        top = QHBoxLayout()
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-weight: 650;")
        self.status_label = QLabel(direction)
        self.status_label.setObjectName("muted")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        top.addWidget(self.title_label, 1)
        top.addWidget(self.status_label)
        layout.addLayout(top)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

        self.detail_label = QLabel("Preparing transfer")
        self.detail_label.setObjectName("muted")
        self.detail_label.setStyleSheet("font-size: 9pt;")
        layout.addWidget(self.detail_label)

    def set_status(self, status: str, detail: str | None = None) -> None:
        self.status_label.setText(status)
        if detail:
            self.detail_label.setText(detail)
        if status in {"Sent", "Received"}:
            self.progress.setValue(100)
            self.progress.hide()
        elif status in {"Failed", "Declined"}:
            self.progress.hide()

    def set_progress(
        self,
        current: int,
        total: int,
        speed: float,
        eta: int,
        detail: str | None = None,
    ) -> None:
        self.progress.show()
        self.progress.setValue(round(100 * current / total) if total else 100)
        text = f"{format_bytes(current)} of {format_bytes(total)}"
        if speed > 0:
            text += f"  ·  {format_bytes(int(speed))}/s  ·  {format_duration(eta)} left"
        if detail:
            text = f"{detail}  ·  {text}"
        self.detail_label.setText(text)


class IncomingTransferDialog(QDialog):
    def __init__(self, offer: IncomingOffer, download_directory: Path, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Incoming transfer")
        self.setMinimumWidth(460)
        self.setModal(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)

        title = QLabel(f"{offer.sender_name} wants to send files")
        title.setStyleSheet("font-size: 15pt; font-weight: 700;")
        layout.addWidget(title)
        total = format_bytes(offer.total_bytes)
        summary = QLabel(f"{len(offer.files)} files  ·  {total}")
        summary.setObjectName("muted")
        layout.addWidget(summary)
        safety_note = QLabel("Only accept files from devices you recognize.")
        safety_note.setObjectName("muted")
        safety_note.setStyleSheet("font-size: 9pt;")
        layout.addWidget(safety_note)

        file_list = QListWidget()
        file_list.setMinimumHeight(min(40 + 40 * len(offer.files), 220))
        file_list.setMaximumHeight(220)
        for item in offer.files:
            entry = QListWidgetItem(f"{item.name}  ·  {format_bytes(item.size)}")
            entry.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
            file_list.addItem(entry)
        layout.addWidget(file_list)

        destination = QLabel(f"Files will be saved to\n{download_directory}")
        destination.setObjectName("muted")
        destination.setWordWrap(True)
        layout.addWidget(destination)

        buttons = QHBoxLayout()
        buttons.addStretch()
        reject = QPushButton("Reject")
        accept = QPushButton("Accept and save")
        accept.setObjectName("primaryButton")
        reject.clicked.connect(self.reject)
        accept.clicked.connect(self.accept)
        buttons.addWidget(reject)
        buttons.addWidget(accept)
        layout.addLayout(buttons)


class PairingDialog(QDialog):
    """Shows the 3-digit code on both devices while they pair."""

    def __init__(
        self, device_name: str, code: str, incoming: bool, parent=None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Pair device")
        self.setMinimumWidth(420)
        self.setModal(True)
        self._incoming = incoming
        self._finished = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)

        title = QLabel(
            f"Pair with {device_name}?"
            if incoming
            else f"Pairing with {device_name}"
        )
        title.setStyleSheet("font-size: 15pt; font-weight: 700;")
        title.setWordWrap(True)
        layout.addWidget(title)

        note = QLabel(
            "Check that this 3-digit code matches the one shown on the other "
            "device. Only pair with devices you recognize."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.code_label = QLabel("  ".join(code))
        self.code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.code_label.setStyleSheet(
            "font-size: 34pt; font-weight: 750; letter-spacing: 6px; color: #4da3ff;"
        )
        layout.addWidget(self.code_label)

        self.status_label = QLabel(
            "" if incoming else "Waiting for the other device to confirm…"
        )
        self.status_label.setObjectName("muted")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        buttons.addStretch()
        self.decline_button = QPushButton("Decline" if incoming else "Cancel")
        self.accept_button = QPushButton("Pair" if incoming else "Done")
        self.accept_button.setObjectName("primaryButton")
        if not incoming:
            self.accept_button.setEnabled(False)
        self.decline_button.clicked.connect(self.reject)
        self.accept_button.clicked.connect(self.accept)
        buttons.addWidget(self.decline_button)
        buttons.addWidget(self.accept_button)
        layout.addLayout(buttons)

    def finish(self, success: bool, message: str, code: str | None = None) -> None:
        if self._finished:
            return
        self._finished = True
        if code:
            self.code_label.setText("  ".join(code))
        self.status_label.setText(message)
        if success:
            self.accept_button.setEnabled(True)
            self.accept_button.setText("Done")
            self.decline_button.setVisible(False)
            self.accept_button.setFocus()
        else:
            self.reject()


class MainWindow(QMainWindow):
    def __init__(
        self,
        service: LanTransferService,
        settings: QSettings,
        device_id: str,
        display_name: str,
        download_directory: Path,
    ) -> None:
        super().__init__()
        self.service = service
        self.settings = settings
        self.device_id = device_id
        self.display_name = display_name
        self.download_directory = download_directory.expanduser()
        self.devices: dict[str, PeerDevice] = {}
        self.device_rows: dict[str, DeviceRow] = {}
        self.selected_device_id: str | None = None
        self.workers: dict[str, SendWorker] = {}
        self.pair_workers: dict[str, PairWorker] = {}
        self.transfer_rows: dict[str, TransferRow] = {}
        self._secret_buffer = ""
        self._seen_devices: set[str] = set()
        self._intro_played = False

        self.setWindowTitle("MadDrop")
        self.setWindowIcon(QIcon(str(asset_path("maddrop.ico"))))
        self.setMinimumSize(900, 680)
        self.resize(1180, 800)
        self.setStyleSheet(APP_STYLE)
        self._build_ui()

        self.service.devices_changed.connect(self._update_devices)
        self.service.status_changed.connect(self._set_network_status)
        self.service.offer_received.connect(self._handle_incoming_offer)
        self.service.incoming_progress.connect(self._update_incoming_progress)
        self.service.incoming_complete.connect(self._incoming_complete)
        self.service.incoming_failed.connect(self._incoming_failed)
        self.service.pair_requested.connect(self._handle_pair_request)

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(34, 22, 34, 24)
        outer.setSpacing(20)

        header = QHBoxLayout()
        header.setSpacing(12)
        logo = QLabel()
        logo.setObjectName("brandLogo")
        logo.setFixedSize(42, 42)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setPixmap(
            QPixmap(str(asset_path("maddrop_logo.png"))).scaled(
                QSize(34, 34),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )
        header.addWidget(logo)
        brand = QLabel("MadDrop")
        brand.setObjectName("brand")
        header.addWidget(brand)
        header.addSpacing(14)
        tagline = QLabel("Send directly. Stay in control.")
        tagline.setObjectName("muted")
        header.addWidget(tagline)
        header.addStretch()

        self.network_status = QPushButton("Starting local discovery…")
        self.network_status.setObjectName("statusPill")
        self.network_status.setCursor(Qt.CursorShape.PointingHandCursor)
        self.network_status.clicked.connect(self.start_network)
        header.addWidget(self.network_status)

        self.device_menu_button = QPushButton(self.display_name)
        self.device_menu_button.setObjectName("quietButton")
        self.device_menu_button.setMenu(self._create_device_menu())
        header.addWidget(self.device_menu_button)
        outer.addLayout(header)

        intro = QVBoxLayout()
        intro.setSpacing(5)
        headline = QLabel("Share files with nearby devices")
        headline.setObjectName("headline")
        subtitle = QLabel(
            "Fast, direct transfers over your local network. Your files stay between devices."
        )
        subtitle.setObjectName("muted")
        intro.addWidget(headline)
        intro.addWidget(subtitle)
        outer.addLayout(intro)

        main_row = QHBoxLayout()
        main_row.setSpacing(16)
        main_row.addWidget(self._build_send_panel(), 11)
        main_row.addWidget(self._build_devices_panel(), 9)
        outer.addLayout(main_row, 1)

        self.history_panel = self._build_history_panel()
        outer.addWidget(self.history_panel)

    def _panel(self, title: str, subtitle: str | None = None) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setObjectName("panel")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 17, 18, 17)
        layout.setSpacing(12)
        header = QHBoxLayout()
        label = QLabel(title)
        label.setObjectName("sectionTitle")
        header.addWidget(label)
        header.addStretch()
        if subtitle:
            note = QLabel(subtitle)
            note.setObjectName("muted")
            header.addWidget(note)
        layout.addLayout(header)
        return frame, layout

    def _build_send_panel(self) -> QFrame:
        frame, layout = self._panel("Send files")
        self.drop_zone = DropZone()
        self.drop_zone.files_dropped.connect(self._add_files)
        layout.addWidget(self.drop_zone)

        buttons = QHBoxLayout()
        self.add_files_button = QPushButton("Choose files")
        self.add_files_button.clicked.connect(self._choose_files)
        self.remove_file_button = QPushButton("Remove selected")
        self.remove_file_button.setObjectName("quietButton")
        self.remove_file_button.clicked.connect(self._remove_selected_file)
        buttons.addWidget(self.add_files_button)
        buttons.addWidget(self.remove_file_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.file_list.setMinimumHeight(106)
        self.file_list.setMaximumHeight(160)
        self.file_list.itemSelectionChanged.connect(self._update_send_button)
        layout.addWidget(self.file_list)
        self.file_count_label = QLabel("No files selected")
        self.file_count_label.setObjectName("muted")
        layout.addWidget(self.file_count_label)

        target_line = QHBoxLayout()
        target_title = QLabel("Send to")
        target_title.setObjectName("muted")
        self.selected_target = QLabel("Choose a nearby device")
        self.selected_target.setStyleSheet("font-weight: 650;")
        target_line.addWidget(target_title)
        target_line.addSpacing(8)
        target_line.addWidget(self.selected_target, 1)
        self.send_button = QPushButton("Send files")
        self.send_button.setObjectName("primaryButton")
        self.send_button.setMinimumWidth(135)
        self.send_button.clicked.connect(self._send_files)
        target_line.addWidget(self.send_button)
        layout.addLayout(target_line)

        # Hidden gesture: type "drop" on the window to reveal the swipe rail.
        self.swipe = SwipeToSend("Swipe to send")
        self.swipe.setEnabled(False)
        self.swipe.swiped.connect(self._send_files)
        self.swipe.hide()
        layout.addWidget(self.swipe)
        return frame

    def _build_devices_panel(self) -> QFrame:
        frame, layout = self._panel("Nearby devices", "Same Wi-Fi or LAN")
        self.device_count = QLabel("Searching")
        self.device_count.setObjectName("muted")
        layout.addWidget(self.device_count)

        self.device_scroll = QScrollArea()
        self.device_scroll.setWidgetResizable(True)
        self.device_scroll.setMinimumHeight(300)
        self.device_scroll.setStyleSheet("background: transparent;")
        self.device_scroll.viewport().setStyleSheet("background: transparent;")
        self.device_contents = QWidget()
        self.device_contents.setStyleSheet("background: transparent;")
        self.device_list_layout = QVBoxLayout(self.device_contents)
        self.device_list_layout.setContentsMargins(0, 0, 0, 0)
        self.device_list_layout.setSpacing(8)
        self.device_scroll.setWidget(self.device_contents)
        layout.addWidget(self.device_scroll, 1)

        self.empty_devices = QLabel(
            "No other devices yet.\n\nOpen MadDrop on another device connected to this network."
        )
        self.empty_devices.setObjectName("muted")
        self.empty_devices.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_devices.setWordWrap(True)
        self.empty_devices.setMinimumHeight(170)
        layout.addWidget(self.empty_devices)
        self.device_scroll.hide()
        self.empty_devices.show()

        tip = QLabel("Transfers use an encrypted direct connection. Nothing is uploaded to a cloud.")
        tip.setObjectName("muted")
        tip.setWordWrap(True)
        tip.setStyleSheet("font-size: 9pt; border-top: 1px solid #202b3f; padding-top: 10px;")
        layout.addWidget(tip)
        return frame

    def _build_history_panel(self) -> QFrame:
        frame, layout = self._panel("Recent transfers")
        self.history_empty = QLabel("Your transfer activity will appear here.")
        self.history_empty.setObjectName("muted")
        layout.addWidget(self.history_empty)
        self.history_rows = QVBoxLayout()
        self.history_rows.setSpacing(7)
        layout.addLayout(self.history_rows)
        return frame

    def _create_device_menu(self) -> QMenu:
        menu = QMenu(self)
        rename = menu.addAction("Change device name")
        rename.triggered.connect(self._change_device_name)
        folder = menu.addAction("Change receive folder")
        folder.triggered.connect(self._choose_receive_folder)
        open_folder = menu.addAction("Open receive folder")
        open_folder.triggered.connect(self._open_receive_folder)
        return menu

    def start_network(self) -> None:
        try:
            self.service.start()
        except Exception as exc:
            self._set_network_status("Network unavailable — click to retry")
            QMessageBox.warning(
                self,
                "Local network unavailable",
                f"MadDrop could not start local discovery.\n\n{exc}\n\n"
                "Check that this device is connected to Wi-Fi and allow MadDrop through "
                "the private-network firewall.",
            )

    def _set_network_status(self, status: str) -> None:
        self.network_status.setText(status)
        flash(self.network_status)

    def _create_transfer_row(
        self, transfer_id: str, title: str, direction: str
    ) -> TransferRow:
        existing = self.transfer_rows.get(transfer_id)
        if existing is not None:
            return existing
        row = TransferRow(title, direction)
        self.transfer_rows[transfer_id] = row
        self.history_empty.hide()
        self.history_rows.insertWidget(0, row)
        slide_in(row)
        while len(self.transfer_rows) > 5:
            oldest_id = next(iter(self.transfer_rows))
            if oldest_id == transfer_id:
                break
            oldest = self.transfer_rows.pop(oldest_id)
            self.history_rows.removeWidget(oldest)
            oldest.deleteLater()
        return row

    def _update_devices(self, devices: list[PeerDevice]) -> None:
        self.devices = {peer.device_id: peer for peer in devices}
        if self.selected_device_id not in self.devices:
            self.selected_device_id = None
        while self.device_list_layout.count():
            item = self.device_list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        self.device_rows = {}
        peers = sorted(self.devices.values(), key=lambda peer: peer.name.casefold())
        self.device_count.setText(
            f"{len(peers)} available" if peers else "Searching your local network"
        )
        self.empty_devices.setVisible(not peers)
        self.device_scroll.setVisible(bool(peers))
        arrivals = [
            peer.device_id for peer in peers if peer.device_id not in self._seen_devices
        ]
        for peer in peers:
            row = DeviceRow(peer, peer.device_id == self.selected_device_id)
            row.selected.connect(self._select_device)
            row.pair_requested.connect(self._pair_device)
            self.device_rows[peer.device_id] = row
            self.device_list_layout.addWidget(row)
            if peer.device_id in arrivals:
                fade_in(row, 240, min(arrivals.index(peer.device_id), 5) * 50)
        self._seen_devices.update(self.devices)
        self.device_list_layout.addStretch()
        if self.selected_device_id:
            self.selected_target.setText(self.devices[self.selected_device_id].name)
        else:
            self.selected_target.setText("Choose a nearby device")
        self._update_send_button()

    def _select_device(self, device_id: str) -> None:
        if device_id not in self.devices:
            return
        self.selected_device_id = device_id
        self._update_devices(list(self.devices.values()))

    def _add_files(self, paths: list[Path]) -> None:
        known = {self.file_list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.file_list.count())}
        for path in paths:
            try:
                path = path.expanduser().resolve(strict=True)
                if not path.is_file() or str(path) in known:
                    continue
                item = QListWidgetItem(
                    QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon),
                    f"{path.name}  ·  {format_bytes(path.stat().st_size)}",
                )
                item.setData(Qt.ItemDataRole.UserRole, str(path))
                self.file_list.addItem(item)
                known.add(str(path))
            except OSError:
                continue
        count = self.file_list.count()
        total = 0
        for i in range(count):
            try:
                total += Path(
                    self.file_list.item(i).data(Qt.ItemDataRole.UserRole)
                ).stat().st_size
            except OSError:
                continue
        self.file_count_label.setText(
            "No files selected" if not count else f"{count} files  ·  {format_bytes(total)}"
        )
        self.drop_zone.title.setText(
            "Drop more files here" if count else "Drop files here"
        )
        self._update_send_button()

    def _choose_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files to send")
        if files:
            self._add_files([Path(value) for value in files])

    def _remove_selected_file(self) -> None:
        for item in self.file_list.selectedItems():
            row = self.file_list.row(item)
            self.file_list.takeItem(row)
        self._add_files([])

    def _update_send_button(self) -> None:
        busy = any(worker.isRunning() for worker in self.workers.values())
        self.add_files_button.setEnabled(not busy)
        self.remove_file_button.setEnabled(
            not busy and bool(self.file_list.selectedItems())
        )
        self.drop_zone.setEnabled(not busy)
        can_send = (
            bool(self.file_list.count())
            and self.selected_device_id in self.devices
            and not busy
        )
        self.send_button.setEnabled(can_send)
        self.swipe.setEnabled(can_send)

    def _send_files(self) -> None:
        peer = self.devices.get(self.selected_device_id or "")
        if peer is None:
            return
        if peer.identity_changed:
            QMessageBox.warning(
                self,
                "Device identity changed",
                "This device's security identity changed since you paired with "
                "it. Pair again before sending files.",
            )
            return
        self._play_send_animation(peer)
        paths = [
            Path(self.file_list.item(i).data(Qt.ItemDataRole.UserRole))
            for i in range(self.file_list.count())
        ]
        transfer_id = str(uuid.uuid4())
        row = self._create_transfer_row(transfer_id, f"To {peer.name}", "Outgoing")
        row.set_status("Waiting for acceptance", "Waiting for the recipient to approve")

        worker = SendWorker(
            peer=peer,
            paths=paths,
            sender_name=self.display_name,
            sender_device_id=self.device_id,
            transfer_id=transfer_id,
        )
        worker.status_changed.connect(self._outgoing_status)
        worker.progress_changed.connect(self._outgoing_progress)
        worker.transfer_done.connect(self._outgoing_done)
        worker.finished.connect(lambda key=transfer_id: self._cleanup_worker(key))
        self.workers[transfer_id] = worker
        worker.start()
        self._update_send_button()

    def _play_send_animation(self, peer: PeerDevice) -> None:
        row = self.device_rows.get(peer.device_id)
        if row is None:
            return
        row.pulse()
        start = self.file_list.mapTo(
            self,
            QPoint(self.file_list.width() // 2, self.file_list.height() // 2),
        )
        end = row.mapTo(self, QPoint(row.width() // 2, row.height() // 2))
        names = [
            self.file_list.item(index).text().split("  ·  ")[0]
            for index in range(min(3, self.file_list.count()))
        ]
        for index, name in enumerate(names):
            FlyingChip(self, name, start, end).launch(index * 80)

    def _outgoing_status(self, transfer_id: str, status: str) -> None:
        row = self.transfer_rows.get(transfer_id)
        if row is not None:
            row.set_status(status)

    def _outgoing_progress(
        self,
        transfer_id: str,
        filename: str,
        current: int,
        total: int,
        speed: float,
        eta: int,
    ) -> None:
        row = self.transfer_rows.get(transfer_id)
        if row is not None:
            row.set_progress(current, total, speed, eta, filename)

    def _outgoing_done(self, transfer_id: str, success: bool, message: str) -> None:
        row = self.transfer_rows.get(transfer_id)
        if row is not None:
            row.set_status("Sent" if success else ("Declined" if "declined" in message.lower() else "Failed"), message)
        if success:
            self.file_list.clear()
            self._add_files([])
        elif "declined" not in message.lower() and "cancelled" not in message.lower():
            self.statusBar().showMessage(message, 7000)
        self._update_send_button()

    def _cleanup_worker(self, transfer_id: str) -> None:
        worker = self.workers.pop(transfer_id, None)
        if worker is not None:
            worker.deleteLater()
        self._update_send_button()

    def _handle_incoming_offer(self, offer: IncomingOffer) -> None:
        dialog = IncomingTransferDialog(offer, self.download_directory, self)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        if accepted:
            row = self._create_transfer_row(
                offer.transfer_id, f"From {offer.sender_name}", "Incoming"
            )
            row.set_status(
                "Accepted",
                f"Waiting for {len(offer.files)} file(s)  ·  {format_bytes(offer.total_bytes)}",
            )
        else:
            row = self._create_transfer_row(
                offer.transfer_id, f"From {offer.sender_name}", "Incoming"
            )
            row.set_status("Declined", "The request was rejected")
        self.service.decide_offer(offer.transfer_id, accepted)

    def _update_incoming_progress(
        self,
        transfer_id: str,
        filename: str,
        current: int,
        total: int,
        index: int,
        count: int,
        speed: float,
        eta: int,
    ) -> None:
        row = self.transfer_rows.get(transfer_id)
        if row is not None:
            row.set_status("Receiving")
            row.set_progress(
                current,
                total,
                speed,
                eta,
                f"{index}/{count}  ·  {filename}",
            )

    def _incoming_complete(
        self, transfer_id: str, paths: list[str], _directory: str
    ) -> None:
        row = self.transfer_rows.get(transfer_id)
        if row is not None:
            names = ", ".join(Path(path).name for path in paths[:3])
            if len(paths) > 3:
                names += f" and {len(paths) - 3} more"
            row.set_status("Received", f"Saved to {self.download_directory}  ·  {names}")

    def _incoming_failed(self, transfer_id: str, message: str) -> None:
        row = self.transfer_rows.get(transfer_id)
        if row is not None:
            row.set_status("Failed", message)
        self.statusBar().showMessage(message, 7000)

    def _pair_device(self, device_id: str) -> None:
        peer = self.devices.get(device_id)
        if peer is None:
            return
        try:
            certificate = certificate_der(self.service.certificate_path)
            private_key = load_private_key(self.service.private_key_path)
        except Exception as exc:
            QMessageBox.warning(
                self, "Pairing unavailable", f"MadDrop could not read its identity.\n\n{exc}"
            )
            return

        worker = PairWorker(
            peer=peer,
            device_id=self.device_id,
            display_name=self.display_name,
            fingerprint=self.service.fingerprint,
            certificate_der=certificate,
            private_key=private_key,
        )
        dialog = PairingDialog(
            peer.name,
            pairing_code(self.service.fingerprint, peer.fingerprint),
            incoming=False,
            parent=self,
        )
        worker.pairing_done.connect(partial(self._pairing_finished, dialog))
        worker.finished.connect(partial(self._forget_pair_worker, device_id))
        self.pair_workers[device_id] = worker
        worker.start()
        dialog.exec()

    def _pairing_finished(
        self, dialog: PairingDialog, success: bool, message: str, code: str
    ) -> None:
        dialog.finish(success, message, code or None)
        if success:
            self.service.refresh_devices()
            self.statusBar().showMessage(message, 6000)

    def _forget_pair_worker(self, device_id: str) -> None:
        self.pair_workers.pop(device_id, None)

    def _handle_pair_request(self, request: PairingRequest) -> None:
        dialog = PairingDialog(request.name, request.code, incoming=True, parent=self)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        self.service.decide_pair(request.request_id, accepted)
        if accepted:
            self.statusBar().showMessage(f"Paired with {request.name}", 6000)

    def _change_device_name(self) -> None:
        value, accepted = QInputDialog.getText(
            self,
            "Change device name",
            "Name shown to nearby devices:",
            QLineEdit.EchoMode.Normal,
            self.display_name,
        )
        if accepted and value.strip():
            self.display_name = value.strip()[:48]
            self.settings.setValue("device/name", self.display_name)
            self.device_menu_button.setText(self.display_name)
            self.service.set_display_name(self.display_name)

    def _choose_receive_folder(self) -> None:
        current = str(self.download_directory)
        selected = QFileDialog.getExistingDirectory(
            self, "Choose receive folder", current
        )
        if not selected:
            return
        try:
            self.service.set_download_directory(Path(selected))
            self.download_directory = Path(selected).expanduser().resolve()
            self.settings.setValue("receive/directory", str(self.download_directory))
        except OSError as exc:
            QMessageBox.warning(self, "Folder unavailable", str(exc))

    def _open_receive_folder(self) -> None:
        self.download_directory.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.download_directory)))

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._intro_played:
            self._intro_played = True
            fade_in(self.centralWidget(), 360)

    def keyPressEvent(self, event) -> None:
        text = event.text().lower()
        if text and text.isalpha():
            self._secret_buffer = (self._secret_buffer + text)[-6:]
            if self._secret_buffer.endswith("drop"):
                self._secret_buffer = ""
                self._reveal_swipe()
        super().keyPressEvent(event)

    def _reveal_swipe(self) -> None:
        if self.swipe.isHidden():
            self.swipe.show()
            self.statusBar().showMessage("Swipe mode unlocked", 4000)
        self._update_send_button()

    def closeEvent(self, event) -> None:
        for worker in self.workers.values():
            worker.requestInterruption()
        for worker in self.pair_workers.values():
            worker.requestInterruption()
        # Accept first: a dead network stack must never keep the window open.
        event.accept()
        self.service.stop()
        for worker in self.workers.values():
            worker.wait(1200)
        for worker in self.pair_workers.values():
            worker.wait(1200)
        event.accept()
