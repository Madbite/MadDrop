from __future__ import annotations

import platform
import sys
import uuid
from pathlib import Path

from PySide6.QtCore import QSettings, QStandardPaths
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from maddrop.core.identity import app_data_directory
from maddrop.core.network import LanTransferService
from maddrop.resources import asset_path
from maddrop.ui.main_window import MainWindow


def _default_receive_directory() -> Path:
    downloads = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
    return Path(downloads or (Path.home() / "Downloads")) / "MadDrop"


def main() -> int:
    application = QApplication(sys.argv)
    application.setApplicationName("MadDrop")
    application.setOrganizationName("MadDrop")
    application.setApplicationDisplayName("MadDrop")
    application.setWindowIcon(QIcon(str(asset_path("maddrop.ico"))))

    settings = QSettings("MadDrop", "MadDrop")
    device_id = str(settings.value("identity/deviceId", "") or "")
    if not device_id:
        device_id = str(uuid.uuid4())
        settings.setValue("identity/deviceId", device_id)

    default_name = platform.node().strip() or "This device"
    display_name = str(settings.value("device/name", default_name))
    download_directory = Path(
        str(settings.value("receive/directory", str(_default_receive_directory())))
    ).expanduser()

    try:
        service = LanTransferService(
            device_id=device_id,
            display_name=display_name,
            identity_directory=app_data_directory() / "identity",
            download_directory=download_directory,
        )
    except Exception as exc:
        QMessageBox.critical(None, "MadDrop could not start", str(exc))
        return 1

    window = MainWindow(
        service=service,
        settings=settings,
        device_id=device_id,
        display_name=display_name,
        download_directory=download_directory,
    )
    window.show()
    window.start_network()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
