# MadDrop

MadDrop is a native PySide6 desktop app for discovering nearby devices and sending files directly over a local network. Discovery uses mDNS; file contents travel over a TLS-encrypted connection between the two devices. The recipient must accept each transfer before file data is sent. No account, cloud storage, or external service is used.

## Branding

The desktop app uses the supplied MadDrop mark and its electric-blue `#006FFF` on a near-black palette. The cropped transparent app logo and Windows icon are in `src/maddrop/assets/`.

## Run on Windows

Install Python 3.11 or newer, then from this folder run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m maddrop
```

To build the portable app folder and a per-user Windows setup installer:

```powershell
python -m pip install -e ".[windows-build]"
# Install Inno Setup 6 once, then:
.\scripts\build_windows.ps1
```

The installer is created at `dist\installer\MadDrop-Setup-0.1.0.exe`. The portable app folder is `dist\MadDrop`. To create only the portable folder without Inno Setup, run `.\scripts\build_windows.ps1 -PortableOnly`.

The setup is unsigned, so Windows SmartScreen may show a warning during testing. Windows may also ask you to allow MadDrop on private networks. Allow it only for a network you trust; discovery needs local multicast, and transfers need an inbound TCP connection. Public-network access is not required.

## Network notes

- Both devices must have MadDrop open and be on the same Wi-Fi or wired LAN.
- The network must allow mDNS multicast and peer-to-peer device connections. Guest Wi-Fi and client isolation can prevent discovery or transfers.
- Transfers are direct between devices. MadDrop does not route or store file contents.
- Incoming requests show the sender, file names, and total size. Nothing is written until you accept.
- Pairing shows the same 3-digit code on both devices; compare it, then the device is remembered locally and does not need to be paired again.
- After you send, a small animation carries each file across to the target device.
- Received files go to `Downloads\MadDrop` by default. Existing files are never overwritten; duplicate names receive a numbered suffix.
- Current transfer limits are 30 GB per file and 50 GB per batch.

## Project layout

- `src/maddrop/core/identity.py` — local TLS device identity and network address selection
- `src/maddrop/core/pairing.py` — 3-digit pairing codes, key-possession proof, trusted devices
- `src/maddrop/core/network.py` — mDNS discovery, incoming request handling, and safe file writes
- `src/maddrop/core/protocol.py` — protocol validation and filename safety
- `src/maddrop/core/sender.py` — cancellable, streamed outgoing transfers
- `src/maddrop/ui/main_window.py` — native desktop interface
- `src/maddrop/ui/swipe.py` — swipe-to-send rail and the flying file animation
- `scripts/build_windows.ps1` and `scripts/MadDrop.iss` — Windows app and installer build
- `src/maddrop/assets/` — MadDrop app and installer icons
- `tests/` — protocol checks and a local TLS transfer test

The discovery and transfer protocol is kept separate from the desktop UI so a future Android client can implement the same local-network protocol.
