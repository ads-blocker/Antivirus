# MalwareDetector

A lightweight **EDR-style** Windows tray app that combines hash-based lookup, YARA rule scanning, and behavioral detection. It only **quarantines** or **terminates** when external APIs report a file hash as malicious—reducing false positives.

---

## Overview

**MalwareDetector** runs as a system-tray application. Double‑click the tray icon or choose **Dashboard** to open a modern UI where you can run quick/full scans, manage quarantine, view logs and alerts, and optionally install the app for persistence (start with Windows).

- **Kill & quarantine** are gated by **CleanGuard** rules: action is taken only when **MalwareBazaar** or **Cymru** (or equivalent) APIs flag a hash as malicious. **Circl hashlookup** is used to **auto‑trust** known-good files (trust ≥ threshold).
- **Whitelist** includes `explorer.exe`, `Antivirus.exe`, and other common system binaries—they are never flagged or acted upon.
- **YARA** scans suspicious paths when `yara.exe` and `rules.yar` are present next to the app (or in the install directory).

---

## Features

### Detection modules (40+)

| Category | Modules |
|----------|---------|
| **Hash & files** | Hash detection, Simple antivirus (ELF removal, unsigned DLLs), File entropy, Advanced threat |
| **Process & behavior** | Process anomaly, Process hollowing, Process creation, Reflective DLL injection, Code injection, Fileless |
| **Credentials & abuse** | Credential dump, AMSI bypass, Keylogger, Token manipulation, LOLBin, Attack tools, IDS |
| **Persistence** | Registry persistence, WMI persistence, Scheduled tasks, DLL hijacking |
| **Network** | Network anomaly, Network traffic, DNS exfiltration, Data exfiltration, Lateral movement, Beacon, GFocus |
| **System & devices** | Rootkit, Service monitoring, Shadow copy, USB monitoring, Mobile device, Webcam guardian |
| **Other** | Clipboard, COM, Browser extensions, Named pipes, Memory scanning, Event log, Firewall rules, Honeypot, Quarantine management, MITRE mapping, YARA detection, Password management, PrivacyForge spoofing |

### CleanGuard (global kill & quarantine rules)

- **Quarantine**: Only when MalwareBazaar or Cymru reports the file hash as **malicious**.
- **Kill**: Only when the process executable’s hash is reported **malicious** by those APIs.
- **Auto-trust**: If Circl hashlookup trust ≥ 50, the file is considered known-good—no quarantine, no kill.
- **Whitelist**: Explorer, Antivirus, common system processes (e.g. `dllhost`, `conhost`, `RuntimeBroker`, `Taskmgr`, `msiexec`, `TrustedInstaller`) are always excluded.

### YARA

- Rule-based scanning over suspicious paths (e.g. Temp, AppData, Downloads).
- Uses `yara.exe` and `rules.yar` from the app directory (or `InstallPath\Yara` and `Data` when installed).
- Matches are logged; quarantine still follows CleanGuard (hash must be API‑malicious).

### Dashboard

- **Quick scan** / **Full scan** – trigger scans and open logs.
- **Quarantine** – open quarantine folder.
- **Logs** – open log directory.
- **Alerts** – preview recent entries from `yara_detections.log` / `response_engine.log`.
- **Settings** – view paths and options (AutoQuarantine, AutoKillThreats).
- **Install & persistence** – optional copy to `C:\ProgramData\AntivirusProtection`, and **Enable** / **Disable** “start with Windows” (HKCU Run). **Uninstall** removes persistence and the install folder.

---

## Requirements

- **Windows** (64‑bit).
- **.NET Framework 4.5** (or later).
- **Antivirus.exe** (and ideally `yara.exe` + `rules.yar` in the same folder for YARA scans).

---

## Installation & usage

1. **Portable**
   - Run `Antivirus.exe`. The app appears in the system tray.
   - Double‑click the tray icon or right‑click → **Dashboard** to open the UI.

2. **Optional install**
   - Open **Dashboard** → **Install** to copy the app (and YARA files if present) to `C:\ProgramData\AntivirusProtection` and create Logs, Quarantine, Reports, Data.
   - Use **Enable persistence** to add an HKCU Run entry so MalwareDetector starts with Windows. **Disable persistence** removes it.
   - **Uninstall** removes the Run entry and deletes the install folder.

3. **Scans**
   - Scans run automatically in the background. Use **Quick scan** / **Full scan** in the dashboard to open the log folder; detection and response continue via the scheduled jobs.

---

## Paths & layout

| Purpose | Default path |
|--------|-------------------------------|
| Install root | `C:\ProgramData\AntivirusProtection` |
| Logs | `…\Logs` |
| Quarantine | `…\Quarantine` |
| Reports | `…\Reports` |
| Data | `…\Data` |
| YARA (when installed) | `…\Yara\yara.exe`, `…\rules.yar` |

When run **portable**, logs and quarantine use the same layout under `C:\ProgramData\AntivirusProtection` once that directory exists (e.g. after first **Install** or first write).

---

## APIs used

- **Circl hashlookup** – `https://hashlookup.circl.lu/lookup/sha256` (trust score → auto‑trust).
- **MalwareBazaar** – `https://mb-api.abuse.ch/api/v1/` (malware hash check).
- **Cymru** – `https://api.malwarehash.cymru.com/v1/hash` (malware hash check).

Quarantine and kill actions are taken only when an API reports **malicious**. No API hit or “unknown” → no action.

---

## Whitelist (always skipped)

Explorer, Antivirus, and common system binaries are whitelisted by filename, e.g.:

`explorer.exe`, `Antivirus.exe`, `dllhost.exe`, `conhost.exe`, `sihost.exe`, `fontdrvhost.exe`, `SearchHost.exe`, `RuntimeBroker.exe`, `StartMenuExperienceHost.exe`, `SystemSettings.exe`, `ApplicationFrameHost.exe`, `Taskmgr.exe`, `msiexec.exe`, `TrustedInstaller.exe`.

---

## Options

- **AutoQuarantine** – when `true`, files considered malicious by CleanGuard are moved to Quarantine.
- **AutoKillThreats** – when `true`, processes whose executables are malicious are terminated.

Both default to `true`. Kill and quarantine still require **malicious** API verdicts; whitelisted items are never acted upon.

---

## License

See repository license file (if applicable). Third‑party components (e.g. YARA) have their own licenses.
