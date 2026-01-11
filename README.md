<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Admin-Required-red?style=for-the-badge" alt="Admin Required">
</p>

<h1 align="center">🛡️ Modular Antivirus & EDR</h1>

<p align="center">
  <strong>A comprehensive, single-file PowerShell-based Endpoint Detection and Response (EDR) solution</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-detection-modules">Modules</a> •
  <a href="#%EF%B8%8F-configuration">Configuration</a> •
  <a href="#-uninstallation">Uninstallation</a>
</p>

---

## 📋 Overview

**Modular Antivirus & EDR** is a powerful, lightweight security solution written entirely in PowerShell. It provides real-time threat detection, behavioral analysis, and automated response capabilities—all contained in a single portable script file.

Designed for system administrators, security professionals, and power users who need robust endpoint protection without the overhead of traditional antivirus solutions.

### ✨ Highlights

- 🎯 **43+ Detection Modules** covering malware, persistence, injection, and exfiltration techniques
- 🔄 **Real-time Monitoring** with configurable scan intervals
- 🛑 **Automated Threat Response** with quarantine and process termination
- 🔐 **Self-Protection** mechanisms against tampering and termination
- 📊 **Comprehensive Logging** with Windows Event Log integration
- 🌐 **Threat Intelligence** via CIRCL, Cymru, and MalwareBazaar APIs
- 💾 **Single File Deployment** – no dependencies or complex installation

---

## 🚀 Features

### 🔍 Threat Detection

| Category | Capabilities |
|----------|-------------|
| **Malware Detection** | Hash-based scanning, entropy analysis, signature matching |
| **Process Monitoring** | Anomaly detection, hollowing detection, injection detection |
| **Persistence Detection** | Registry, scheduled tasks, WMI subscriptions, startup items |
| **Network Security** | Traffic monitoring, DNS exfiltration, beacon detection, lateral movement |
| **Memory Security** | Fileless malware, reflective DLL injection, memory scanning |
| **Privacy Protection** | Webcam guardian, clipboard monitoring, keylogger detection |

### 🛠️ Detection Modules

<details>
<summary><strong>Click to expand full module list (43 modules)</strong></summary>

| Module | Description | Default Interval |
|--------|-------------|------------------|
| `HashDetection` | Scans running processes against known malware hashes | 15s |
| `LOLBinDetection` | Detects Living-off-the-Land binary abuse | 15s |
| `ProcessAnomalyDetection` | Identifies suspicious process behavior | 15s |
| `AMSIBypassDetection` | Detects AMSI bypass attempts | 15s |
| `CredentialDumpDetection` | Monitors for credential harvesting tools | 15s |
| `WMIPersistenceDetection` | Detects WMI-based persistence mechanisms | 120s |
| `ScheduledTaskDetection` | Monitors suspicious scheduled tasks | 120s |
| `RegistryPersistenceDetection` | Scans registry run keys for persistence | 120s |
| `DLLHijackingDetection` | Detects DLL search order hijacking | 90s |
| `TokenManipulationDetection` | Identifies token privilege escalation | 60s |
| `ProcessHollowingDetection` | Detects process hollowing techniques | 30s |
| `KeyloggerDetection` | Identifies keylogging activity | 45s |
| `KeyScramblerManagement` | Anti-keylogger protection management | 60s |
| `RansomwareDetection` | Real-time ransomware behavior detection | 15s |
| `NetworkAnomalyDetection` | Identifies suspicious network patterns | 30s |
| `NetworkTrafficMonitoring` | Monitors outbound connections | 45s |
| `RootkitDetection` | Scans for rootkit indicators | 180s |
| `ClipboardMonitoring` | Monitors clipboard for sensitive data theft | 30s |
| `COMMonitoring` | Detects COM object hijacking | 120s |
| `BrowserExtensionMonitoring` | Scans for malicious browser extensions | 300s |
| `ShadowCopyMonitoring` | Protects Volume Shadow Copies | 30s |
| `USBMonitoring` | Monitors USB device connections | 20s |
| `EventLogMonitoring` | Analyzes Windows Event Logs | 60s |
| `FirewallRuleMonitoring` | Detects unauthorized firewall changes | 120s |
| `ServiceMonitoring` | Monitors Windows services for anomalies | 60s |
| `FilelessDetection` | Detects fileless malware techniques | 20s |
| `MemoryScanning` | Scans process memory for threats | 90s |
| `NamedPipeMonitoring` | Monitors named pipes for C2 activity | 45s |
| `DNSExfiltrationDetection` | Detects DNS tunneling/exfiltration | 30s |
| `PasswordManagement` | Monitors for credential theft attempts | 120s |
| `WebcamGuardian` | Protects against unauthorized webcam access | 5s |
| `BeaconDetection` | Identifies C2 beaconing patterns | 60s |
| `CodeInjectionDetection` | Detects various code injection techniques | 30s |
| `DataExfiltrationDetection` | Monitors for data exfiltration attempts | 30s |
| `ElfCatcher` | Detects ELF binaries (WSL threats) | 30s |
| `FileEntropyDetection` | Identifies packed/encrypted malware | 120s |
| `HoneypotMonitoring` | Monitors honeypot files for access | 30s |
| `LateralMovementDetection` | Detects lateral movement techniques | 30s |
| `ProcessCreationDetection` | Real-time process creation monitoring | 10s |
| `QuarantineManagement` | Manages quarantined threats | 300s |
| `ReflectiveDLLInjectionDetection` | Detects reflective DLL loading | 30s |
| `ResponseEngine` | Automated threat response system | 10s |
| `PrivacyForgeSpoofing` | Anti-fingerprinting protection | 60s |
| `YouTubeAdBlocker` | Ad blocking via proxy (optional) | 300s |

</details>

### 🔒 Self-Protection

- **Mutex-based single instance** enforcement
- **Ctrl+C protection** with configurable termination threshold
- **Auto-restart** on unexpected termination
- **Process watchdog** for continuous protection
- **PID file locking** to prevent duplicate instances

---

## 📦 Installation

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- **Administrator privileges** (required)

### Quick Start

1. **Download** the script file `Antivirus.ps1`

2. **Run as Administrator**:
   \`\`\`powershell
   # Right-click PowerShell → "Run as Administrator"
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   .\Antivirus.ps1
   \`\`\`

3. **The script will automatically**:
   - Create installation directory at `C:\ProgramData\AntivirusProtection`
   - Copy itself to the installation location
   - Create a scheduled task for automatic startup
   - Initialize all detection modules

### Installation Directory Structure

\`\`\`
C:\ProgramData\AntivirusProtection\
├── Antivirus.ps1          # Main script
├── Data/
│   ├── whitelist.json     # Process/file whitelist
│   ├── db_integrity.hmac  # Database integrity key
│   └── antivirus.pid      # Process ID file
├── Logs/
│   ├── antivirus_log.txt  # Main activity log
│   └── stability_log.txt  # Stability/startup log
├── Quarantine/            # Quarantined threats
└── Reports/               # Detection reports
\`\`\`

---

## 💻 Usage

### Running the Antivirus

\`\`\`powershell
# Standard run (installs if not already installed)
.\Antivirus.ps1

# The script will display:
# - Module loading status
# - Active job count
# - Real-time threat detections
\`\`\`

### Uninstalling

\`\`\`powershell
# Complete removal
.\Antivirus.ps1 -Uninstall
\`\`\`

This will:
- Stop all detection modules
- Remove scheduled tasks
- Delete installation directory
- Reset any proxy/network settings
- Clean up hosts file modifications

---

## ⚙️ Configuration

### Detection Intervals

Modify `$Script:ManagedJobConfig` at the top of the script:

\`\`\`powershell
$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15          # Faster for critical detection
    RansomwareDetectionIntervalSeconds = 15    # Real-time ransomware protection
    WebcamGuardianIntervalSeconds = 5          # Very frequent webcam checks
    BrowserExtensionMonitoringIntervalSeconds = 300  # Less frequent for browser
    # ... customize as needed
}
\`\`\`

### Global Settings

\`\`\`powershell
$Config = @{
    EDRName = "MalwareDetector"                # Event log source name
    EnableUnsignedDLLScanner = $true           # Scan for unsigned DLLs
    AutoKillThreats = $true                    # Auto-terminate malicious processes
    AutoQuarantine = $true                     # Auto-quarantine malicious files
    MaxMemoryUsageMB = 500                     # Memory usage limit
}
\`\`\`

### Exclusions

Add trusted paths or processes to prevent false positives:

\`\`\`powershell
$Config = @{
    ExclusionPaths = @(
        "C:\MyTrustedApp",
        "D:\Development"
    )
    ExclusionProcesses = @("myapp", "devtool")
}
\`\`\`

---

## 📊 Logging

### Log Locations

| Log File | Purpose |
|----------|---------|
| `Logs\antivirus_log.txt` | Main detection and activity log |
| `Logs\stability_log.txt` | Startup, shutdown, and stability events |
| Windows Event Log | Critical events under "MalwareDetector" source |

### Log Levels

- `INFO` - General information
- `WARN` - Warnings and suspicious activity  
- `ERROR` - Errors and failures
- `THREAT` - Confirmed threat detections

### Sample Log Entry

\`\`\`
[2025-01-11 14:32:15] [THREAT] Ransomware behavior detected: suspicious file encryption activity in C:\Users\...
[2025-01-11 14:32:15] [INFO] Process terminated: malware.exe (PID: 1234)
[2025-01-11 14:32:16] [INFO] File quarantined: C:\Users\...\malware.exe
\`\`\`

---

## 🌐 Threat Intelligence Integration

The solution integrates with multiple threat intelligence APIs:

| Service | Purpose | URL |
|---------|---------|-----|
| **CIRCL HashLookup** | Known malware hash database | hashlookup.circl.lu |
| **Team Cymru** | Malware hash repository | api.malwarehash.cymru.com |
| **MalwareBazaar** | Abuse.ch threat database | mb-api.abuse.ch |

---

## 🔧 Troubleshooting

### Common Issues

<details>
<summary><strong>Script won't start</strong></summary>

1. Ensure you're running as Administrator
2. Check execution policy: `Get-ExecutionPolicy`
3. If restricted: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`

</details>

<details>
<summary><strong>"Another instance is already running"</strong></summary>

1. Check for existing processes: `Get-Process powershell | Where-Object {$_.CommandLine -like "*Antivirus*"}`
2. Remove stale PID file: `Remove-Item "C:\ProgramData\AntivirusProtection\Data\antivirus.pid" -Force`

</details>

<details>
<summary><strong>High CPU/Memory usage</strong></summary>

1. Increase detection intervals in `$Script:ManagedJobConfig`
2. Disable resource-intensive modules like `MemoryScanning` or `FileEntropyDetection`
3. Adjust `MaxMemoryUsageMB` in config

</details>

<details>
<summary><strong>False positives</strong></summary>

1. Add trusted paths to `ExclusionPaths`
2. Add trusted processes to `ExclusionProcesses`
3. Update `whitelist.json` with known-good hashes

</details>

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This software is provided "as-is" for educational and defensive security purposes. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before deploying security tools in any environment.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 👤 Author

**Gorstak**

---

<p align="center">
  <strong>⭐ Star this repository if you find it useful! ⭐</strong>
</p>
\`\`\`

I've created a comprehensive and visually appealing GitHub README.md that covers all aspects of your PowerShell Antivirus & EDR solution. The README includes:

- **Eye-catching badges** for quick project info
- **Complete feature overview** with categorized tables
- **Expandable module list** with all 43 detection modules and their intervals
- **Installation & usage instructions** with code examples
- **Configuration guide** for customizing detection intervals and exclusions
- **Troubleshooting section** with collapsible FAQs
- **Proper attribution** to you as the author (Gorstak)

The markdown uses modern GitHub features like collapsible sections, emoji icons, centered content, and structured tables for maximum readability.
