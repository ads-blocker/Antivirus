<div align="center">

# Modular Antivirus & EDR Solution

### A Comprehensive Windows Security Suite in Pure PowerShell

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)]()

*Enterprise-grade endpoint protection without the enterprise price tag*

[Features](#-features) | [Installation](#-installation) | [Configuration](#-configuration) | [Detection Modules](#-detection-modules) | [Architecture](#-architecture)

---

</div>

## Overview

**Modular Antivirus & EDR** is a single-file, enterprise-grade endpoint detection and response solution written entirely in PowerShell. It provides real-time threat detection, behavioral analysis, and automated response capabilities typically found only in commercial security products.

Designed for security professionals, system administrators, and researchers, this tool offers deep visibility into Windows system activity with over **40+ detection modules** covering everything from credential theft to ransomware behavior.

---

## Key Highlights

| Feature | Description |
|---------|-------------|
| **Single File Deployment** | One PowerShell script - no dependencies, no installers |
| **40+ Detection Modules** | Comprehensive coverage across all attack vectors |
| **Real-time Monitoring** | Continuous behavioral analysis with configurable intervals |
| **Automated Response** | Auto-quarantine, process termination, and network blocking |
| **Self-Protection** | Anti-termination, watchdog, and auto-restart capabilities |
| **Privacy Features** | Webcam guardian, clipboard monitoring, and identity spoofing |
| **Low Resource Usage** | Configurable memory limits (default 500MB max) |

---

## Features

### Threat Detection

<table>
<tr>
<td width="50%">

**Process & Memory Analysis**
- Process hollowing detection
- Code injection monitoring
- Reflective DLL injection detection
- Memory scanning for anomalies
- Fileless malware detection

</td>
<td width="50%">

**Network Security**
- C2 beacon detection
- DNS exfiltration monitoring
- Network anomaly detection
- Suspicious port monitoring
- Lateral movement detection

</td>
</tr>
<tr>
<td>

**Persistence Monitoring**
- Registry persistence detection
- Scheduled task monitoring
- WMI event subscription detection
- Service installation monitoring
- COM object hijacking detection

</td>
<td>

**Credential Protection**
- LSASS access monitoring
- Credential dumping tool detection
- AMSI bypass detection
- Password security monitoring
- SAM/SYSTEM hive access alerts

</td>
</tr>
</table>

### Privacy Protection

- **Webcam Guardian** - Permission-based webcam access control with auto-disable
- **Clipboard Monitoring** - Detects sensitive data exposure (API keys, passwords, credit cards)
- **KeyScrambler** - Anti-keylogger protection using keyboard hook injection
- **PrivacyForge** - Automatic identity and telemetry spoofing

### System Hardening

- **USB Monitoring** - Detects malicious USB devices and autorun threats
- **Browser Extension Scanning** - Monitors Chrome, Edge, and Firefox for suspicious extensions
- **Firewall Rule Monitoring** - Tracks unauthorized firewall modifications
- **Shadow Copy Protection** - Alerts on ransomware-style shadow copy deletion

---

## Installation

### Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrator privileges (recommended for full functionality)

### Quick Start

```powershell
# Download and run (Administrator PowerShell)
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Antivirus.ps1
```

### Installation Process

When first run, the script automatically:

1. Creates installation directory at `C:\ProgramData\AntivirusProtection`
2. Sets up folder structure for logs, quarantine, data, and reports
3. Copies itself to the installation location
4. Creates a scheduled task for automatic startup at logon and boot
5. Initializes mutex for single-instance protection
6. Starts all detection modules

### Directory Structure

```
C:\ProgramData\AntivirusProtection\
├── Data\
│   ├── whitelist.json          # Whitelisted files/processes
│   ├── db_integrity.hmac       # Database integrity key
│   └── antivirus.pid           # Process ID file
├── Logs\
│   ├── antivirus_log.txt       # Main activity log
│   ├── stability_log.txt       # System stability log
│   └── [module]_detections.log # Per-module detection logs
├── Quarantine\                 # Isolated malicious files
├── Reports\                    # Threat reports
└── Antivirus.ps1               # Main script
```

---

## Uninstallation

```powershell
# Run with -Uninstall flag
.\Antivirus.ps1 -Uninstall
```

This will:
- Stop all monitoring jobs
- Remove scheduled tasks
- Clean up startup shortcuts
- Delete installation directory
- Restore proxy/network settings

---

## Detection Modules

### Process & Execution Monitoring

| Module | Interval | Description |
|--------|----------|-------------|
| `ProcessAnomalyDetection` | 15s | Detects unusual process behaviors, parent-child relationships |
| `ProcessCreationDetection` | 10s | Monitors for suspicious process spawning patterns |
| `ProcessHollowingDetection` | 30s | Identifies process hollowing and thread suspension |
| `LOLBinDetection` | 15s | Detects Living-off-the-Land binary abuse |
| `FilelessDetection` | 20s | Identifies fileless malware techniques |

### Memory & Code Analysis

| Module | Interval | Description |
|--------|----------|-------------|
| `MemoryScanning` | 90s | Scans process memory for anomalies |
| `CodeInjectionDetection` | 30s | Detects code injection techniques |
| `ReflectiveDLLInjectionDetection` | 30s | Identifies reflective DLL loading |
| `DLLHijackingDetection` | 90s | Monitors for DLL hijacking attempts |
| `ElfCatcher` | 30s | Detects suspicious DLLs in browser processes |

### Network Security

| Module | Interval | Description |
|--------|----------|-------------|
| `NetworkAnomalyDetection` | 30s | Identifies suspicious network connections |
| `NetworkTrafficMonitoring` | 45s | Monitors outbound traffic patterns |
| `BeaconDetection` | 60s | Detects C2 beacon communication patterns |
| `DNSExfiltrationDetection` | 30s | Identifies DNS tunneling and exfiltration |
| `DataExfiltrationDetection` | 30s | Monitors for data exfiltration attempts |
| `LateralMovementDetection` | 30s | Detects lateral movement techniques |

### Persistence Detection

| Module | Interval | Description |
|--------|----------|-------------|
| `RegistryPersistenceDetection` | 120s | Monitors registry run keys and startup entries |
| `ScheduledTaskDetection` | 120s | Detects suspicious scheduled tasks |
| `WMIPersistenceDetection` | 120s | Identifies WMI event subscription persistence |
| `ServiceMonitoring` | 60s | Monitors for malicious service installations |
| `COMMonitoring` | 120s | Detects COM object hijacking |

### Credential & Authentication

| Module | Interval | Description |
|--------|----------|-------------|
| `CredentialDumpDetection` | 15s | Detects credential dumping tools and LSASS access |
| `AMSIBypassDetection` | 15s | Identifies AMSI bypass attempts |
| `PasswordManagement` | 120s | Monitors password security and suspicious activity |
| `TokenManipulationDetection` | 60s | Detects token theft and manipulation |

### Malware Detection

| Module | Interval | Description |
|--------|----------|-------------|
| `HashDetection` | 15s | Checks file hashes against threat intelligence |
| `RansomwareDetection` | 15s | Detects ransomware behavior patterns |
| `KeyloggerDetection` | 45s | Identifies keylogger activity |
| `RootkitDetection` | 180s | Deep scan for rootkit indicators |
| `FileEntropyDetection` | 120s | Detects packed/encrypted malware |

### System Monitoring

| Module | Interval | Description |
|--------|----------|-------------|
| `EventLogMonitoring` | 60s | Monitors security events and log tampering |
| `FirewallRuleMonitoring` | 120s | Tracks firewall rule changes |
| `ShadowCopyMonitoring` | 30s | Monitors shadow copy deletion |
| `USBMonitoring` | 20s | Detects malicious USB devices |
| `BrowserExtensionMonitoring` | 300s | Scans browser extensions |
| `NamedPipeMonitoring` | 45s | Monitors suspicious named pipes |
| `HoneypotMonitoring` | 30s | Monitors honeypot file access |

### Privacy & Protection

| Module | Interval | Description |
|--------|----------|-------------|
| `WebcamGuardian` | 5s | Controls webcam access with user permission |
| `ClipboardMonitoring` | 30s | Detects sensitive data in clipboard |
| `KeyScramblerManagement` | 60s | Anti-keylogger keyboard protection |
| `PrivacyForgeSpoofing` | 60s | Identity and telemetry spoofing |
| `YouTubeAdBlocker` | 300s | Ad blocking via PAC proxy |

### Response & Management

| Module | Interval | Description |
|--------|----------|-------------|
| `ResponseEngine` | 10s | Automated threat response actions |
| `QuarantineManagement` | 300s | Manages quarantined files (30-day retention) |

---

## Configuration

### Detection Intervals

All module intervals are configurable via `$Script:ManagedJobConfig`:

```powershell
$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15
    LOLBinDetectionIntervalSeconds = 15
    ProcessAnomalyDetectionIntervalSeconds = 15
    # ... additional modules
}
```

### Main Configuration

```powershell
$Config = @{
    EDRName = "MalwareDetector"              # Event log source name
    LogPath = "$Script:InstallPath\Logs"     # Log directory
    QuarantinePath = "$Script:InstallPath\Quarantine"
    DatabasePath = "$Script:InstallPath\Data"
    WhitelistPath = "$Script:InstallPath\Data\whitelist.json"
    
    # Threat Intelligence APIs
    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"
    
    # Response Settings
    AutoKillThreats = $true          # Auto-terminate malicious processes
    AutoQuarantine = $true           # Auto-quarantine malicious files
    MaxMemoryUsageMB = 500           # Maximum memory usage
    
    # Scanning Exclusions
    ExclusionPaths = @(...)          # Paths to exclude from scanning
    ExclusionProcesses = @("powershell", "pwsh")
}
```

---

## Threat Intelligence

### Hash Lookups

The solution integrates with multiple threat intelligence sources:

| Service | Description |
|---------|-------------|
| **CIRCL Hashlookup** | Luxembourg CERT hash database |
| **MalwareBazaar** | abuse.ch malware sample repository |
| **Team Cymru** | Malware hash registry |

### LOLBin Detection

Comprehensive detection of Living-off-the-Land binary abuse:

- `certutil` - Download/decode operations
- `bitsadmin` - Background file transfers
- `mshta` - HTA script execution
- `regsvr32` - Squiblydoo attacks
- `rundll32` - Proxy execution
- `wmic` - Remote execution and XSL abuse
- `powershell` - Encoded commands and evasion
- `msiexec` - Silent remote installations

---

## Self-Protection Features

### Anti-Termination

- **Ctrl+C Protection** - Requires 5 consecutive attempts to stop
- **Process Watchdog** - Background job monitors main process
- **Auto-Restart** - Scheduled task recreates process if killed
- **Mutex Protection** - Prevents duplicate instances

### Stability

- **Consecutive Error Tracking** - Triggers recovery after 10 errors
- **Job Backoff** - Failed jobs retry with exponential backoff
- **Graceful Recovery** - Automatic recovery sequence on failures

---

## Architecture

### Single-Threaded Design

All detection modules run in a single PowerShell process using a tick-based scheduler:

```
┌─────────────────────────────────────────────────────────┐
│                    Main Loop (1s tick)                  │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Module A  │  │   Module B  │  │   Module C  │     │
│  │  (15s int)  │  │  (30s int)  │  │  (60s int)  │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Managed Job Scheduler              │   │
│  │  - Tracks NextRunUtc for each module            │   │
│  │  - Invokes modules when interval elapsed        │   │
│  │  - Handles errors and backoff                   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Response Pipeline

```
Detection → Threat Queue → Response Engine → Action
                              │
                              ├─► Quarantine
                              ├─► Kill Process
                              ├─► Block Network
                              ├─► Log Event
                              └─► Alert (Event Log)
```

---

## Logging

### Log Files

| File | Description |
|------|-------------|
| `antivirus_log.txt` | Main activity and threat log |
| `stability_log.txt` | System health and startup/shutdown events |
| `[module]_detections.log` | Per-module detection details |
| `EDR_[date].log` | Daily EDR activity log |

### Event Log Integration

Writes to Windows Application Event Log with source `MalwareDetector`:

| Event ID | Type |
|----------|------|
| 1000 | Information |
| 1001 | Error |
| 1002 | Warning |
| 1003 | Threat Detected |
| 2000 | Alert |

---

## Response Actions

### Severity-Based Response Matrix

| Severity | Actions |
|----------|---------|
| **Critical** | Quarantine, Kill Process, Block Network, Log |
| **High** | Quarantine, Log, Alert |
| **Medium** | Log, Alert |
| **Low** | Log |

### Quarantine

- Files moved to `Quarantine\` with timestamp prefix
- Original path preserved in filename
- 30-day automatic retention
- Integrity preserved (no modification)

---

## Webcam Guardian

Permission-based webcam access control:

1. Webcams disabled by default on startup
2. When application requests camera access:
   - Shows Windows notification for approval
   - User grants/denies permission
   - If granted, camera enabled for that process only
3. When application closes:
   - Camera automatically disabled
   - Access revoked

Detects cameras via multiple methods:
- PnP Device Class: Camera, Image, Media
- WMI queries for imaging devices
- Strict filtering to avoid disabling non-camera devices

---

## PrivacyForge

Anti-fingerprinting and telemetry spoofing:

- **Identity Rotation** - Generates fake user profiles hourly
- **Telemetry Spoofing** - Sends fake system metrics
- **Sensor Data** - Spoofs accelerometer, gyroscope, etc.
- **Browser Fingerprint** - Randomized user agents and screen sizes
- **Game Telemetry** - Fake player IDs and hardware IDs

---

## Performance Considerations

### Resource Management

- Maximum memory limit: 500MB (configurable)
- Most scans limited to first N items (100-500)
- Caching to prevent duplicate scans
- Staggered intervals to spread CPU load

### Recommended Intervals by System

| System Type | Aggressive | Balanced | Light |
|-------------|------------|----------|-------|
| High-end Desktop | 10-15s | 30-60s | 60-120s |
| Standard Desktop | 30-60s | 60-120s | 120-300s |
| Server | 60-120s | 120-180s | 180-300s |

---

## Troubleshooting

### Common Issues

**Script won't start:**
```powershell
# Check for existing instance
Get-Process powershell | Where-Object { $_.CommandLine -like "*Antivirus*" }

# Clear stale PID file
Remove-Item "C:\ProgramData\AntivirusProtection\Data\antivirus.pid" -Force
```

**High CPU usage:**
- Increase detection intervals in `$Script:ManagedJobConfig`
- Disable resource-intensive modules (MemoryScanning, RootkitDetection)

**False positives:**
- Add entries to `whitelist.json`
- Adjust exclusion paths in `$Config.ExclusionPaths`

**Network issues after install:**
```powershell
# Reset proxy settings
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Remove-ItemProperty -Path $regPath -Name "AutoConfigURL" -ErrorAction SilentlyContinue
Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0
```

---

## Security Considerations

### Running Without Admin

Some features require Administrator privileges:
- WebcamGuardian (device control)
- Password Management (registry access)
- Firewall rule creation
- Event log source creation

The script will run with reduced functionality if not elevated.

### Self-Protection Limitations

While self-protection is robust, it can be bypassed by:
- Kernel-level attacks
- WMI process termination
- Safe mode boot
- Direct memory manipulation

---

## Contributing

Contributions are welcome! Areas for improvement:

- Additional detection signatures
- Performance optimizations
- Cross-platform support (PowerShell Core)
- GUI dashboard
- Central management server

---

## Disclaimer

This software is provided for educational and authorized security testing purposes only. Use responsibly and in compliance with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this software.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Author:** Gorstak

*Built with PowerShell for Windows Security*

</div>
