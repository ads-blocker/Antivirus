# 🛡️ Modular Antivirus & EDR Solution

<div align="center">

**Enterprise-grade endpoint protection without the enterprise price tag**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/powershell)
[![Windows](https://img.shields.io/badge/Windows-10%2F11%2BServer-0078D6.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)](https://github.com/ads-blocker/Antivirus)

*A comprehensive Windows security suite written entirely in PowerShell*

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Detection Modules](#-detection-modules) • [Documentation](#-documentation)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Detection Modules](#-detection-modules)
- [Configuration](#-configuration)
- [Advanced Features](#-advanced-features)
- [Architecture](#-architecture)
- [Threat Intelligence](#-threat-intelligence)
- [Logging & Monitoring](#-logging--monitoring)
- [Performance](#-performance)
- [Troubleshooting](#-troubleshooting)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**Modular Antivirus & EDR** is a single-file, enterprise-grade endpoint detection and response solution written entirely in PowerShell. It provides real-time threat detection, behavioral analysis, and automated response capabilities typically found only in commercial security products.

### Why This Solution?

- ✅ **Zero Dependencies** - Single PowerShell script, no installers or external tools
- ✅ **40+ Detection Modules** - Comprehensive coverage across all attack vectors
- ✅ **Real-time Monitoring** - Continuous behavioral analysis with configurable intervals
- ✅ **Automated Response** - Auto-quarantine, process termination, and network blocking
- ✅ **Self-Protection** - Anti-termination, watchdog, and auto-restart capabilities
- ✅ **Privacy Features** - Webcam guardian, clipboard monitoring, and identity spoofing
- ✅ **Low Resource Usage** - Configurable memory limits (default 500MB max)

---

## ✨ Key Features

### 🔍 Threat Detection

| Category | Capabilities |
|----------|-------------|
| **Process & Memory** | Process hollowing, code injection, reflective DLL injection, memory scanning, fileless malware |
| **Network Security** | C2 beacon detection, DNS exfiltration, network anomalies, suspicious ports, lateral movement |
| **Persistence** | Registry monitoring, scheduled tasks, WMI subscriptions, service installation, COM hijacking |
| **Credentials** | LSASS access monitoring, credential dumping tools, AMSI bypass, password security, SAM/SECURITY hive alerts |
| **Mobile Devices** | iPhone/Android monitoring, banking trojan detection, ADB connection monitoring, mobile malware signatures |
| **Attack Tools** | Dark web tool detection (Hydra, Mimikatz, Metasploit, etc.), hash-based detection, behavioral analysis |

### 🛡️ Advanced Detection Framework

**Multi-layered detection resistant to renaming and obfuscation:**

- 🔐 **Hash-Based Detection** - SHA256 hash matching for known threats
- 📝 **Signature Matching** - YARA-like pattern detection in file content
- 🎲 **Entropy Analysis** - Detects packed/obfuscated malware
- 🎭 **Behavioral Analysis** - Command-line pattern and API call monitoring
- ✅ **Digital Signature Verification** - Validates executable authenticity

### 🔒 Privacy Protection

- **Webcam Guardian** - Permission-based webcam access control with auto-disable
- **Clipboard Monitoring** - Detects sensitive data exposure (API keys, passwords, credit cards)
- **KeyScrambler** - Anti-keylogger protection using keyboard hook injection
- **PrivacyForge** - Automatic identity and telemetry spoofing

### 🚨 System Hardening

- **USB Monitoring** - Detects malicious USB devices and autorun threats
- **Browser Extension Scanning** - Monitors Chrome, Edge, and Firefox for suspicious extensions
- **Firewall Rule Monitoring** - Tracks unauthorized firewall modifications
- **Shadow Copy Protection** - Alerts on ransomware-style shadow copy deletion

---

## 📦 Installation

### Requirements

- **OS**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator (recommended for full functionality)
- **Memory**: Minimum 500MB available RAM

### Quick Start

```powershell
# Download the script
# Run in Administrator PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Antivirus.ps1
```

### Installation Process

When first run, the script automatically:

1. ✅ Creates installation directory at `C:\ProgramData\AntivirusProtection`
2. ✅ Sets up folder structure (logs, quarantine, data, reports)
3. ✅ Copies itself to the installation directory
4. ✅ Creates Windows scheduled task for auto-start
5. ✅ Initializes threat intelligence databases
6. ✅ Sets up event log source (`MalwareDetector`)

### Uninstallation

```powershell
# Run with -Uninstall switch
.\Antivirus.ps1 -Uninstall
```

This will:
- Stop all monitoring jobs
- Remove scheduled task
- Optionally delete installation directory (with confirmation)

---

## 🚀 Quick Start

### Basic Usage

```powershell
# Start the antivirus (Administrator PowerShell)
.\Antivirus.ps1

# The script will:
# - Install itself if first run
# - Start all detection modules
# - Begin real-time monitoring
# - Display status and active job count
```

### Check Status

```powershell
# View running processes
Get-Process powershell | Where-Object { $_.CommandLine -like "*Antivirus*" }

# Check logs
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" -Tail 50

# View quarantined files
Get-ChildItem "C:\ProgramData\AntivirusProtection\Quarantine"
```

---

## 🔬 Detection Modules

### Core Detection Modules (40+)

| Module | Interval | Description |
|--------|----------|-------------|
| **HashDetection** | 15s | SHA256 hash lookups against threat intelligence APIs |
| **LOLBinDetection** | 15s | Living-off-the-Land binary abuse detection |
| **ProcessAnomalyDetection** | 15s | Unusual process behavior and parent-child relationships |
| **AMSIBypassDetection** | 15s | Anti-Malware Scan Interface bypass attempts |
| **CredentialDumpDetection** | 15s | LSASS access, Mimikatz, and credential dumping tools |
| **RansomwareDetection** | 15s | File encryption patterns, shadow copy deletion |
| **KeyloggerDetection** | 45s | Keyboard hooks and keylogging behavior |
| **ProcessHollowingDetection** | 30s | Process replacement and hollowing techniques |
| **CodeInjectionDetection** | 30s | Memory injection and code injection APIs |
| **FilelessDetection** | 20s | PowerShell fileless attacks, WMI, Registry-based |
| **ReflectiveDLLInjectionDetection** | 30s | Reflective DLL loading in memory |
| **DLLHijackingDetection** | 90s | DLL search order hijacking |
| **TokenManipulationDetection** | 60s | Token impersonation and privilege escalation |
| **BeaconDetection** | 60s | C2 beacon patterns and communication |
| **NetworkAnomalyDetection** | 30s | Suspicious network connections and ports |
| **NetworkTrafficMonitoring** | 45s | Deep packet inspection and traffic analysis |
| **DNSExfiltrationDetection** | 30s | DNS tunneling and data exfiltration |
| **LateralMovementDetection** | 30s | SMB, WMI, and remote execution patterns |
| **DataExfiltrationDetection** | 30s | Unauthorized data transfer patterns |
| **MobileDeviceMonitoring** | 15s | iPhone/Android device monitoring and malware detection |
| **AttackToolsDetection** | 30s | Dark web attack tools (Hydra, Mimikatz, etc.) |
| **AdvancedThreatDetection** | 20s | Multi-layered advanced threat detection framework |

### Persistence Detection

| Module | Interval | Description |
|--------|----------|-------------|
| **WMIPersistenceDetection** | 120s | WMI event subscription persistence |
| **ScheduledTaskDetection** | 120s | Unauthorized scheduled task creation |
| **RegistryPersistenceDetection** | 120s | Registry run keys and startup items |
| **ServiceMonitoring** | 60s | New service installation and monitoring |

### System Monitoring

| Module | Interval | Description |
|--------|----------|-------------|
| **USBMonitoring** | 20s | USB device connection and autorun detection |
| **BrowserExtensionMonitoring** | 300s | Chrome/Edge/Firefox extension scanning |
| **FirewallRuleMonitoring** | 120s | Unauthorized firewall rule changes |
| **EventLogMonitoring** | 60s | Security event log analysis |
| **ShadowCopyMonitoring** | 30s | Volume shadow copy deletion alerts |
| **COMMonitoring** | 120s | COM object hijacking detection |
| **NamedPipeMonitoring** | 45s | Named pipe creation and access |

### Advanced Analysis

| Module | Interval | Description |
|--------|----------|-------------|
| **MemoryScanning** | 90s | Memory region scanning for shellcode |
| **RootkitDetection** | 180s | Rootkit and kernel-level threat detection |
| **FileEntropyDetection** | 120s | High entropy file detection (packed malware) |
| **ProcessCreationDetection** | 10s | Real-time process creation monitoring |
| **HoneypotMonitoring** | 30s | Honeypot file access detection |
| **ElfCatcher** | 30s | Executable and Linkable Format analysis |

### Privacy & Protection

| Module | Interval | Description |
|--------|----------|-------------|
| **WebcamGuardian** | 5s | Permission-based webcam access control |
| **ClipboardMonitoring** | 30s | Sensitive data exposure detection |
| **KeyScramblerManagement** | 60s | Anti-keylogger keyboard hook protection |
| **PrivacyForgeSpoofing** | 60s | Identity and telemetry spoofing |

### Management

| Module | Interval | Description |
|--------|----------|-------------|
| **QuarantineManagement** | 300s | Automatic quarantine cleanup (30-day retention) |
| **ResponseEngine** | 10s | Automated threat response actions |
| **PasswordManagement** | 120s | Password security and policy enforcement |

---

## ⚙️ Configuration

### Job Intervals

Customize detection intervals in `$Script:ManagedJobConfig`:

```powershell
$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15
    RansomwareDetectionIntervalSeconds = 15
    ProcessHollowingDetectionIntervalSeconds = 30
    # ... adjust intervals based on system resources
}
```

### Main Configuration

Modify `$Config` hashtable for core settings:

```powershell
$Config = @{
    EDRName = "MalwareDetector"              # Event log source name
    LogPath = "$Script:InstallPath\Logs"     # Log directory
    QuarantinePath = "$Script:InstallPath\Quarantine"
    DatabasePath = "$Script:InstallPath\Data"
    
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

### Recommended Intervals by System

| System Type | Aggressive | Balanced | Light |
|-------------|------------|----------|-------|
| **High-end Desktop** | 10-15s | 30-60s | 60-120s |
| **Standard Desktop** | 30-60s | 60-120s | 120-300s |
| **Server** | 60-120s | 120-180s | 180-300s |

---

## 🎯 Advanced Features

### Multi-Layered Threat Detection

The advanced detection framework provides **renaming-resistant** threat detection:

```powershell
# Framework automatically uses:
# - Hash-based detection (SHA256)
# - Signature pattern matching (YARA-like)
# - Entropy analysis (packed/obfuscated)
# - Behavioral pattern detection
# - Digital signature verification
```

### Mobile Device Protection

**Comprehensive mobile device monitoring:**

- ✅ iPhone/iPad detection via WPD/MTP
- ✅ Android device monitoring
- ✅ Banking trojan detection (Anatsa, RatOn, Klopatra, Sturnus, etc.)
- ✅ ADB connection monitoring
- ✅ Chat app data access detection (WhatsApp/Telegram)
- ✅ NFC-based attack detection (RatOn)
- ✅ Mobile malware signature database (40+ families)

### Attack Tools Detection

**Dark web attack tool detection:**

- 🔍 **Password Crackers**: Hydra, John the Ripper, Hashcat, Medusa
- 🔍 **Exploitation Frameworks**: Metasploit, Cobalt Strike, Empire, Covenant
- 🔍 **Network Scanners**: Nmap, Masscan, Zmap
- 🔍 **Credential Dumpers**: Mimikatz, LaZagne, WCE, Procdump
- 🔍 **Post-Exploitation**: BloodHound, PowerSploit, Impacket, CrackMapExec
- 🔍 **Web Attack Tools**: SQLMap, Burp Suite, Nikto, OWASP ZAP

**Detection methods:**
- Hash-based (works even if renamed)
- Signature-based (file content patterns)
- Behavioral (command-line analysis)
- Entropy analysis (packed tools)

### Webcam Guardian

**Permission-based webcam protection:**

1. Webcams **disabled by default** on startup
2. When application requests camera access:
   - Shows Windows notification for approval
   - User grants/denies permission
   - If granted, camera enabled for that process only
3. When application closes:
   - Camera automatically disabled
   - Access revoked

### PrivacyForge

**Anti-fingerprinting and telemetry spoofing:**

- 🔄 **Identity Rotation** - Generates fake user profiles hourly
- 📊 **Telemetry Spoofing** - Sends fake system metrics
- 📱 **Sensor Data** - Spoofs accelerometer, gyroscope, etc.
- 🌐 **Browser Fingerprint** - Randomized user agents and screen sizes
- 🎮 **Game Telemetry** - Fake player IDs and hardware IDs

---

## 🏗️ Architecture

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

### Self-Protection

- **Ctrl+C Protection** - Requires 5 consecutive attempts to stop
- **Process Watchdog** - Background job monitors main process
- **Auto-Restart** - Scheduled task recreates process if killed
- **Mutex Protection** - Prevents duplicate instances
- **Consecutive Error Tracking** - Triggers recovery after 10 errors
- **Job Backoff** - Failed jobs retry with exponential backoff

---

## 🌐 Threat Intelligence

### Hash Lookups

Integrated with multiple threat intelligence sources:

| Service | Description | API Endpoint |
|---------|-------------|--------------|
| **CIRCL Hashlookup** | Luxembourg CERT hash database | `hashlookup.circl.lu` |
| **MalwareBazaar** | abuse.ch malware sample repository | `mb-api.abuse.ch` |
| **Team Cymru** | Malware hash registry | `api.malwarehash.cymru.com` |

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

### Mobile Malware Database

**Banking Trojans (40+ families):**
- Anatsa, RatOn, Klopatra, Sturnus, Frogblight, GodFather
- Anubis, Cerberus, EventBot, Exobot, FakeBank, Ginp, Gustuff
- Hydra, Marcher, Medusa, Octo, Svpeng, TinyBanker, Zeus, Zitmo
- BankBot, Asacub, Acecard, TeaBot, and more

**Spyware & RATs:**
- Pegasus, FinFisher, mSpy, Spyera, FlexiSpy
- RatOn, Klopatra, SpyNote, AndroRAT, DroidJack

**Ransomware:**
- Simplocker, Koler, Lockerpin, Fusob, Jisut, Charger

---

## 📊 Logging & Monitoring

### Log Files

| File | Description | Location |
|------|-------------|----------|
| `antivirus_log.txt` | Main activity and threat log | `Logs\` |
| `stability_log.txt` | System health and startup/shutdown events | `Logs\` |
| `[module]_detections.log` | Per-module detection details | `Logs\` |
| `EDR_[date].log` | Daily EDR activity log | `Logs\` |
| `MobileDeviceMonitoring_[date].log` | Mobile device detection log | `Logs\` |
| `AttackToolsDetection_[date].log` | Attack tool detection log | `Logs\` |
| `AdvancedThreatDetection_[date].log` | Advanced threat detection log | `Logs\` |

### Event Log Integration

Writes to Windows Application Event Log with source `MalwareDetector`:

| Event ID | Type | Description |
|----------|------|-------------|
| 1000 | Information | General information events |
| 1001 | Error | Error conditions |
| 1002 | Warning | Warning conditions |
| 1003 | Threat Detected | Threat detection events |
| 2000 | Alert | High-priority alerts |

### View Logs

```powershell
# View main log
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" -Tail 100

# View event log
Get-WinEvent -LogName Application -ProviderName MalwareDetector | Select-Object -First 50

# View quarantined items
Get-ChildItem "C:\ProgramData\AntivirusProtection\Quarantine" | Format-Table
```

---

## ⚡ Performance

### Resource Management

- **Maximum Memory**: 500MB (configurable)
- **Scan Limits**: Most scans limited to first 100-500 items
- **Caching**: Prevents duplicate scans
- **Staggered Intervals**: Spreads CPU load across time

### Optimization Tips

1. **Adjust Intervals**: Increase intervals for lower-end systems
2. **Disable Modules**: Comment out unused modules in job list
3. **Exclusion Lists**: Add trusted paths to `ExclusionPaths`
4. **Memory Limit**: Reduce `MaxMemoryUsageMB` if needed

### System Impact

| System Type | CPU Usage | Memory Usage | Disk I/O |
|-------------|-----------|--------------|----------|
| **Idle** | < 1% | ~100-200MB | Minimal |
| **Active Scanning** | 5-15% | ~200-400MB | Low |
| **Threat Detected** | 10-20% | ~300-500MB | Moderate |

---

## 🔧 Troubleshooting

### Common Issues

#### Script Won't Start

```powershell
# Check for existing instance
Get-Process powershell | Where-Object { $_.CommandLine -like "*Antivirus*" }

# Clear stale PID file
Remove-Item "C:\ProgramData\AntivirusProtection\Data\antivirus.pid" -Force

# Check mutex
# Restart computer if mutex is stuck
```

#### High CPU Usage

- Increase detection intervals in `$Script:ManagedJobConfig`
- Disable resource-intensive modules (MemoryScanning, RootkitDetection)
- Reduce scan limits in individual modules

#### False Positives

```powershell
# Add to whitelist
$whitelist = Get-Content "C:\ProgramData\AntivirusProtection\Data\whitelist.json" | ConvertFrom-Json
$whitelist.Processes += "YourProcess.exe"
$whitelist | ConvertTo-Json | Set-Content "C:\ProgramData\AntivirusProtection\Data\whitelist.json"

# Adjust exclusion paths
$Config.ExclusionPaths += "C:\YourPath"
```

#### Network Issues After Install

```powershell
# Reset proxy settings
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Remove-ItemProperty -Path $regPath -Name "AutoConfigURL" -ErrorAction SilentlyContinue
Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0
```

#### Webcam Issues

```powershell
# Manually enable webcam if needed
Get-PnpDevice -Class Camera | Enable-PnpDevice -Confirm:$false
```

---

## 🔐 Security Considerations

### Running Without Admin

Some features require Administrator privileges:

- ❌ WebcamGuardian (device control)
- ❌ Password Management (registry access)
- ❌ Firewall rule creation
- ❌ Event log source creation
- ⚠️ Reduced functionality if not elevated

### Self-Protection Limitations

While self-protection is robust, it can be bypassed by:

- ⚠️ Kernel-level attacks
- ⚠️ WMI process termination
- ⚠️ Safe mode boot
- ⚠️ Direct memory manipulation

### Best Practices

1. ✅ Run with Administrator privileges for full protection
2. ✅ Keep PowerShell execution policy appropriately configured
3. ✅ Regularly review logs for false positives
4. ✅ Update threat signatures regularly
5. ✅ Use in conjunction with other security tools
6. ✅ Test in isolated environment before production

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- 🔧 Additional detection signatures
- ⚡ Performance optimizations
- 🌍 Cross-platform support (PowerShell Core)
- 🖥️ GUI dashboard
- 🖥️ Central management server
- 📚 Additional documentation
- 🧪 Test cases and validation

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**This software is provided for educational and authorized security testing purposes only.**

Use responsibly and in compliance with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this software.

**Always:**
- ✅ Use only on systems you own or have explicit permission to test
- ✅ Comply with local laws and regulations
- ✅ Respect privacy and data protection requirements
- ✅ Use in isolated test environments when possible

---

## 👤 Author

**Gorstak**

*Built with PowerShell for Windows Security*

---

## 🙏 Acknowledgments

- Threat intelligence providers (CIRCL, MalwareBazaar, Team Cymru)
- PowerShell community
- Security researchers and contributors
- Open source security tools and frameworks

---

<div align="center">

**⭐ If you find this project useful, please consider giving it a star! ⭐**

[Report Bug](https://github.com/ads-blocker/Antivirus/issues) • [Request Feature](https://github.com/ads-blocker/Antivirus/issues) • [Documentation](https://github.com/ads-blocker/Antivirus)

</div>
