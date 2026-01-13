# 🛡️ Modular Antivirus & EDR System

<div align="center">

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

**A comprehensive, single-file PowerShell-based Antivirus and Endpoint Detection & Response (EDR) solution with 48+ detection modules**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-detection-modules) • [Configuration](#-configuration)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Detection Modules](#-detection-modules)
- [Configuration](#-configuration)
- [API Integration](#-api-integration)
- [Security Features](#-security-features)
- [Logging](#-logging)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

This is a comprehensive, enterprise-grade antivirus and EDR solution written entirely in PowerShell. It provides real-time threat detection, automatic response actions, and extensive monitoring capabilities across 48+ detection modules. The system is designed as a single-file solution for easy deployment and management.

### Key Highlights

- ✅ **48+ Detection Modules** - Comprehensive threat coverage
- ✅ **Real-time Monitoring** - Continuous system surveillance
- ✅ **Automatic Response** - Quarantine, kill processes, block network
- ✅ **API Integration** - MalwareBazaar, CIRCL, Cymru hash lookups
- ✅ **Zero Configuration** - Works out of the box
- ✅ **Single File** - Easy deployment and management
- ✅ **Auto-Persistence** - Scheduled task for automatic startup
- ✅ **Key Scrambler** - Protection against keyloggers

---

## ✨ Features

### Core Capabilities

- **Hash-based Detection** - SHA256 hash matching against threat databases
- **Behavioral Analysis** - Anomaly detection and pattern matching
- **Memory Scanning** - In-memory threat detection
- **Network Monitoring** - Traffic analysis and exfiltration detection
- **Process Monitoring** - Real-time process anomaly detection
- **File System Protection** - Real-time file scanning and quarantine
- **Registry Monitoring** - Persistence mechanism detection
- **Rootkit Detection** - Advanced kernel-level threat detection

### Advanced Features

- **Fileless Malware Detection** - PowerShell, WMI, and registry-based threats
- **Ransomware Protection** - Real-time encryption detection
- **Credential Dumping Prevention** - LSASS and SAM protection
- **Lateral Movement Detection** - Network-based attack detection
- **Code Injection Detection** - Process hollowing and DLL injection
- **USB Device Monitoring** - Removable media threat detection
- **Webcam Protection** - Unauthorized camera access prevention
- **Clipboard Monitoring** - Sensitive data exfiltration detection

### Response Capabilities

- **Automatic Quarantine** - Isolate threats automatically
- **Process Termination** - Kill malicious processes
- **Network Blocking** - Block malicious network connections
- **Driver Protection** - Prevent removal of critical system drivers
- **API Verification** - Cross-reference with external threat intelligence

---

## 📦 Requirements

- **PowerShell 5.1 or higher** (Windows PowerShell or PowerShell Core)
- **Windows 10/11 or Windows Server 2016+**
- **Administrator privileges** (required for full functionality)
- **Internet connection** (optional, for API lookups)

---

## 🚀 Installation

### Quick Start

1. **Download the script**
   ```powershell
   # Clone or download Antivirus.ps1
   ```

2. **Run with Administrator privileges**
   ```powershell
   # Right-click PowerShell and select "Run as Administrator"
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\Antivirus.ps1
   ```

3. **The script will automatically:**
   - Create installation directory (`C:\ProgramData\AntivirusProtection`)
   - Set up scheduled task for auto-start
   - Initialize all 48 detection modules
   - Begin monitoring immediately

### Installation Details

The script installs to:
```
C:\ProgramData\AntivirusProtection\
├── Antivirus.ps1          # Main script
├── Data\                  # Databases and state
├── Logs\                  # All log files
├── Quarantine\           # Isolated threats
└── Reports\              # Detection reports
```

---

## 💻 Usage

### Starting the Antivirus

```powershell
# Run the script (auto-installs if first run)
.\Antivirus.ps1
```

### Stopping the Antivirus

Press `Ctrl+C` **5 times** (termination protection enabled)

Or manually stop:
```powershell
# Find the process
Get-Process | Where-Object {$_.Path -like "*AntivirusProtection*"}

# Stop it
Stop-Process -Name powershell -Force
```

### Uninstalling

```powershell
.\Antivirus.ps1 -Uninstall
```

This will:
- Stop all running instances
- Remove scheduled task
- Delete installation directory
- Clean up all files

---

## 🔍 Detection Modules

The system includes **48 specialized detection modules**:

### Malware Detection
| Module | Interval | Description |
|--------|----------|-------------|
| **HashDetection** | 15s | SHA256 hash matching against threat databases |
| **AdvancedThreatDetection** | 20s | Comprehensive threat signature and behavioral analysis |
| **AttackToolsDetection** | 30s | Detection of hacking tools (Metasploit, Mimikatz, etc.) |
| **FileEntropyDetection** | 120s | High entropy file detection (packed/encrypted malware) |

### Process & Memory Protection
| Module | Interval | Description |
|--------|----------|-------------|
| **ProcessAnomalyDetection** | 15s | Unusual process behavior detection |
| **ProcessHollowingDetection** | 30s | Process hollowing attack detection |
| **ProcessCreationDetection** | 10s | Real-time process creation monitoring |
| **MemoryScanning** | 90s | In-memory threat scanning |
| **CodeInjectionDetection** | 30s | DLL injection and code injection detection |
| **ReflectiveDLLInjectionDetection** | 30s | Reflective DLL loading detection |

### Network Security
| Module | Interval | Description |
|--------|----------|-------------|
| **NetworkAnomalyDetection** | 30s | Unusual network activity detection |
| **NetworkTrafficMonitoring** | 45s | Continuous network traffic analysis |
| **DNSExfiltrationDetection** | 30s | DNS-based data exfiltration detection |
| **BeaconDetection** | 60s | C2 beacon communication detection |
| **DataExfiltrationDetection** | 30s | Data exfiltration attempt detection |
| **LateralMovementDetection** | 30s | Lateral movement attack detection |

### Persistence Detection
| Module | Interval | Description |
|--------|----------|-------------|
| **ScheduledTaskDetection** | 120s | Malicious scheduled task detection |
| **RegistryPersistenceDetection** | 120s | Registry-based persistence detection |
| **WMIPersistenceDetection** | 120s | WMI event subscription persistence |
| **DLLHijackingDetection** | 90s | DLL hijacking vulnerability detection |

### System Protection
| Module | Interval | Description |
|--------|----------|-------------|
| **RootkitDetection** | 180s | Kernel-level rootkit detection |
| **ServiceMonitoring** | 60s | Suspicious service detection |
| **FirewallRuleMonitoring** | 120s | Firewall rule change detection |
| **EventLogMonitoring** | 60s | Security event log analysis |
| **ShadowCopyMonitoring** | 30s | Shadow copy deletion detection (ransomware) |

### Credential Protection
| Module | Interval | Description |
|--------|----------|-------------|
| **CredentialDumpDetection** | 15s | LSASS/SAM dump detection |
| **TokenManipulationDetection** | 60s | Token impersonation detection |
| **PasswordManagement** | 120s | Password policy enforcement |

### Advanced Threats
| Module | Interval | Description |
|--------|----------|-------------|
| **FilelessDetection** | 20s | Fileless malware detection (PowerShell, WMI) |
| **RansomwareDetection** | 15s | Real-time ransomware encryption detection |
| **AMSIBypassDetection** | 15s | AMSI bypass attempt detection |
| **LOLBinDetection** | 15s | Living Off The Land binary detection |

### Device & Privacy Protection
| Module | Interval | Description |
|--------|----------|-------------|
| **USBMonitoring** | 20s | USB device insertion monitoring |
| **MobileDeviceMonitoring** | 15s | Mobile device connection monitoring |
| **WebcamGuardian** | 5s | Unauthorized webcam access prevention |
| **ClipboardMonitoring** | 30s | Clipboard data exfiltration detection |

### System Monitoring
| Module | Interval | Description |
|--------|----------|-------------|
| **COMMonitoring** | 120s | COM object modification detection |
| **BrowserExtensionMonitoring** | 300s | Browser extension analysis |
| **NamedPipeMonitoring** | 45s | Named pipe communication monitoring |
| **HoneypotMonitoring** | 30s | Honeypot file access detection |

### Response & Management
| Module | Interval | Description |
|--------|----------|-------------|
| **ResponseEngine** | 10s | Automated threat response actions |
| **QuarantineManagement** | 300s | Quarantine file lifecycle management |
| **ElfDLLUnloader** | 10s | Event Log File (ELF) DLL unloading |
| **UnsignedDLLRemover** | 300s | Unsigned DLL detection and removal |
| **PrivacyForgeSpoofing** | 60s | Privacy protection and data spoofing |

### Special Features
| Module | Interval | Description |
|--------|----------|-------------|
| **KeyScramblerManagement** | 60s | Keylogger protection via input scrambling |

---

## ⚙️ Configuration

### Default Configuration

The script uses sensible defaults, but you can modify the `$Config` hashtable in the script:

```powershell
$Config = @{
    # Paths
    LogPath = "C:\ProgramData\AntivirusProtection\Logs"
    QuarantinePath = "C:\ProgramData\AntivirusProtection\Quarantine"
    DatabasePath = "C:\ProgramData\AntivirusProtection\Data"
    
    # API Endpoints
    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"
    
    # Behavior
    AutoKillThreats = $true      # Automatically terminate threats
    AutoQuarantine = $true       # Automatically quarantine files
    EnableUnsignedDLLScanner = $true
    MaxMemoryUsageMB = 500
}
```

### Module Intervals

Adjust detection intervals in `$Script:ManagedJobConfig`:

```powershell
$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15
    RootkitDetectionIntervalSeconds = 180
    # ... etc
}
```

### Exclusion Lists

Add paths or processes to exclude from scanning:

```powershell
$Config.ExclusionPaths = @(
    "C:\Program Files\YourApp",
    "C:\CustomPath"
)

$Config.ExclusionProcesses = @(
    "yourprocess",
    "anotherprocess"
)
```

---

## 🌐 API Integration

The system integrates with three external threat intelligence APIs:

### 1. CIRCL Hash Lookup
- **URL**: `https://hashlookup.circl.lu/lookup/sha256`
- **Purpose**: SHA256 hash verification
- **Response**: Known malicious file identification

### 2. MalwareBazaar
- **URL**: `https://mb-api.abuse.ch/api/v1/`
- **Purpose**: Comprehensive malware database
- **Response**: Malware family classification

### 3. Cymru Malware Hash Registry
- **URL**: `https://api.malwarehash.cymru.com/v1/hash`
- **Purpose**: Community-driven hash registry
- **Response**: Malware confirmation

### API Verification Flow

1. File detected as suspicious
2. Calculate SHA256 hash
3. Query all three APIs (with timeout)
4. If any API confirms malicious → Quarantine
5. If APIs unavailable → Quarantine based on detection engine assessment

**Note**: API checks are advisory - the detection engine can quarantine based on behavioral analysis even if APIs don't respond.

---

## 🔒 Security Features

### Protection Mechanisms

- **Mutex-based Single Instance** - Prevents multiple instances
- **PID File Tracking** - Process identification and verification
- **Termination Protection** - Requires 5 Ctrl+C attempts to stop
- **Auto-Restart** - Scheduled task ensures continuous operation
- **Process Watchdog** - Monitors and restarts if crashed

### Driver Protection

- **Inbox Driver Protection** - Prevents removal of Windows system drivers
- **Minifilter Driver Safety** - Automatic removal disabled to prevent BSODs
- **Driver Signature Verification** - Validates Microsoft-signed drivers

### Quarantine System

- **Automatic Isolation** - Threats moved to quarantine automatically
- **API Verification** - Cross-referenced with threat intelligence
- **File Preservation** - Original files preserved with timestamp
- **Auto-Cleanup** - Files older than 30 days automatically removed

---

## 📊 Logging

### Log Locations

All logs are stored in `C:\ProgramData\AntivirusProtection\Logs\`:

- **EDR Logs**: `EDR_YYYY-MM-DD.log` - All detection events
- **Stability Log**: `stability_log.txt` - System stability and errors
- **Module Logs**: Individual module logs (e.g., `advanced_threat_detection.log`)

### Log Levels

- **Debug** - Detailed diagnostic information
- **Info** - General informational messages
- **Warning** - Potential threats or issues
- **Error** - Errors and failures

### Example Log Entry

```
[2026-01-13 07:08:58] [Warning] [ResponseEngine] SUCCESS: Quarantined C:\Temp\malware.exe -> C:\ProgramData\AntivirusProtection\Quarantine\20260113_070858_malware.exe (Reason: Advanced Threat Detected, Source: ResponseEngine)
```

---

## 🐛 Troubleshooting

### Issue: "Another instance is already running"

**Solution**: 
```powershell
# Uninstall first
.\Antivirus.ps1 -Uninstall

# Then reinstall
.\Antivirus.ps1
```

### Issue: "Script requires administrator privileges"

**Solution**: Right-click PowerShell and select "Run as Administrator"

### Issue: Quarantine folder is empty

**Check**:
1. Review logs: `C:\ProgramData\AntivirusProtection\Logs\EDR_*.log`
2. Verify `AutoQuarantine = $true` in config
3. Check if files exist at threat paths (some threats may be process-based)

### Issue: High CPU/Memory Usage

**Solution**: 
- Increase module intervals in `$Script:ManagedJobConfig`
- Add more exclusions to reduce scan scope
- Adjust `MaxMemoryUsageMB` in config

### Issue: False Positives

**Solution**:
- Add legitimate paths to `$Config.ExclusionPaths`
- Add process names to `$Config.ExclusionProcesses`
- Review detection logs to identify patterns

---

## 📝 Module Development

### Adding a New Detection Module

1. **Create the function**:
```powershell
function Invoke-YourModuleName {
    try {
        # Your detection logic here
        $threats = @()
        
        # Detection code...
        
        if ($threats.Count -gt 0) {
            foreach ($threat in $threats) {
                Add-ThreatToResponseQueue -ThreatType "YourThreatType" -ThreatPath $threat.Path -Severity "High"
            }
        }
        
        return $threats.Count
    } catch {
        Write-EDRLog -Module "YourModuleName" -Message "Error: $_" -Level "Error"
        return 0
    }
}
```

2. **Register the module**:
```powershell
# Add to module list (around line 10254)
"YourModuleName",

# Add interval config (around line 19)
YourModuleNameIntervalSeconds = 60
```

3. **Start the module**:
```powershell
# Module will auto-start with others
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Follow PowerShell best practices**
4. **Add comprehensive logging**
5. **Test thoroughly** before submitting
6. **Update documentation** as needed
7. **Submit a pull request**

### Code Style

- Use `Write-EDRLog` for all logging
- Follow existing function naming conventions (`Invoke-ModuleName`)
- Include error handling in all functions
- Document complex logic with comments

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## ⚠️ Disclaimer

**This software is provided "as is" without warranty of any kind.**

- Use at your own risk
- Not a replacement for commercial antivirus solutions
- Designed for educational and research purposes
- Always maintain backups
- Test in isolated environments before production use

---

## 🙏 Acknowledgments

- **CIRCL** - Hash lookup service
- **MalwareBazaar** - Malware database
- **Team Cymru** - Malware hash registry
- **PowerShell Community** - Inspiration and support

---

## 📞 Support

For issues, questions, or contributions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review log files for detailed error messages
3. Open an issue on GitHub
4. Check existing issues for similar problems

---

<div align="center">

**Made with ❤️ for the security community**

⭐ **Star this repo if you find it useful!** ⭐

</div>
