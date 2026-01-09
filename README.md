# AlmostPerfect.ps1

**A Comprehensive Modular Antivirus & EDR Solution - Single File Build**

A powerful, all-in-one security monitoring and protection script for Windows that combines antivirus capabilities, endpoint detection and response (EDR), and advanced security features in a single PowerShell script.

## 🛡️ Overview

AlmostPerfect.ps1 is a modular security solution that provides real-time threat detection, monitoring, and response capabilities. It runs as a managed job system with 40+ detection modules, each operating at configurable intervals to provide comprehensive system protection.

**Author:** Gorstak  
**Version:** 1.0  
**Requires:** PowerShell 5.1+, Windows 10/11, Administrator privileges

## ✨ Key Features

### Core Security Modules (40+ Detection Systems)

- **Hash-Based Detection** - Scans files against known malware hash databases
- **LOLBin Detection** - Detects Living Off The Land binary abuse
- **Process Anomaly Detection** - Identifies suspicious process behavior
- **AMSI Bypass Detection** - Detects attempts to bypass Windows AMSI
- **Credential Dump Detection** - Monitors for credential harvesting tools
- **WMI Persistence Detection** - Detects WMI-based persistence mechanisms
- **Scheduled Task Detection** - Monitors for suspicious scheduled tasks
- **Registry Persistence Detection** - Detects registry-based persistence
- **DLL Hijacking Detection** - Identifies DLL hijacking attempts
- **Token Manipulation Detection** - Detects token manipulation attacks
- **Process Hollowing Detection** - Identifies process hollowing techniques
- **Keylogger Detection** - Detects keylogging software and hooks
- **Ransomware Detection** - Early warning system for ransomware attacks
- **Network Anomaly Detection** - Monitors for suspicious network activity
- **Network Traffic Monitoring** - Analyzes network connections and traffic
- **Rootkit Detection** - Scans for rootkit presence
- **Clipboard Monitoring** - Monitors clipboard for sensitive data
- **COM Monitoring** - Detects suspicious COM object registrations
- **Browser Extension Monitoring** - Monitors browser extensions
- **Shadow Copy Monitoring** - Detects shadow copy deletion (ransomware indicator)
- **USB Monitoring** - Monitors USB device connections
- **Event Log Monitoring** - Analyzes Windows event logs for threats
- **Firewall Rule Monitoring** - Detects unauthorized firewall changes
- **Service Monitoring** - Monitors Windows services for anomalies
- **Fileless Detection** - Detects fileless malware techniques
- **Memory Scanning** - Scans process memory for threats
- **Named Pipe Monitoring** - Detects suspicious named pipe usage
- **DNS Exfiltration Detection** - Identifies DNS tunneling and exfiltration
- **Beacon Detection** - Detects C2 beaconing patterns
- **Code Injection Detection** - Identifies code injection attacks
- **Data Exfiltration Detection** - Monitors for data exfiltration attempts
- **ELF Catcher** - Detects Linux binaries on Windows (WSL/malicious)
- **File Entropy Detection** - Identifies encrypted/packed files
- **Honeypot Monitoring** - Monitors honeypot files for unauthorized access
- **Lateral Movement Detection** - Detects lateral movement techniques
- **Process Creation Detection** - Monitors process creation events
- **Quarantine Management** - Automatic threat quarantine system
- **Reflective DLL Injection Detection** - Detects reflective DLL injection
- **Response Engine** - Automated threat response system

### Advanced Security Features

- **YouTube Ad Blocker** - Local proxy-based ad blocking for YouTube
- **Password Management** - Automatic password rotation and security monitoring
- **Webcam Guardian** - Permission-based webcam access control
- **Key Scrambler** - Inline keystroke scrambling protection
- **Auto-Restart Protection** - Automatic restart on termination
- **Termination Protection** - Prevents unauthorized script termination
- **Process Watchdog** - Monitors and restarts the protection system

## 📋 Requirements

- **Operating System:** Windows 10/11
- **PowerShell:** Version 5.1 or higher
- **Privileges:** Administrator rights (required)
- **Internet:** Optional (for hash lookups and YouTube ad blocking)

## 🚀 Installation

1. **Download the script:**
   ```powershell
   # Clone or download AlmostPerfect.ps1
   ```

2. **Run as Administrator:**
   ```powershell
   # Right-click PowerShell and select "Run as Administrator"
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
   .\AlmostPerfect.ps1
   ```

3. **The script will automatically:**
   - Install itself to `C:\ProgramData\AntivirusProtection\`
   - Create necessary directories (Logs, Data, Quarantine, Reports)
   - Set up persistence via scheduled task
   - Start all detection modules

## 💻 Usage

### Basic Usage

```powershell
# Start the protection system
.\AlmostPerfect.ps1

# Uninstall (removes scheduled task and cleans up)
.\AlmostPerfect.ps1 -Uninstall
```

### Module Configuration

All modules run at configurable intervals defined in `$Script:ManagedJobConfig`:

```powershell
$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15
    ProcessAnomalyDetectionIntervalSeconds = 15
    RansomwareDetectionIntervalSeconds = 15
    # ... and 37 more modules
}
```

### Password Management

The password management module provides:

- **Automatic Password Rotation** - Rotates passwords every 10 minutes (configurable)
- **Shutdown Reset** - Resets password to blank on shutdown/restart
- **Security Monitoring** - Tracks password age, policy compliance, and suspicious activity
- **Dumping Tool Detection** - Detects credential dumping tools (Mimikatz, etc.)

Enabled by default with:
- `EnablePasswordRotation = $true`
- `ResetOnShutdown = $true`

### YouTube Ad Blocker

The YouTube ad blocker uses a local proxy server approach:

- **Local Proxy Server** - Runs on `127.0.0.1:8080`
- **PAC Configuration** - Uses GitHub-hosted PAC file
- **JavaScript Injection** - Injects ad-skipping scripts into YouTube pages
- **Safe Fallback** - Automatically restores internet settings if issues occur

Runs every 5 minutes (300 seconds) by default.

### Webcam Guardian

Permission-based webcam access control:

- **Default Disabled** - Webcam disabled by default
- **Permission Prompts** - Shows dialog when applications request webcam access
- **Auto-Disable** - Automatically disables when application closes
- **Access Logging** - Logs all webcam access attempts

### Key Scrambler

Inline keystroke protection:

- **C# Hook Implementation** - Low-level keyboard hook
- **Random Flooding** - Injects random keystrokes to confuse keyloggers
- **Process Protection** - Protects specific processes from keylogging

## 📁 Directory Structure

```
C:\ProgramData\AntivirusProtection\
├── Logs\
│   ├── antivirus_log.txt
│   ├── stability_log.txt
│   └── EDR_YYYY-MM-DD.log
├── Data\
│   ├── whitelist.json
│   ├── db_integrity.hmac
│   └── antivirus.pid
├── Quarantine\
│   └── [quarantined threats]
└── Reports\
    └── [threat reports]
```

## ⚙️ Configuration

### Main Configuration

```powershell
$Config = @{
    EDRName = "MalwareDetector"
    LogPath = "$Script:InstallPath\Logs"
    QuarantinePath = "$Script:InstallPath\Quarantine"
    DatabasePath = "$Script:InstallPath\Data"
    
    # Threat Intelligence APIs
    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"
    
    # Auto-response settings
    AutoKillThreats = $true
    AutoQuarantine = $true
    EnableUnsignedDLLScanner = $true
}
```

### YouTube Ad Blocker Configuration

```powershell
$Script:YouTubeAdBlockerConfig = @{
    ProxyPort = 8080
    ProxyHost = "127.0.0.1"
    PACUrl = "https://raw.githubusercontent.com/ads-blocker/Pac/refs/heads/main/BlockAds.pac"
    InstallDir = "$env:ProgramData\YouTubeAdBlocker"
}
```

## 🔍 Detection Capabilities

### Threat Intelligence Integration

- **CIRCL Hash Lookup** - SHA256 hash verification
- **MalwareBazaar API** - Malware hash database
- **Cymru Malware Hash Registry** - Additional hash verification

### Behavioral Analysis

- Process anomaly detection
- Network traffic analysis
- File entropy analysis
- Memory scanning
- Registry monitoring

### Persistence Detection

- Scheduled tasks
- Registry run keys
- WMI event consumers
- Service modifications
- Startup folder monitoring

## 🛡️ Security Features

### Anti-Tampering

- **Mutex Protection** - Prevents multiple instances
- **Termination Protection** - Requires 5 Ctrl+C attempts to stop
- **Auto-Restart** - Automatically restarts if terminated
- **Process Watchdog** - Monitors and restarts the protection system

### Logging & Reporting

- Comprehensive event logging
- Threat detection reports
- Stability monitoring
- EDR-style logging with module-specific logs

## ⚠️ Important Notes

### Administrator Privileges

This script **requires** Administrator privileges to function properly. Many detection modules need elevated permissions to:
- Access system processes
- Monitor registry changes
- Scan system directories
- Quarantine threats
- Modify firewall rules

### Internet Connectivity

Some features require internet connectivity:
- Hash lookups (CIRCL, MalwareBazaar, Cymru)
- YouTube ad blocker (PAC file download)
- Threat intelligence updates

### Performance Impact

The script is designed to be lightweight, but running 40+ detection modules may have some performance impact:
- CPU usage varies by module interval
- Memory usage: ~500MB max (configurable)
- Disk I/O for logging and scanning

### Password Management Warning

⚠️ **IMPORTANT:** The password management feature will:
- Automatically rotate your Windows password every 10 minutes
- Reset your password to blank on shutdown/restart

**This may lock you out of your system if you don't have alternative access methods!**

## 🔧 Troubleshooting

### Script Won't Start

1. Ensure you're running as Administrator
2. Check PowerShell execution policy:
   ```powershell
   Get-ExecutionPolicy
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

### Modules Not Starting

- Check logs in `C:\ProgramData\AntivirusProtection\Logs\`
- Review stability log for errors
- Verify all required directories exist

### YouTube Ad Blocker Not Working

1. Restart your browser after installation
2. Check proxy is running: `netstat -an | findstr 8080`
3. Verify internet connectivity
4. Check logs in `$env:ProgramData\YouTubeAdBlocker\proxy.log`

### Password Issues

- Password rotation requires Administrator privileges
- Ensure the account has permission to change passwords
- Check event logs for password change errors

## 📝 Logging

All activities are logged to:

- **Main Log:** `C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt`
- **Stability Log:** `C:\ProgramData\AntivirusProtection\Logs\stability_log.txt`
- **EDR Logs:** `C:\ProgramData\AntivirusProtection\Logs\EDR_YYYY-MM-DD.log`
- **Module-Specific Logs:** Individual logs for each detection module

## 🗑️ Uninstallation

To completely remove AlmostPerfect.ps1:

```powershell
.\AlmostPerfect.ps1 -Uninstall
```

This will:
- Stop all running jobs
- Remove scheduled task
- Clean up proxy settings (YouTube ad blocker)
- Remove startup shortcuts
- **Note:** Logs and quarantined files are preserved

## 📄 License

This project is provided as-is for educational and security research purposes.

## ⚖️ Disclaimer

**USE AT YOUR OWN RISK**

This software is provided without warranty. The authors are not responsible for:
- System lockouts due to password management
- Performance impacts on your system
- False positive detections
- Any damage to your system or data

Always test in a non-production environment first.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## 📧 Support

For issues, questions, or contributions, please open an issue on the repository.

---

**Stay Protected! 🛡️**
