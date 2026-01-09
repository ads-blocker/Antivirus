# Antivirus Protection - Modular EDR System

A comprehensive, modular Antivirus and Endpoint Detection and Response (EDR) system written in PowerShell. This single-file solution provides enterprise-grade security monitoring and threat detection capabilities.

## 📋 Overview

This PowerShell-based antivirus and EDR system offers real-time threat detection, monitoring, and response capabilities. It includes multiple detection modules that run as managed background jobs, providing continuous protection against various types of malware and security threats.

## ✨ Features

### Core Capabilities
- **Modular Architecture**: 40+ independent detection modules
- **Real-time Monitoring**: Continuous background monitoring with configurable intervals
- **Auto-restart Protection**: Automatic restart on termination (requires admin privileges)
- **Termination Protection**: Multiple safeguards against unauthorized termination
- **Quarantine System**: Automatic threat isolation and management
- **Logging & Reporting**: Comprehensive logging and threat reporting

### Detection Modules

#### Malware Detection
- **Hash Detection**: SHA-256 hash-based malware identification with online lookup
- **File Entropy Detection**: Detects suspicious file entropy patterns
- **Unsigned DLL Scanner**: Identifies unsigned DLLs loaded into processes

#### Process & Memory Protection
- **Process Anomaly Detection**: Monitors for suspicious process behavior
- **Process Hollowing Detection**: Detects process hollowing attacks
- **Process Creation Detection**: Real-time monitoring of new process creation
- **Memory Scanning**: Scans process memory for malicious patterns
- **Code Injection Detection**: Detects code injection techniques
- **Reflective DLL Injection Detection**: Identifies reflective DLL loading

#### Persistence Detection
- **Registry Persistence Detection**: Monitors registry for persistence mechanisms
- **Scheduled Task Detection**: Identifies suspicious scheduled tasks
- **WMI Persistence Detection**: Detects WMI-based persistence
- **Service Monitoring**: Monitors system services for anomalies

#### Network Security
- **Network Anomaly Detection**: Identifies unusual network patterns
- **Network Traffic Monitoring**: Monitors network connections and traffic
- **DNS Exfiltration Detection**: Detects DNS-based data exfiltration
- **Beacon Detection**: Identifies C2 beacon communications
- **Data Exfiltration Detection**: Monitors for unauthorized data transfers

#### Advanced Threat Detection
- **LOLBin Detection**: Identifies Living Off The Land binary usage
- **AMSIBypass Detection**: Detects AMSI bypass attempts
- **Credential Dump Detection**: Monitors for credential harvesting
- **Token Manipulation Detection**: Detects token manipulation attacks
- **DLL Hijacking Detection**: Identifies DLL hijacking attempts
- **Rootkit Detection**: Scans for rootkit presence
- **Fileless Detection**: Detects fileless malware techniques

#### Ransomware & Data Protection
- **Ransomware Detection**: Real-time ransomware activity monitoring
- **Shadow Copy Monitoring**: Protects against shadow copy deletion
- **Clipboard Monitoring**: Monitors clipboard for sensitive data

#### System Monitoring
- **USB Monitoring**: Tracks USB device connections
- **Event Log Monitoring**: Monitors Windows event logs
- **Firewall Rule Monitoring**: Tracks firewall rule changes
- **Named Pipe Monitoring**: Monitors inter-process communication
- **COM Monitoring**: Monitors COM object usage
- **Browser Extension Monitoring**: Tracks browser extension installations

#### Privacy & Additional Features
- **Webcam Guardian**: Protects against unauthorized webcam access
- **Keylogger Detection**: Detects keylogging attempts
- **Key Scrambler Management**: Provides keyboard input protection
- **Password Management**: Secure password management and rotation
- **PrivacyForge Spoofing**: System fingerprint spoofing for privacy
- **YouTube Ad Blocker**: Built-in ad blocking for YouTube
- **Honeypot Monitoring**: Deceptive file monitoring
- **Lateral Movement Detection**: Detects lateral movement attempts
- **ElfCatcher**: Advanced threat detection module

#### Response & Management
- **Response Engine**: Automated threat response actions
- **Quarantine Management**: Automatic threat quarantine and cleanup

## 🔧 Requirements

- **PowerShell Version**: 5.1 or higher
- **Permissions**: Administrator privileges (required)
- **OS**: Windows 10/11 or Windows Server
- **Internet Connection**: Optional (for hash lookups and API queries)

## 📦 Installation

1. **Download the script**: Save `Antivirus.ps1` to your desired location

2. **Run as Administrator**: Right-click PowerShell and select "Run as Administrator"

3. **Execute the script**:
   ```powershell
   .\Antivirus.ps1
   ```

4. The script will:
   - Create installation directory: `C:\ProgramData\AntivirusProtection`
   - Set up logging, quarantine, and data directories
   - Initialize detection modules
   - Start all monitoring jobs

## 🚀 Usage

### Starting the Antivirus

```powershell
# Run with default settings
.\Antivirus.ps1
```

### Uninstalling

```powershell
# Remove all components and stop monitoring
.\Antivirus.ps1 -Uninstall
```

### Stopping the Antivirus

- Press `Ctrl+C` multiple times (termination protection requires multiple attempts)
- Or use the uninstall switch to properly remove the service

## ⚙️ Configuration

The script uses a configuration hash that can be modified at the top of the file:

```powershell
$Config = @{
    EDRName = "MalwareDetector"
    LogPath = "C:\ProgramData\AntivirusProtection\Logs"
    QuarantinePath = "C:\ProgramData\AntivirusProtection\Quarantine"
    DatabasePath = "C:\ProgramData\AntivirusProtection\Data"
    WhitelistPath = "C:\ProgramData\AntivirusProtection\Data\whitelist.json"
    ReportsPath = "C:\ProgramData\AntivirusProtection\Reports"
    
    EnableUnsignedDLLScanner = $true
    AutoKillThreats = $true
    AutoQuarantine = $true
    MaxMemoryUsageMB = 500
}
```

### Detection Intervals

Detection module intervals can be configured in `$Script:ManagedJobConfig`:

```powershell
$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15
    ProcessAnomalyDetectionIntervalSeconds = 15
    RansomwareDetectionIntervalSeconds = 15
    # ... etc
}
```

## 📁 Directory Structure

After installation, the following structure is created:

```
C:\ProgramData\AntivirusProtection\
├── Logs\              # System and detection logs
├── Quarantine\        # Quarantined threats
├── Data\              # Databases, whitelists, PID files
└── Reports\           # Threat reports
```

## 🔍 Detection Capabilities

### Hash Lookup Services
- **CIRCL Hash Lookup**: SHA-256 hash verification
- **MalwareHash Cymru**: Malware hash database
- **MalwareBazaar**: Abuse.ch malware database

### Threat Response
- **Automatic Quarantine**: Suspicious files are automatically quarantined
- **Process Termination**: Malicious processes can be automatically terminated
- **Logging**: All detections are logged with timestamps and details
- **Reporting**: Comprehensive threat reports generated

## 🛡️ Protection Features

### Anti-Termination
- Multiple termination protection mechanisms
- Ctrl+C protection requiring multiple attempts
- Process watchdog for automatic restart
- Mutex-based single instance enforcement

### Persistence
- Automatic restart on system reboot (when run as admin)
- Service-like behavior for continuous protection
- Recovery sequences for failed modules

## 📊 Monitoring & Logging

- **Stability Log**: System stability and module status
- **EDR Log**: Detection events and threat information
- **Module Stats**: Performance metrics for each module
- **Threat Reports**: Detailed threat analysis reports

## ⚠️ Important Notes

1. **Administrator Rights**: This script requires administrator privileges to function properly
2. **Resource Usage**: Multiple background jobs run simultaneously; monitor system resources
3. **Whitelisting**: Configure whitelist paths to avoid false positives
4. **Internet Access**: Some features require internet connectivity for hash lookups
5. **Termination**: Use the `-Uninstall` switch for proper cleanup

## 🔐 Security Considerations

- The script modifies system settings and monitors sensitive areas
- Review exclusion paths to ensure legitimate software isn't blocked
- Whitelist trusted applications and paths
- Monitor logs regularly for false positives
- Consider the privacy implications of system monitoring

## 📝 Author

**Gorstak**

## 📄 License

This script is provided as-is for security and educational purposes.

## 🤝 Contributing

This is a single-file modular system. To contribute:
1. Review the module structure
2. Follow existing function naming conventions
3. Ensure proper error handling and logging
4. Test thoroughly before deployment

## ⚡ Performance Tips

- Adjust detection intervals based on system resources
- Configure appropriate exclusion paths
- Monitor memory usage (default max: 500MB)
- Review and optimize whitelist configurations
- Consider disabling unused modules for better performance

## 🐛 Troubleshooting

### Script won't start
- Ensure PowerShell 5.1+ is installed
- Verify administrator privileges
- Check if another instance is running (mutex lock)

### High resource usage
- Increase detection intervals in `$Script:ManagedJobConfig`
- Disable unused modules
- Review exclusion paths

### False positives
- Add legitimate applications to whitelist
- Review detection logs for patterns
- Adjust detection sensitivity if possible

### Module failures
- Check stability logs: `C:\ProgramData\AntivirusProtection\Logs\stability_log.txt`
- Verify system permissions
- Review error messages in logs

---

**⚠️ Disclaimer**: This tool is for security and educational purposes. Use responsibly and in accordance with applicable laws and regulations.
