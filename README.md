# 🛡️ Enterprise EDR Antivirus

A comprehensive Enterprise Detection and Response (EDR) system built with PowerShell, featuring 42 integrated detection modules running as managed tick jobs for real-time threat detection and automated response capabilities.

## 🌟 Features

### 🔍 **Multi-Vector Threat Detection (42 Modules)**

- **AMSI Bypass Detection** - Identifies PowerShell AMSI circumvention attempts (30s interval)
- **Beacon Detection** - Identifies C2 communication beacons (60s interval)
- **Browser Extension Monitoring** - Detects malicious browser extensions (120s interval)
- **Clipboard Monitoring** - Monitors for clipboard data theft (30s interval)
- **Code Injection Detection** - Identifies code injection techniques (30s interval)
- **COM Object Monitoring** - Identifies suspicious COM object usage (60s interval)
- **Credential Dump Detection** - Identifies credential harvesting attempts (20s interval)
- **Data Exfiltration Detection** - Comprehensive outbound data transfer monitoring (30s interval)
- **DLL Hijacking Detection** - Detects DLL hijacking attacks (60s interval)
- **DNS Exfiltration Detection** - Identifies DNS tunneling and data exfiltration (30s interval)
- **ELF Catcher** - Linux executable detection in Windows environments (30s interval)
- **Event Log Monitoring** - Analyzes Windows Event Logs for threat indicators (60s interval)
- **File Entropy Detection** - Detects suspicious file entropy patterns (120s interval)
- **Fileless Malware Detection** - Detects fileless malware techniques (20s interval)
- **Firewall Rule Monitoring** - Tracks suspicious firewall modifications (60s interval)
- **Hash Detection** - Monitors file hashes against threat intelligence (60s interval)
- **Honeypot Monitoring** - Decoy resources to attract and detect attackers (30s interval)
- **Keylogger Detection** - Identifies keylogging attempts (30s interval)
- **Key Scrambler Management** - Key protection and monitoring (60s interval)
- **Lateral Movement Detection** - Identifies network lateral movement attempts (30s interval)
- **Memory Scanning** - Monitors process memory for malicious injections (60s interval)
- **Named Pipe Monitoring** - Detects malicious named pipe usage (30s interval)
- **Network Anomaly Detection** - Identifies anomalous network traffic patterns (30s interval)
- **Network Traffic Monitoring** - Comprehensive network traffic analysis (30s interval)
- **Password Management** - Password security monitoring and enforcement (300s interval)
- **Process Anomaly Detection** - Detects suspicious process behavior (20s interval)
- **Process Creation Detection** - Monitors process creation patterns (10s interval)
- **Process Hollowing Detection** - Detects process hollowing techniques (30s interval)
- **Quarantine Management** - Automatic file isolation and recovery (300s interval)
- **Ransomware Detection** - Detects ransomware activity and file encryption (15s interval)
- **Reflective DLL Detection** - Identifies reflective DLL injection techniques (30s interval)
- **Registry Persistence Detection** - Detects registry-based persistence mechanisms (60s interval)
- **Response Engine** - Centralized automated response coordinator (10s interval)
- **Rootkit Detection** - Identifies kernel-level and user-mode rootkit indicators (120s interval)
- **Scheduled Task Detection** - Identifies suspicious scheduled task creation (60s interval)
- **Service Monitoring** - Detects malicious service creation and modifications (60s interval)
- **Shadow Copy Monitoring** - Detects shadow copy manipulation and deletion (30s interval)
- **Token Manipulation Detection** - Identifies privilege escalation attempts (30s interval)
- **USB Monitoring** - Tracks unauthorized USB device connections (30s interval)
- **Webcam Guardian** - Prevents unauthorized webcam access and monitoring (20s interval)
- **WMI Persistence Detection** - Monitors WMI-based persistence mechanisms (60s interval)

### 🤖 **Automated Response System**

- **Quarantine Management** - Automatic file isolation and recovery
- **Process Termination** - Automated killing of malicious processes
- **Network Blocking** - Dynamic network access restriction
- **Alert Generation** - Real-time notifications and escalation
- **Comprehensive Logging** - Detailed audit trails and forensic data
- **Windows Event Log Integration** - All detections logged to Windows Event Log

### 🏗️ **Architecture**

- **Unified Script** - All 42 detection modules in a single PowerShell script
- **Tick-Based Execution** - Each module runs at its configured interval
- **Priority-Based Scheduling** - Modules execute based on priority levels
- **Centralized Response** - Unified response engine coordinates all actions
- **Event-Driven** - Real-time detection and response capabilities
- **Auto-Restart Capability** - Automatic recovery from failures
- **Mutex Protection** - Prevents multiple instances from running simultaneously
- **Process Watchdog** - Monitors and restarts the antivirus process if needed

## 🚀 Quick Start

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ (PowerShell 7+ recommended)
- **Administrative privileges** (required)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/antivirus.git
   cd antivirus
   ```

2. **Run the script with installation**
   ```powershell
   # Run as Administrator
   .\Antivirus.ps1 -AutoStart
   ```
   
   This will:
   - Install the antivirus to `C:\ProgramData\Antivirus\`
   - Create a scheduled task for automatic startup
   - Initialize logging and configuration systems
   - Start all detection modules

3. **Verify installation**
   ```powershell
   # Check if scheduled task was created
   Get-ScheduledTask -TaskName "Antivirus" -ErrorAction SilentlyContinue
   
   # Check if antivirus is running
   Get-Process powershell | Where-Object {$_.CommandLine -match "Antivirus.ps1"}
   
   # View logs
   Get-Content "C:\ProgramData\Antivirus\Logs\System_$(Get-Date -Format 'yyyy-MM-dd').log" -Tail 20
   ```

### Manual Execution

Run the script directly (requires Administrator privileges):

```powershell
.\Antivirus.ps1
```

### Uninstallation

To remove the antivirus system:

```powershell
.\Antivirus.ps1 -Uninstall
```

## 📁 Project Structure

```
antivirus/
├── Antivirus.ps1          # Main unified script with all 42 detection modules
└── README.md              # This file
```

**Installation Directory Structure:**
```
C:\ProgramData\Antivirus\
├── Antivirus.ps1          # Installed script
├── Logs\                  # All log files
│   ├── System_YYYY-MM-DD.log
│   ├── Threats_YYYY-MM-DD.log
│   ├── Responses_YYYY-MM-DD.log
│   └── stability_log.txt
├── Data\                  # Configuration and state files
│   ├── config.json
│   ├── agent_status.json
│   ├── antivirus.pid
│   └── [module baselines]
└── Quarantine\            # Quarantined files
    └── quarantine_log.txt
```

## ⚙️ Configuration

### Script Parameters

```powershell
.\Antivirus.ps1
    [-AllowedDomains <string[]>]    # Whitelist of allowed domains
    [-AutoStart]                     # Enable auto-start on boot
    [-Uninstall]                     # Remove installation
    [-MainLoopInterval <int>]        # Main loop check interval (default: 5 seconds)
    [-LogLevel <string>]             # Logging level: Debug, Info, Warning, Error
```

### Module Configuration

Each module has a configurable tick interval defined in the script. To modify intervals, edit the `$script:ModuleDefinitions` hashtable in `Antivirus.ps1`:

```powershell
$script:ModuleDefinitions = @{
    "AMSIBypassDetection" = @{ TickInterval = 30; Priority = 1; Function = "Invoke-AMSIBypassScan" }
    # Modify TickInterval to change how often the module runs
}
```

### Response Engine Configuration

The response engine automatically handles threats based on severity:

- **Critical**: Quarantine + Kill Process + Block Network + Log
- **High**: Quarantine + Log + Alert
- **Medium**: Log + Alert
- **Low**: Log only

## 📊 Monitoring and Logging

### Log Locations

- **System Logs**: `C:\ProgramData\Antivirus\Logs\System_YYYY-MM-DD.log`
- **Threat Logs**: `C:\ProgramData\Antivirus\Logs\Threats_YYYY-MM-DD.log`
- **Response Logs**: `C:\ProgramData\Antivirus\Logs\Responses_YYYY-MM-DD.log`
- **Stability Log**: `C:\ProgramData\Antivirus\Logs\stability_log.txt`

### Windows Event Log

All detections are logged to the Windows Application Event Log with source `AntivirusEDR`.

View events:
```powershell
Get-WinEvent -LogName Application -ProviderName AntivirusEDR | Select-Object -First 20
```

### Real-time Monitoring

Monitor agent activity in real-time:
```powershell
Get-Content "C:\ProgramData\Antivirus\Logs\System_$(Get-Date -Format 'yyyy-MM-dd').log" -Wait
```

### Module Statistics

Each module outputs statistics in the format:
```
STATS:ModuleName:Detections=<count>
```

Monitor module performance:
```powershell
Get-Content "C:\ProgramData\Antivirus\Logs\System_$(Get-Date -Format 'yyyy-MM-dd').log" | Select-String "STATS:"
```

## 🔧 Management

### Start/Stop

**Start:**
```powershell
# Via scheduled task
Start-ScheduledTask -TaskName "Antivirus"

# Or run directly
.\Antivirus.ps1 -AutoStart
```

**Stop:**
```powershell
# Stop via scheduled task
Stop-ScheduledTask -TaskName "Antivirus"

# Or stop PowerShell processes running the script
Get-Process powershell | Where-Object {$_.CommandLine -match "Antivirus"} | Stop-Process
```

**Check Status:**
```powershell
# Check if running
Get-Process powershell | Where-Object {$_.CommandLine -match "Antivirus"}

# Check scheduled task status
Get-ScheduledTask -TaskName "Antivirus" | Select-Object State, LastRunTime
```

### Quarantine Management

```powershell
# View quarantined files
Get-ChildItem "C:\ProgramData\Antivirus\Quarantine" -Recurse

# View quarantine log
Get-Content "C:\ProgramData\Antivirus\Quarantine\quarantine_log.txt"
```

Files are automatically quarantined when threats are detected. The quarantine system maintains metadata about each quarantined file.

## 🛠️ Customization

### Modifying Detection Modules

Each detection module is a function in the script. To modify a module:

1. Locate the function (e.g., `Invoke-AMSIBypassScan`)
2. Modify the detection logic
3. Ensure the function follows the standard pattern:
   - Returns detection count
   - Uses `Write-Detection` for logging threats
   - Uses `Write-EDRLog` for general logging

### Adding New Detection Modules

1. Create a new detection function following the pattern:
   ```powershell
   function Invoke-YourDetection {
       $detections = @()
       
       # Your detection logic here
       
       foreach ($detection in $detections) {
           Write-Detection -Module "YourModule" -Severity "High" -Message $detection
       }
       
       return $detections.Count
   }
   ```

2. Add the module to `$script:ModuleDefinitions`:
   ```powershell
   "YourModule" = @{ TickInterval = 30; Priority = 42; Function = "Invoke-YourDetection" }
   ```

3. The module will automatically be included in the tick-based execution system.

### Custom Response Actions

Modify the `Invoke-ResponseAction` function to add custom response behaviors or integrate with external systems (SIEM, ticketing systems, etc.).

## 🔍 Troubleshooting

### Common Issues

**Script won't run:**
- Verify you're running as Administrator: `([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`
- Check PowerShell execution policy: `Get-ExecutionPolicy`
- If restricted, run: `Set-ExecutionPolicy Bypass -Scope Process -Force`

**High resource usage:**
- Increase tick intervals in `$script:ModuleDefinitions`
- Disable unnecessary modules by commenting them out
- Monitor with Task Manager or `Get-Process powershell`

**False positives:**
- Review detection logic in specific modules
- Add exclusions to module functions
- Adjust sensitivity thresholds

**Module not running:**
- Check logs for errors: `Get-Content "C:\ProgramData\Antivirus\Logs\System_*.log" | Select-String "ERROR"`
- Verify module is in `$script:ModuleDefinitions`
- Check module function name matches

### Debug Mode

Enable verbose logging:
```powershell
.\Antivirus.ps1 -LogLevel Debug
```

View detailed module execution:
```powershell
Get-Content "C:\ProgramData\Antivirus\Logs\System_*.log" | Select-String "DEBUG"
```

### Stability Issues

Check the stability log:
```powershell
Get-Content "C:\ProgramData\Antivirus\Logs\stability_log.txt" -Tail 50
```

The script includes auto-restart capabilities and process watchdog functionality to maintain stability.

## 🔒 Security Considerations

- **Administrative Privileges**: Required for full functionality (process monitoring, registry access, etc.)
- **Execution Policy**: May need to adjust PowerShell execution policy
- **Network Monitoring**: May trigger alerts for legitimate network activity
- **Performance Impact**: 42 modules running simultaneously may impact system performance
- **False Positives**: Some legitimate activities may trigger detections

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-detection-module`
3. **Follow existing code style and patterns**
4. **Test thoroughly** in a non-production environment
5. **Submit a pull request** with detailed description

### Development Guidelines

- Use PowerShell best practices
- Include comprehensive error handling
- Follow the established logging format (`Write-EDRLog`, `Write-Detection`)
- Document new detection capabilities
- Test with various Windows versions
- Maintain module independence and tick-based execution pattern

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/your-username/antivirus/issues)
- **Discussions**: Join our [GitHub Discussions](https://github.com/your-username/antivirus/discussions)
- **Security**: For security vulnerabilities, please report responsibly

## 🙏 Acknowledgments

- PowerShell community for inspiration and techniques
- Security researchers for detection methodologies
- Enterprise security teams for feedback and testing
- Open source contributors who made this project possible

## 📈 Roadmap

- [ ] Web-based management dashboard
- [ ] SIEM integration (Splunk, ELK, Sentinel)
- [ ] Machine learning-based anomaly detection
- [ ] Cloud deployment support
- [ ] Advanced threat hunting capabilities
- [ ] API for third-party integrations
- [ ] Configuration file for easier customization
- [ ] Performance optimization for large-scale deployments

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. Use at your own risk.

**Author**: Gorstak  
**Version**: 1.0.0
