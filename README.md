# 🛡️ Enterprise EDR Antivirus

A comprehensive Enterprise Detection and Response (EDR) system built with PowerShell, featuring modular standalone agents for real-time threat detection and automated response capabilities.

## 🌟 Features

### 🔍 **Multi-Vector Threat Detection**
- **AMSI Bypass Detection** - Identifies PowerShell AMSI circumvention attempts
- **Process Anomaly Detection** - Detects suspicious process behavior and creation patterns
- **Memory Scanning** - Monitors process memory for malicious injections and unusual allocations
- **Network Threat Detection** - Identifies data exfiltration, DNS tunneling, and anomalous traffic
- **Registry Persistence Detection** - Detects registry-based persistence mechanisms
- **File System Monitoring** - Monitors for ransomware, file entropy, and suspicious modifications
- **Rootkit Detection** - Identifies kernel-level and user-mode rootkit indicators
- **USB Device Monitoring** - Tracks unauthorized USB device connections and activities
- **Webcam Protection** - Prevents unauthorized webcam access and monitoring
- **Service Monitoring** - Detects malicious service creation and modifications
- **Scheduled Task Analysis** - Identifies suspicious scheduled task creation
- **WMI Persistence Detection** - Monitors WMI-based persistence mechanisms
- **Token Manipulation Detection** - Identifies privilege escalation attempts
- **Shadow Copy Monitoring** - Detects shadow copy manipulation and deletion
- **DLL Injection Detection** - Identifies reflective DLL and code injection techniques
- **Browser Extension Monitoring** - Detects malicious browser extensions
- **Clipboard Monitoring** - Monitors for clipboard data theft
- **Credential Dump Detection** - Identifies credential harvesting attempts
- **LOLBin Detection** - Detects Living-Off-the-Land binary abuse
- **Firewall Rule Monitoring** - Tracks suspicious firewall modifications
- **Data Exfiltration Detection** - Comprehensive outbound data transfer monitoring
- **Event Log Monitoring** - Analyzes Windows Event Logs for threat indicators
- **Named Pipe Monitoring** - Detects malicious named pipe usage
- **COM Object Monitoring** - Identifies suspicious COM object usage
- **Process Hollowing Detection** - Detects process hollowing techniques
- **Lateral Movement Detection** - Identifies network lateral movement attempts
- **Hash Detection** - Monitors file hashes against threat intelligence
- **Honeypot Module** - Decoy resources to attract and detect attackers
- **Beacon Detection** - Identifies C2 communication beacons
- **Fileless Detection** - Detects fileless malware techniques
- **ELF Catcher** - Linux executable detection in Windows environments

### 🤖 **Automated Response System**
- **Quarantine Management** - Automatic file isolation and recovery
- **Process Termination** - Automated killing of malicious processes
- **Network Blocking** - Dynamic network access restriction
- **Alert Generation** - Real-time notifications and escalation
- **Comprehensive Logging** - Detailed audit trails and forensic data

### 🏗️ **Architecture**
- **Standalone Agents** - Each detection module operates independently
- **Centralized Response** - Unified response engine coordinates all actions
- **Event-Driven** - Real-time detection and response capabilities
- **Scalable Design** - Modular architecture allows easy expansion
- **Low Resource Impact** - Optimized for enterprise environments

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ (PowerShell 7+ recommended)
- Administrative privileges for installation

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/enterprise-edr-antivirus.git
   cd enterprise-edr-antivirus
   ```

2. **Run the setup script**
   ```cmd
   Setup.cmd
   ```
   *This will:*
   - Elevate privileges automatically
   - Install all detection agents to `C:\ProgramData\Antivirus\`
   - Create scheduled tasks for automatic startup
   - Initialize logging and configuration systems

3. **Verify installation**
   ```powershell
   # Check if scheduled task was created
   Get-ScheduledTask -TaskName "Antivirus"
   
   # Check agent status
   Get-Content "C:\ProgramData\Antivirus\Data\agent_status.json"
   ```

### Manual Deployment

For custom deployments, copy all files from the `Bin/` directory to your desired location and run:
```cmd
Antivirus.cmd
```

## 📁 Project Structure

```
enterprise-edr-antivirus/
├── Setup.cmd                    # Installation script
├── Bin/                         # All detection and response modules
│   ├── Antivirus.cmd           # Main agent launcher
│   ├── Antivirus.xml           # Scheduled task configuration
│   ├── Initializer.ps1         # Environment initialization agent
│   ├── ResponseEngine.ps1       # Centralized response coordinator
│   ├── QuarantineManagement.ps1 # File quarantine operations
│   ├── AMSIBypassDetection.ps1  # AMSI bypass detection
│   ├── ProcessAnomalyDetection.ps1 # Process behavior analysis
│   ├── MemoryScanning.ps1       # Memory threat detection
│   ├── NetworkAnomalyDetection.ps1 # Network threat analysis
│   ├── RegistryPersistenceDetection.ps1 # Registry monitoring
│   ├── RansomwareDetection.ps1  # Ransomware detection
│   ├── RootkitDetection.ps1     # Rootkit identification
│   ├── USBMonitoring.ps1        # USB device monitoring
│   ├── WebcamGuardian.ps1       # Webcam protection
│   ├── ServiceMonitoring.ps1    # Service analysis
│   ├── ScheduledTaskDetection.ps1 # Task monitoring
│   ├── WMIPersistenceDetection.ps1 # WMI persistence
│   ├── TokenManipulationDetection.ps1 # Privilege escalation
│   ├── ShadowCopyMonitoring.ps1 # Shadow copy analysis
│   ├── ReflectiveDLLInjectionDetection.ps1 # DLL injection
│   ├── BrowserExtensionMonitoring.ps1 # Browser security
│   ├── ClipboardMonitoring.ps1  # Clipboard protection
│   ├── CredentialDumpDetection.ps1 # Credential theft
│   ├── LOLBinDetection.ps1      # LOLBin abuse
│   ├── FirewallRuleMonitoring.ps1 # Firewall monitoring
│   ├── DataExfiltrationDetection.ps1 # Data theft detection
│   ├── EventLogMonitoring.ps1   # Event log analysis
│   ├── NamedPipeMonitoring.ps1  # Named pipe monitoring
│   ├── COMMonitoring.ps1        # COM object monitoring
│   ├── ProcessHollowingDetection.ps1 # Process hollowing
│   ├── LateralMovementDetection.ps1 # Lateral movement
│   ├── HashDetection.ps1        # Hash-based detection
│   ├── HoneypotModule.ps1       # Honeypot decoys
│   ├── BeaconDetection.ps1      # C2 beacon detection
│   ├── FilelessDetection.ps1    # Fileless malware
│   ├── ElfCatcher.ps1           # Linux executable detection
│   ├── ProcessCreationDetection.ps1 # Process creation
│   ├── PasswordManagement.ps1   # Password security
│   ├── NetworkTrafficMonitoring.ps1 # Traffic analysis
│   ├── FileEntropyDetection.ps1 # File analysis
│   └── KeyScramblerManagement.ps1 # Key protection
├── README.md                    # This file
└── LICENSE                      # License information
```

## ⚙️ Configuration

### Agent Configuration
Each agent can be configured independently by passing a hashtable configuration:

```powershell
# Example: Configure AMSI detection with custom interval
@{
    TickInterval = 15  # Check every 15 seconds instead of default 30
    Sensitivity = "High"
    LogLevel = "Verbose"
}
```

### Global Configuration
Main configuration is stored in `C:\ProgramData\Antivirus\Data\config.json`:

```json
{
    "Version": "1.0",
    "Settings": {
        "MaxLogSizeMB": 100,
        "QuarantineRetentionDays": 30,
        "EnableRealTimeResponse": true,
        "ResponseSeverity": "Medium"
    }
}
```

### Response Engine Configuration
Configure automated response actions by severity level:

- **Critical**: Quarantine + Kill Process + Block Network + Log
- **High**: Quarantine + Log + Alert
- **Medium**: Log + Alert
- **Low**: Log only

## 📊 Monitoring and Logging

### Log Locations
- **System Logs**: `C:\ProgramData\Antivirus\Logs\System_YYYY-MM-DD.log`
- **Threat Logs**: `C:\ProgramData\Antivirus\Logs\Threats_YYYY-MM-DD.log`
- **Response Logs**: `C:\ProgramData\Antivirus\Logs\Responses_YYYY-MM-DD.log`
- **Agent-Specific Logs**: `C:\ProgramData\Antivirus\Logs\[ModuleName]_YYYY-MM-DD.log`

### Windows Event Log
All detections are logged to the Windows Application Event Log with source `AntivirusEDR`.

### Real-time Monitoring
Monitor agent activity in real-time:
```powershell
Get-Content "C:\ProgramData\Antivirus\Logs\System_$(Get-Date -Format 'yyyy-MM-dd').log" -Wait
```

## 🔧 Management

### Start/Stop Agents
```powershell
# Start all agents
& "C:\ProgramData\Antivirus\Antivirus.cmd"

# Stop all agents
Get-Process powershell | Where-Object {$_.CommandLine -match "Antivirus"} | Stop-Process

# Check agent status
Get-Content "C:\ProgramData\Antivirus\Data\agent_status.json"
```

### Update Agents
To update individual agents, replace the `.ps1` files in `C:\ProgramData\Antivirus\` and restart the system or agents.

### Quarantine Management
```powershell
# View quarantined files
Get-ChildItem "C:\ProgramData\Antivirus\Quarantine"

# Restore quarantined file
& "C:\ProgramData\Antivirus\QuarantineManagement.ps1" -Action Restore -FilePath "quarantined_file.txt"

# View quarantine log
Get-Content "C:\ProgramData\Antivirus\Quarantine\quarantine_log.txt"
```

## 🛠️ Customization

### Adding New Detection Modules
1. Create a new `.ps1` file following the standard template:
```powershell
param([hashtable]$ModuleConfig)

$ModuleName = "YourModuleName"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-YourDetection {
    # Your detection logic here
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-YourDetection
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{ TickInterval = 30 }
}
```

2. Place the file in the `Bin/` directory
3. The agent will be automatically launched by `Antivirus.cmd`

### Custom Response Actions
Modify `ResponseEngine.ps1` to add custom response actions or integrate with external systems.

## 🔍 Troubleshooting

### Common Issues

**Agents not starting:**
- Verify PowerShell execution policy: `Set-ExecutionPolicy Bypass -Scope Process`
- Check if running as administrator
- Verify file permissions in `C:\ProgramData\Antivirus\`

**High resource usage:**
- Increase tick intervals in agent configurations
- Disable unnecessary detection modules
- Monitor system performance with Task Manager

**False positives:**
- Adjust sensitivity settings in individual agents
- Add exclusions to configuration files
- Review detection patterns and modify as needed

### Debug Mode
Enable verbose logging by modifying agent configurations:
```powershell
@{
    TickInterval = 30
    LogLevel = "Debug"
    VerboseLogging = $true
}
```

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-detection-module`
3. **Follow the existing code style and patterns**
4. **Test thoroughly** in a non-production environment
5. **Submit a pull request** with detailed description

### Development Guidelines
- Use PowerShell best practices
- Include comprehensive error handling
- Follow the established logging format
- Document new detection capabilities
- Test with various Windows versions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/your-org/enterprise-edr-antivirus/issues)
- **Discussions**: Join our [GitHub Discussions](https://github.com/your-org/enterprise-edr-antivirus/discussions)
- **Security**: For security vulnerabilities, email security@your-org.com

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
- [ ] Mobile device management integration
- [ ] Advanced threat hunting capabilities
- [ ] API for third-party integrations

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.
