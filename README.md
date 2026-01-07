# Enterprise EDR Antivirus System

A production-ready, enterprise-grade Endpoint Detection and Response (EDR) system with 42 specialized detection and monitoring modules.

## Features

- **Hot-Swap Module Support**: Modules can be updated without stopping the orchestrator
- **Managed Tick Jobs**: Low RAM usage through efficient timed execution
- **Module Health Monitoring**: Automatic detection and restart of failed modules
- **Automatic Response Engine**: Centralized threat response system that automatically quarantines, kills processes, blocks network connections, and alerts based on threat severity
- **Comprehensive Logging**: All detections logged to Event Log and file system
- **Enterprise-Ready**: Production-grade error handling and resource management

## Architecture

### Main Orchestrator (`Antivirus.ps1`)
- Manages all detection modules
- Handles module deployment to ProgramData
- Monitors module health and auto-restarts failed modules
- Performs hot-swap module updates
- Provides centralized logging and event reporting

### Response Engine (`ResponseEngine.ps1`)
- **Automatic Threat Response**: Processes all detections from all modules
- **Severity-Based Actions**:
  - **Critical**: Quarantine files, Kill processes, Block network connections, Log, Alert
  - **High**: Quarantine files, Log, Alert
  - **Medium**: Log, Alert
  - **Low**: Log only
- **Real-Time Processing**: Monitors detection logs and Event Log continuously
- **Action Tracking**: Logs all response actions for audit purposes

### Detection Modules (42 Total)

1. **HashDetection** - Malware hash-based detection
2. **LOLBinDetection** - Living-Off-The-Land binary detection
3. **ProcessAnomalyDetection** - Unusual process behavior detection
4. **AMSIBypassDetection** - Enhanced AMSI bypass attempt detection (includes obfuscated bypass detection)
5. **CredentialDumpDetection** - Credential dumping tool detection
6. **WMIPersistenceDetection** - WMI-based persistence detection
7. **ScheduledTaskDetection** - Malicious scheduled task detection
8. **RegistryPersistenceDetection** - Registry-based persistence detection
9. **DLLHijackingDetection** - DLL hijacking detection
10. **TokenManipulationDetection** - Token theft and impersonation detection
11. **ProcessHollowingDetection** - Process hollowing attack detection
12. **KeyloggerDetection** - Keylogger detection
13. **KeyScramblerManagement** - Keyboard encryption management
14. **RansomwareDetection** - Ransomware encryption pattern detection
15. **NetworkAnomalyDetection** - Unusual network activity detection
16. **NetworkTrafficMonitoring** - Comprehensive network traffic monitoring
17. **RootkitDetection** - Rootkit installation and activity detection
18. **ClipboardMonitoring** - Clipboard content monitoring for sensitive data
19. **COMMonitoring** - COM object instantiation monitoring
20. **BrowserExtensionMonitoring** - Browser extension security monitoring
21. **ShadowCopyMonitoring** - Shadow copy deletion monitoring (ransomware indicator)
22. **USBMonitoring** - USB device connection monitoring
23. **EventLogMonitoring** - Security event log monitoring
24. **FirewallRuleMonitoring** - Firewall rule change monitoring
25. **ServiceMonitoring** - Windows service monitoring
26. **FilelessDetection** - Fileless malware detection
27. **MemoryScanning** - Process memory scanning
28. **NamedPipeMonitoring** - Named pipe communication monitoring
29. **DNSExfiltrationDetection** - DNS-based data exfiltration detection
30. **PasswordManagement** - Password policy and storage monitoring
31. **WebcamGuardian** - Webcam access monitoring and protection
32. **ElfCatcher** - Browser DLL injection monitoring (detects suspicious DLLs like _elf.dll patterns)
33. **FileEntropyDetection** - Packed/encrypted file detection via entropy analysis
34. **QuarantineManagement** - File quarantine operations and tracking
35. **ProcessCreationDetection** - Process creation anomaly detection
36. **ReflectiveDLLInjectionDetection** - Reflective DLL injection and memory-only DLL detection
37. **ResponseEngine** - Centralized automatic threat response system
38. **BeaconDetection** - C2 beaconing and command & control communication detection
39. **CodeInjectionDetection** - Various code injection technique detection
40. **LateralMovementDetection** - Lateral movement techniques (SMB, RDP, WMI, PsExec)
41. **DataExfiltrationDetection** - Comprehensive data exfiltration detection
42. **HoneypotModule** - Decoy file creation and monitoring for threat detection

## Installation

1. Place all files in a directory (e.g., `C:\Antivirus`)
2. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. Run with elevated privileges (Administrator):
   ```powershell
   .\Antivirus.ps1
   ```

## Usage

### Basic Usage
```powershell
.\Antivirus.ps1
```

### Advanced Options
```powershell
# Custom tick interval (seconds)
.\Antivirus.ps1 -TickInterval 60

# Custom module path
.\Antivirus.ps1 -ModulesPath "C:\Custom\Modules"

# Custom ProgramData path
.\Antivirus.ps1 -ProgramDataPath "C:\Custom\ProgramData\Antivirus\Modules"

# Run as service
.\Antivirus.ps1 -RunAsService

# Enable detailed logging
.\Antivirus.ps1 -Configuration @{EnableDetailedLogging=$true}
```

## Module Hot-Swapping

1. Update any `.ps1` file in the `modules` directory
2. The orchestrator will automatically detect changes every 5 minutes
3. Running modules will be stopped and restarted with the new version
4. No system restart required

## Module Health Monitoring

- **Automatic Health Checks**: Every 60 seconds
- **Error Threshold**: Modules exceeding 3 errors are disabled
- **Auto-Restart**: Failed modules automatically restart below threshold
- **Timeout Protection**: Modules timing out (>300 seconds) are restarted

## Logging

### Event Log
- Source: `AntivirusEDR`
- Log: `Application`
- Event IDs: 2001-2041 (module-specific), 2100+ (ResponseEngine actions)
- Response Actions: Event ID 2100+ for automatic response actions

### File Logs
- Location: `%ProgramData%\Antivirus\Logs\`
- Format: `ModuleName_YYYY-MM-DD.log`
- Main Log: `Antivirus_YYYY-MM-DD.log`

## Module Structure

Each module follows a consistent structure:
- `Start-Module` function (entry point)
- `Invoke-ModuleScan` function (detection logic)
- Managed tick job with configurable intervals
- Standard output format: `STATS:`, `DETECTION:`, `ERROR:`
- Event Log integration

## Configuration

Module configuration is passed via `$ModuleConfig` hashtable:
- `TickInterval`: Execution interval in seconds
- `MaxConcurrentModules`: Maximum modules running simultaneously
- `ModuleTimeout`: Module execution timeout
- `ErrorThreshold`: Maximum errors before disable

## Requirements

- PowerShell 5.1 or higher
- Windows 10/11 or Windows Server 2016+
- Administrative privileges
- Execution policy allowing script execution

## Performance

- **Low RAM Usage**: Managed tick jobs prevent memory buildup
- **Efficient Scanning**: Configurable intervals prevent resource exhaustion
- **Concurrent Execution**: Multiple modules run simultaneously (up to 10 by default)
- **Non-Blocking**: Modules run in background jobs

## Security

- All detections are logged with timestamps
- **Automatic Response**: Critical/High threats are automatically quarantined, processes killed, and network connections blocked
- Event Log integration for SIEM compatibility
- Detailed file-based logging for forensic analysis
- Error handling prevents system crashes
- Module isolation prevents cross-module interference
- **Honeypot Files**: Decoy files detect unauthorized access attempts
- **Quarantine System**: Infected files are automatically moved to quarantine with hash tracking

## Response Actions

The ResponseEngine automatically takes actions based on threat severity:

| Severity | Actions |
|----------|---------|
| **Critical** | Quarantine file, Kill process, Block network, Log, Alert |
| **High** | Quarantine file, Log, Alert |
| **Medium** | Log, Alert |
| **Low** | Log only |

Response actions are logged to:
- Event Log (Event ID 2100+)
- `ResponseEngine_YYYY-MM-DD.log`
- Module-specific detection logs

## Troubleshooting

### Module Not Starting
- Check Event Log for errors
- Verify module syntax with: `powershell -File modules\ModuleName.ps1`
- Check ProgramData path permissions

### High CPU Usage
- Increase `TickInterval` for affected modules
- Reduce number of concurrent modules
- Check for infinite loops in module code

### No Detections
- Verify modules are running: Check orchestrator output
- Review module logs in `%ProgramData%\Antivirus\Logs\`
- Ensure modules have necessary permissions

### Response Engine Not Acting
- Check `ResponseEngine_YYYY-MM-DD.log` for processing status
- Verify threat severity levels are set correctly
- Check Event Log for ResponseEngine events (2100+)
- Ensure quarantine directory has write permissions

## License

Enterprise EDR Antivirus System - Production Ready

## Support

For issues or enhancements, review module logs and Event Log entries.
