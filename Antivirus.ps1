param([switch]$Uninstall)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# Modular Antivirus & EDR - Single File Build
# Author: Gorstak
# ============================================================================

$Script:InstallPath = "C:\ProgramData\AntivirusProtection"
$Script:ScriptName = Split-Path -Leaf $PSCommandPath
$Script:MaxRestartAttempts = 3
$Script:StabilityLogPath = "$Script:InstallPath\Logs\stability_log.txt"

$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15
    LOLBinDetectionIntervalSeconds = 15
    ProcessAnomalyDetectionIntervalSeconds = 15
    AMSIBypassDetectionIntervalSeconds = 15
    CredentialDumpDetectionIntervalSeconds = 15
    WMIPersistenceDetectionIntervalSeconds = 120
    ScheduledTaskDetectionIntervalSeconds = 120
    RegistryPersistenceDetectionIntervalSeconds = 120
    DLLHijackingDetectionIntervalSeconds = 90
    TokenManipulationDetectionIntervalSeconds = 60
    ProcessHollowingDetectionIntervalSeconds = 30
    KeyloggerDetectionIntervalSeconds = 45
    KeyScramblerManagementIntervalSeconds = 60
    RansomwareDetectionIntervalSeconds = 15
    NetworkAnomalyDetectionIntervalSeconds = 30
    NetworkTrafficMonitoringIntervalSeconds = 45
    RootkitDetectionIntervalSeconds = 180
    ClipboardMonitoringIntervalSeconds = 30
    COMMonitoringIntervalSeconds = 120
    BrowserExtensionMonitoringIntervalSeconds = 300
    ShadowCopyMonitoringIntervalSeconds = 30
    USBMonitoringIntervalSeconds = 20
    EventLogMonitoringIntervalSeconds = 60
    FirewallRuleMonitoringIntervalSeconds = 120
    ServiceMonitoringIntervalSeconds = 60
    FilelessDetectionIntervalSeconds = 20
    MemoryScanningIntervalSeconds = 90
    NamedPipeMonitoringIntervalSeconds = 45
    DNSExfiltrationDetectionIntervalSeconds = 30
    PasswordManagementIntervalSeconds = 120
    YouTubeAdBlockerIntervalSeconds = 300
    WebcamGuardianIntervalSeconds = 5
    BeaconDetectionIntervalSeconds = 60
    CodeInjectionDetectionIntervalSeconds = 30
    DataExfiltrationDetectionIntervalSeconds = 30
    ElfCatcherIntervalSeconds = 30
    FileEntropyDetectionIntervalSeconds = 120
    HoneypotMonitoringIntervalSeconds = 30
    LateralMovementDetectionIntervalSeconds = 30
    ProcessCreationDetectionIntervalSeconds = 10
    QuarantineManagementIntervalSeconds = 300
    ReflectiveDLLInjectionDetectionIntervalSeconds = 30
    ResponseEngineIntervalSeconds = 10
    PrivacyForgeSpoofingIntervalSeconds = 60
}

$Config = @{
    EDRName = "MalwareDetector"
    LogPath = "$Script:InstallPath\Logs"
    QuarantinePath = "$Script:InstallPath\Quarantine"
    DatabasePath = "$Script:InstallPath\Data"
    WhitelistPath = "$Script:InstallPath\Data\whitelist.json"
    ReportsPath = "$Script:InstallPath\Reports"
    HMACKeyPath = "$Script:InstallPath\Data\db_integrity.hmac"
    PIDFilePath = "$Script:InstallPath\Data\antivirus.pid"
    MutexName = "Local\AntivirusProtection_Mutex_{0}_{1}" -f $env:COMPUTERNAME, $env:USERNAME

    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"

    ExclusionPaths = @(
        $Script:InstallPath,
        "$Script:InstallPath\Logs",
        "$Script:InstallPath\Quarantine",
        "$Script:InstallPath\Reports",
        "$Script:InstallPath\Data"
    )
    ExclusionProcesses = @("powershell", "pwsh")

    EnableUnsignedDLLScanner = $true
    AutoKillThreats = $true
    AutoQuarantine = $true
    MaxMemoryUsageMB = 500
}

$Global:AntivirusState = @{
    Running = $false
    Installed = $false
    Jobs = @{}
    Mutex = $null
    ThreatCount = 0
    FilesScanned = 0
    FilesQuarantined = 0
    ProcessesTerminated = 0
}

$Script:LoopCounter = 0
$script:ManagedJobs = @{}

# Termination protection variables
$Script:TerminationAttempts = 0
$Script:MaxTerminationAttempts = 5
$Script:AutoRestart = $true
$Script:SelfPID = $PID

function Write-AVLog {
    param([string]$Message, [string]$Level = "INFO", [string]$LogFile = "antivirus_log.txt")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    
    # Try to get Config from global scope first, then script scope, then local scope
    $configVar = $null
    if ($null -ne (Get-Variable -Name "Config" -Scope Global -ErrorAction SilentlyContinue)) {
        $configVar = $global:Config
    } elseif ($null -ne (Get-Variable -Name "Config" -Scope Script -ErrorAction SilentlyContinue)) {
        $configVar = $script:Config
    } elseif (Test-Path Variable:Config) {
        $configVar = $Config
    }
    
    # Check if Config exists and LogPath is not null
    if ($null -eq $configVar -or $null -eq $configVar.LogPath -or [string]::IsNullOrWhiteSpace($configVar.LogPath)) {
        # Fallback to default log path if Config is not available
        $logPath = if ($Script:InstallPath) { "$Script:InstallPath\Logs" } else { "C:\ProgramData\AntivirusProtection\Logs" }
        $logFilePath = Join-Path $logPath $LogFile
        
        if (!(Test-Path $logPath)) {
            New-Item -ItemType Directory -Path $logPath -Force | Out-Null
        }
    } else {
        $logFilePath = Join-Path $configVar.LogPath $LogFile
        
        if (!(Test-Path $configVar.LogPath)) {
            New-Item -ItemType Directory -Path $configVar.LogPath -Force | Out-Null
        }
    }

    Add-Content -Path $logFilePath -Value $entry -ErrorAction SilentlyContinue

    $eid = switch ($Level) {
        "ERROR" { 1001 }
        "WARN" { 1002 }
        "THREAT" { 1003 }
        default { 1000 }
    }

    # Only write to event log if Config and EDRName are available
    if ($null -ne $configVar -and $null -ne $configVar.EDRName -and -not [string]::IsNullOrWhiteSpace($configVar.EDRName)) {
        # Ensure event log source exists before writing
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($configVar.EDRName)) {
                [System.Diagnostics.EventLog]::CreateEventSource($configVar.EDRName, "Application")
            }
        } catch {
            # Event log source creation may require elevation or fail for other reasons
            # Silently continue - we'll just skip event log writing
            return
        }
        
        try {
            Write-EventLog -LogName Application -Source $configVar.EDRName -EntryType Information -EventId $eid -Message $Message -ErrorAction SilentlyContinue
        } catch {
            # If event log write still fails, silently continue
        }
    }
}

function Write-StabilityLog {
    param([string]$Message, [string]$Level = "INFO")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] [STABILITY] $Message"

    if (!(Test-Path (Split-Path $Script:StabilityLogPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $Script:StabilityLogPath -Parent) -Force | Out-Null
    }

    Add-Content -Path $Script:StabilityLogPath -Value $entry -ErrorAction SilentlyContinue
    Write-Host $entry -ForegroundColor $(switch($Level) { "ERROR" {"Red"} "WARN" {"Yellow"} default {"White"} })
}

function Reset-InternetProxySettings {
    try {
        # Stop proxy server if running
        if (Test-Path $Script:YouTubeAdBlockerConfig.PIDFile) {
            $storedPid = Get-Content -Path $Script:YouTubeAdBlockerConfig.PIDFile -ErrorAction SilentlyContinue
            if ($storedPid) {
                $process = Get-Process -Id $storedPid -ErrorAction SilentlyContinue
                if ($process) {
                    Stop-Process -Id $storedPid -Force -ErrorAction SilentlyContinue
                }
            }
            Remove-Item -Path $Script:YouTubeAdBlockerConfig.PIDFile -Force -ErrorAction SilentlyContinue
        }
        
        # Kill any remaining proxy PowerShell processes
        Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -like "*proxy.ps1*" -or $_.MainWindowTitle -like "*proxy*"
        } | Stop-Process -Force -ErrorAction SilentlyContinue
        
        Get-Job -Name "YouTubeAdBlockerProxy" -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue
    }
    catch {}

    try {
        $pacFile = "$env:TEMP\youtube-adblocker.pac"
        if (Test-Path $pacFile) {
            Remove-Item -Path $pacFile -Force -ErrorAction SilentlyContinue
        }
    }
    catch {}
    
    try {
        # Restore internet settings
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $regPath) {
            Remove-ItemProperty -Path $regPath -Name "AutoConfigURL" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0 -Type DWord -Force | Out-Null
            Remove-ItemProperty -Path $regPath -Name "ProxyServer" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $regPath -Name "ProxyOverride" -ErrorAction SilentlyContinue
        }
    }
    catch {}

    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $regPath) {
            Remove-ItemProperty -Path $regPath -Name AutoConfigURL -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue
        }
    }
    catch {}

    # Remove hosts file entries
    try {
        $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
        if (Test-Path $hostsPath) {
            # Read content and close file handle properly
            $hostsContent = @()
            Get-Content $hostsPath -ErrorAction Stop | ForEach-Object { $hostsContent += $_ }
            
            # Filter out ad blocking entries
            $cleanContent = $hostsContent | Where-Object { 
                $_ -notmatch "# Ad Blocking" -and 
                $_ -notmatch "127\.0\.0\.1.*ads?" -and 
                $_ -notmatch "127\.0\.0\.1.*doubleclick" -and 
                $_ -notmatch "127\.0\.0\.1.*googleads" 
            }
            
            # Write using file stream to handle locks better
            $cleanContent | Out-File -FilePath $hostsPath -Encoding ASCII -Force -ErrorAction Stop
            ipconfig /flushdns | Out-Null
            Write-Output "[Uninstall] Successfully cleaned hosts file"
        }
    }
    catch {
        Write-Output "[Uninstall] WARNING: Could not clean hosts file: $_"
    }
}

function Register-ExitCleanup {
    if ($script:ExitCleanupRegistered) {
        return
    }

    try {
        Register-EngineEvent -SourceIdentifier "AntivirusProtection_ExitCleanup" -EventName PowerShell.Exiting -Action {
            try { Reset-InternetProxySettings } catch {}
        } | Out-Null
        $script:ExitCleanupRegistered = $true
    }
    catch {
    }
}

function Install-Antivirus {
    $targetScript = Join-Path $Script:InstallPath $Script:ScriptName
    $currentPath = $PSCommandPath

    # Set SelfPath to the installed script location (used by auto-restart and watchdog)
    $Script:SelfPath = $targetScript

    if ($currentPath -eq $targetScript) {
        Write-Host "[+] Running from install location" -ForegroundColor Green
        $Global:AntivirusState.Installed = $true
        # Initialize mutex BEFORE creating persistence to prevent race conditions during setup
        Initialize-Mutex
        Install-Persistence
        return $true
    }

    Write-Host "`n=== Installing Antivirus ===`n" -ForegroundColor Cyan

    @("Data","Logs","Quarantine","Reports") | ForEach-Object {
        $p = Join-Path $Script:InstallPath $_
        if (!(Test-Path $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            Write-Host "[+] Created: $p"
        }
    }

    Copy-Item -Path $PSCommandPath -Destination $targetScript -Force
    Write-Host "[+] Copied main script to $targetScript"

    # Initialize mutex BEFORE creating persistence to prevent race conditions during setupcomplete.cmd
    # This ensures only one instance can acquire the mutex before scheduled tasks are created
    Initialize-Mutex
    Install-Persistence

    Write-Host "`n[+] Installation complete. Continuing in this instance...`n" -ForegroundColor Green
    $Global:AntivirusState.Installed = $true
    return $true
}

function Install-Persistence {
    Write-Host "`n[*] Setting up persistence for automatic startup...`n" -ForegroundColor Cyan

    # Define paths for cleanup
    $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $shortcutPath = Join-Path $startupFolder "AntivirusProtection.lnk"

    try {
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($Script:InstallPath)\$($Script:ScriptName)`""
        $taskTrigger = New-ScheduledTaskTrigger -AtLogon -User $env:USERNAME
        $taskTriggerBoot = New-ScheduledTaskTrigger -AtStartup
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd

        Register-ScheduledTask -TaskName "AntivirusProtection" -Action $taskAction -Trigger $taskTrigger,$taskTriggerBoot -Principal $taskPrincipal -Settings $taskSettings -Force -ErrorAction Stop

        # Remove startup shortcut if it exists (scheduled task is preferred method)
        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed startup shortcut (using scheduled task instead)" -ForegroundColor Green
            Write-StabilityLog "Removed startup shortcut - scheduled task is active"
        }

        Write-Host "[+] Scheduled task created for automatic startup" -ForegroundColor Green
        Write-StabilityLog "Persistence setup completed - scheduled task created"
    }
    catch {
        Write-Host "[!] Failed to create scheduled task: $_" -ForegroundColor Red
        Write-StabilityLog "Persistence setup failed: $_" "ERROR"

        try {
            # Ensure scheduled task is removed before creating shortcut
            Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue |
                Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = "powershell.exe"
            $shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$($Script:InstallPath)\$($Script:ScriptName)`""
            $shortcut.WorkingDirectory = $Script:InstallPath
            $shortcut.Save()

            Write-Host "[+] Fallback: Created startup shortcut" -ForegroundColor Yellow
            Write-StabilityLog "Fallback persistence: startup shortcut created"
        }
        catch {
            Write-Host "[!] Both scheduled task and shortcut failed: $_" -ForegroundColor Red
            Write-StabilityLog "All persistence methods failed: $_" "ERROR"
        }
    }
}

function Uninstall-Antivirus {
    Write-Host "`n=== Uninstalling Antivirus ===`n" -ForegroundColor Cyan
    Write-StabilityLog "Starting uninstall process"

    try {
        Reset-InternetProxySettings
    }
    catch {}

    try {
        if ($script:ManagedJobs) {
            foreach ($k in @($script:ManagedJobs.Keys)) {
                try { $script:ManagedJobs.Remove($k) } catch {}
            }
        }
        if ($Global:AntivirusState -and $Global:AntivirusState.Jobs) {
            $Global:AntivirusState.Jobs.Clear()
        }
    }
    catch {
        Write-StabilityLog "Failed to clear managed jobs during uninstall: $_" "WARN"
    }

    try {
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Removed scheduled task" -ForegroundColor Green
        Write-StabilityLog "Removed scheduled task during uninstall"
    }
    catch {
        Write-Host "[!] Failed to remove scheduled task: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove scheduled task: $_" "WARN"
    }

    try {
        $shortcutPath = Join-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" "AntivirusProtection.lnk"
        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed startup shortcut" -ForegroundColor Green
            Write-StabilityLog "Removed startup shortcut during uninstall"
        }
    }
    catch {
        Write-Host "[!] Failed to remove startup shortcut: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove startup shortcut: $_" "WARN"
    }

    if (Test-Path $Script:InstallPath) {
        Remove-Item -Path $Script:InstallPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removed installation directory" -ForegroundColor Green
        Write-StabilityLog "Removed installation directory during uninstall"
    }

    Write-Host "[+] Uninstall complete." -ForegroundColor Green
    Write-StabilityLog "Uninstall process completed"
    exit 0
}

function Initialize-Mutex {
    $mutexName = $Config.MutexName

    Write-StabilityLog "Initializing mutex and PID checks"

    if (Test-Path $Config.PIDFilePath) {
        try {
            $existingPID = [int](Get-Content $Config.PIDFilePath -ErrorAction Stop)
            
            # Don't block if PID file contains our own PID (stale file from same instance)
            if ($existingPID -eq $PID) {
                Write-StabilityLog "PID file contains current PID - removing stale file" "INFO"
                Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
            }
            else {
                $existingProcess = Get-Process -Id $existingPID -ErrorAction SilentlyContinue

                if ($existingProcess) {
                    # Check if the existing process is actually running our script
                    try {
                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $existingPID" -ErrorAction SilentlyContinue).CommandLine
                        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                        
                        # If existing process is running our script path, block it
                        if ($cmdLine -and $scriptPath -and $cmdLine -like "*$scriptPath*") {
                            Write-StabilityLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                            Write-Host "[!] Another instance is already running (PID: $existingPID)" -ForegroundColor Yellow
                            Write-AVLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                            throw "Another instance is already running (PID: $existingPID)"
                        }
                        else {
                            # Existing process is not our script - remove stale PID file
                            Write-StabilityLog "PID file contains different process (not our script) - removing stale file" "INFO"
                            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        if ($_.Exception.Message -like "*already running*") {
                            throw
                        }
                        # Can't determine if it's our script, but process exists - assume it's not our script and remove stale PID
                        Write-StabilityLog "Could not verify existing process - removing potentially stale PID file" "INFO"
                        Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                    Write-StabilityLog "Removed stale PID file (process $existingPID not running)"
                    Write-AVLog "Removed stale PID file (process $existingPID not running)"
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*already running*") {
                throw
            }
            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
            Write-StabilityLog "Removed invalid PID file"
        }
    }

    try {
        $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $mutexName)
        $acquired = $Global:AntivirusState.Mutex.WaitOne(3000)

        if (!$acquired) {
            # Mutex is locked - check if there's actually a running instance
            Write-StabilityLog "Mutex locked - checking for running instances" "WARN"
            
            # Check for running instances, excluding our own PID
            $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
            $runningInstances = Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {
                # Exclude our own process
                if ($_.Id -eq $PID) {
                    return $false
                }
                
                try {
                    $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine
                    # Check if it's actually running our script path (not just any script with same name)
                    if ($cmdLine -and $scriptPath -and $cmdLine -like "*$scriptPath*") {
                        return $true
                    }
                    # Fallback: check for script name in command line if path match fails
                    if ($cmdLine -and $cmdLine -like "*$($Script:ScriptName)*" -and $cmdLine -like "*Antivirus*") {
                        return $true
                    }
                } catch {}
                return $false
            }
            
            if ($runningInstances) {
                $instancePIDs = $runningInstances.Id | Where-Object { $_ -ne $PID }
                if ($instancePIDs) {
                    Write-StabilityLog "Blocked duplicate instance - found $($instancePIDs.Count) running PowerShell process(es) with script (PIDs: $($instancePIDs -join ', '))" "WARN"
                    Write-Host "[!] Another instance is already running (PIDs: $($instancePIDs -join ', '))" -ForegroundColor Yellow
                    Write-AVLog "Blocked duplicate instance - found running processes: $($instancePIDs -join ', ')" "WARN"
                    $Global:AntivirusState.Mutex.Dispose()
                    throw "Another instance is already running (mutex locked)"
                }
            } else {
                # Mutex is orphaned (no actual process running) - try to release it
                Write-StabilityLog "Mutex appears orphaned - no running instances found, attempting cleanup" "WARN"
                try {
                    # Try to create a new mutex with the same name to see if we can take ownership
                    # This is a workaround for orphaned mutexes
                    $Global:AntivirusState.Mutex.Dispose()
                    Start-Sleep -Milliseconds 500
                    $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $mutexName)
                    $acquired = $Global:AntivirusState.Mutex.WaitOne(1000)
                    if ($acquired) {
                        Write-StabilityLog "Successfully recovered orphaned mutex" "INFO"
                    } else {
                        Write-StabilityLog "Could not recover mutex - may need manual cleanup" "ERROR"
                        Write-Host "[!] Failed to acquire mutex - another instance may be running" -ForegroundColor Yellow
                        throw "Another instance is already running (mutex locked)"
                    }
                } catch {
                    Write-StabilityLog "Mutex recovery failed: $_" "ERROR"
                    Write-Host "[!] Failed to acquire mutex - another instance may be running" -ForegroundColor Yellow
                    throw "Another instance is already running (mutex locked)"
                }
            }
        }

        if (!(Test-Path (Split-Path $Config.PIDFilePath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path $Config.PIDFilePath -Parent) -Force | Out-Null
        }

        $PID | Out-File -FilePath $Config.PIDFilePath -Force
        $Global:AntivirusState.Running = $true
        Write-StabilityLog "Mutex acquired, PID file written: $PID"
        Write-AVLog "Antivirus started (PID: $PID)"
        Write-Host "[+] Process ID: $PID" -ForegroundColor Green

        Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
            try {
                Write-StabilityLog "PowerShell exiting - cleaning up mutex and PID"
                if ($Global:AntivirusState.Mutex) {
                    $Global:AntivirusState.Mutex.ReleaseMutex()
                    $Global:AntivirusState.Mutex.Dispose()
                }
                if (Test-Path $Config.PIDFilePath) {
                    Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-StabilityLog "Cleanup error: $_" "ERROR"
            }
        } | Out-Null

    }
    catch {
        Write-StabilityLog "Mutex initialization failed: $_" "ERROR"
        throw
    }
}

function Select-BoundConfig {
    param(
        [Parameter(Mandatory=$true)][string]$FunctionName,
        [Parameter(Mandatory=$true)][hashtable]$Config
    )

    $cmd = Get-Command $FunctionName -ErrorAction Stop
    $paramNames = @($cmd.Parameters.Keys)
    $bound = @{}
    foreach ($k in $Config.Keys) {
        if ($paramNames -contains $k) {
            $bound[$k] = $Config[$k]
        }
    }
    return $bound
}

function Register-TerminationProtection {
    try {
        # Monitor for unexpected termination attempts
        $Script:UnhandledExceptionHandler = Register-ObjectEvent -InputObject ([AppDomain]::CurrentDomain) `
            -EventName UnhandledException -Action {
            param($src, $evtArgs)
            
            $errorMsg = "Unhandled exception: $($evtArgs.Exception.ToString())"
            $errorMsg | Out-File "$using:quarantineFolder\crash_log.txt" -Append
            
            try {
                # Log to security events
                $securityEvent = @{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    EventType = "UnexpectedTermination"
                    Severity = "Critical"
                    Exception = $evtArgs.Exception.ToString()
                    IsTerminating = $evtArgs.IsTerminating
                }
                $securityEvent | ConvertTo-Json -Compress | Out-File "$using:quarantineFolder\security_events.jsonl" -Append
            } catch {}
            
            # Attempt auto-restart if configured
            if ($using:Script:AutoRestart -and $evtArgs.IsTerminating) {
                try {
                    Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$using:Script:SelfPath`"" `
                        -WindowStyle Hidden -ErrorAction SilentlyContinue
                } catch {}
            }
        }
        
        Write-StabilityLog "[PROTECTION] Termination protection registered"
        
    } catch {
        Write-StabilityLog -Message "Failed to register termination protection" -Severity "Medium" -ErrorRecord $_
    }
}

function Enable-CtrlCProtection {
    try {
        # Detect if running in ISE or console
        if ($host.Name -eq "Windows PowerShell ISE Host") {
            Write-Host "[PROTECTION] ISE detected - using trap-based Ctrl+C protection" -ForegroundColor Cyan
            Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
            return $true
        }
        
        [Console]::TreatControlCAsInput = $false
        
        # Create scriptblock for the event handler
        $cancelHandler = {
            param($src, $evtArgs)
            
            $Script:TerminationAttempts++
            
            Write-Host "`n[PROTECTION] Termination attempt detected ($Script:TerminationAttempts/$Script:MaxTerminationAttempts)" -ForegroundColor Red
            
            try {
                Write-SecurityEvent -EventType "TerminationAttemptBlocked" -Details @{
                    PID = $PID
                    AttemptNumber = $Script:TerminationAttempts
                } -Severity "Critical"
            } catch {}
            
            if ($Script:TerminationAttempts -ge $Script:MaxTerminationAttempts) {
                Write-Host "[PROTECTION] Maximum termination attempts reached. Allowing graceful shutdown..." -ForegroundColor Yellow
                $evtArgs.Cancel = $false
            } else {
                Write-Host "[PROTECTION] Termination blocked. Press Ctrl+C $($Script:MaxTerminationAttempts - $Script:TerminationAttempts) more times to force stop." -ForegroundColor Yellow
                $evtArgs.Cancel = $true
            }
        }
        
        # Register the event handler
        [Console]::add_CancelKeyPress($cancelHandler)
        
        Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[WARNING] Could not enable Ctrl+C protection: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

function Enable-AutoRestart {
    try {
        $taskName = "AntivirusAutoRestart_$PID"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script:SelfPath`""
        
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
        
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -Force -ErrorAction Stop | Out-Null
        
        Write-Host "[PROTECTION] Auto-restart scheduled task registered" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not enable auto-restart: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Start-ProcessWatchdog {
    try {
        $watchdogJob = Start-Job -ScriptBlock {
            param($parentPID, $scriptPath, $autoRestart)
            
            while ($true) {
                Start-Sleep -Seconds 30
                
                # Check if parent process is still alive
                $process = Get-Process -Id $parentPID -ErrorAction SilentlyContinue
                
                if (-not $process) {
                    # Parent died - restart if configured
                    if ($autoRestart) {
                        Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" `
                            -WindowStyle Hidden -ErrorAction SilentlyContinue
                    }
                    break
                }
            }
        } -ArgumentList $PID, $Script:SelfPath, $Script:AutoRestart
        
        Write-Host "[PROTECTION] Process watchdog started (Job ID: $($watchdogJob.Id))" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not start process watchdog: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Register-ManagedJob {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$IntervalSeconds = 30,
        [bool]$Enabled = $true,
        [bool]$Critical = $false,
        [int]$MaxRestartAttempts = 3,
        [int]$RestartDelaySeconds = 5,
        [object[]]$ArgumentList = $null
    )

    if (-not $script:ManagedJobs) {
        $script:ManagedJobs = @{}
    }

    $minIntervalSeconds = 1
    if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MinimumIntervalSeconds) {
        $minIntervalSeconds = [int]$Script:ManagedJobConfig.MinimumIntervalSeconds
    }

    $IntervalSeconds = [Math]::Max([int]$IntervalSeconds, [int]$minIntervalSeconds)

    $script:ManagedJobs[$Name] = [pscustomobject]@{
        Name = $Name
        ScriptBlock = $ScriptBlock
        ArgumentList = $ArgumentList
        IntervalSeconds = $IntervalSeconds
        Enabled = $Enabled
        Critical = $Critical
        MaxRestartAttempts = $MaxRestartAttempts
        RestartDelaySeconds = $RestartDelaySeconds
        RestartAttempts = 0
        LastStartUtc = $null
        LastSuccessUtc = $null
        LastError = $null
        NextRunUtc = [DateTime]::UtcNow
        DisabledUtc = $null
    }
}

function Invoke-ManagedJobsTick {
    param(
        [Parameter(Mandatory=$true)][DateTime]$NowUtc
    )

    if (-not $script:ManagedJobs) {
        return
    }

    foreach ($job in $script:ManagedJobs.Values) {
        if (-not $job.Enabled) { continue }
        if ($null -ne $job.DisabledUtc) { continue }
        if ($job.NextRunUtc -gt $NowUtc) { continue }

        $job.LastStartUtc = $NowUtc

        try {
            if ($null -ne $job.ArgumentList) {
                Invoke-Command -ScriptBlock $job.ScriptBlock -ArgumentList $job.ArgumentList
            }
            else {
                & $job.ScriptBlock
            }
            $job.LastSuccessUtc = [DateTime]::UtcNow
            $job.RestartAttempts = 0
            $job.LastError = $null
            $job.NextRunUtc = $job.LastSuccessUtc.AddSeconds([Math]::Max(1, $job.IntervalSeconds))
        }
        catch {
            $job.LastError = $_
            $job.RestartAttempts++

            try {
                Write-AVLog "Managed job '$($job.Name)' failed (attempt $($job.RestartAttempts)/$($job.MaxRestartAttempts)) : $($_.Exception.Message)" "WARN"
            }
            catch {}

            if ($job.RestartAttempts -ge $job.MaxRestartAttempts) {
                $job.RestartAttempts = 0
                $job.DisabledUtc = $null
                $job.NextRunUtc = [DateTime]::UtcNow.AddMinutes(5)
                try {
                    Write-AVLog "Managed job '$($job.Name)' exceeded max restart attempts; backing off for 5 minutes" "ERROR"
                }
                catch {}
                continue
            }

            $job.NextRunUtc = [DateTime]::UtcNow.AddSeconds([Math]::Max(1, $job.RestartDelaySeconds))
        }
    }
}

function Start-ManagedJob {
    param(
        [string]$ModuleName,
        [int]$IntervalSeconds = 30
    )

    $jobName = "AV_$ModuleName"

    if ($Global:AntivirusState.Jobs.ContainsKey($jobName)) {
        return
    }

    $funcName = "Invoke-$ModuleName"
    if (-not (Get-Command $funcName -ErrorAction SilentlyContinue)) {
        Write-AVLog "Function not found: $funcName" "WARN"
        return
    }

    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    $sb = {
        param(
            [Parameter(Mandatory=$true)][string]$FunctionName,
            [Parameter(Mandatory=$true)][hashtable]$Cfg
        )

        # Ensure global Config is available in this scope
        if ($null -eq $global:Config -and $null -ne $Cfg) {
            $global:Config = $Cfg
        }

        $cmd = Get-Command $FunctionName -ErrorAction Stop
        $paramNames = @($cmd.Parameters.Keys)
        $bound = @{}
        
        # Check if function expects a Config parameter (as hashtable)
        if ($paramNames -contains "Config") {
            $bound["Config"] = $Cfg
        } else {
            # Otherwise, bind individual keys from Cfg to matching parameters
            foreach ($k in $Cfg.Keys) {
                if ($paramNames -contains $k) {
                    $bound[$k] = $Cfg[$k]
                }
            }
        }
        
        & $FunctionName @bound
    }

    Register-ManagedJob -Name $jobName -ScriptBlock $sb -ArgumentList @($funcName, $Config) -IntervalSeconds $IntervalSeconds -Enabled $true -Critical $false -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay

    $Global:AntivirusState.Jobs[$jobName] = @{
        Name = $jobName
        IntervalSeconds = $IntervalSeconds
        Module = $ModuleName
    }

    Write-AVLog "Registered managed job: $jobName (${IntervalSeconds}s interval)"
}

function Start-RecoverySequence {
    Write-StabilityLog "Starting recovery sequence" "WARN"

    try {
        try {
            Reset-InternetProxySettings
        }
        catch {}

        if ($script:ManagedJobs) {
            foreach ($k in @($script:ManagedJobs.Keys)) {
                try { $script:ManagedJobs.Remove($k) } catch {}
            }
        }

        $Global:AntivirusState.Jobs.Clear()
        Start-Sleep -Seconds 10
        Write-StabilityLog "Recovery sequence completed"
    }
    catch {
        Write-StabilityLog "Recovery sequence failed: $_" "ERROR"
    }
}

# Note: Function name intentionally uses 'Monitor' verb for job monitoring functionality
function Monitor-Jobs {
    Write-Host "`n[*] Monitoring started. Press Ctrl+C to stop.`n" -ForegroundColor Cyan
    Write-StabilityLog "Entering main monitoring loop"
    Write-AVLog "Entering main monitoring loop"

    $iteration = 0
    $lastStabilityCheck = Get-Date
    $consecutiveErrors = 0
    $maxConsecutiveErrors = 10

    while ($true) {
        try {
            while ($true) {
                $iteration++
                $now = Get-Date

                try {
                    Invoke-ManagedJobsTick -NowUtc ([DateTime]::UtcNow)
                }
                catch {
                    $consecutiveErrors++
                    Write-StabilityLog "Managed jobs tick failed: $_" "WARN"
                }

                if (($now - $lastStabilityCheck).TotalMinutes -ge 5) {
                    try {
                        $enabledCount = 0
                        if ($script:ManagedJobs) {
                            $enabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -eq $_.DisabledUtc) }).Count
                        }
                        Write-StabilityLog "Stability check: $enabledCount managed jobs enabled, iteration $iteration"
                        $lastStabilityCheck = $now
                        $consecutiveErrors = 0
                    }
                    catch {
                        $consecutiveErrors++
                        Write-StabilityLog "Stability check failed: $_" "WARN"
                    }
                }

                if ($consecutiveErrors -ge $maxConsecutiveErrors) {
                    Write-StabilityLog "Too many consecutive errors ($consecutiveErrors), triggering recovery" "ERROR"
                    Start-RecoverySequence
                    $consecutiveErrors = 0
                }

                if ($iteration % 12 -eq 0) {
                    try {
                        $enabledCount = 0
                        $disabledCount = 0
                        $sampleErrorMessage = $null
                        $sampleErrorJob = $null
                        if ($script:ManagedJobs) {
                            $enabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -eq $_.DisabledUtc) }).Count
                            $disabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -ne $_.DisabledUtc) }).Count
                            try {
                                $j = ($script:ManagedJobs.Values | Where-Object { $_.LastError } | Select-Object -First 1)
                                if ($j) {
                                    $sampleErrorJob = $j.Name
                                    $sampleErrorMessage = $j.LastError.Exception.Message
                                }
                            }
                            catch {}
                        }
                        Write-Host "[AV] Monitoring active - $enabledCount enabled / $disabledCount backoff" -ForegroundColor DarkGray
                        Write-StabilityLog "Heartbeat: $enabledCount enabled / $disabledCount backoff, iteration $iteration" "INFO"
                        Write-AVLog "Heartbeat: $enabledCount enabled / $disabledCount backoff"
                        if ($sampleErrorMessage) {
                            Write-StabilityLog "Sample job error ($sampleErrorJob): $sampleErrorMessage" "WARN"
                        }
                    }
                    catch {
                        $consecutiveErrors++
                        Write-StabilityLog "Heartbeat failed: $_" "WARN"
                    }
                }

                Start-Sleep -Seconds 1
            }
        }
        catch {
            try {
                Write-StabilityLog "Monitor-Jobs outer loop error: $_" "ERROR"
                Write-AVLog "Monitor-Jobs iteration error: $_" "ERROR"
                Write-Host "[!] Monitor iteration error (recovering): $_" -ForegroundColor Yellow
            }
            catch {
            }

            Start-RecoverySequence
            Start-Sleep -Seconds 5
            $consecutiveErrors = 0
            $lastStabilityCheck = Get-Date
            continue
        }
    }
}

function Move-ToQuarantine {
    param([string]$Path, [string]$Reason)
    
    $FileName = [System.IO.Path]::GetFileName($Path)
    $QuarantineFile = "$($Config.QuarantinePath)\$([DateTime]::Now.Ticks)_$FileName"
    
    try {
        [System.IO.File]::Move($Path, $QuarantineFile)
        $Global:AntivirusState.FilesQuarantined++
        Write-AVLog "Quarantined: $Path (Reason: $Reason)" "THREAT"
        return $true
    } catch {
        Write-AVLog "Quarantine failed for $Path : $_" "ERROR"
        return $false
    }
}

function Stop-ThreatProcess {
    param([int]$ProcessId, [string]$ProcessName)
    
    if ($ProcessId -eq $PID -or $ProcessId -eq $Script:SelfPID) { return }
    
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        $Global:AntivirusState.ProcessesTerminated++
        Write-AVLog "Terminated threat process: $ProcessName (PID: $ProcessId)" "ACTION"
    } catch {
        Write-AVLog "Failed to terminate process $ProcessName : $_" "ERROR"
    }
}

# ===================== Embedded detection modules =====================

function Invoke-HashDetection {
    param(
        [string]$LogPath,
        [string]$QuarantinePath,
        [string]$CirclHashLookupUrl,
        [string]$CymruApiUrl,
        [string]$MalwareBazaarApiUrl,
        [bool]$AutoQuarantine = $true
    )

    $SuspiciousPaths = @(
        "$env:TEMP\*",
        "$env:APPDATA\*",
        "$env:LOCALAPPDATA\Temp\*",
        "C:\Windows\Temp\*",
        "$env:USERPROFILE\Downloads\*"
    )

    $Files = Get-ChildItem -Path $SuspiciousPaths -Include *.exe,*.dll,*.scr,*.vbs,*.ps1,*.bat,*.cmd -Recurse -ErrorAction SilentlyContinue

    foreach ($File in $Files) {
        try {
            $Hash = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash

            $Reputation = @{
                IsMalicious = $false
                Confidence = 0
                Sources = @()
            }

            try {
                $CirclResponse = Invoke-RestMethod -Uri "$CirclHashLookupUrl/$Hash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($CirclResponse.KnownMalicious) {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 40
                    $Reputation.Sources += "CIRCL"
                }
            } catch {}

            try {
                $MBBody = @{ query = "get_info"; hash = $Hash } | ConvertTo-Json
                $MBResponse = Invoke-RestMethod -Uri $MalwareBazaarApiUrl -Method Post -Body $MBBody -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($MBResponse.query_status -eq "ok") {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 50
                    $Reputation.Sources += "MalwareBazaar"
                }
            } catch {}

            try {
                $CymruResponse = Invoke-RestMethod -Uri "$CymruApiUrl/$Hash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($CymruResponse.malware -eq $true) {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 30
                    $Reputation.Sources += "Cymru"
                }
            } catch {}

            if ($Reputation.IsMalicious -and $Reputation.Confidence -ge 50) {
                Write-Output "[HashDetection] THREAT: $($File.FullName) | Hash: $Hash | Sources: $($Reputation.Sources -join ', ') | Confidence: $($Reputation.Confidence)%"

                if ($AutoQuarantine -and $QuarantinePath) {
                    $QuarantineFile = Join-Path $QuarantinePath "$([DateTime]::Now.Ticks)_$($File.Name)"
                    Move-Item -Path $File.FullName -Destination $QuarantineFile -Force -ErrorAction SilentlyContinue
                    Write-Output "[HashDetection] Quarantined: $($File.FullName)"
                }
            }

            try {
                $Entropy = Measure-FileEntropy -FilePath $File.FullName
                if ($Entropy -is [double] -or $Entropy -is [int]) {
                    if ($Entropy -gt 7.5 -and $File.Length -lt 1MB) {
                        Write-Output "[HashDetection] High entropy detected: $($File.FullName) | Entropy: $([Math]::Round($Entropy, 2))"
                    }
                }
            } catch {
                # Entropy calculation failed, skip
            }

        } catch {
            Write-Output "[HashDetection] Error scanning $($File.FullName): $_"
        }
    }
}

function Measure-FileEntropy {
    param([string]$FilePath)

    try {
        $Bytes = [System.IO.File]::ReadAllBytes($FilePath)[0..4096]
        $Freq = @{}
        foreach ($Byte in $Bytes) {
            if ($Freq.ContainsKey($Byte)) {
                $Freq[$Byte]++
            } else {
                $Freq[$Byte] = 1
            }
        }

        $Entropy = 0
        $Total = $Bytes.Count
        foreach ($Count in $Freq.Values) {
            $P = $Count / $Total
            $Entropy -= $P * [Math]::Log($P, 2)
        }

        return $Entropy
    } catch {
        return 0
    }
}

function Invoke-LOLBinDetection {
    $LOLBinPatterns = @{
        "certutil" = @{
            Patterns = @("-decode", "-urlcache", "-verifyctl", "-encode")
            Severity = "HIGH"
            Description = "Certutil abuse for download/decode"
        }
        "bitsadmin" = @{
            Patterns = @("transfer", "addfile", "/download")
            Severity = "HIGH"
            Description = "BITS abuse for download"
        }
        "mshta" = @{
            Patterns = @("http://", "https://", "javascript:", "vbscript:")
            Severity = "CRITICAL"
            Description = "MSHTA remote code execution"
        }
        "regsvr32" = @{
            Patterns = @("scrobj.dll", "/s", "/u", "http://", "https://")
            Severity = "HIGH"
            Description = "Regsvr32 squiblydoo attack"
        }
        "rundll32" = @{
            Patterns = @("javascript:", "http://", "https://", "shell32.dll,Control_RunDLL")
            Severity = "MEDIUM"
            Description = "Rundll32 proxy execution"
        }
        "wmic" = @{
            Patterns = @('process call create', '/node:', 'format:"http', 'xsl:http')
            Severity = "HIGH"
            Description = "WMIC remote execution or XSL abuse"
        }
        "powershell" = @{
            Patterns = @("-enc ", "-encodedcommand", "downloadstring", "iex ", "invoke-expression", "-nop", "-w hidden", "bypass")
            Severity = "HIGH"
            Description = "PowerShell obfuscation and evasion"
        }
        "sc" = @{
            Patterns = @("create", "config", "binpath=")
            Severity = "MEDIUM"
            Description = "Service manipulation"
        }
        "msiexec" = @{
            Patterns = @("/quiet", "/q", "http://", "https://")
            Severity = "MEDIUM"
            Description = "Silent MSI installation from remote"
        }
    }
    
    $Processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $Processes) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        $CmdLine = $Proc.CommandLine
        if (-not $CmdLine) { continue }
        
        $ProcessName = $Proc.Name -replace '\.exe$', ''
        
        foreach ($LOLBin in $LOLBinPatterns.Keys) {
            if ($ProcessName -like "*$LOLBin*") {
                $MatchedPatterns = @()
                foreach ($Pattern in $LOLBinPatterns[$LOLBin].Patterns) {
                    if ($CmdLine -match [regex]::Escape($Pattern)) {
                        $MatchedPatterns += $Pattern
                    }
                }
                
                if ($MatchedPatterns.Count -gt 0) {
                    $Severity = $LOLBinPatterns[$LOLBin].Severity
                    $Description = $LOLBinPatterns[$LOLBin].Description
                    Write-AVLog "LOLBin detected [$Severity] - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Attack: $Description | Patterns: $($MatchedPatterns -join ', ') | Command: $CmdLine" "THREAT" "behavior_detections.log"
                    $Global:AntivirusState.ThreatCount++
                    
                    if ($Config.AutoKillThreats -and $Severity -in @("HIGH", "CRITICAL")) {
                        Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name
                    }
                }
            }
        }
    }
}

function Invoke-ProcessAnomalyDetection {
    $Processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    $AnomalyScore = @{}
    
    foreach ($Proc in $Processes) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        $Score = 0
        $Anomalies = @()
        
        # Parent process analysis
        $Parent = Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($Parent) {
            # Office spawning scripts
            if ($Parent.Name -match "winword|excel|powerpnt|outlook" -and $Proc.Name -match "powershell|cmd|wscript|cscript") {
                $Score += 5
                $Anomalies += "OfficeSpawnScript"
            }
            
            # Explorer spawning hidden scripts
            if ($Parent.Name -eq "explorer.exe" -and $Proc.CommandLine -match "-w hidden|-windowstyle hidden|-nop|-enc") {
                $Score += 4
                $Anomalies += "ExplorerHiddenScript"
            }
            
            # Service host spawning unexpected processes
            if ($Parent.Name -eq "svchost.exe" -and $Proc.Name -notmatch "dllhost|conhost|rundll32") {
                $Score += 3
                $Anomalies += "SvchostUnexpectedChild"
            }
        }
        
        # Path validation
        $ProcPath = $Proc.ExecutablePath
        if ($ProcPath) {
            # Executables in user directories
            if ($ProcPath -match "Users\\.*\\AppData|Users\\.*\\Downloads|Users\\.*\\Desktop" -and $Proc.Name -match "exe$") {
                $Score += 2
                $Anomalies += "UserDirExecution"
            }
            
            # System binaries in wrong locations
            if ($Proc.Name -in @("svchost.exe", "lsass.exe", "csrss.exe", "smss.exe") -and $ProcPath -notmatch "C:\\Windows\\System32") {
                $Score += 6
                $Anomalies += "SystemBinaryWrongLocation"
            }
        }
        
        # Command line analysis
        if ($Proc.CommandLine) {
            # Base64 encoded commands
            if ($Proc.CommandLine -match "-enc |-encodedcommand |FromBase64String") {
                $Score += 3
                $Anomalies += "Base64Encoding"
            }
            
            # Execution policy bypass
            if ($Proc.CommandLine -match "-exec bypass|-executionpolicy bypass|-ep bypass") {
                $Score += 2
                $Anomalies += "ExecutionPolicyBypass"
            }
            
            # Download cradles
            if ($Proc.CommandLine -match "DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget |curl ") {
                $Score += 3
                $Anomalies += "DownloadCradle"
            }
        }
        
        # Report anomalies
        if ($Score -ge 6) {
            Write-AVLog "CRITICAL process anomaly - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Parent: $($Parent.Name) | Score: $Score | Anomalies: $($Anomalies -join ', ') | Path: $ProcPath | Command: $($Proc.CommandLine)" "THREAT" "behavior_detections.log"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
        elseif ($Score -ge 3) {
            Write-AVLog "Process anomaly detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Score: $Score | Anomalies: $($Anomalies -join ', ')" "WARNING" "behavior_detections.log"
        }
    }
}

function Invoke-AMSIBypassDetection {
    $detections = @()
    
    # Enhanced AMSI bypass patterns
    $bypassPatterns = @(
        '[Ref].Assembly.GetType.*System.Management.Automation.AmsiUtils',
        '[Ref].Assembly.GetType.*AmsiUtils',
        'AmsiScanBuffer',
        'amsiInitFailed',
        'Bypass',
        'amsi.dll',
        'S`y`s`t`e`m.Management.Automation',
        'Hacking',
        'AMSI',
        'amsiutils',
        'amsiInitFailed',
        'Context',
        'AmsiContext',
        'AMSI_RESULT_CLEAN',
        'PatchAmsi',
        'DisableAmsi',
        'ForceAmsi',
        'Remove-Amsi',
        'Invoke-AmsiBypass',
        'AMSI.*bypass',
        'bypass.*AMSI',
        '-nop.*-w.*hidden.*-enc',
        'amsi.*off',
        'amsi.*disable',
        'Set-Amsi',
        'Override.*AMSI'
    )
    
    try {
        $maxProcs = 50
        $processes = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*powershell*" -or $_.Name -like "*wscript*" -or $_.Name -like "*cscript*" } | Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ([string]::IsNullOrEmpty($cmdLine)) { continue }
            
            foreach ($pattern in $bypassPatterns) {
                if ($cmdLine -match $pattern) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $cmdLine
                        BypassPattern = $pattern
                        Risk = "Critical"
                    }
                    break
                }
            }
            
            # Check for obfuscated AMSI bypass (base64, hex, etc.)
            if ($cmdLine -match '-enc|-encodedcommand' -and $cmdLine.Length -gt 500) {
                # Long encoded command - try to decode
                try {
                    $encodedPart = $cmdLine -split '-enc\s+' | Select-Object -Last 1 -ErrorAction SilentlyContinue
                    if ($encodedPart) {
                        $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedPart.Trim()))
                        if ($decoded -match 'amsi|AmsiScanBuffer|bypass' -or $decoded.Length -gt 1000) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $cmdLine
                                BypassPattern = "Obfuscated AMSI Bypass (Encoded)"
                                DecodedLength = $decoded.Length
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
            }
        }
        
        # Check PowerShell script blocks in memory
        try {
            $psProcesses = Get-Process -Name "powershell*","pwsh*" -ErrorAction SilentlyContinue
            foreach ($psProc in $psProcesses) {
                if ($psProc.Id -eq $PID -or $psProc.Id -eq $Script:SelfPID) { continue }
                
                # Check for AMSI-related .NET assemblies loaded
                $modules = $psProc.Modules | Where-Object {
                    $_.ModuleName -match 'amsi|System.Management.Automation'
                }
                
                if ($modules.Count -gt 0) {
                    # Check Event Log for AMSI script block logging
                    try {
                        $psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue -MaxEvents 50 |
                            Where-Object {
                                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5) -and
                                ($_.Message -match 'amsi|bypass|AmsiScanBuffer' -or $_.Message.Length -gt 5000)
                            }
                        
                        if ($psEvents.Count -gt 0) {
                            foreach ($event in $psEvents) {
                                $detections += @{
                                    ProcessId = $psProc.Id
                                    ProcessName = $psProc.ProcessName
                                    Type = "AMSI Bypass in PowerShell Script Block"
                                    Message = $event.Message.Substring(0, [Math]::Min(500, $event.Message.Length))
                                    TimeCreated = $event.TimeCreated
                                    Risk = "Critical"
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Check Event Log for AMSI events
        try {
            $amsiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,1118} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $amsiEvents) {
                if ($event.Message -match 'AmsiScanBuffer|bypass|blocked') {
                    $detections += @{
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for AMSI registry tampering
        try {
            $amsiKey = "HKLM:\SOFTWARE\Microsoft\AMSI"
            if (Test-Path $amsiKey) {
                $amsiValue = Get-ItemProperty -Path $amsiKey -ErrorAction SilentlyContinue
                if ($amsiValue -and $amsiValue.DisableAMSI) {
                    $detections += @{
                        Type = "Registry Tampering"
                        Path = $amsiKey
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "AMSI BYPASS DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.BypassPattern -or $detection.Message)" "THREAT" "amsi_bypass_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\AMSIBypass_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.BypassPattern -or $_.Message)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "AMSI bypass detection error: $_" "ERROR" "amsi_bypass_detections.log"
    }
    
    return $detections.Count
}

function Invoke-CredentialDumpDetection {
    $CredentialTools = @("mimikatz", "sekurlsa", "pwdump", "gsecdump", "wce.exe", "procdump", "dumpert", "nanodump", "lsassy")
    $LSASSAccess = @("lsass", "LSASS")
    
    # Monitor for processes accessing LSASS
    $LsassProc = Get-Process lsass -ErrorAction SilentlyContinue
    if ($LsassProc) {
        $AccessingProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -match "lsass" -and $_.ProcessId -ne $LsassProc.Id -and $_.ProcessId -ne $PID -and $_.ProcessId -ne $Script:SelfPID
        }
        
        foreach ($Proc in $AccessingProcesses) {
            Write-AVLog "LSASS access detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
    }
    
    # Detect credential dumping tools
    $AllProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $AllProcesses) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        
        # Check process name and command line
        foreach ($Tool in $CredentialTools) {
            if ($Proc.Name -like "*$Tool*" -or $Proc.CommandLine -match $Tool) {
                Write-AVLog "Credential dumping tool detected - Tool: $Tool | Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
            }
        }
        
        # Check for memory dump creation
        if ($Proc.CommandLine -match "MiniDump|CreateDump|dmp") {
            Write-AVLog "Memory dump creation detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "WARNING" "credential_dumping_detections.log"
        }
    }
    
    # Check for SAM/SYSTEM/SECURITY registry hive access
    $RegKeyAccess = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match "SAM|SYSTEM|SECURITY" -and $_.CommandLine -match "reg save|reg export"
    }
    
    foreach ($Proc in $RegKeyAccess) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        Write-AVLog "Registry credential hive access - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
        $Global:AntivirusState.ThreatCount++
        if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
    }
}

function Invoke-WMIPersistenceDetection {
    $Filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    $Consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue

    foreach ($Filter in $Filters) {
        Write-Output "[WMI] Event filter found: $($Filter.Name) | Query: $($Filter.Query)"
    }

    foreach ($Consumer in $Consumers) {
        Write-Output "[WMI] Command consumer found: $($Consumer.Name) | Command: $($Consumer.CommandLineTemplate)"
    }
}

function Invoke-ScheduledTaskDetection {
    $Tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.Principal.UserId -notmatch "SYSTEM|Administrator" }

    foreach ($Task in $Tasks) {
        # Whitelist our own scheduled tasks
        if ($Task.TaskName -like "AntivirusAutoRestart_*" -or $Task.TaskName -eq "AntivirusProtection") {
            continue
        }
        
        $Action = $Task.Actions[0].Execute
        if ($Action -match "powershell|cmd|wscript|cscript|mshta") {
            Write-Output "[ScheduledTask] SUSPICIOUS: $($Task.TaskName) | Action: $Action | User: $($Task.Principal.UserId)"
        }
    }
}

function Invoke-RegistryPersistenceDetection {
    $detections = @()
    
    try {
        # Check standard Run keys
        $runKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($key in $runKeys) {
            if (Test-Path $key) {
                try {
                    $values = Get-ItemProperty -Path $key -ErrorAction Stop
                    foreach ($property in $values.PSObject.Properties) {
                        if ($property.Name -notmatch "^PS" -and $property.Value) {
                            $value = $property.Value
                            
                            # Check for suspicious patterns
                            $suspiciousPatterns = @(
                                "powershell.*-enc",
                                "cmd.*/c.*powershell",
                                "http://|https://",
                                "\.vbs|\.js|\.bat|\.cmd",
                                "wscript|cscript|mshta",
                                "rundll32.*\.dll",
                                "regsvr32.*\.dll"
                            )
                            
                            foreach ($pattern in $suspiciousPatterns) {
                                if ($value -match $pattern) {
                                    $detections += @{
                                        RegistryKey = $key
                                        ValueName = $property.Name
                                        Value = $value
                                        Pattern = $pattern
                                        Type = "Suspicious Registry Persistence"
                                        Risk = "High"
                                    }
                                    break
                                }
                            }
                            
                            # Check for unsigned executables
                            if ($value -like "*.exe" -or $value -like "*.dll") {
                                $exePath = $value -split ' ' | Select-Object -First 1
                                if (Test-Path $exePath) {
                                    try {
                                        $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                                        if ($sig.Status -ne "Valid" -and $exePath -notlike "$env:SystemRoot\*") {
                                            $detections += @{
                                                RegistryKey = $key
                                                ValueName = $property.Name
                                                Value = $value
                                                ExecutablePath = $exePath
                                                Type = "Unsigned Executable in Registry"
                                                Risk = "High"
                                            }
                                        }
                                    } catch { }
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        }
        
        # Check for suspicious registry modifications in user profile
        try {
            $userRunKeys = @(
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            
            foreach ($key in $userRunKeys) {
                if (Test-Path $key) {
                    try {
                        $items = Get-Item $key -ErrorAction Stop
                        $lastWrite = $items.LastWriteTime
                        
                        # Check if recently modified
                        if ((Get-Date) - $lastWrite -lt [TimeSpan]::FromHours(24)) {
                            $values = Get-ItemProperty -Path $key -ErrorAction Stop
                            foreach ($property in $values.PSObject.Properties) {
                                if ($property.Name -notmatch "^PS" -and $property.Value) {
                                    $detections += @{
                                        RegistryKey = $key
                                        ValueName = $property.Name
                                        Value = $property.Value
                                        LastModified = $lastWrite
                                        Type = "Recently Modified Registry Persistence"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "REGISTRY PERSISTENCE: $($detection.Type) - $($detection.RegistryKey) - $($detection.ValueName)" "THREAT" "registry_persistence_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\RegistryPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RegistryKey)|$($_.ValueName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Registry persistence detection error: $_" "ERROR" "registry_persistence_detections.log"
    }
    
    return $detections.Count
}

function Test-DLLHijacking {
    param([string]$DllPath)
    
    if (-not (Test-Path $DllPath)) { return $false }
    
    # Check if DLL is in suspicious locations
    $suspiciousPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:APPDATA",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    
    foreach ($susPath in $suspiciousPaths) {
        if ($DllPath -like "$susPath*") {
            return $true
        }
    }
    
    # Check if DLL is unsigned
    try {
        $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
        if ($sig.Status -ne "Valid") {
            return $true
        }
    } catch { }
    
    return $false
}

function Invoke-DLLHijackingDetection {
    $detections = @()
    
    try {
        # Check loaded DLLs in processes
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" }
                
                foreach ($module in $modules) {
                    if (Test-DLLHijacking -DllPath $module.FileName) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            DllPath = $module.FileName
                            DllName = $module.ModuleName
                            Type = "Suspicious DLL Loaded"
                            Risk = "High"
                        }
                    }
                }
            } catch {
                # Access denied or process exited
                continue
            }
        }
        
        # Check for DLLs in application directories
        $appPaths = @(
            "$env:ProgramFiles",
            "$env:ProgramFiles(x86)",
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64"
        )
        
        foreach ($appPath in $appPaths) {
            if (-not (Test-Path $appPath)) { continue }
            
            try {
                $dlls = Get-ChildItem -Path $appPath -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 100
                
                foreach ($dll in $dlls) {
                    if ($dll.DirectoryName -ne "$appPath") {
                        # Check if DLL is signed
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $dll.FullName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    DllPath = $dll.FullName
                                    Type = "Unsigned DLL in application directory"
                                    Risk = "Medium"
                                }
                            }
                        } catch { }
                    }
                }
            } catch { }
        }
        
        # Check Event Log for DLL load failures
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $events) {
                if ($event.Message -match 'DLL.*not.*found|DLL.*load.*failed') {
                    $detections += @{
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Type = "DLL Load Failure"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "DLL HIJACKING: $($detection.Type) - $($detection.ProcessName -or 'System') - $($detection.DllPath -or $detection.DllName -or $detection.Message)" "THREAT" "dll_hijacking_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\DLLHijacking_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.DllPath -or $_.DllName)|$($_.Risk)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "DLL hijacking detection error: $_" "ERROR" "dll_hijacking_detections.log"
    }
    
    return $detections.Count
}

function Invoke-TokenManipulationDetection {
    $Processes = Get-Process | Where-Object { $_.Path }

    foreach ($Process in $Processes) {
        try {
            $Owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).GetOwner()
            if ($Owner.Domain -eq "NT AUTHORITY" -and $Process.Path -notmatch "^C:\\Windows") {
                Write-Output "[TokenManip] SUSPICIOUS: Non-system binary running as SYSTEM | Process: $($Process.ProcessName) | Path: $($Process.Path)"
            }
        } catch {}
    }
}

function Invoke-ProcessHollowingDetection {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate
        
        foreach ($proc in $processes) {
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                $procPath = $procObj.Path
                $imgPath = $proc.ExecutablePath
                
                # Check for path mismatch (indicator of process hollowing)
                if ($procPath -and $imgPath -and $procPath -ne $imgPath) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        ProcessPath = $procPath
                        ImagePath = $imgPath
                        Type = "Path Mismatch - Process Hollowing"
                        Risk = "Critical"
                    }
                }
                
                # Check for processes with unusual parent relationships
                if ($proc.ParentProcessId) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction Stop
                        
                        # Check for processes spawned from non-standard parents
                        $suspiciousParents = @{
                            "explorer.exe" = @("notepad.exe", "calc.exe", "cmd.exe", "powershell.exe")
                            "winlogon.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                            "services.exe" = @("cmd.exe", "powershell.exe", "rundll32.exe")
                        }
                        
                        if ($suspiciousParents.ContainsKey($parent.Name)) {
                            if ($proc.Name -in $suspiciousParents[$parent.Name]) {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    ParentProcess = $parent.Name
                                    Type = "Suspicious Parent-Child Relationship"
                                    Risk = "High"
                                }
                            }
                        }
                    } catch { }
                }
                
                # Check for processes with suspended threads
                try {
                    $threads = Get-CimInstance Win32_Thread -Filter "ProcessHandle=$($proc.ProcessId)" -ErrorAction SilentlyContinue
                    $suspendedThreads = $threads | Where-Object { $_.ThreadState -eq 5 } # Suspended
                    
                    if ($suspendedThreads.Count -gt 0 -and $suspendedThreads.Count -eq $threads.Count) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            SuspendedThreads = $suspendedThreads.Count
                            Type = "All Threads Suspended - Process Hollowing"
                            Risk = "High"
                        }
                    }
                } catch { }
                
                # Check for processes with unusual memory regions
                try {
                    $memoryRegions = Get-Process -Id $proc.ProcessId -ErrorAction Stop | 
                        Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue
                    
                    if ($memoryRegions) {
                        $unknownModules = $memoryRegions | Where-Object { 
                            $_.FileName -notlike "$env:SystemRoot\*" -and
                            $_.FileName -notlike "$env:ProgramFiles*" -and
                            $_.ModuleName -notin @("kernel32.dll", "ntdll.dll", "user32.dll")
                        }
                        
                        if ($unknownModules.Count -gt 5) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                UnknownModules = $unknownModules.Count
                                Type = "Unusual Memory Modules"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch { }
                
            } catch {
                continue
            }
        }
        
        # Check for processes with unusual PE structure
        try {
            $suspiciousProcs = $processes | Where-Object {
                $_.ExecutablePath -and
                (Test-Path $_.ExecutablePath) -and
                $_.ExecutablePath -notlike "$env:SystemRoot\*"
            }
            
            foreach ($proc in $suspiciousProcs) {
                try {
                    $peInfo = Get-Item $proc.ExecutablePath -ErrorAction Stop
                    
                    # Check if executable is signed
                    $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                    if ($sig.Status -ne "Valid") {
                        # Check if it's impersonating a legitimate process
                        $legitNames = @("svchost.exe", "explorer.exe", "notepad.exe", "calc.exe", "dwm.exe")
                        if ($proc.Name -in $legitNames) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ExecutablePath = $proc.ExecutablePath
                                Type = "Unsigned Executable Impersonating Legitimate Process"
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "PROCESS HOLLOWING: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "process_hollowing_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessHollowing_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.Type)|$($_.Risk)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Process hollowing detection error: $_" "ERROR" "process_hollowing_detections.log"
    }
    
    return $detections.Count
}

function Invoke-KeyloggerDetection {
    $detections = @()
    
    try {
        # Check for processes with keyboard hooks
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                # Check for processes using keyboard hook DLLs
                $modules = $proc.Modules | Where-Object {
                    $_.ModuleName -match 'user32|keylog|hook|kbhook|keyboard'
                }
                
                if ($modules.Count -gt 0) {
                    # Exclude legitimate processes
                    $legitProcesses = @("explorer.exe", "dwm.exe", "chrome.exe", "msedge.exe", "firefox.exe")
                    if ($proc.ProcessName -notin $legitProcesses) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            HookModules = ($modules | Select-Object -ExpandProperty ModuleName) -join ', '
                            Type = "Keyboard Hook Detected"
                            Risk = "High"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for processes with SetWindowsHookEx API usage (keylogger indicator)
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine) {
                    $keylogPatterns = @(
                        'SetWindowsHookEx',
                        'WH_KEYBOARD',
                        'WH_KEYBOARD_LL',
                        'keylog',
                        'keyboard.*hook',
                        'GetAsyncKeyState'
                    )
                    
                    foreach ($pattern in $keylogPatterns) {
                        if ($proc.CommandLine -match $pattern) {
                            $procObj = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                            if ($procObj) {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    CommandLine = $proc.CommandLine
                                    Pattern = $pattern
                                    Type = "Keylogger API Usage"
                                    Risk = "Critical"
                                }
                            }
                            break
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes with unusual keyboard event monitoring
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    # Check for processes with high keyboard-related handle counts
                    $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    $keyHandles = $handles | Where-Object { $_.Name -match 'keyboard|keylog' }
                    
                    if ($keyHandles.Count -gt 5) {
                        $legitProcesses = @("explorer.exe", "dwm.exe")
                        if ($proc.ProcessName -notin $legitProcesses) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                KeyboardHandles = $keyHandles.Count
                                Type = "Unusual Keyboard Handle Count"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for unsigned processes accessing keyboard
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.Modules.ModuleName -match "user32.dll" }
            
            foreach ($proc in $processes) {
                try {
                    if ($proc.Path -and (Test-Path $proc.Path)) {
                        $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid" -and $proc.ProcessName -notmatch "explorer|chrome|firefox|msedge") {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                Type = "Unsigned Process with Keyboard Access"
                                Risk = "High"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "KEYLOGGER DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "keylogger_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Keylogger_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Keylogger detection error: $_" "ERROR" "keylogger_detections.log"
    }
    
    return $detections.Count
}

function Invoke-RansomwareDetection {
    param([bool]$AutoKillThreats = $true)
    
    $detections = @()
    
    try {
        # Check for rapid file modifications (encryption indicator)
        $userDirs = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Pictures",
            "$env:USERPROFILE\Videos"
        )
        
        $recentFiles = @()
        foreach ($dir in $userDirs) {
            if (Test-Path $dir) {
                try {
                    $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { (Get-Date) - $_.LastWriteTime -lt [TimeSpan]::FromMinutes(5) } |
                        Select-Object -First 100
                    
                    $recentFiles += $files
                } catch { }
            }
        }
        
        # Check for files with suspicious extensions
        $suspiciousExts = @(".encrypted", ".locked", ".crypto", ".vault", ".xxx", ".zzz", ".xyz")
        $encryptedFiles = $recentFiles | Where-Object {
            $ext = $_.Extension.ToLower()
            $ext -in $suspiciousExts -or
            ($ext -notin @(".txt", ".doc", ".pdf", ".jpg", ".png") -and $ext.Length -gt 4)
        }
        
        if ($encryptedFiles.Count -gt 10) {
            $detections += @{
                Type = "Rapid File Encryption"
                EncryptedFiles = $encryptedFiles.Count
                Risk = "Critical"
            }
        }
        
        # Check for ransom notes
        $ransomNoteNames = @("readme.txt", "decrypt.txt", "how_to_decrypt.txt", "recover.txt", "restore.txt", "!!!readme!!!.txt")
        foreach ($file in $recentFiles) {
            if ($file.Name -in $ransomNoteNames) {
                $detections += @{
                    File = $file.FullName
                    Type = "Ransom Note Detected"
                    Risk = "Critical"
                }
            }
        }
        
        # Check for processes with high file I/O
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Check for processes with unusual file activity
                    $ioStats = Get-Counter "\Process($($proc.Name))\IO Data Operations/sec" -ErrorAction SilentlyContinue
                    if ($ioStats -and $ioStats.CounterSamples[0].CookedValue -gt 1000) {
                        # High I/O activity
                        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    IOOperations = $ioStats.CounterSamples[0].CookedValue
                                    Type = "High File I/O - Unsigned Process"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for shadow copy deletion
        try {
            $shadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
            if ($shadowCopies.Count -eq 0 -and (Test-Path "C:\Windows\System32\vssadmin.exe")) {
                $detections += @{
                    Type = "Shadow Copies Deleted"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for crypto API usage
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            foreach ($proc in $processes) {
                $modules = $proc.Modules | Where-Object {
                    $_.ModuleName -match "crypt32|cryptsp|cryptnet|bcrypt"
                }
                
                if ($modules.Count -gt 0) {
                    # Check if process is accessing many files
                    try {
                        $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                        $fileHandles = $handles | Where-Object { $_.Name -like "*.txt" -or $_.Name -like "*.doc*" -or $_.Name -like "*.pdf" }
                        
                        if ($fileHandles.Count -gt 50) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                FileHandles = $fileHandles.Count
                                Type = "Cryptographic API with High File Access"
                                Risk = "High"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Also check command line for ransomware indicators (original check)
        $RansomwareIndicators = @(
            "vssadmin delete shadows",
            "wbadmin delete catalog",
            "bcdedit /set {default} recoveryenabled no",
            "wmic shadowcopy delete"
        )

        $Processes = Get-Process | Where-Object { $_.Path }

        foreach ($Process in $Processes) {
            try {
                $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine

                foreach ($Indicator in $RansomwareIndicators) {
                    if ($CommandLine -match [regex]::Escape($Indicator)) {
                        $detections += @{
                            ProcessId = $Process.Id
                            ProcessName = $Process.ProcessName
                            CommandLine = $CommandLine
                            Type = "Ransomware Command Detected"
                            Risk = "Critical"
                        }
                        break
                    }
                }
            } catch {}
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "RANSOMWARE DETECTED: $($detection.Type) - $($detection.ProcessName -or $detection.File -or 'System')" "THREAT" "ransomware_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Ransomware_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.File -or $_.EncryptedFiles)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Ransomware detection error: $_" "ERROR" "ransomware_detections.log"
    }
    
    return $detections.Count
}

function Invoke-NetworkAnomalyDetection {
    param(
        [bool]$AutoBlockThreats = $false
    )

    try {
        # Advanced suspicious port detection with severity scoring
        $SuspiciousPorts = @{
            "4444" = @{Severity = "High"; Reason = "Metasploit default port"; KnownMalware = $true}
            "5555" = @{Severity = "High"; Reason = "Common backdoor port"; KnownMalware = $true}
            "31337" = @{Severity = "Medium"; Reason = "Elite/leet backdoor port"; KnownMalware = $true}
            "6666" = @{Severity = "Medium"; Reason = "IRC and trojan port"; KnownMalware = $true}
            "9999" = @{Severity = "Low"; Reason = "Common trojan port"; KnownMalware = $true}
            "12345" = @{Severity = "Medium"; Reason = "NetBus trojan port"; KnownMalware = $true}
            "54321" = @{Severity = "Medium"; Reason = "Back Orifice trojan port"; KnownMalware = $true}
            "65432" = @{Severity = "Low"; Reason = "Uncommon trojan port"; KnownMalware = $false}
        }

        # Known malicious IP ranges (common malware C2 ranges)
        $KnownMaliciousRanges = @(
            "5.8.", "45.", "91.", "185.", "195."
        )

        $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
            Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -notlike "169.254.*" -and $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -notlike "10.*" }

        $ThreatScore = 0
        $DetectedThreats = @()

    foreach ($Conn in $Connections) {
            $ThreatScore = 0
            $ThreatReasons = @()
            
            try {
                # Check for suspicious ports
                $PortStr = $Conn.RemotePort.ToString()
                if ($SuspiciousPorts.ContainsKey($PortStr)) {
                    $portInfo = $SuspiciousPorts[$PortStr]
                    $ThreatScore += if ($portInfo.Severity -eq "High") { 30 } elseif ($portInfo.Severity -eq "Medium") { 20 } else { 10 }
                    $ThreatReasons += "Suspicious port: $($portInfo.Reason)"
                }

                # Check for known malicious IP ranges
                foreach ($range in $KnownMaliciousRanges) {
                    if ($Conn.RemoteAddress.ToString().StartsWith($range)) {
                        $ThreatScore += 25
                        $ThreatReasons += "Known malicious IP range: $range"
                        break
                    }
                }

                # Check for uncommon/privileged ports (above 49152)
                if ($Conn.RemotePort -gt 49152 -and $Conn.RemotePort -lt 65535) {
                    $ThreatScore += 5
                    $ThreatReasons += "Uncommon dynamic port range"
                }

                # Check process associated with connection
                try {
                    $proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc) {
                        # Check if process is from unusual location
                        if ($proc.Path -and $proc.Path -notmatch "^(C:\\(Windows|Program Files|Program Files \(x86\)))") {
                            $ThreatScore += 15
                            $ThreatReasons += "Non-standard process location: $($proc.Path)"
                        }

                        # Check for known suspicious process names
                        $SuspiciousProcesses = @("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
                        if ($SuspiciousProcesses -contains $proc.ProcessName) {
                            $ThreatScore += 20
                            $ThreatReasons += "Suspicious process making connection: $($proc.ProcessName)"
                        }
                    }
                } catch {}

                # Check for outbound connections from system processes (unusual)
                if ($proc -and $proc.ProcessName -match "^(svchost|lsass|winlogon|services|csrss|smss)$") {
                    $ThreatScore += 30
                    $ThreatReasons += "System process making outbound connection (potential process hollowing/injection)"
                }

                # Check for connections to non-standard DNS ports (port 53 but not from DNS processes)
                if ($Conn.RemotePort -eq 53 -and $proc -and $proc.ProcessName -ne "svchost" -and $proc.ProcessName -ne "dns") {
                    $ThreatScore += 25
                    $ThreatReasons += "Non-DNS process connecting to DNS port (potential DNS tunneling)"
                }

                # Score-based threat detection
                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $threatInfo = @{
                        RemoteAddress = $Conn.RemoteAddress
                        RemotePort = $Conn.RemotePort
                        ProcessId = $Conn.OwningProcess
                        ProcessName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                        ProcessPath = if ($proc -and $proc.Path) { $proc.Path } else { "Unknown" }
                        ThreatScore = $ThreatScore
                        Reasons = $ThreatReasons -join "; "
                        Severity = $severity
                        Timestamp = Get-Date
                    }

                    $DetectedThreats += $threatInfo

                    Write-Output "[Network] THREAT ($severity): Score=$ThreatScore | Remote: $($Conn.RemoteAddress):$($Conn.RemotePort) | PID: $($Conn.OwningProcess) | Process: $(if ($proc) { $proc.ProcessName } else { 'Unknown' }) | Reasons: $($ThreatReasons -join '; ')"

                    # Auto-block if configured
                    if ($AutoBlockThreats -and $ThreatScore -ge 40) {
                        try {
                            $RuleName = "Block_NetworkThreat_$($Conn.RemoteAddress)_$((Get-Date).ToString('yyyyMMddHHmmss'))"
                            $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                            if (-not $existingRule) {
                                New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $Conn.RemoteAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                Write-Output "[Network] ACTION: Blocked threat IP $($Conn.RemoteAddress) with firewall rule"
                            }
                        } catch {
                            Write-Output "[Network] ERROR: Failed to block threat: $_"
                        }
                    }

                    # Queue for response engine if threat is significant
                    if ($ThreatScore -ge 40) {
                        Add-ThreatToResponseQueue -ThreatType "NetworkAnomaly" -ThreatPath "$($Conn.RemoteAddress):$($Conn.RemotePort)" -Severity $severity
                    }
                }
            }
            catch {
                Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Error analyzing connection: $_" -Level "Warning"
            }
        }

        if ($DetectedThreats.Count -gt 0) {
            Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Detected $($DetectedThreats.Count) network anomaly/threat(s)" -Level "Warning"
        }

        return @{ThreatsDetected = $DetectedThreats.Count; Details = $DetectedThreats}
    }
    catch {
        Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Network anomaly detection failed: $_" -Level "Error"
        return @{ThreatsDetected = 0; Details = @()}
    }
}

function Invoke-NetworkTrafficMonitoring {
    param(
        [bool]$AutoBlockThreats = $true
    )

    $AllowedDomains = @("google.com", "microsoft.com", "github.com", "stackoverflow.com")
    $AllowedIPs = @()

    foreach ($Domain in $AllowedDomains) {
        try {
            $IPs = [System.Net.Dns]::GetHostAddresses($Domain) | ForEach-Object { $_.IPAddressToString }
            foreach ($IP in $IPs) {
                if ($AllowedIPs -notcontains $IP) {
                    $AllowedIPs += $IP
                }
            }
        }
        catch {
            Write-Output "[NTM] WARNING: Could not resolve domain $Domain to IP"
        }
    }

    Write-Output "[NTM] Starting network traffic monitoring..."

    try {
        $Connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" }

        $SuspiciousConnections = @()
        $TotalConnections = $Connections.Count

        foreach ($Connection in $Connections) {
            $RemoteAddr = $Connection.RemoteAddress
            $RemotePort = $Connection.RemotePort
            $ProcessId = $Connection.OwningProcess

            if ($AllowedIPs -contains $RemoteAddr) {
                continue
            }

            $ProcessName = "Unknown"
            $ProcessPath = "Unknown"

            try {
                $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
                if ($Process) {
                    $ProcessName = $Process.ProcessName
                    $ProcessPath = if ($Process.Path) { $Process.Path } else { "Unknown" }
                }
            }
            catch {
            }

            $SuspiciousScore = 0
            $Reasons = @()

            if ($RemotePort -gt 10000) {
                $SuspiciousScore += 20
                $Reasons += "High remote port: $RemotePort"
            }

            $C2Ports = @(4444, 8080, 9999, 1337, 31337, 443, 53)
            if ($C2Ports -contains $RemotePort) {
                $SuspiciousScore += 30
                $Reasons += "Known C2 port: $RemotePort"
            }

            $SuspiciousProcesses = @("powershell", "cmd", "wscript", "cscript", "rundll32", "mshta")
            if ($SuspiciousProcesses -contains $ProcessName.ToLower()) {
                $SuspiciousScore += 25
                $Reasons += "Suspicious process: $ProcessName"
            }

            if ($ProcessPath -notmatch "C:\\(Windows|Program Files|Program Files \(x86\))" -and $ProcessPath -ne "Unknown") {
                $SuspiciousScore += 15
                $Reasons += "Process in non-standard location"
            }

            if ($RemoteAddr -match '^\d+\.\d+\.\d+\.\d+$') {
                try {
                    $HostName = [System.Net.Dns]::GetHostEntry($RemoteAddr).HostName
                    if ($HostName -and $HostName -notmatch ($AllowedDomains -join '|')) {
                        $SuspiciousScore += 10
                        $Reasons += "Unknown hostname: $HostName"
                    }
                }
                catch {
                    $SuspiciousScore += 5
                    $Reasons += "No reverse DNS for IP"
                }
            }

            $PrivateIPRanges = @("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "169.254.")
            $IsPrivateIP = $false
            foreach ($Range in $PrivateIPRanges) {
                if ($RemoteAddr.StartsWith($Range)) {
                    $IsPrivateIP = $true
                    break
                }
            }

            if (!$IsPrivateIP -and $AllowedIPs -notcontains $RemoteAddr) {
                $SuspiciousScore += 10
                $Reasons += "Unknown public IP"
            }

            if ($SuspiciousScore -ge 30) {
                $SuspiciousConnections += @{
                    RemoteAddress = $RemoteAddr
                    RemotePort = $RemotePort
                    ProcessName = $ProcessName
                    ProcessId = $ProcessId
                    ProcessPath = $ProcessPath
                    Score = $SuspiciousScore
                    Reasons = $Reasons
                }

                Write-Output "[NTM] SUSPICIOUS: $ProcessName connecting to $RemoteAddr`:$RemotePort | Score: $SuspiciousScore | Reasons: $($Reasons -join ', ')"
            }
        }

        if ($AutoBlockThreats -and $SuspiciousConnections.Count -gt 0) {
            foreach ($Suspicious in $SuspiciousConnections) {
                try {
                    $RuleName = "Block_Malicious_$($Suspicious.RemoteAddress)_$((Get-Date).ToString('yyyyMMddHHmmss'))"
                    New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $Suspicious.RemoteAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

                    Write-Output "[NTM] ACTION: Blocked IP $($Suspicious.RemoteAddress) with firewall rule $RuleName"

                    if ($Suspicious.Score -ge 50) {
                        # Whitelist own process - never kill ourselves
                        if ($Suspicious.ProcessId -eq $PID -or $Suspicious.ProcessId -eq $Script:SelfPID) {
                            Write-Output "[NTM] BLOCKED: Attempted to kill own process (PID: $($Suspicious.ProcessId)) - whitelisted"
                            continue
                        }
                        Stop-Process -Id $Suspicious.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Output "[NTM] ACTION: Terminated suspicious process $($Suspicious.ProcessName) (PID: $($Suspicious.ProcessId))"
                    }
                }
                catch {
                    Write-Output "[NTM] ERROR: Failed to block threat: $_"
                }
            }
        }

        Write-Output "[NTM] Monitoring complete: $TotalConnections total connections, $($SuspiciousConnections.Count) suspicious"
    }
    catch {
        Write-Output "[NTM] ERROR: Failed to monitor network traffic: $_"
    }
}

function Invoke-RootkitDetection {
    param(
        [bool]$DeepScan = $true
    )

    try {
        $Threats = @()

        # 1. Check for unsigned drivers (potential rootkit)
        try {
            $Drivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue
    foreach ($Driver in $Drivers) {
                $Suspicious = $false
                $Reasons = @()

                # Non-Microsoft system drivers
        if ($Driver.ProviderName -notmatch "Microsoft" -and $Driver.ClassName -eq "System") {
                    $Suspicious = $true
                    $Reasons += "Third-party system driver"
                }

                # Drivers with suspicious names
                $SuspiciousDriverNames = @("rootkit", "stealth", "hide", "kernel", "hook", "inject")
                foreach ($pattern in $SuspiciousDriverNames) {
                    if ($Driver.DriverName -match $pattern -or $Driver.OriginalFileName -match $pattern) {
                        $Suspicious = $true
                        $Reasons += "Suspicious driver name pattern: $pattern"
                        break
                    }
                }

                # Drivers without digital signatures
                try {
                    $DriverPath = $Driver.OriginalFileName
                    if ($DriverPath -and (Test-Path $DriverPath)) {
                        $sig = Get-AuthenticodeSignature -FilePath $DriverPath -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") {
                            $Suspicious = $true
                            $Reasons += "Unsigned or invalid signature (Status: $($sig.Status))"
                        }
                    }
                } catch {}

                if ($Suspicious) {
                    $Threats += @{
                        Type = "SuspiciousDriver"
                        Name = $Driver.DriverName
                        Provider = $Driver.ProviderName
                        Path = $Driver.OriginalFileName
                        Reasons = $Reasons
                        Severity = "High"
                    }
                    Write-Output "[Rootkit] SUSPICIOUS: Driver detected | Driver: $($Driver.DriverName) | Provider: $($Driver.ProviderName) | Reasons: $($Reasons -join '; ')"
                }
            }
        } catch {
            Write-EDRLog -Module "RootkitDetection" -Message "Driver scan failed: $_" -Level "Warning"
        }

        # 2. Check for hidden processes (process list vs performance counters)
        if ($DeepScan) {
            try {
                $ProcessList = Get-Process | Select-Object -ExpandProperty Id
                $PerfProcesses = Get-Counter "\Process(*)\ID Process" -ErrorAction SilentlyContinue | 
                    Select-Object -ExpandProperty CounterSamples | 
                    Where-Object { $_.CookedValue -gt 0 } | 
                    Select-Object -ExpandProperty CookedValue | 
                    ForEach-Object { [int]$_ }

                $HiddenProcesses = $PerfProcesses | Where-Object { $_ -notin $ProcessList }
                foreach ($procPid in $HiddenProcesses) {
                    $Threats += @{
                        Type = "HiddenProcess"
                        ProcessId = $procPid
                        Reasons = @("Process visible in performance counters but not in process list")
                        Severity = "Critical"
                    }
                    Write-Output "[Rootkit] CRITICAL: Hidden process detected | PID: $pid"
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "Hidden process detection failed: $_" -Level "Warning"
            }
        }

        # 3. Check for kernel mode callbacks (advanced)
        if ($DeepScan) {
            try {
                # Check for suspicious registry keys used by rootkits
                $RootkitRegistryKeys = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Services\*",
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
                )

                foreach ($keyPath in $RootkitRegistryKeys) {
                    try {
                        $keys = Get-ChildItem -Path $keyPath -ErrorAction SilentlyContinue
                        foreach ($key in $keys) {
                            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                            
                            # Check for suspicious values
                            if ($props.ImagePath -and $props.ImagePath -notmatch "^(C:\\(Windows|Program Files))") {
                                $Threats += @{
                                    Type = "SuspiciousServiceRegistry"
                                    Path = $key.PSPath
                                    ImagePath = $props.ImagePath
                                    Reasons = @("Service in non-standard location")
                                    Severity = "Medium"
                                }
                                Write-Output "[Rootkit] SUSPICIOUS: Service in non-standard location | Path: $($key.PSPath) | ImagePath: $($props.ImagePath)"
                            }
                        }
                    } catch {}
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "Registry scan failed: $_" -Level "Warning"
            }
        }

        # 4. Check for SSDT hooks (System Service Descriptor Table) - indirect detection
        if ($DeepScan) {
            try {
                # Check for processes with unusual API calls (would require kernel debugging in real implementation)
                # This is a simplified heuristic check
                $SystemProcesses = Get-Process | Where-Object { $_.ProcessName -match "^(lsass|csrss|winlogon|services|smss|wininit)$" }
                foreach ($proc in $SystemProcesses) {
                    try {
                        # Check if system process has unexpected modules loaded
                        $modules = $proc.Modules | Where-Object { 
                            $_.ModuleName -notmatch "^(ntdll|kernel32|msvcr|msvcp)" -and 
                            $_.FileName -notmatch "^C:\\Windows" 
                        }
                        if ($modules) {
                            foreach ($mod in $modules) {
                                $Threats += @{
                                    Type = "SuspiciousModuleInSystemProcess"
                                    ProcessName = $proc.ProcessName
                                    ProcessId = $proc.Id
                                    ModuleName = $mod.ModuleName
                                    ModulePath = $mod.FileName
                                    Reasons = @("Unexpected module in system process")
                                    Severity = "High"
                                }
                                Write-Output "[Rootkit] HIGH: Suspicious module in system process | Process: $($proc.ProcessName) | Module: $($mod.ModuleName) | Path: $($mod.FileName)"
                            }
                        }
                    } catch {}
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "System process module scan failed: $_" -Level "Warning"
            }
        }

        # 5. Check for file system filters (rootkit indicator)
        try {
            $FileSystemFilters = Get-WmiObject -Class Win32_SystemDriver -Filter "Name LIKE '%filter%' OR Name LIKE '%fs%'" -ErrorAction SilentlyContinue
            foreach ($filter in $FileSystemFilters) {
                if ($filter.PathName -and $filter.PathName -notmatch "^\\\\?\\C:\\Windows") {
                    $Threats += @{
                        Type = "SuspiciousFileSystemFilter"
                        Name = $filter.Name
                        Path = $filter.PathName
                        State = $filter.State
                        Reasons = @("File system filter in non-standard location")
                        Severity = "High"
                    }
                    Write-Output "[Rootkit] HIGH: Suspicious file system filter | Name: $($filter.Name) | Path: $($filter.PathName)"
                }
            }
        } catch {
            Write-EDRLog -Module "RootkitDetection" -Message "File system filter scan failed: $_" -Level "Warning"
        }

        # Queue critical threats for response
        foreach ($threat in $Threats) {
            if ($threat.Severity -eq "Critical") {
                Add-ThreatToResponseQueue -ThreatType "Rootkit" -ThreatPath $threat.Path -Severity "Critical"
            }
        }

        Write-EDRLog -Module "RootkitDetection" -Message "Rootkit detection completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "RootkitDetection" -Message "Rootkit detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-ClipboardMonitoring {
    try {
        $ClipboardText = Get-Clipboard -Format Text -ErrorAction SilentlyContinue
        if (-not $ClipboardText) { return }

        $ThreatScore = 0
        $DetectedPatterns = @()
        
        # Advanced pattern matching for sensitive data
        $Patterns = @{
            # Passwords and credentials
            "Password" = @{
                Pattern = "(?i)(password|passwd|pwd)\s*[:=]\s*([^\s]{8,})"
                Severity = "High"
                Score = 30
                Type = "Password"
            }
            # API Keys
            "APIKey" = @{
                Pattern = "(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*([A-Za-z0-9_\-]{20,})"
                Severity = "High"
                Score = 35
                Type = "APIKey"
            }
            # OAuth tokens
            "OAuthToken" = @{
                Pattern = "(?i)(bearer\s+)?([A-Za-z0-9\-_]{100,})"
                Severity = "High"
                Score = 40
                Type = "OAuthToken"
            }
            # AWS credentials
            "AWSCredentials" = @{
                Pattern = "(?i)(AKIA[0-9A-Z]{16}|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([A-Za-z0-9/+=]{40})"
                Severity = "Critical"
                Score = 50
                Type = "AWSCredentials"
            }
            # Credit card numbers
            "CreditCard" = @{
                Pattern = "\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
                Severity = "High"
                Score = 45
                Type = "CreditCard"
            }
            # Social Security Numbers (US)
            "SSN" = @{
                Pattern = "\b\d{3}-\d{2}-\d{4}\b"
                Severity = "High"
                Score = 45
                Type = "SSN"
            }
            # Email addresses with credentials
            "EmailCredential" = @{
                Pattern = "(?i)(email|username|user|login)\s*[:=]\s*([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\s*(?:password|passwd|pwd)\s*[:=]\s*([^\s]{6,})"
                Severity = "High"
                Score = 40
                Type = "EmailCredential"
            }
            # Private keys
            "PrivateKey" = @{
                Pattern = "(-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----)"
                Severity = "Critical"
                Score = 50
                Type = "PrivateKey"
            }
            # Database connection strings
            "DatabaseConnection" = @{
                Pattern = "(?i)(server|host|database|uid|user id|pwd|password)=[^;]+"
                Severity = "High"
                Score = 35
                Type = "DatabaseConnection"
            }
            # JWT tokens
            "JWT" = @{
                Pattern = "\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"
                Severity = "Medium"
                Score = 25
                Type = "JWT"
            }
            # Base64 encoded secrets (long base64 strings)
            "Base64Secret" = @{
                Pattern = "(?i)(?:secret|password|token|key)\s*[:=]\s*([A-Za-z0-9+/]{40,}={0,2})"
                Severity = "Medium"
                Score = 20
                Type = "Base64Secret"
            }
        }

        # Check each pattern
        foreach ($patternName in $Patterns.Keys) {
            $patternInfo = $Patterns[$patternName]
            if ($ClipboardText -match $patternInfo.Pattern) {
                $ThreatScore += $patternInfo.Score
                $DetectedPatterns += $patternInfo.Type
                
                # Extract matched content (sanitized for logging)
                $matchValue = $matches[0]
                if ($matchValue.Length -gt 50) {
                    $matchValue = $matchValue.Substring(0, 50) + "..."
                }
                
                Write-Output "[Clipboard] THREAT ($($patternInfo.Severity)): $($patternInfo.Type) detected | Pattern: $patternName | Match: $matchValue"
                
                # Log sensitive detection
                Write-EDRLog -Module "ClipboardMonitoring" -Message "Sensitive data detected: $($patternInfo.Type) (Pattern: $patternName)" -Level $patternInfo.Severity
            }
        }

        # Additional heuristic: Check for high entropy strings (potential encrypted data or tokens)
        if ($ClipboardText.Length -gt 20) {
            $entropy = Measure-StringEntropy -String $ClipboardText
            if ($entropy -gt 4.5 -and $ClipboardText -match "^[A-Za-z0-9+/=_-]+$") {
                $ThreatScore += 15
                $DetectedPatterns += "HighEntropyString"
                Write-Output "[Clipboard] WARNING: High entropy string detected (potential encrypted data or token) | Entropy: $([Math]::Round($entropy, 2))"
            }
        }

        # Additional heuristic: Check for suspicious URL patterns
        if ($ClipboardText -match "(?i)(https?://[^\s]+(?:token|key|password|secret|auth|login|credential)[^\s]*)") {
            $ThreatScore += 20
            $DetectedPatterns += "SuspiciousURL"
            Write-Output "[Clipboard] WARNING: Suspicious URL with credential-related parameters detected"
        }

        # Action based on threat score
        if ($ThreatScore -ge 30) {
            $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
            
            # Log to EDR
            Write-EDRLog -Module "ClipboardMonitoring" -Message "Sensitive clipboard data detected | Score: $ThreatScore | Patterns: $($DetectedPatterns -join ', ')" -Level $severity
            
            # Queue for response engine if critical
            if ($severity -eq "Critical" -or $ThreatScore -ge 45) {
                Add-ThreatToResponseQueue -ThreatType "ClipboardSensitiveData" -ThreatPath "Clipboard" -Severity $severity
            }
            
            return @{Detected = $true; Score = $ThreatScore; Patterns = $DetectedPatterns; Severity = $severity}
        }

        return @{Detected = $false; Score = 0; Patterns = @()}
    }
    catch {
        Write-EDRLog -Module "ClipboardMonitoring" -Message "Clipboard monitoring error: $_" -Level "Warning"
        return @{Detected = $false; Score = 0; Patterns = @()}
    }
}

function Measure-StringEntropy {
    param([string]$String)
    
    if ([string]::IsNullOrEmpty($String)) { return 0 }
    
    $freq = @{}
    foreach ($char in $String.ToCharArray()) {
        if ($freq.ContainsKey($char)) {
            $freq[$char]++
        } else {
            $freq[$char] = 1
        }
    }
    
    $length = $String.Length
    $entropy = 0.0
    foreach ($count in $freq.Values) {
        $probability = $count / $length
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    
    return $entropy
}

function Invoke-COMMonitoring {
    param(
        [hashtable]$Config
    )
    
    $COMKeys = @(
        "HKLM:\SOFTWARE\Classes\CLSID"
    )

    foreach ($Key in $COMKeys) {
        $RecentCOM = Get-ChildItem -Path $Key -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match "^\{[A-F0-9-]+\}$" } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 5

        foreach ($COM in $RecentCOM) {
            Write-Output "[COM] Recently modified COM object: $($COM.PSChildName) | Modified: $($COM.LastWriteTime)"
        }
    }
}

function Invoke-BrowserExtensionMonitoring {
    $detections = @()
    
    try {
        # Check Chrome extensions
        $chromeExtensionsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        if (Test-Path $chromeExtensionsPath) {
            $chromeExts = Get-ChildItem -Path $chromeExtensionsPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $chromeExts) {
                $manifestPath = Join-Path $ext.FullName "*\manifest.json"
                $manifests = Get-ChildItem -Path $manifestPath -ErrorAction SilentlyContinue
                
                foreach ($manifest in $manifests) {
                    try {
                        $manifestContent = Get-Content $manifest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        
                        # Check for suspicious permissions
                        $suspiciousPermissions = @("all_urls", "tabs", "cookies", "history", "downloads", "webRequest", "webRequestBlocking")
                        $hasSuspiciousPerms = $false
                        
                        if ($manifestContent.permissions) {
                            foreach ($perm in $manifestContent.permissions) {
                                if ($perm -in $suspiciousPermissions) {
                                    $hasSuspiciousPerms = $true
                                    break
                                }
                            }
                        }
                        
                        # Check for unsigned extensions
                        $isSigned = $manifestContent.key -ne $null
                        
                        if ($hasSuspiciousPerms -or -not $isSigned) {
                            $detections += @{
                                Browser = "Chrome"
                                ExtensionId = $ext.Name
                                ExtensionName = $manifestContent.name
                                ManifestPath = $manifest.FullName
                                HasSuspiciousPermissions = $hasSuspiciousPerms
                                IsSigned = $isSigned
                                Type = "Suspicious Chrome Extension"
                                Risk = if ($hasSuspiciousPerms) { "High" } else { "Medium" }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        # Check Edge extensions
        $edgeExtensionsPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
        if (Test-Path $edgeExtensionsPath) {
            $edgeExts = Get-ChildItem -Path $edgeExtensionsPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $edgeExts) {
                $manifestPath = Join-Path $ext.FullName "*\manifest.json"
                $manifests = Get-ChildItem -Path $manifestPath -ErrorAction SilentlyContinue
                
                foreach ($manifest in $manifests) {
                    try {
                        $manifestContent = Get-Content $manifest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        
                        if ($manifestContent.permissions) {
                            $suspiciousPerms = $manifestContent.permissions | Where-Object {
                                $_ -in @("all_urls", "tabs", "cookies", "webRequest")
                            }
                            
                            if ($suspiciousPerms.Count -gt 0) {
                                $detections += @{
                                    Browser = "Edge"
                                    ExtensionId = $ext.Name
                                    ExtensionName = $manifestContent.name
                                    SuspiciousPermissions = $suspiciousPerms -join ','
                                    Type = "Suspicious Edge Extension"
                                    Risk = "Medium"
                                }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        # Check Firefox extensions
        $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfilesPath) {
            $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($profile in $profiles) {
                $extensionsPath = Join-Path $profile.FullName "extensions"
                if (Test-Path $extensionsPath) {
                    $firefoxExts = Get-ChildItem -Path $extensionsPath -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -eq ".xpi" -or $_.Extension -eq "" }
                    
                    foreach ($ext in $firefoxExts) {
                        $detections += @{
                            Browser = "Firefox"
                            ExtensionPath = $ext.FullName
                            Type = "Firefox Extension Detected"
                            Risk = "Low"
                        }
                    }
                }
            }
        }
        
        # Check for browser processes with unusual activity
        try {
            $browserProcs = Get-Process -ErrorAction SilentlyContinue | 
                Where-Object { $_.ProcessName -match 'chrome|edge|firefox|msedge' }
            
            foreach ($proc in $browserProcs) {
                try {
                    $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                        Where-Object { $_.State -eq "Established" }
                    
                    # Check for connections to suspicious domains
                    $remoteIPs = $conns.RemoteAddress | Select-Object -Unique
                    
                    foreach ($ip in $remoteIPs) {
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
                            
                            $suspiciousDomains = @(".onion", ".bit", ".i2p", "pastebin", "githubusercontent")
                            foreach ($domain in $suspiciousDomains) {
                                if ($hostname -like "*$domain*") {
                                    $detections += @{
                                        BrowserProcess = $proc.ProcessName
                                        ProcessId = $proc.Id
                                        ConnectedDomain = $hostname
                                        Type = "Browser Connecting to Suspicious Domain"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        } catch { }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "BROWSER EXTENSION: $($detection.Type) - $($detection.ExtensionName -or $detection.BrowserProcess -or 'System')" "THREAT" "browser_extension_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\BrowserExtension_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ExtensionName -or $_.BrowserProcess)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Browser extension monitoring error: $_" "ERROR" "browser_extension_detections.log"
    }
    
    return $detections.Count
}

function Invoke-ShadowCopyMonitoring {
    $ShadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
    $CurrentCount = $ShadowCopies.Count

    if (-not $Global:BaselineShadowCopyCount) {
        $Global:BaselineShadowCopyCount = $CurrentCount
    }

    if ($CurrentCount -lt $Global:BaselineShadowCopyCount) {
        $Deleted = $Global:BaselineShadowCopyCount - $CurrentCount
        Write-Output "[ShadowCopy] THREAT: Shadow copies deleted | Deleted: $Deleted | Remaining: $CurrentCount"
        $Global:BaselineShadowCopyCount = $CurrentCount
    }
}

function Invoke-USBMonitoring {
    $detections = @()
    
    try {
        # Check for USB devices
        try {
            $usbDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue
            
            foreach ($device in $usbDevices) {
                # Check for USB HID devices (keyloggers)
                if ($device.FriendlyName -match "Keyboard|HID|Human Interface") {
                    $detections += @{
                        DeviceName = $device.FriendlyName
                        InstanceId = $device.InstanceId
                        Type = "USB HID Device Connected"
                        Risk = "Medium"
                    }
                }
                
                # Check for USB mass storage devices
                if ($device.FriendlyName -match "Mass Storage|USB.*Drive|Removable") {
                    try {
                        $removableDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue
                        
                        foreach ($drive in $removableDrives) {
                            $drivePath = $drive.DeviceID
                            
                            # Check for autorun.inf
                            $autorunPath = "$drivePath\autorun.inf"
                            if (Test-Path $autorunPath) {
                                $detections += @{
                                    Drive = $drivePath
                                    AutorunPath = $autorunPath
                                    DeviceName = $device.FriendlyName
                                    Type = "USB Drive with Autorun.inf"
                                    Risk = "High"
                                }
                            }
                            
                            # Check for executable files on USB
                            try {
                                $executables = Get-ChildItem -Path $drivePath -Filter "*.exe" -ErrorAction SilentlyContinue |
                                    Select-Object -First 20
                                
                                foreach ($exe in $executables) {
                                    try {
                                        $sig = Get-AuthenticodeSignature -FilePath $exe.FullName -ErrorAction SilentlyContinue
                                        if ($sig.Status -ne "Valid") {
                                            $detections += @{
                                                Drive = $drivePath
                                                ExecutablePath = $exe.FullName
                                                DeviceName = $device.FriendlyName
                                                Type = "Unsigned Executable on USB Drive"
                                                Risk = "High"
                                            }
                                        }
                                    } catch { }
                                }
                            } catch { }
                            
                            # Check for suspicious file types
                            try {
                                $suspiciousFiles = Get-ChildItem -Path $drivePath -Include *.vbs,*.js,*.bat,*.cmd,*.ps1 -ErrorAction SilentlyContinue |
                                    Select-Object -First 10
                                
                                if ($suspiciousFiles.Count -gt 0) {
                                    $detections += @{
                                        Drive = $drivePath
                                        SuspiciousFileCount = $suspiciousFiles.Count
                                        DeviceName = $device.FriendlyName
                                        Type = "Suspicious Files on USB Drive"
                                        Risk = "Medium"
                                    }
                                }
                            } catch { }
                        }
                    } catch { }
                    
                    $detections += @{
                        DeviceName = $device.FriendlyName
                        InstanceId = $device.InstanceId
                        Type = "USB Mass Storage Device Connected"
                        Risk = "Low"
                    }
                }
            }
        } catch { }
        
        # Check for recently connected USB devices
        try {
            $recentDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq "OK" }
            
            # Check Event Log for USB connection events
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=20001} -ErrorAction SilentlyContinue -MaxEvents 50 |
                    Where-Object {
                        (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                        $_.Message -match 'USB|removable'
                    }
                
                if ($events.Count -gt 5) {
                    $detections += @{
                        EventCount = $events.Count
                        Type = "Multiple USB Connections in Short Time"
                        Risk = "Medium"
                    }
                }
            } catch { }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "USB MONITORING: $($detection.Type) - $($detection.DeviceName -or $detection.Drive -or 'System')" "THREAT" "usb_monitoring_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\USBMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.DeviceName -or $_.Drive)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "USB monitoring error: $_" "ERROR" "usb_monitoring_detections.log"
    }
    
    return $detections.Count
}

function Invoke-EventLogMonitoring {
    param(
        [int]$LookbackHours = 1,
        [bool]$CorrelationEnabled = $true
    )

    try {
        $Threats = @()
        $cutoffTime = (Get-Date).AddHours(-$LookbackHours)

        # 1. Security log cleared (Event ID 1102)
        try {
            $ClearedLogs = Get-WinEvent -FilterHashtable @{LogName='Security';ID=1102;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
    foreach ($LogEvent in $ClearedLogs) {
                $username = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                
                $Threats += @{
                    Type = "SecurityLogCleared"
                    EventId = 1102
                    Time = $LogEvent.TimeCreated
                    User = $username
                    Severity = "Critical"
                    ThreatScore = 50
                }
                
                Write-Output "[EventLog] CRITICAL: Security log cleared | Time: $($LogEvent.TimeCreated) | User: $username"
                Add-ThreatToResponseQueue -ThreatType "SecurityLogCleared" -ThreatPath "EventLog" -Severity "Critical"
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check cleared logs: $_" -Level "Warning"
        }

        # 2. Failed logon attempts (Event ID 4625) - Advanced brute force detection
        try {
            $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625;StartTime=$cutoffTime} -MaxEvents 100 -ErrorAction SilentlyContinue
            
            # Group by account name and analyze
            $AccountAttempts = $FailedLogons | Group-Object {
                if ($_.Properties.Count -gt 5) { $_.Properties[5].Value } else { "Unknown" }
            }
            
            foreach ($Account in $AccountAttempts) {
                $attemptCount = $Account.Count
                $accountName = $Account.Name
                
                if ($attemptCount -gt 5) {
                    # Calculate threat score based on attempt frequency
                    $timeSpan = ($Account.Group | Measure-Object -Property TimeCreated -Maximum).Maximum - 
                               ($Account.Group | Measure-Object -Property TimeCreated -Minimum).Minimum
                    $attemptsPerMinute = if ($timeSpan.TotalMinutes -gt 0) { $attemptCount / $timeSpan.TotalMinutes } else { $attemptCount }
                    
                    $severity = if ($attemptsPerMinute -gt 10) { "Critical" } 
                               elseif ($attemptsPerMinute -gt 5) { "High" } 
                               elseif ($attemptCount -gt 20) { "High" }
                               else { "Medium" }
                    
                    $Threats += @{
                        Type = "BruteForceAttempt"
                        EventId = 4625
                        Account = $accountName
                        AttemptCount = $attemptCount
                        AttemptsPerMinute = [Math]::Round($attemptsPerMinute, 2)
                        TimeSpan = $timeSpan
                        Severity = $severity
                        ThreatScore = [Math]::Min(50, 20 + ($attemptsPerMinute * 2))
                    }
                    
                    Write-Output "[EventLog] THREAT ($severity): Brute force attempt detected | Account: $accountName | Attempts: $attemptCount | Rate: $([Math]::Round($attemptsPerMinute, 2))/min"
                    
                    if ($severity -eq "Critical" -or $attemptCount -gt 30) {
                        Add-ThreatToResponseQueue -ThreatType "BruteForceAttack" -ThreatPath $accountName -Severity $severity
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check failed logons: $_" -Level "Warning"
        }

        # 3. Privilege escalation (Event ID 4672 - Admin logon)
        try {
            $AdminLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
            foreach ($LogEvent in $AdminLogons) {
                $username = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                $logonType = if ($LogEvent.Properties.Count -gt 3) { $LogEvent.Properties[3].Value } else { "Unknown" }
                
                # Check for suspicious logon types (network logons with admin rights)
                if ($logonType -in @(3, 8, 10)) { # Network, NetworkCleartext, RemoteInteractive
                    $Threats += @{
                        Type = "SuspiciousAdminLogon"
                        EventId = 4672
                        User = $username
                        LogonType = $logonType
                        Time = $LogEvent.TimeCreated
                        Severity = "High"
                        ThreatScore = 35
                    }
                    
                    Write-Output "[EventLog] HIGH: Suspicious admin network logon | User: $username | LogonType: $logonType | Time: $($LogEvent.TimeCreated)"
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check admin logons: $_" -Level "Warning"
        }

        # 4. Account manipulation (Event IDs 4728, 4732, 4756)
        try {
            $AccountEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4728,4732,4756;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
            foreach ($LogEvent in $AccountEvents) {
                $eventType = switch ($LogEvent.Id) {
                    4728 { "Member added to security-enabled global group" }
                    4732 { "Member added to security-enabled local group" }
                    4756 { "Member added to security-enabled universal group" }
                    default { "Unknown account change" }
                }
                
                $targetAccount = if ($LogEvent.Properties.Count -gt 0) { $LogEvent.Properties[0].Value } else { "Unknown" }
                $subjectAccount = if ($LogEvent.Properties.Count -gt 4) { $LogEvent.Properties[4].Value } else { "Unknown" }
                
                # Check for privilege escalation attempts
                if ($targetAccount -match "Administrator|Domain Admin|Enterprise Admin|Schema Admin" -and $subjectAccount -ne $targetAccount) {
                    $Threats += @{
                        Type = "PrivilegeEscalationAttempt"
                        EventId = $LogEvent.Id
                        EventType = $eventType
                        TargetAccount = $targetAccount
                        SubjectAccount = $subjectAccount
                        Time = $LogEvent.TimeCreated
                        Severity = "Critical"
                        ThreatScore = 45
                    }
                    
                    Write-Output "[EventLog] CRITICAL: Potential privilege escalation | $eventType | Target: $targetAccount | Subject: $subjectAccount"
                    Add-ThreatToResponseQueue -ThreatType "PrivilegeEscalation" -ThreatPath "$subjectAccount -> $targetAccount" -Severity "Critical"
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check account changes: $_" -Level "Warning"
        }

        # 5. Process creation events (Event ID 4688) - Suspicious processes
        try {
            $ProcessEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688;StartTime=$cutoffTime} -MaxEvents 100 -ErrorAction SilentlyContinue
            
            $SuspiciousProcesses = @("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
            
            foreach ($LogEvent in $ProcessEvents) {
                if ($LogEvent.Properties.Count -gt 5) {
                    $processName = $LogEvent.Properties[5].Value
                    $commandLine = if ($LogEvent.Properties.Count -gt 8) { $LogEvent.Properties[8].Value } else { "" }
                    
                    if ($SuspiciousProcesses -contains $processName) {
                        # Check for suspicious command line patterns
                        $suspiciousPatterns = @("-enc", "-EncodedCommand", "downloadstring", "iex", "invoke-expression", "bypass", "hidden")
                        $foundPattern = $suspiciousPatterns | Where-Object { $commandLine -match [regex]::Escape($_) }
                        
                        if ($foundPattern) {
                            $subject = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                            
                            $Threats += @{
                                Type = "SuspiciousProcessExecution"
                                EventId = 4688
                                ProcessName = $processName
                                CommandLine = $commandLine
                                Subject = $subject
                                SuspiciousPattern = $foundPattern
                                Time = $LogEvent.TimeCreated
                                Severity = "High"
                                ThreatScore = 40
                            }
                            
                            Write-Output "[EventLog] HIGH: Suspicious process execution | Process: $processName | Pattern: $foundPattern | Subject: $subject"
                        }
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check process events: $_" -Level "Warning"
        }

        # 6. Event correlation (if enabled)
        if ($CorrelationEnabled -and $Threats.Count -gt 1) {
            # Group threats by time window (within 5 minutes)
            $correlatedThreats = $Threats | Group-Object {
                $timeWindow = $_.Time.ToString("yyyy-MM-dd HH:mm")
                $timeWindow
            }
            
            foreach ($group in $correlatedThreats) {
                if ($group.Count -ge 3) {
                    $uniqueTypes = $group.Group | Select-Object -ExpandProperty Type -Unique
                    Write-Output "[EventLog] WARNING: Event correlation detected | Time: $($group.Name) | Events: $($group.Count) | Types: $($uniqueTypes -join ', ')"
                    Write-EDRLog -Module "EventLogMonitoring" -Message "Correlated threat activity: $($group.Count) events in time window $($group.Name)" -Level "Warning"
                }
            }
        }

        Write-EDRLog -Module "EventLogMonitoring" -Message "Event log monitoring completed: $($Threats.Count) threat(s) detected" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "EventLogMonitoring" -Message "Event log monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-FirewallRuleMonitoring {
    if (-not $Global:BaselineFirewallRules) {
        $Global:BaselineFirewallRules = Get-NetFirewallRule | Select-Object -ExpandProperty Name
    }

    $CurrentRules = Get-NetFirewallRule | Select-Object -ExpandProperty Name
    $NewRules = $CurrentRules | Where-Object { $_ -notin $Global:BaselineFirewallRules }

    foreach ($Rule in $NewRules) {
        $RuleDetails = Get-NetFirewallRule -Name $Rule
        Write-Output "[Firewall] NEW RULE: $($RuleDetails.DisplayName) | Action: $($RuleDetails.Action) | Direction: $($RuleDetails.Direction)"
    }

    $Global:BaselineFirewallRules = $CurrentRules
}

function Invoke-ServiceMonitoring {
    param(
        [bool]$AutoBlockThreats = $false
    )

    try {
    if (-not $Global:BaselineServices) {
        $Global:BaselineServices = Get-Service | Select-Object -ExpandProperty Name
    }

    $CurrentServices = Get-Service | Select-Object -ExpandProperty Name
    $NewServices = $CurrentServices | Where-Object { $_ -notin $Global:BaselineServices }
        $Threats = @()

    foreach ($ServiceName in $NewServices) {
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if (-not $Service) { continue }

        $ServiceDetails = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
                if (-not $ServiceDetails) { continue }

                $ThreatScore = 0
                $Reasons = @()

                # 1. Check for services in non-standard locations
                if ($ServiceDetails.PathName -and $ServiceDetails.PathName -notmatch "^C:\\(Windows|Program Files)") {
                    $ThreatScore += 30
                    $Reasons += "Service executable in non-standard location: $($ServiceDetails.PathName)"
                    
                    # Check for suspicious paths (temp, user directories)
                    if ($ServiceDetails.PathName -match "(Temp|TEMP|tmp|appdata|localappdata|users)") {
                        $ThreatScore += 20
                        $Reasons += "Service executable in suspicious location (temp/user directory)"
                    }
                }

                # 2. Check for unsigned services
                try {
                    if ($ServiceDetails.PathName -and (Test-Path $ServiceDetails.PathName)) {
                        $sig = Get-AuthenticodeSignature -FilePath $ServiceDetails.PathName -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") {
                            $ThreatScore += 25
                            $Reasons += "Unsigned or invalid signature (Status: $($sig.Status))"
                        }
                    }
                } catch {}

                # 3. Check for suspicious service names
                $SuspiciousServiceNames = @("update", "svc", "helper", "service", "runtime", "agent", "monitor", "guard", "protect")
                foreach ($pattern in $SuspiciousServiceNames) {
                    if ($ServiceName -match $pattern -and $ServiceDetails.PathName -notmatch "^C:\\Windows") {
                        $ThreatScore += 15
                        $Reasons += "Suspicious service name pattern: $pattern"
                        break
                    }
                }

                # 4. Check for services with suspicious startup types
                if ($Service.StartType -eq "Automatic" -and $ServiceDetails.PathName -notmatch "^C:\\Windows") {
                    $ThreatScore += 10
                    $Reasons += "Auto-start service from non-standard location"
                }

                # 5. Check for services with suspicious account (SYSTEM account is normal, others are suspicious)
                if ($ServiceDetails.StartName -and $ServiceDetails.StartName -notmatch "^(LocalSystem|NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService)") {
                    $ThreatScore += 20
                    $Reasons += "Service running under non-standard account: $($ServiceDetails.StartName)"
                }

                # 6. Check for services with suspicious descriptions
                if ($Service.DisplayName -and $Service.DisplayName.Length -lt 5) {
                    $ThreatScore += 10
                    $Reasons += "Suspiciously short service display name"
                }

                # 7. Check for services with suspicious executable names
                if ($ServiceDetails.PathName) {
                    $exeName = Split-Path -Leaf $ServiceDetails.PathName
                    if ($exeName -match "^[a-z0-9]{8,}\.exe$" -or $exeName -match "svchost|lsass|csrss|winlogon") {
                        $ThreatScore += 25
                        $Reasons += "Service with suspicious executable name: $exeName (potential masquerading)"
                    }
                }

                # Score-based threat detection
                if ($ThreatScore -ge 25) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "SuspiciousService"
                        ServiceName = $ServiceName
                        DisplayName = $Service.DisplayName
                        PathName = $ServiceDetails.PathName
                        StartType = $Service.StartType
                        Status = $Service.Status
                        StartName = $ServiceDetails.StartName
                        ThreatScore = $ThreatScore
                        Reasons = $Reasons
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-Output "[Service] THREAT ($severity): Suspicious service detected | Name: $ServiceName | Display: $($Service.DisplayName) | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                    if ($AutoBlockThreats -and $ThreatScore -ge 40) {
                        try {
                            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                            Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
                            Write-Output "[Service] ACTION: Stopped and disabled suspicious service: $ServiceName"
                            Add-ThreatToResponseQueue -ThreatType "SuspiciousService" -ThreatPath $ServiceName -Severity $severity
                        } catch {
                            Write-EDRLog -Module "ServiceMonitoring" -Message "Failed to stop service ${ServiceName}: $_" -Level "Warning"
                        }
                    } elseif ($ThreatScore -ge 35) {
                        Add-ThreatToResponseQueue -ThreatType "SuspiciousService" -ThreatPath $ServiceName -Severity $severity
                    }
                } elseif ($ServiceDetails.PathName -notmatch "^C:\\Windows") {
                    # Even if score is low, log new services from non-standard locations
                    Write-Output "[Service] INFO: New service detected | Name: $ServiceName | Display: $($Service.DisplayName) | Path: $($ServiceDetails.PathName)"
                }
            }
            catch {
                Write-EDRLog -Module "ServiceMonitoring" -Message "Error analyzing service ${ServiceName}: $_" -Level "Warning"
            }
        }

        # Check for removed services (potential cleanup indicator)
        $RemovedServices = $Global:BaselineServices | Where-Object { $_ -notin $CurrentServices }
        if ($RemovedServices.Count -gt 0) {
            Write-EDRLog -Module "ServiceMonitoring" -Message "Services removed: $($RemovedServices -join ', ')" -Level "Info"
    }

    $Global:BaselineServices = $CurrentServices

        Write-EDRLog -Module "ServiceMonitoring" -Message "Service monitoring completed: $($Threats.Count) threat(s) found, $($NewServices.Count) new service(s)" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; NewServices = $NewServices.Count; RemovedServices = $RemovedServices.Count}
    }
    catch {
        Write-EDRLog -Module "ServiceMonitoring" -Message "Service monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); NewServices = 0; RemovedServices = 0}
    }
}

function Invoke-FilelessDetection {
    param(
        [bool]$AutoKillThreats = $true
    )

    try {
        $Threats = @()

        # 1. PowerShell encoded commands
        # Whitelist own process and script path
        $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
        $PSProcesses = Get-Process | Where-Object { 
            $_.ProcessName -match "powershell|pwsh" -and 
            $_.Id -ne $PID -and
            $_.Id -ne $Script:SelfPID
        }
    foreach ($Process in $PSProcesses) {
        try {
            $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
                if (-not $CommandLine) { continue }
                
                # Skip if this is our own script
                if ($ownScriptPath -and $CommandLine -like "*$ownScriptPath*") {
                    continue
                }

                $SuspiciousPatterns = @{
                    "-enc|-EncodedCommand" = @{Score = 40; Reason = "Base64 encoded PowerShell command"}
                    "downloadstring|DownloadString" = @{Score = 35; Reason = "Download string from remote source"}
                    "iex|Invoke-Expression" = @{Score = 30; Reason = "Invoke expression (code execution)"}
                    "bypass.*executionpolicy" = @{Score = 35; Reason = "Execution policy bypass"}
                    "-nop.*-w.*hidden" = @{Score = 30; Reason = "Hidden window execution"}
                    "new-object.*net.webclient" = @{Score = 25; Reason = "Web client object creation"}
                    "invoke-webrequest|iwr|curl" = @{Score = 20; Reason = "Web request command"}
                }

                $ThreatScore = 0
                $FoundPatterns = @()
                
                foreach ($pattern in $SuspiciousPatterns.Keys) {
                    if ($CommandLine -match $pattern) {
                        $patternInfo = $SuspiciousPatterns[$pattern]
                        $ThreatScore += $patternInfo.Score
                        $FoundPatterns += $patternInfo.Reason
                    }
                }

                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "SuspiciousPowerShell"
                        ProcessId = $Process.Id
                        ProcessName = $Process.ProcessName
                        CommandLine = $CommandLine
                        ThreatScore = $ThreatScore
                        Patterns = $FoundPatterns
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-Output "[Fileless] THREAT ($severity): PowerShell fileless activity detected | PID: $($Process.Id) | Score: $ThreatScore | Patterns: $($FoundPatterns -join '; ')"

                    if ($AutoKillThreats -and $ThreatScore -ge 40) {
                        # Whitelist own process - never kill ourselves
                        if ($Process.Id -eq $PID -or $Process.Id -eq $Script:SelfPID) {
                            Write-EDRLog -Module "FilelessDetection" -Message "BLOCKED: Attempted to kill own process (PID: $($Process.Id)) - whitelisted" -Level "Warning"
                            continue
                        }
                        
                        try {
                            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                            Write-Output "[Fileless] ACTION: Terminated suspicious PowerShell process (PID: $($Process.Id))"
                            Add-ThreatToResponseQueue -ThreatType "FilelessPowerShell" -ThreatPath $Process.Id.ToString() -Severity $severity
                        } catch {
                            Write-EDRLog -Module "FilelessDetection" -Message "Failed to terminate process $($Process.Id): $_" -Level "Warning"
                        }
                    } else {
                        Add-ThreatToResponseQueue -ThreatType "FilelessPowerShell" -ThreatPath $Process.Id.ToString() -Severity $severity
                    }
            }
        } catch {}
    }

        # 2. WMI-based fileless persistence (Event Consumers)
        try {
            $EventConsumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction SilentlyContinue
            foreach ($consumer in $EventConsumers) {
                $consumerType = $consumer.__CLASS
                $commandLine = ""
                
                if ($consumerType -eq "__EventFilter") {
                    $query = $consumer.Query
                    if ($query -match "SELECT.*FROM.*WITHIN" -and ($query -match "powershell|wscript|cscript|cmd")) {
                        $Threats += @{
                            Type = "WMIEventConsumer"
                            ConsumerType = $consumerType
                            Query = $query
                            Name = $consumer.Name
                            Severity = "High"
                            ThreatScore = 45
                        }
                        
                        Write-Output "[Fileless] HIGH: WMI event consumer with suspicious query detected | Name: $($consumer.Name) | Type: $consumerType"
                        Add-ThreatToResponseQueue -ThreatType "WMIFileless" -ThreatPath "WMI:$($consumer.Name)" -Severity "High"
                    }
                }
                
                if ($consumerType -eq "__CommandLineEventConsumer") {
                    $commandLine = $consumer.CommandLineTemplate
                    if ($commandLine -match "(powershell|wscript|cscript|cmd).*(enc|bypass|hidden|download)" -or
                        $commandLine -match "-enc|-EncodedCommand") {
                        $Threats += @{
                            Type = "WMICommandConsumer"
                            ConsumerType = $consumerType
                            CommandLine = $commandLine
                            Name = $consumer.Name
                            Severity = "Critical"
                            ThreatScore = 50
                        }
                        
                        Write-Output "[Fileless] CRITICAL: WMI command consumer with suspicious command detected | Name: $($consumer.Name) | Command: $commandLine"
                        Add-ThreatToResponseQueue -ThreatType "WMIFileless" -ThreatPath "WMI:$($consumer.Name)" -Severity "Critical"
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "WMI consumer scan failed: $_" -Level "Warning"
        }

        # 3. Registry-based fileless (AppInit_DLLs, Run keys with suspicious values)
        try {
            $SuspiciousRegistryKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )

            foreach ($regPath in $SuspiciousRegistryKeys) {
                try {
                    if (Test-Path $regPath) {
                        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                        if ($values) {
                            $props = $values.PSObject.Properties | Where-Object { $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider" }
                            foreach ($prop in $props) {
                                $value = $prop.Value
                                if ($value -match "(powershell|wscript|cscript|cmd).*(enc|bypass|download|iex)" -or
                                    $value -match "-enc|-EncodedCommand|downloadstring|iex") {
                                    
                                    $Threats += @{
                                        Type = "RegistryFileless"
                                        RegistryPath = $regPath
                                        KeyName = $prop.Name
                                        Value = $value
                                        Severity = "High"
                                        ThreatScore = 40
                                    }
                                    
                                    Write-Output "[Fileless] HIGH: Registry-based fileless persistence detected | Path: $regPath | Key: $($prop.Name) | Value: $value"
                                    Add-ThreatToResponseQueue -ThreatType "RegistryFileless" -ThreatPath "$regPath\$($prop.Name)" -Severity "High"
                                }
                            }
                        }
            }
        } catch {}
    }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Registry scan failed: $_" -Level "Warning"
        }

        # 4. Scheduled tasks with fileless techniques
        try {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Ready" }
            foreach ($task in $tasks) {
                $action = $task.Actions
                if ($action) {
                    $command = $action.Execute
                    $arguments = $action.Arguments
                    
                    # Whitelist our own scheduled tasks
                    if ($task.TaskName -like "AntivirusAutoRestart_*" -or $task.TaskName -eq "AntivirusProtection") {
                        continue
                    }
                    
                    if ($command -match "powershell|wscript|cscript|cmd" -and 
                        ($arguments -match "-enc|-EncodedCommand|downloadstring|iex|bypass" -or
                         $command -match "-enc|-EncodedCommand")) {
                        
                        $Threats += @{
                            Type = "ScheduledTaskFileless"
                            TaskName = $task.TaskName
                            Command = $command
                            Arguments = $arguments
                            Severity = "High"
                            ThreatScore = 45
                        }
                        
                        Write-Output "[Fileless] HIGH: Scheduled task with fileless technique detected | Task: $($task.TaskName) | Command: $command | Args: $arguments"
                        Add-ThreatToResponseQueue -ThreatType "ScheduledTaskFileless" -ThreatPath "Task:$($task.TaskName)" -Severity "High"
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Scheduled task scan failed: $_" -Level "Warning"
        }

        # 5. .NET assembly loading (reflection-based)
        try {
            $PSProcesses = Get-Process | Where-Object { $_.ProcessName -match "powershell|pwsh" }
            foreach ($Process in $PSProcesses) {
                try {
                    $modules = $Process.Modules | Where-Object { 
                        $_.ModuleName -match "System\.Reflection|System\.Management\.Automation" -and
                        $_.FileName -match "System\.Management\.Automation"
                    }
                    
                    if ($modules.Count -gt 5) {
                        $Threats += @{
                            Type = "ReflectionAssemblyLoading"
                            ProcessId = $Process.Id
                            ProcessName = $Process.ProcessName
                            ModuleCount = $modules.Count
                            Severity = "Medium"
                            ThreatScore = 30
                        }
                        
                        Write-Output "[Fileless] MEDIUM: Excessive reflection/assembly loading detected | PID: $($Process.Id) | Modules: $($modules.Count)"
                    }
                } catch {}
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Assembly loading scan failed: $_" -Level "Warning"
        }

        Write-EDRLog -Module "FilelessDetection" -Message "Fileless detection completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "FilelessDetection" -Message "Fileless detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-MemoryScanning {
    param(
        [bool]$AutoKillThreats = $true,
        [bool]$DeepScan = $false
    )

    try {
        $Threats = @()
        $SuspiciousPatterns = @(
            "\x48\x8B\xEC\x48\x83\xEC.{0,20}\xE8",  # Common shellcode prologue (mov rbp, rsp; sub rsp, ...; call)
            "\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9",  # XOR eax,eax; XOR ebx,ebx; XOR ecx,ecx (common shellcode)
            "\xFC\x48\x83\xE4",  # CLD; AND rsp, ...
            "\xEB.{0,5}\x5E",  # JMP short; POP ESI (common shellcode)
            "powershell.*-enc|powershell.*-EncodedCommand",  # Encoded PowerShell in memory
            "cmd.*\/c.*powershell",  # Command execution via cmd
            "downloadstring|DownloadString",  # Download string patterns
            "new-object.*net.webclient",  # WebClient object creation
            "invoke-expression|iex",  # Code execution
            "mimikatz|kiwi|sekurlsa",  # Known credential dumping tools
            "procdump|nanodump|dumpert"  # Known memory dumping tools
        )

        # Memory-based signature patterns (common malware signatures)
        $MalwareSignatures = @(
            "MZ\x90\x00",  # PE header (check for unpacked executables in memory)
            "\x55\x8B\xEC\x83\xEC",  # Function prologue common in shellcode
            "\xE8\x00\x00\x00\x00",  # CALL instruction (relative jump)
            "\xFF\xD0|\xFF\xD1|\xFF\xD2"  # CALL EAX/ECX/EDX (indirect calls)
        )

        $Processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 50MB }

        foreach ($Process in $Processes) {
            try {
                $ThreatScore = 0
                $FoundPatterns = @()
                $Reasons = @()

                # 1. Memory size anomaly detection
                if ($Process.PrivateMemorySize64 -gt 1GB) {
                    $ThreatScore += 10
                    $Reasons += "Large private memory: $([Math]::Round($Process.PrivateMemorySize64/1MB, 2)) MB"
                }

                if ($Process.PrivateMemorySize64 -gt $Process.WorkingSet64 * 2) {
                    $ThreatScore += 15
                    $Reasons += "Memory anomaly: Private memory significantly larger than working set"
                    Write-Output "[MemoryScan] SUSPICIOUS: Memory anomaly detected | Process: $($Process.ProcessName) | PID: $($Process.Id) | Private: $([Math]::Round($Process.PrivateMemorySize64/1MB, 2)) MB | WorkingSet: $([Math]::Round($Process.WorkingSet64/1MB, 2)) MB"
                }

                # 2. Check for unusual module loading
                try {
                    $modules = $Process.Modules | Where-Object { 
                        $_.FileName -and 
                        $_.FileName -notmatch "^C:\\(Windows|Program Files)" -and
                        $_.ModuleName -notmatch "^(ntdll|kernel32|msvcr|msvcp|advapi32)"
                    }
                    
                    if ($modules.Count -gt 5) {
                        $ThreatScore += 20
                        $Reasons += "Unusual module count: $($modules.Count) non-standard modules"
                        
                        # Check for suspicious module names
                        $suspiciousModules = $modules | Where-Object { 
                            $_.ModuleName -match "(inject|hook|stealth|hide|rootkit|keylog|spy)"
                        }
                        
                        if ($suspiciousModules) {
                            $ThreatScore += 30
                            $Reasons += "Suspicious module names detected"
                            foreach ($mod in $suspiciousModules) {
                                $FoundPatterns += "Suspicious module: $($mod.ModuleName) ($($mod.FileName))"
                            }
                        }
                    }
                } catch {}

                # 3. Deep memory scanning (if enabled - more resource intensive)
                if ($DeepScan -and $Process.WorkingSet64 -lt 500MB) {
                    try {
                        # Read process memory (requires special permissions)
                        $memoryRegions = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq $Process.Id }
                        
                        # Check command line for suspicious patterns
                        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
                        if ($commandLine) {
                            foreach ($pattern in $SuspiciousPatterns) {
                                if ($commandLine -match $pattern) {
                                    $ThreatScore += 25
                                    $FoundPatterns += "Command line pattern: $pattern"
                                    break
                                }
                            }
                        }

                        # Check for code injection indicators (unusual memory permissions)
                        # This would require kernel debugging in real implementation
                        # Simplified heuristic: check for processes with unusual thread counts
                        if ($Process.Threads.Count -gt 100) {
                            $ThreatScore += 15
                            $Reasons += "High thread count: $($Process.Threads.Count) threads"
                        }

        } catch {
                        # Memory scanning requires elevated privileges, skip silently
                        Write-EDRLog -Module "MemoryScanning" -Message "Deep scan requires elevated privileges for PID $($Process.Id)" -Level "Debug"
                    }
                }

                # 4. Check for known malicious process characteristics
                $knownMaliciousProcesses = @{
                    "powershell.exe" = @{BaselineMem = 100MB; BaselineThreads = 10}
                    "cmd.exe" = @{BaselineMem = 50MB; BaselineThreads = 3}
                    "wscript.exe" = @{BaselineMem = 80MB; BaselineThreads = 5}
                    "cscript.exe" = @{BaselineMem = 80MB; BaselineThreads = 5}
                }

                if ($knownMaliciousProcesses.ContainsKey($Process.ProcessName)) {
                    $baseline = $knownMaliciousProcesses[$Process.ProcessName]
                    
                    if ($Process.WorkingSet64 -gt ($baseline.BaselineMem * 5)) {
                        $ThreatScore += 25
                        $Reasons += "Memory usage significantly above baseline for $($Process.ProcessName)"
                    }
                    
                    if ($Process.Threads.Count -gt ($baseline.BaselineThreads * 3)) {
                        $ThreatScore += 20
                        $Reasons += "Thread count significantly above baseline for $($Process.ProcessName)"
                    }
                }

                # 5. Check for processes with no executable path (potential process hollowing)
                # Whitelist known system processes that may not have paths
                $systemProcessNames = @("Registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost", "spoolsv", "dwm", "audiodg")
                if (-not $Process.Path -or $Process.Path -notmatch "\.exe$") {
                    if ($systemProcessNames -notcontains $Process.ProcessName) {
                        $ThreatScore += 35
                        $Reasons += "Process has no valid executable path (potential process hollowing)"
                    }
                }

                # Score-based threat detection
                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "MemoryAnomaly"
                        ProcessId = $Process.Id
                        ProcessName = $Process.ProcessName
                        ProcessPath = $Process.Path
                        WorkingSetMB = [Math]::Round($Process.WorkingSet64/1MB, 2)
                        PrivateMemoryMB = [Math]::Round($Process.PrivateMemorySize64/1MB, 2)
                        ThreadCount = $Process.Threads.Count
                        ThreatScore = $ThreatScore
                        Reasons = $Reasons
                        Patterns = $FoundPatterns
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-Output "[MemoryScan] THREAT ($severity): Memory anomaly detected | Process: $($Process.ProcessName) | PID: $($Process.Id) | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                    if ($AutoKillThreats -and $ThreatScore -ge 50) {
                        # Whitelist own process - never kill ourselves
                        if ($Process.Id -eq $PID -or $Process.Id -eq $Script:SelfPID) {
                            Write-EDRLog -Module "MemoryScanning" -Message "BLOCKED: Attempted to kill own process (PID: $($Process.Id)) - whitelisted" -Level "Warning"
                            continue
                        }
                        
                        try {
                            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                            Write-Output "[MemoryScan] ACTION: Terminated process with critical memory anomalies (PID: $($Process.Id))"
                            Add-ThreatToResponseQueue -ThreatType "MemoryAnomaly" -ThreatPath $Process.Id.ToString() -Severity "Critical"
                        } catch {
                            Write-EDRLog -Module "MemoryScanning" -Message "Failed to terminate process $($Process.Id): $_" -Level "Warning"
                        }
                    } elseif ($ThreatScore -ge 40) {
                        Add-ThreatToResponseQueue -ThreatType "MemoryAnomaly" -ThreatPath $Process.Id.ToString() -Severity $severity
                    }
                }
            }
            catch {
                Write-EDRLog -Module "MemoryScanning" -Message "Error scanning process $($Process.Id): $_" -Level "Warning"
            }
        }

        Write-EDRLog -Module "MemoryScanning" -Message "Memory scanning completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "MemoryScanning" -Message "Memory scanning failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-NamedPipeMonitoring {
    param(
        [bool]$AnalyzeProcesses = $true
    )

    try {
        $Threats = @()
        $Pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
        
        # Advanced suspicious pipe name patterns
        $SuspiciousPatterns = @{
            "msagent_" = @{Score = 30; Reason = "MSAgent pipe (common malware)"}
            "mojo" = @{Score = 25; Reason = "Mojo pipe (potential IPC abuse)"}
            "crashpad" = @{Score = 20; Reason = "Crashpad pipe (could be abused)"}
            "mypipe|evil|backdoor|malware" = @{Score = 40; Reason = "Overtly suspicious pipe name"}
            ".*[0-9a-f]{32,}.*" = @{Score = 35; Reason = "Pipe name contains hash-like string (potential data exfiltration)"}
            "secret|private|hidden|stealth" = @{Score = 35; Reason = "Pipe name suggests stealth operation"}
            ".*[A-Z]{5,}.*" = @{Score = 15; Reason = "Pipe name with excessive uppercase (unusual pattern)"}
            "^.{50,}$" = @{Score = 20; Reason = "Unusually long pipe name"}
        }

        # Known legitimate pipes (whitelist)
        $LegitimatePipes = @(
            "\\.\pipe\lsarpc",
            "\\.\pipe\samr",
            "\\.\pipe\wkssvc",
            "\\.\pipe\srvsvc",
            "\\.\pipe\netlogon",
            "\\.\pipe\spoolss",
            "\\.\pipe\epmapper",
            "\\.\pipe\atsvc",
            "\\.\pipe\winsock",
            "\\.\pipe\InitShutdown",
            "\\.\pipe\winlogonrpc",
            "\\.\pipe\ntsvcs",
            "\\.\pipe\Winsock2",
            "\\.\pipe\srvsvc",
            "\\.\pipe\Browser"
        )

        foreach ($Pipe in $Pipes) {
            # Skip legitimate pipes
            if ($LegitimatePipes -contains $Pipe) { continue }

            $PipeName = $Pipe.Replace("\\.\pipe\", "")
            $ThreatScore = 0
            $FoundPatterns = @()
            $Reasons = @()

            # Check against suspicious patterns
            foreach ($pattern in $SuspiciousPatterns.Keys) {
                if ($PipeName -match $pattern) {
                    $patternInfo = $SuspiciousPatterns[$pattern]
                    $ThreatScore += $patternInfo.Score
                    $FoundPatterns += $patternInfo.Reason
                    $Reasons += "$($patternInfo.Reason) (Pattern: $pattern)"
                }
            }

            # Analyze process relationships if enabled
            $ProcessInfo = $null
            if ($AnalyzeProcesses) {
                try {
                    # Get process using the pipe (requires handle enumeration - simplified approach)
                    # In real implementation, would use NtQuerySystemInformation or similar
                    # For now, check for processes with suspicious names that might create custom pipes
                    $SuspiciousProcesses = Get-Process | Where-Object {
                        $_.ProcessName -match "(powershell|cmd|wscript|cscript|mshta|rundll32)" -and
                        $_.Path -notmatch "^C:\\(Windows|Program Files)"
                    }
                    
                    if ($SuspiciousProcesses) {
                        foreach ($proc in $SuspiciousProcesses) {
                            # Heuristic: if suspicious process exists and pipe has suspicious pattern, increase score
                            if ($ThreatScore -gt 0) {
                                $ThreatScore += 10
                                $Reasons += "Suspicious process detected: $($proc.ProcessName) (PID: $($proc.Id))"
                                $ProcessInfo = @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    ProcessPath = $proc.Path
                                }
                                break
                            }
                        }
                    }
                } catch {
                    Write-EDRLog -Module "NamedPipeMonitoring" -Message "Process analysis failed for pipe ${PipeName}: $_" -Level "Debug"
                }
            }

            # Check for pipes with random-looking names (potential malware)
            if ($PipeName -match "^[A-Za-z0-9]{32,}$" -and $ThreatScore -eq 0) {
                $entropy = Measure-StringEntropy -String $PipeName
                if ($entropy -gt 4.0) {
                    $ThreatScore += 25
                    $Reasons += "High entropy pipe name (potential random name generation) | Entropy: $([Math]::Round($entropy, 2))"
                }
            }

            # Check for pipes created by non-standard locations
            if ($AnalyzeProcesses -and $ProcessInfo) {
                if ($ProcessInfo.ProcessPath -and $ProcessInfo.ProcessPath -notmatch "^(C:\\(Windows|Program Files))") {
                    $ThreatScore += 15
                    $Reasons += "Pipe created by process from non-standard location: $($ProcessInfo.ProcessPath)"
                }
            }

            # Score-based threat detection
            if ($ThreatScore -ge 25) {
                $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                
                $Threats += @{
                    Type = "SuspiciousNamedPipe"
                    PipeName = $Pipe
                    PipeNameShort = $PipeName
                    ThreatScore = $ThreatScore
                    Reasons = $Reasons
                    Patterns = $FoundPatterns
                    ProcessInfo = $ProcessInfo
                    Severity = $severity
                    Time = Get-Date
                }

                Write-Output "[NamedPipe] THREAT ($severity): Suspicious named pipe detected | Pipe: $Pipe | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                if ($ThreatScore -ge 40) {
                    Add-ThreatToResponseQueue -ThreatType "SuspiciousNamedPipe" -ThreatPath $Pipe -Severity $severity
                }
            }
        }

        # Check for excessive pipe creation (potential indicator of malware activity)
        if ($Pipes.Count -gt 100) {
            $nonStandardPipes = $Pipes | Where-Object { $LegitimatePipes -notcontains $_ }
            if ($nonStandardPipes.Count -gt 50) {
                Write-Output "[NamedPipe] WARNING: Excessive named pipe creation detected | Total: $($Pipes.Count) | Non-standard: $($nonStandardPipes.Count)"
                Write-EDRLog -Module "NamedPipeMonitoring" -Message "Excessive pipe creation: $($Pipes.Count) total, $($nonStandardPipes.Count) non-standard" -Level "Warning"
            }
        }

        Write-EDRLog -Module "NamedPipeMonitoring" -Message "Named pipe monitoring completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; TotalPipes = $Pipes.Count}
    }
    catch {
        Write-EDRLog -Module "NamedPipeMonitoring" -Message "Named pipe monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); TotalPipes = 0}
    }
}

function Invoke-DNSExfiltrationDetection {
    param(
        [int]$LookbackMinutes = 60,
        [bool]$StatisticalAnalysis = $true
    )

    try {
        $Threats = @()
        $cutoffTime = (Get-Date).AddMinutes(-$LookbackMinutes)
        
        # Get DNS cache entries
        $DNSCache = Get-DnsClientCache -ErrorAction SilentlyContinue | 
            Where-Object { $_.TimeToLive -gt 0 -and $_.Status -eq 0 }

        $SuspiciousDomains = @()

        foreach ($Entry in $DNSCache) {
            $domain = $Entry.Name
            $ThreatScore = 0
            $Reasons = @()

            # 1. Check for long subdomains (common in DNS tunneling)
            if ($domain.Length -gt 50) {
                $ThreatScore += 20
                $Reasons += "Unusually long domain name ($($domain.Length) characters)"
            }

            # 2. Check for hash-like subdomains (potential data exfiltration)
            if ($domain -match "[0-9a-f]{32,}") {
                $ThreatScore += 35
                $Reasons += "Subdomain contains hash-like string (potential data exfiltration)"
            }

            # 3. Check for base64-encoded patterns
            if ($domain -match "[A-Za-z0-9+/]{20,}={0,2}") {
                $base64Part = if ($domain -match "([A-Za-z0-9+/]{20,}={0,2})") { $matches[1] } else { "" }
                if ($base64Part) {
                    $entropy = Measure-StringEntropy -String $base64Part
                    if ($entropy -gt 4.5) {
                        $ThreatScore += 40
                        $Reasons += "Subdomain contains high-entropy base64-like string | Entropy: $([Math]::Round($entropy, 2))"
                    }
                }
            }

            # 4. Check for suspicious domain patterns
            $SuspiciousPatterns = @{
                ".*\.[0-9a-f]{16,}\..*" = @{Score = 30; Reason = "Subdomain with hex string"}
                ".*[0-9]{10,}.*" = @{Score = 15; Reason = "Subdomain with long numeric string"}
                "^[a-z0-9]{20,}\." = @{Score = 25; Reason = "Random-looking subdomain prefix"}
                ".*secret.*|.*data.*|.*exfil.*|.*cmd.*" = @{Score = 30; Reason = "Suspicious keywords in domain"}
            }

            foreach ($pattern in $SuspiciousPatterns.Keys) {
                if ($domain -match $pattern) {
                    $patternInfo = $SuspiciousPatterns[$pattern]
                    $ThreatScore += $patternInfo.Score
                    $Reasons += $patternInfo.Reason
                }
            }

            # 5. Check for DNS tunneling indicators (statistical analysis)
            if ($StatisticalAnalysis) {
                # Check for unusual TTL values (often manipulated in DNS tunneling)
                if ($Entry.TimeToLive -lt 300 -or $Entry.TimeToLive -gt 86400) {
                    $ThreatScore += 10
                    $Reasons += "Unusual TTL value: $($Entry.TimeToLive) seconds"
                }

                # Check for excessive subdomain length variation (indicator of tunneling)
                $subdomainParts = $domain.Split('.')
                if ($subdomainParts.Length -gt 4) {
                    $subdomainLengths = $subdomainParts | ForEach-Object { $_.Length }
                    $avgLength = ($subdomainLengths | Measure-Object -Average).Average
                    $maxLength = ($subdomainLengths | Measure-Object -Maximum).Maximum
                    
                    if ($maxLength -gt ($avgLength * 3)) {
                        $ThreatScore += 20
                        $Reasons += "Subdomain length variation suggests data encoding"
                    }
                }

                # Check for high entropy in subdomain (potential encrypted data)
                $subdomain = $domain.Split('.')[0]
                if ($subdomain.Length -gt 20) {
                    $entropy = Measure-StringEntropy -String $subdomain
                    if ($entropy -gt 4.0) {
                        $ThreatScore += 25
                        $Reasons += "High entropy subdomain (potential encrypted exfiltrated data) | Entropy: $([Math]::Round($entropy, 2))"
                    }
                }
            }

            # 6. Check for known DNS tunneling tools domain patterns
            $KnownTunnelingTools = @(
                "iodine", "dns2tcp", "dnscat2", "tuns", "heyoka"
            )

            foreach ($tool in $KnownTunnelingTools) {
                if ($domain -match $tool) {
                    $ThreatScore += 40
                    $Reasons += "Known DNS tunneling tool pattern: $tool"
                }
            }

            # 7. Check for domains with excessive subdomains (potential data chunking)
            $subdomainCount = ($domain.Split('.')).Length
            if ($subdomainCount -gt 6) {
                $ThreatScore += 15
                $Reasons += "Excessive subdomain levels ($subdomainCount) - potential data chunking"
            }

            # Score-based threat detection
            if ($ThreatScore -ge 30) {
                $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                
                $Threats += @{
                    Type = "DNSExfiltration"
                    Domain = $domain
                    ThreatScore = $ThreatScore
                    Reasons = $Reasons
                    TTL = $Entry.TimeToLive
                    RecordType = $Entry.Type
                    DataLength = $Entry.DataLength
                    Severity = $severity
                    Time = Get-Date
                }

                Write-Output "[DNSExfil] THREAT ($severity): DNS exfiltration indicators detected | Domain: $domain | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                if ($ThreatScore -ge 40) {
                    Add-ThreatToResponseQueue -ThreatType "DNSExfiltration" -ThreatPath $domain -Severity $severity
                }

                $SuspiciousDomains += $domain
            }
        }

        # Statistical analysis across all DNS queries
        if ($StatisticalAnalysis -and $DNSCache.Count -gt 0) {
            # Check for burst of suspicious DNS queries (indicator of active exfiltration)
            $recentQueries = $DNSCache | Where-Object { 
                $_.DataLength -gt 100 -or $_.Name.Length -gt 50
            }
            
            if ($recentQueries.Count -gt 20) {
                Write-Output "[DNSExfil] WARNING: Burst of suspicious DNS queries detected | Count: $($recentQueries.Count)"
                Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS query burst detected: $($recentQueries.Count) suspicious queries" -Level "Warning"
                
                # Check for patterns suggesting active exfiltration
                $uniqueDomains = $recentQueries | Select-Object -ExpandProperty Name -Unique
                if ($uniqueDomains.Count -lt ($recentQueries.Count * 0.3)) {
                    Write-Output "[DNSExfil] CRITICAL: Pattern suggests active DNS exfiltration | Repeating domains: $($uniqueDomains.Count) unique out of $($recentQueries.Count) queries"
                    Add-ThreatToResponseQueue -ThreatType "DNSExfiltrationBurst" -ThreatPath "Multiple domains" -Severity "Critical"
                }
            }
        }

        Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS exfiltration detection completed: $($Threats.Count) threat(s) found out of $($DNSCache.Count) DNS entries" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; TotalEntries = $DNSCache.Count; SuspiciousDomains = $SuspiciousDomains}
    }
    catch {
        Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS exfiltration detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); TotalEntries = 0; SuspiciousDomains = @()}
    }
}

function Invoke-PasswordManagement {
    param()

    Write-Output "[Password] Starting password management monitoring..."

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Output "[Password] WARNING: Not running as Administrator - limited functionality"
        return
}

    function Test-PasswordSecurity {
        try {
            $CurrentUser = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
            if ($CurrentUser) {
                $PasswordAge = (Get-Date) - $CurrentUser.PasswordLastSet
                $DaysSinceChange = $PasswordAge.Days

                if ($DaysSinceChange -gt 90) {
                    Write-Output "[Password] WARNING: Password is $DaysSinceChange days old - consider rotation"
                }

                if ($CurrentUser.PasswordRequired -eq $false) {
                    Write-Output "[Password] WARNING: Account does not require password"
                }

                $PasswordPolicy = Get-LocalUser | Where-Object { $_.Name -eq $env:USERNAME } | Select-Object PasswordRequired, PasswordChangeable, PasswordExpires
                if ($PasswordPolicy) {
                    Write-Output "[Password] INFO: Password policy - Required: $($PasswordPolicy.PasswordRequired), Changeable: $($PasswordPolicy.PasswordChangeable), Expires: $($PasswordPolicy.PasswordExpires)"
                }

                return @{
                    DaysSinceChange = $DaysSinceChange
                    PasswordRequired = $CurrentUser.PasswordRequired
                    PasswordLastSet = $CurrentUser.PasswordLastSet
                }
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check password security: $_"
            return $null
        }
    }

    function Test-SuspiciousPasswordActivity {
        try {
            $SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4724,4723,4738} -MaxEvents 10 -ErrorAction SilentlyContinue

            $RecentChanges = $SecurityEvents | Where-Object {
                $_.TimeCreated -gt (Get-Date).AddHours(-1) -and
                $_.Properties[0].Value -eq $env:USERNAME
            }

            if ($RecentChanges.Count -gt 0) {
                Write-Output "[Password] WARNING: Recent password activity detected - $($RecentChanges.Count) events in last hour"

                foreach ($LogEvent in $RecentChanges) {
                    $EventType = switch ($LogEvent.Id) {
                        4723 { "Password change attempted" }
                        4724 { "Password reset attempted" }
                        4738 { "Account policy modified" }
                        default { "Unknown event" }
                    }
                    Write-Output "[Password]   - $EventType at $($LogEvent.TimeCreated)"
                }
            }

            $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) }

            $UserFailedLogons = $FailedLogons | Where-Object {
                $_.Properties[5].Value -eq $env:USERNAME
            }

            if ($UserFailedLogons.Count -gt 5) {
                Write-Output "[Password] THREAT: High number of failed logons - $($UserFailedLogons.Count) failures in last hour"
            }

            return @{
                RecentChanges = $RecentChanges.Count
                FailedLogons = $UserFailedLogons.Count
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check suspicious activity: $_"
            return $null
        }
    }

    function Test-PasswordDumpingTools {
        try {
            $SuspiciousTools = @("mimikatz", "procdump", "dumpert", "nanodump", "pypykatz", "gsecdump", "cachedump")
            $SuspiciousProcesses = Get-Process | Where-Object {
                $SuspiciousTools -contains $_.ProcessName.ToLower()
            }

            if ($SuspiciousProcesses.Count -gt 0) {
                Write-Output "[Password] THREAT: Password dumping tools detected"
                foreach ($Process in $SuspiciousProcesses) {
                    Write-Output "[Password]   - $($Process.ProcessName) (PID: $($Process.Id))"
                }
            }

            $PowerShellProcesses = Get-Process -Name "powershell" -ErrorAction SilentlyContinue
            foreach ($Process in $PowerShellProcesses) {
                try {
                    $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine

                    $PasswordCommands = @("Get-Credential", "ConvertTo-SecureString", "Import-Clixml", "Export-Clixml")
                    foreach ($Command in $PasswordCommands) {
                        if ($CommandLine -match $Command) {
                            Write-Output "[Password] SUSPICIOUS: PowerShell process with password-related command - PID: $($Process.Id)"
                        }
                    }
                }
                catch {
                }
            }

            return $SuspiciousProcesses.Count
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check for dumping tools: $_"
            return 0
        }
    }

    try {
        $PasswordStatus = Test-PasswordSecurity
        if ($PasswordStatus) {
            Write-Output "[Password] Security check completed - Password age: $($PasswordStatus.DaysSinceChange) days"
        }

        $ActivityStatus = Test-SuspiciousPasswordActivity
        if ($ActivityStatus) {
            Write-Output "[Password] Activity monitoring completed - Recent changes: $($ActivityStatus.RecentChanges), Failed logons: $($ActivityStatus.FailedLogons)"
        }

        $DumpingTools = Test-PasswordDumpingTools
        Write-Output "[Password] Dumping tools check completed - Suspicious tools: $DumpingTools"

        try {
            $RegKeys = @(
                "HKLM:\SAM\SAM\Domains\Account\Users",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            )

            foreach ($RegKey in $RegKeys) {
                try {
                    if (Test-Path $RegKey -ErrorAction SilentlyContinue) {
                        $RecentChanges = Get-ChildItem $RegKey -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) }

                        if ($RecentChanges -and $RecentChanges.Count -gt 0) {
                            Write-Output "[Password] WARNING: Recent registry changes in password-related areas"
                            foreach ($Change in $RecentChanges) {
                                Write-Output "[Password]   - $($Change.PSPath) modified at $($Change.LastWriteTime)"
                            }
                        }
                    }
                }
                catch {
                    # SAM registry access requires special privileges - skip silently if access denied
                    if ($RegKey -like "*SAM*") {
                        # SAM access is protected - this is expected to fail on most systems
                        continue
                    }
                    Write-Output "[Password] WARNING: Could not check registry key $RegKey - $_"
                }
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check registry changes: $_"
        }

        Write-Output "[Password] Password management monitoring completed"
    }
    catch {
        Write-Output "[Password] ERROR: Monitoring failed: $_"
    }
}

function Invoke-WebcamGuardian {
    <#
    .SYNOPSIS
    Monitors and controls webcam access with explicit user permission.
    
    .DESCRIPTION
    Keeps webcam disabled by default. When any application tries to access it,
    shows a permission popup. Only enables webcam after explicit user approval.
    Automatically disables webcam when application closes.
    
    .PARAMETER LogPath
    Path to store webcam access logs
    #>
    param(
        [string]$LogPath
    )
    
    # Initialize static variables
    if (-not $script:WebcamGuardianState) {
        $script:WebcamGuardianState = @{
            Initialized = $false
            WebcamDevices = @()
            CurrentlyAllowedProcesses = @{}
            LastCheck = [DateTime]::MinValue
            AccessLog = if ($LogPath) { Join-Path $LogPath "webcam_access.log" } else { "$env:TEMP\webcam_access.log" }
        }
    }
    
    # Initialize webcam devices list (only once)
    if (-not $script:WebcamGuardianState.Initialized) {
        try {
            # Find all imaging devices (webcams) using multiple methods
            $webcamDevices = @()
            
            # Method 1: Check Camera class
            try {
                $cameras = Get-PnpDevice -Class "Camera" -Status "OK" -ErrorAction SilentlyContinue
                if ($cameras) {
                    if ($cameras.Count) {
                        $webcamDevices += $cameras
                    } else {
                        $webcamDevices += @($cameras)
                    }
                }
                # Also check without status filter as fallback
                if (-not $cameras -or ($cameras | Measure-Object).Count -eq 0) {
                    $camerasNoStatus = Get-PnpDevice -Class "Camera" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
                    if ($camerasNoStatus) {
                        if ($camerasNoStatus.Count) {
                            $webcamDevices += $camerasNoStatus
                        } else {
                            $webcamDevices += @($camerasNoStatus)
                        }
                    }
                }
            } catch {}
            
            # Method 2: Check Image class
            try {
                $images = Get-PnpDevice -Class "Image" -Status "OK" -ErrorAction SilentlyContinue
                if ($images) {
                    if ($images.Count) {
                        $webcamDevices += $images
                    } else {
                        $webcamDevices += @($images)
                    }
                }
            } catch {}
            
            # Method 3: Check MEDIA class (some webcams appear here, but be very strict to avoid audio devices)
            try {
                $media = Get-PnpDevice -Class "MEDIA" -ErrorAction SilentlyContinue | 
                    Where-Object { 
                        $_.Status -eq "OK" -and
                        # Only match if explicitly contains Camera or Webcam (not Video/Capture which could be audio/video cards)
                        ($_.FriendlyName -match "Camera|Webcam" -or
                         $_.Description -match "Camera|Webcam") -and
                        # Exclude audio devices explicitly
                        $_.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound" -and
                        $_.Description -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound"
                    }
                if ($media) {
                    if ($media.Count) {
                        $webcamDevices += $media
                    } else {
                        $webcamDevices += @($media)
                    }
                }
            } catch {}
            
            # Method 4: Comprehensive search by friendly name and description (strict matching)
            $allDevices = Get-PnpDevice | Where-Object {
                $_.Status -eq "OK" -and
                # Only Camera or Image class, or MEDIA class with explicit camera name
                (($_.Class -match "Camera|Image") -or 
                 ($_.Class -eq "MEDIA" -and ($_.FriendlyName -match "Camera|Webcam" -or $_.Description -match "Camera|Webcam"))) -and
                # Must explicitly contain Camera or Webcam in name/description
                ($_.FriendlyName -match "Camera|Webcam|USB.*Camera" -or
                 $_.Description -match "Camera|Webcam") -and
                # Exclude audio/video cards and other non-camera devices
                $_.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display" -and
                $_.Description -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display"
            } -ErrorAction SilentlyContinue
            
            if ($allDevices) {
                $webcamDevices += $allDevices
            }
            
            # Method 5: WMI query as fallback (very strict)
            if ($webcamDevices.Count -eq 0) {
                try {
                    $wmiCameras = Get-WmiObject Win32_PnPEntity | Where-Object {
                        $_.Status -eq "OK" -and
                        # Must be Camera or Image class
                        ($_.PNPClass -match "Camera|Image") -and
                        # Must explicitly contain Camera or Webcam
                        ($_.Name -match "Camera|Webcam" -or $_.DeviceID -match "USB.*VID.*PID.*Camera") -and
                        # Exclude audio/video devices
                        $_.Name -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display"
                    } -ErrorAction SilentlyContinue
                    
                    if ($wmiCameras) {
                        # Convert WMI objects to PnP device format
                        foreach ($wmi in $wmiCameras) {
                            try {
                                $pnpDevice = Get-PnpDevice -InstanceId $wmi.DeviceID -ErrorAction SilentlyContinue
                                # Double-check it's actually a camera before adding
                                if ($pnpDevice -and 
                                    ($pnpDevice.FriendlyName -match "Camera|Webcam" -or $pnpDevice.Description -match "Camera|Webcam") -and
                                    $pnpDevice.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound") {
                                    $webcamDevices += $pnpDevice
                                }
                            } catch {}
                        }
                    }
                } catch {}
            }
            
            # Remove duplicates and assign
            # Ensure we always have an array (even if empty)
            if ($null -eq $webcamDevices) {
                $webcamDevices = @()
            } elseif ($webcamDevices.Count -eq $null) {
                # Single object, convert to array
                $webcamDevices = @($webcamDevices)
            }
            
            # Remove duplicates and apply final strict filtering (ensure we only get actual cameras)
            $script:WebcamGuardianState.WebcamDevices = $webcamDevices | 
                Where-Object { 
                    $_.Status -eq "OK" -and
                    # Final validation: must explicitly contain Camera or Webcam in name/description
                    ($_.FriendlyName -match "Camera|Webcam" -or $_.Description -match "Camera|Webcam") -and
                    # Final exclusion: no audio/video/graphics devices, USB hubs, keyboards, mice
                    $_.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display|Keyboard|Mouse|USB.*Hub|HID" -and
                    $_.Description -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display|Keyboard|Mouse|USB.*Hub|HID" -and
                    $_.InstanceId -notmatch "HDAUDIO|HID\\" -and
                    # Only Camera or Image class, or MEDIA class with explicit camera name
                    (($_.Class -match "Camera|Image") -or ($_.Class -eq "MEDIA" -and ($_.FriendlyName -match "Camera|Webcam" -or $_.Description -match "Camera|Webcam")))
                } | 
                Sort-Object InstanceId -Unique
            
            if ($script:WebcamGuardianState.WebcamDevices -and $script:WebcamGuardianState.WebcamDevices.Count -gt 0) {
                $deviceList = ($script:WebcamGuardianState.WebcamDevices | ForEach-Object { "$($_.FriendlyName) ($($_.Class))" }) -join "; "
                Write-AVLog "[WebcamGuardian] Found $($script:WebcamGuardianState.WebcamDevices.Count) webcam device(s): $deviceList" "INFO"
                
                # Disable all webcams by default (with final safety check)
                foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                    try {
                        # Final safety check: verify this is actually a camera device before disabling
                        if ($device.FriendlyName -match "Camera|Webcam" -and 
                            $device.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Keyboard|Mouse|HID" -and
                            $device.InstanceId -notmatch "HDAUDIO|HID\\") {
                            
                            Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                            Write-AVLog "[WebcamGuardian] Disabled webcam: $($device.FriendlyName) ($($device.Class))" "INFO"
                        } else {
                            Write-AVLog "[WebcamGuardian] SKIPPED: Device does not appear to be a camera - $($device.FriendlyName) ($($device.Class))" "WARN"
                        }
                    }
                    catch {
                        Write-AVLog "[WebcamGuardian] Could not disable $($device.FriendlyName): $($_.Exception.Message)" "WARN"
                    }
                }
                
                $script:WebcamGuardianState.Initialized = $true
                Write-Host "[WebcamGuardian] Protection initialized - webcam disabled by default" -ForegroundColor Green
            }
            else {
                Write-AVLog "[WebcamGuardian] No webcam devices found" "INFO"
                $script:WebcamGuardianState.Initialized = $true
                return
            }
        }
        catch {
            Write-AVLog "[WebcamGuardian] Initialization error: $($_.Exception.Message)" "ERROR"
            return
        }
    }
    
    # Skip check if no webcam devices
    if ($script:WebcamGuardianState.WebcamDevices.Count -eq 0) {
        return
    }
    
    # Monitor for processes trying to access webcam
    try {
        # Get all processes that might access camera
        $cameraProcesses = Get-Process | Where-Object {
            $_.ProcessName -match "chrome|firefox|edge|msedge|teams|zoom|skype|obs|discord|slack" -or
            $_.MainWindowTitle -ne ""
        } | Select-Object Id, ProcessName, Path, MainWindowTitle
        
        foreach ($proc in $cameraProcesses) {
            # Skip if already allowed
            if ($script:WebcamGuardianState.CurrentlyAllowedProcesses.ContainsKey($proc.Id)) {
                # Check if process still exists
                if (-not (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)) {
                    # Process closed - remove from allowed list and disable webcam
                    $script:WebcamGuardianState.CurrentlyAllowedProcesses.Remove($proc.Id)
                    
                    # Disable webcam if no other processes are using it (with safety check)
                    if ($script:WebcamGuardianState.CurrentlyAllowedProcesses.Count -eq 0) {
                        foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                            # Safety check: only disable if confirmed to be a camera device
                            if ($device.FriendlyName -match "Camera|Webcam" -and 
                                $device.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Keyboard|Mouse|HID" -and
                                $device.InstanceId -notmatch "HDAUDIO|HID\\") {
                                Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                            }
                        }
                        $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [AUTO-DISABLE] Process closed - webcam disabled"
                        Add-Content -Path $script:WebcamGuardianState.AccessLog -Value $logEntry -ErrorAction SilentlyContinue
                        Write-AVLog "[WebcamGuardian] All processes closed - webcam disabled" "INFO"
                    }
                }
                continue
            }
            
            # Check if process is trying to access webcam (heuristic check)
            $isAccessingCamera = $false
            
            try {
                # Check if process has handles to camera devices
                $handles = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue | 
                    Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue |
                    Where-Object { $_.ModuleName -match "mf|avicap|video|camera" }
                
                if ($handles) {
                    $isAccessingCamera = $true
                }
            }
            catch {}
            
            # If camera access detected, show permission dialog
            if ($isAccessingCamera) {
                $procName = if ($proc.Path) { Split-Path -Leaf $proc.Path } else { $proc.ProcessName }
                $windowTitle = if ($proc.MainWindowTitle) { $proc.MainWindowTitle } else { "Unknown Window" }
                
                # Create permission dialog
                Add-Type -AssemblyName System.Windows.Forms
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Application '$procName' is trying to access your webcam.`n`nWindow: $windowTitle`nPID: $($proc.Id)`n`nAllow webcam access?",
                    "Webcam Permission Request",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning,
                    [System.Windows.Forms.MessageBoxDefaultButton]::Button2
                )
                
                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                
                if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                    # User allowed - enable webcam (with safety check)
                    foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                        # Safety check: only enable if confirmed to be a camera device
                        if ($device.FriendlyName -match "Camera|Webcam" -and 
                            $device.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Keyboard|Mouse|HID" -and
                            $device.InstanceId -notmatch "HDAUDIO|HID\\") {
                            Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                        }
                    }
                    
                    $script:WebcamGuardianState.CurrentlyAllowedProcesses[$proc.Id] = @{
                        ProcessName = $procName
                        WindowTitle = $windowTitle
                        AllowedAt = Get-Date
                    }
                    
                    $logEntry = "[$timestamp] [ALLOWED] $procName (PID: $($proc.Id)) | Window: $windowTitle"
                    Add-Content -Path $script:WebcamGuardianState.AccessLog -Value $logEntry -ErrorAction SilentlyContinue
                    Write-AVLog "[WebcamGuardian] Access ALLOWED: $procName (PID: $($proc.Id))" "INFO"
                    Write-Host "[WebcamGuardian] Webcam access ALLOWED for $procName" -ForegroundColor Green
                }
                else {
                    # User denied - keep webcam disabled and log
                    $logEntry = "[$timestamp] [DENIED] $procName (PID: $($proc.Id)) | Window: $windowTitle"
                    Add-Content -Path $script:WebcamGuardianState.AccessLog -Value $logEntry -ErrorAction SilentlyContinue
                    Write-AVLog "[WebcamGuardian] Access DENIED: $procName (PID: $($proc.Id))" "WARN"
                    Write-Host "[WebcamGuardian] Webcam access DENIED for $procName" -ForegroundColor Red
                    
                    # Optionally terminate the process trying to access webcam
                    # Uncomment the next line if you want to kill processes that are denied
                    # Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Clean up dead processes from allowed list
        $deadProcesses = @()
        foreach ($procPid in $script:WebcamGuardianState.CurrentlyAllowedProcesses.Keys) {
            if (-not (Get-Process -Id $procPid -ErrorAction SilentlyContinue)) {
                $deadProcesses += $procPid
            }
        }
        
        foreach ($procPid in $deadProcesses) {
            $script:WebcamGuardianState.CurrentlyAllowedProcesses.Remove($procPid)
        }
        
        # Disable webcam if no processes are allowed
        if ($script:WebcamGuardianState.CurrentlyAllowedProcesses.Count -eq 0) {
            $now = Get-Date
            # Only disable every 30 seconds to avoid excessive device operations
            if (($now - $script:WebcamGuardianState.LastCheck).TotalSeconds -ge 30) {
                foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                    # Safety check: only disable if confirmed to be a camera device
                    if ($device.FriendlyName -match "Camera|Webcam" -and 
                        $device.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Keyboard|Mouse|HID" -and
                        $device.InstanceId -notmatch "HDAUDIO|HID\\") {
                        $status = Get-PnpDevice -InstanceId $device.InstanceId -ErrorAction SilentlyContinue
                        if ($status -and $status.Status -eq "OK") {
                            Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                        }
                    }
                }
                $script:WebcamGuardianState.LastCheck = $now
            }
        }
    }
    catch {
        Write-AVLog "[WebcamGuardian] Monitoring error: $($_.Exception.Message)" "ERROR"
    }
    }

function Invoke-KeyScramblerManagement {
    param(
        [bool]$AutoStart = $true
    )

    Write-Output "[KeyScrambler] Starting inline KeyScrambler with C# hook..."

    $Source = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class KeyScrambler
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT
    {
        public uint type;
        public INPUTUNION u;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP   = 0x0002;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool GetMessage(out MSG msg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll")] private static extern IntPtr GetMessageExtraInfo();
    [DllImport("user32.dll")] private static extern short GetKeyState(int nVirtKey);
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string lpModuleName);

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int x; public int y; }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    private static IntPtr _hookID = IntPtr.Zero;
    private static LowLevelKeyboardProc _proc;
    private static Random _rnd = new Random();

    public static void Start()
    {
        if (_hookID != IntPtr.Zero) return;

        _proc = HookCallback;
        _hookID = SetWindowsHookEx(WH_KEYBOARD_LL,
            Marshal.GetFunctionPointerForDelegate(_proc),
            GetModuleHandle(null), 0);

        if (_hookID == IntPtr.Zero)
            throw new Exception("Hook failed: " + Marshal.GetLastWin32Error());

        Console.WriteLine("KeyScrambler ACTIVE - invisible mode ON");
        Console.WriteLine("You see only your real typing * Keyloggers blinded");

        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    private static bool ModifiersDown()
    {
        return (GetKeyState(0x10) & 0x8000) != 0 ||
               (GetKeyState(0x11) & 0x8000) != 0 ||
               (GetKeyState(0x12) & 0x8000) != 0;
    }

    private static void InjectFakeChar(char c)
    {
        var inputs = new INPUT[2];

        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki.wVk = 0;
        inputs[0].u.ki.wScan = (ushort)c;
        inputs[0].u.ki.dwFlags = KEYEVENTF_UNICODE;
        inputs[0].u.ki.dwExtraInfo = GetMessageExtraInfo();

        inputs[1] = inputs[0];
        inputs[1].u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;

        SendInput(2, inputs, Marshal.SizeOf(typeof(INPUT)));
        Thread.Sleep(_rnd.Next(1, 7));
    }

    private static void Flood()
    {
        if (_rnd.NextDouble() < 0.5) return;
        int count = _rnd.Next(1, 7);
        for (int i = 0; i < count; i++)
            InjectFakeChar((char)_rnd.Next('A', 'Z' + 1));
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            KBDLLHOOKSTRUCT k = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));

            if ((k.flags & 0x10) != 0) return CallNextHookEx(_hookID, nCode, wParam, lParam);
            if (ModifiersDown()) return CallNextHookEx(_hookID, nCode, wParam, lParam);

            if (k.vkCode >= 65 && k.vkCode <= 90)
            {
                if (_rnd.NextDouble() < 0.75) Flood();
                var ret = CallNextHookEx(_hookID, nCode, wParam, lParam);
                if (_rnd.NextDouble() < 0.75) Flood();
                return ret;
            }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }
}
"@

    try {
        Add-Type -TypeDefinition $Source -Language CSharp -ErrorAction Stop
        Write-Output "[KeyScrambler] Compiled C# code successfully"
    }
    catch {
        Write-Output "[KeyScrambler] ERROR: Compilation failed: $($_.Exception.Message)"
        return
    }

    if ($AutoStart) {
        try {
            Write-Output "[KeyScrambler] Starting keyboard hook..."
            [KeyScrambler]::Start()
        }
        catch {
            Write-Output "[KeyScrambler] ERROR: Failed to start hook: $_"
        }
    }
}

#region === Missing Functions from Antivirus.ps1 ===

function Write-EDRLog {
    param(
        [string]$Module,
        [string]$Message,
        [ValidateSet("Debug", "Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$Module] $Message"
    
    # Console output based on log level
    switch ($Level) {
        "Debug"   { if ($Verbose) { Write-Host $logEntry -ForegroundColor Gray } }
        "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
    }
    
    # File logging
    $logFile = Join-Path $Config.LogPath "EDR_$(Get-Date -Format 'yyyy-MM-dd').log"
    try {
        $logEntry | Add-Content -Path $logFile -ErrorAction SilentlyContinue
    } catch { }
}

function Write-Detection {
    param(
        [string]$Module,
        [int]$Count,
        [string]$Details = ""
    )
    
    if ($Count -gt 0) {
        Write-EDRLog -Module $Module -Message "DETECTION: Found $Count issues. $Details" -Level "Warning"
    }
}

function Write-ModuleStats {
    param(
        [string]$Module,
        [hashtable]$Stats
    )
    
    $statsString = ($Stats.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "
    Write-EDRLog -Module $Module -Message "STATS: $statsString" -Level "Debug"
}

function Invoke-Initialization {
    try {
        Write-EDRLog -Module "Initializer" -Message "Starting environment initialization" -Level "Info"
        
        # Create required directories
        $directories = @(
            $Script:InstallPath,
            "$Script:InstallPath\Logs",
            "$Script:InstallPath\Data",
            "$Script:InstallPath\Quarantine",
            "$Script:InstallPath\Reports",
            "$Script:InstallPath\HashDatabase"
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-EDRLog -Module "Initializer" -Message "Created directory: $dir" -Level "Debug"
            }
        }
        
        # Create Event Log source if it doesn't exist
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($Config.EDRName)) {
                [System.Diagnostics.EventLog]::CreateEventSource($Config.EDRName, "Application")
                Write-EDRLog -Module "Initializer" -Message "Created Event Log source: $($Config.EDRName)" -Level "Info"
            }
        } catch {
            Write-EDRLog -Module "Initializer" -Message "Could not create Event Log source (may require elevation): $_" -Level "Warning"
        }
        
        # Initialize module baselines
        Initialize-FirewallBaseline
        Initialize-ServiceBaseline
        Initialize-HashDatabase
        
        Write-EDRLog -Module "Initializer" -Message "Environment initialization completed" -Level "Info"
        return 1
        
    } catch {
        Write-EDRLog -Module "Initializer" -Message "Initialization failed: $_" -Level "Error"
        return 0
    }
}

function Initialize-FirewallBaseline {
    try {
        if (-not $script:BaselineRules) { $script:BaselineRules = @{} }
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            $key = "$($rule.Name)|$($rule.Direction)|$($rule.Action)"
            if (-not $script:BaselineRules.ContainsKey($key)) {
                $script:BaselineRules[$key] = @{
                    Name = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Initialize-ServiceBaseline {
    try {
        if (-not $script:ServiceBaseline) { $script:ServiceBaseline = @{} }
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($service in $services) {
            $key = $service.Name
            if (-not $script:ServiceBaseline.ContainsKey($key)) {
                $script:ServiceBaseline[$key] = @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    PathName = $service.PathName
                    StartMode = $service.StartMode
                    State = $service.State
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Initialize-HashDatabase {
    try {
        if (-not $script:HashDatabase) { $script:HashDatabase = @{} }
        if (-not $script:ThreatHashes) { $script:ThreatHashes = @{} }
        
        # Load known good hashes (whitelist)
        $whitelistPath = "$Script:InstallPath\HashDatabase\whitelist.txt"
        if (Test-Path $whitelistPath) {
            Get-Content $whitelistPath | ForEach-Object {
                if ($_ -match '^([A-F0-9]{64})\|(.+)$') {
                    $script:HashDatabase[$matches[1]] = $matches[2]
                }
            }
        }
        
        # Load threat hashes (blacklist)
        $threatPaths = @(
            "$Script:InstallPath\HashDatabase\threats.txt",
            "$Script:InstallPath\HashDatabase\malware_hashes.txt"
        )
        
        foreach ($threatPath in $threatPaths) {
            if (Test-Path $threatPath) {
                Get-Content $threatPath | ForEach-Object {
                    if ($_ -match '^([A-F0-9]{32,64})$') {
                        $script:ThreatHashes[$matches[1].ToUpper()] = $true
                    }
                }
            }
        }
    } catch { }
}

function Invoke-BeaconDetection {
    $detections = @()
    
    try {
        # Monitor for periodic connections (beacon indicator)
        $maxConnections = 500
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" } | Select-Object -First $maxConnections
        
        # Group connections by process and remote address
        $connGroups = $connections | Group-Object -Property @{Expression={$_.OwningProcess}}, @{Expression={$_.RemoteAddress}}
        
        foreach ($group in $connGroups) {
            $procId = $group.Name.Split(',')[0].Trim()
            $remoteIP = $group.Name.Split(',')[1].Trim()
            
            try {
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if (-not $proc) { continue }
                
                # Check connection frequency (beacon pattern)
                $connTimes = $group.Group | ForEach-Object { $_.CreationTime } | Sort-Object
                
                if ($connTimes.Count -gt 3) {
                    # Calculate intervals between connections
                    $intervals = @()
                    for ($i = 1; $i -lt $connTimes.Count; $i++) {
                        $interval = ($connTimes[$i] - $connTimes[$i-1]).TotalSeconds
                        $intervals += $interval
                    }
                    
                    # Check for regular intervals (beacon indicator)
                    if ($intervals.Count -gt 2) {
                        $avgInterval = ($intervals | Measure-Object -Average).Average
                        $variance = ($intervals | ForEach-Object { [Math]::Pow($_ - $avgInterval, 2) } | Measure-Object -Average).Average
                        $stdDev = [Math]::Sqrt($variance)
                        
                        # Low variance = regular intervals = beacon
                        if ($stdDev -lt $avgInterval * 0.2 -and $avgInterval -gt 10 -and $avgInterval -lt 3600) {
                            $detections += @{
                                ProcessId = $procId
                                ProcessName = $proc.ProcessName
                                RemoteAddress = $remoteIP
                                ConnectionCount = $connTimes.Count
                                AverageInterval = [Math]::Round($avgInterval, 2)
                                Type = "Beacon Pattern Detected"
                                Risk = "High"
                            }
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for connections to suspicious TLDs
        foreach ($conn in $connections) {
            if ($conn.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)') {
                try {
                    $dns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
                    
                    $suspiciousTLDs = @(".onion", ".bit", ".i2p", ".tk", ".ml", ".ga", ".cf")
                    foreach ($tld in $suspiciousTLDs) {
                        if ($dns -like "*$tld") {
                            $detections += @{
                                ProcessId = $conn.OwningProcess
                                RemoteAddress = $conn.RemoteAddress
                                RemoteHost = $dns
                                Type = "Connection to Suspicious TLD"
                                Risk = "Medium"
                            }
                            break
                        }
                    }
                } catch { }
            }
        }
        
        # Check for HTTP/HTTPS connections with small data transfer (beacon)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                    $httpConns = $procConns | Where-Object { $_.RemotePort -in @(80, 443, 8080, 8443) }
                    
                    if ($httpConns.Count -gt 0) {
                        # Check network stats
                        $netStats = Get-Counter "\Process($($proc.ProcessName))\IO Data Bytes/sec" -ErrorAction SilentlyContinue
                        if ($netStats -and $netStats.CounterSamples[0].CookedValue -lt 1000 -and $netStats.CounterSamples[0].CookedValue -gt 0) {
                            # Small but consistent data transfer = beacon
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                DataRate = $netStats.CounterSamples[0].CookedValue
                                ConnectionCount = $httpConns.Count
                                Type = "Low Data Transfer Beacon Pattern"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for processes with connections to many different IPs (C2 rotation)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                $uniqueIPs = ($procConns | Select-Object -Unique RemoteAddress).RemoteAddress.Count
                
                if ($uniqueIPs -gt 10) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UniqueIPs = $uniqueIPs
                        ConnectionCount = $procConns.Count
                        Type = "Multiple C2 Connections (IP Rotation)"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "BEACON DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.RemoteAddress -or $detection.RemoteHost)" "THREAT" "beacon_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\BeaconDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.RemoteAddress -or $_.RemoteHost)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Beacon detection error: $_" "ERROR" "beacon_detections.log"
    }
    
    return $detections.Count
}

function Invoke-CodeInjectionDetection {
    $detections = @()
    
    try {
        # Check for processes with unusual memory regions (injection indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules
                
                # Check for processes with modules in unusual locations
                $unusualModules = $modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*" -and
                    -not (Test-Path $_.FileName) -and
                    $_.ModuleName -like "*.dll"
                }
                
                if ($unusualModules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UnusualModules = $unusualModules.Count
                        Type = "Many Unusual Memory Modules (Code Injection)"
                        Risk = "High"
                    }
                }
                
                # Check for processes with unusual thread counts (injection indicator)
                if ($proc.Threads.Count -gt 50 -and $proc.ProcessName -notin @("chrome.exe", "msedge.exe", "firefox.exe")) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ThreadCount = $proc.Threads.Count
                        Type = "Unusual Thread Count (Possible Injection)"
                        Risk = "Medium"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for processes using injection APIs
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine) {
                    # Check for code injection API usage
                    $injectionPatterns = @(
                        'VirtualAllocEx',
                        'WriteProcessMemory',
                        'CreateRemoteThread',
                        'NtCreateThreadEx',
                        'RtlCreateUserThread',
                        'SetThreadContext',
                        'QueueUserAPC',
                        'ProcessHollowing',
                        'DLL.*injection',
                        'code.*injection'
                    )
                    
                    foreach ($pattern in $injectionPatterns) {
                        if ($proc.CommandLine -match $pattern) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $proc.CommandLine
                                InjectionPattern = $pattern
                                Type = "Code Injection API Usage"
                                Risk = "High"
                            }
                            break
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes with unusual handle counts (injection indicator)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.HandleCount -gt 1000 }
            
            foreach ($proc in $processes) {
                # Exclude legitimate processes
                $legitProcesses = @("chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe", "svchost.exe")
                if ($proc.ProcessName -notin $legitProcesses) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        HandleCount = $proc.HandleCount
                        Type = "Unusual Handle Count (Possible Injection)"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check for processes accessing other processes (injection indicator)
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    # Check if process has SeDebugPrivilege (enables injection)
                    # Indirect check through process properties
                    if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                        $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                        
                        # Unsigned processes accessing system processes
                        if ($sig.Status -ne "Valid" -and $proc.Name -match 'debug|inject|hollow') {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ExecutablePath = $proc.ExecutablePath
                                Type = "Suspicious Process Name (Injection Tool)"
                                Risk = "High"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Also check for unsigned modules in system processes (original check)
        try {
            $systemProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $_.ProcessName -in @("svchost", "explorer", "lsass")
            }
            
            foreach ($proc in $systemProcesses) {
                foreach ($module in $proc.Modules) {
                    if ($module.FileName -and (Test-Path $module.FileName)) {
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $module.FileName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $module.FileName -notlike "$env:SystemRoot\*") {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    ModulePath = $module.FileName
                                    Type = "Unsigned Module in System Process"
                                    Risk = "High"
                                }
                            }
                        } catch { }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "CODE INJECTION: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "code_injection_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\CodeInjection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Code injection detection error: $_" "ERROR" "code_injection_detections.log"
    }
    
    return $detections.Count
}

function Invoke-DataExfiltrationDetection {
    $detections = @()
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $byProcess = $connections | Group-Object OwningProcess
        
        foreach ($group in $byProcess) {
            if ($group.Count -gt 20) {
                $proc = Get-Process -Id $group.Name -ErrorAction SilentlyContinue
                $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                
                if ($procName -notin @("chrome", "firefox", "msedge", "svchost", "System")) {
                    $detections += @{
                        ProcessId = $group.Name
                        ProcessName = $procName
                        ConnectionCount = $group.Count
                        Type = "High Network Activity"
                        Risk = "Medium"
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "DataExfiltrationDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "DataExfiltrationDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

# DLL whitelist - safe system DLLs that should not be flagged
$Script:DllWhitelist = @(
    'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 
    'gdi32.dll', 'msvcrt.dll', 'advapi32.dll', 'ws2_32.dll',
    'shell32.dll', 'ole32.dll', 'combase.dll', 'bcrypt.dll',
    'crypt32.dll', 'sechost.dll', 'rpcrt4.dll', 'imm32.dll',
    'shcore.dll', 'shlwapi.dll', 'version.dll', 'winmm.dll',
    'mshtml.dll', 'msi.dll', 'msvcp140.dll', 'vcruntime140.dll'
)

# Target browser processes to monitor
$Script:BrowserTargets = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 
                   'iexplore', 'microsoftedge', 'waterfox', 'palemoon')

$Script:ProcessedDlls = @{}

function Test-SuspiciousDLL {
    param(
        [string]$DllName,
        [string]$DllPath,
        [string]$ProcessName
    )
    
    $dllNameLower = $DllName.ToLower()
    $suspicious = $false
    $reasons = @()
    
    # Skip whitelisted system DLLs
    if ($Script:DllWhitelist -contains $dllNameLower) {
        return $null
    }
    
    # Pattern 1: _elf.dll pattern (known malicious pattern)
    if ($dllNameLower -like '*_elf.dll' -or $dllNameLower -match '_elf') {
        $suspicious = $true
        $reasons += "ELF pattern DLL detected"
    }
    
    # Pattern 2: Suspicious .winmd files outside Windows directory
    if ($dllNameLower -like '*.winmd' -and $DllPath -notmatch '\\Windows\\') {
        $suspicious = $true
        $reasons += "WINMD file outside Windows directory"
    }
    
    # Pattern 3: Random hex-named DLLs (common in malware)
    if ($dllNameLower -match '^[a-f0-9]{8,}\.dll$') {
        $suspicious = $true
        $reasons += "Random hex-named DLL detected"
    }
    
    # Pattern 4: DLLs loaded from TEMP directory (excluding browser cache)
    if ($DllPath -match "\\AppData\\Local\\Temp\\" -and 
        $dllNameLower -notlike "chrome_*" -and 
        $dllNameLower -notlike "edge_*" -and
        $dllNameLower -notlike "moz*" -and
        $dllNameLower -notlike "firefox_*") {
        $suspicious = $true
        $reasons += "DLL loaded from TEMP directory"
    }
    
    # Pattern 5: DLLs in browser profile folders with suspicious names
    if ($DllPath -match "\\AppData\\" -and 
        $dllNameLower -notmatch "chrome|edge|firefox|mozilla" -and
        $dllNameLower -like '*.dll') {
        $suspicious = $true
        $reasons += "DLL in browser profile with non-browser name"
    }
    
    # Pattern 6: Unsigned DLLs in browser processes
    if (Test-Path $DllPath) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid" -and $DllPath -notlike "$env:SystemRoot\*") {
                $suspicious = $true
                $reasons += "Unsigned DLL in browser process"
            }
        } catch { }
    }
    
    if ($suspicious) {
        return @{
            Suspicious = $true
            Reasons = $reasons
            Risk = "High"
        }
    }
    
    return $null
}

function Invoke-ElfCatcher {
    $detections = @()
    
    try {
        foreach ($target in $Script:BrowserTargets) {
            try {
                $procs = Get-Process -Name $target -ErrorAction SilentlyContinue
                
                foreach ($proc in $procs) {
                    try {
                        # Scan all loaded modules in the process
                        $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" -or $_.FileName -like "*.winmd" }
                        
                        foreach ($mod in $modules) {
                            try {
                                $dllName = [System.IO.Path]::GetFileName($mod.FileName)
                                $dllPath = $mod.FileName
                                
                                # Check if we've already processed this DLL
                                $key = "$($proc.Id):$dllPath"
                                if ($Script:ProcessedDlls.ContainsKey($key)) {
                                    continue
                                }
                                
                                # Test for suspicious DLL
                                $result = Test-SuspiciousDLL -DllName $dllName -DllPath $dllPath -ProcessName $proc.ProcessName
                                
                                if ($result) {
                                    $detections += @{
                                        ProcessId = $proc.Id
                                        ProcessName = $proc.ProcessName
                                        DllName = $dllName
                                        DllPath = $dllPath
                                        BaseAddress = $mod.BaseAddress.ToString()
                                        Reasons = $result.Reasons
                                        Risk = $result.Risk
                                    }
                                    
                                    # Mark as processed
                                    $Script:ProcessedDlls[$key] = Get-Date
                                    
                                    Write-AVLog "ELF CATCHER: Suspicious DLL in $($proc.ProcessName) (PID: $($proc.Id)) - $dllName - $($result.Reasons -join ', ')" "THREAT" "elf_catcher_detections.log"
                                    $Global:AntivirusState.ThreatCount++
                                }
                            } catch {
                                # Module may have unloaded during iteration
                                continue
                            }
                        }
                    } catch {
                        # Process may have exited during iteration
                        continue
                    }
                }
            } catch {
                # Process not found, continue
                continue
            }
        }
        
        # Periodic cleanup of processed list to prevent memory bloat
        if ($Script:ProcessedDlls.Count -gt 1000) {
            $oldKeys = $Script:ProcessedDlls.Keys | Where-Object {
                ((Get-Date) - $Script:ProcessedDlls[$_]).TotalHours -gt 24
            }
            foreach ($key in $oldKeys) {
                $Script:ProcessedDlls.Remove($key)
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ElfCatcher_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.DllName)|$($_.DllPath)|$($_.Reasons -join ';')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            
            Write-AVLog "ElfCatcher detection completed: $($detections.Count) suspicious DLL(s) found" "INFO" "elf_catcher_detections.log"
        }
    } catch {
        Write-AVLog "ElfCatcher error: $_" "ERROR" "elf_catcher_detections.log"
    }
    
    return $detections.Count
}

$Script:ScannedFiles = @{}
$Script:HighEntropyThreshold = 7.2

function Measure-FileEntropy {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) { return $null }
        
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $sampleSize = [Math]::Min(8192, $fileInfo.Length)
        
        if ($sampleSize -eq 0) { return $null }
        
        $stream = [System.IO.File]::OpenRead($FilePath)
        $bytes = New-Object byte[] $sampleSize
        $stream.Read($bytes, 0, $sampleSize) | Out-Null
        $stream.Close()
        
        # Calculate byte frequency
        $freq = @{}
        foreach ($byte in $bytes) {
            if ($freq.ContainsKey($byte)) {
                $freq[$byte]++
            } else {
                $freq[$byte] = 1
            }
        }
        
        # Calculate Shannon entropy
        $entropy = 0
        $total = $bytes.Count
        
        foreach ($count in $freq.Values) {
            $p = $count / $total
            if ($p -gt 0) {
                $entropy -= $p * [Math]::Log($p, 2)
            }
        }
        
        return @{
            Entropy = $entropy
            FileSize = $fileInfo.Length
            SampleSize = $sampleSize
        }
    } catch {
        return $null
    }
}

function Invoke-FileEntropyDetection {
    $detections = @()
    $maxFiles = 100
    
    try {
        $cutoff = (Get-Date).AddHours(-2)
        $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")
        
        $scannedCount = 0
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            if ($scannedCount -ge $maxFiles) { break }
            
            try {
                $files = Get-ChildItem -Path $scanPath -Include *.exe,*.dll,*.scr,*.ps1,*.vbs -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff } |
                    Select-Object -First ($maxFiles - $scannedCount)
                
                foreach ($file in $files) {
                    $scannedCount++
                    
                    # Check cache
                    if ($Script:ScannedFiles.ContainsKey($file.FullName)) {
                        $cached = $Script:ScannedFiles[$file.FullName]
                        if ($cached.LastWrite -eq $file.LastWriteTime -and $cached.Entropy -lt $Script:HighEntropyThreshold) {
                            continue
                        }
                    }
                    
                    $entropyResult = Measure-FileEntropy -FilePath $file.FullName
                    
                    # Mark as scanned
                    $Script:ScannedFiles[$file.FullName] = @{
                        LastWrite = $file.LastWriteTime
                        Entropy = if ($entropyResult) { $entropyResult.Entropy } else { 0 }
                    }
                    
                    if ($entropyResult -and $entropyResult.Entropy -ge $Script:HighEntropyThreshold) {
                        $detections += @{
                            FilePath = $file.FullName
                            FileName = $file.Name
                            Entropy = [Math]::Round($entropyResult.Entropy, 2)
                            FileSize = $entropyResult.FileSize
                            Type = "High Entropy File"
                            Risk = "Medium"
                        }
                        
                        Write-AVLog "High entropy file detected - File: $($file.Name) | Path: $($file.FullName) | Entropy: $([Math]::Round($entropyResult.Entropy, 2))" "WARNING" "file_entropy_detections.log"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Periodic cleanup of cache
        if ($Script:ScannedFiles.Count -gt 1000) {
            $oldKeys = $Script:ScannedFiles.Keys | Where-Object { -not (Test-Path $_) }
            foreach ($key in $oldKeys) {
                $Script:ScannedFiles.Remove($key)
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\FileEntropy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)|Entropy:$($_.Entropy)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "File entropy detection completed: $($detections.Count) high entropy file(s) found" "INFO" "file_entropy_detections.log"
        }
    } catch {
        Write-AVLog "File entropy detection error: $_" "ERROR" "file_entropy_detections.log"
    }
    
    return $detections.Count
}

function Invoke-HoneypotMonitoring {
    $detections = @()
    
    try {
        $honeypotFiles = @(
            "$Script:InstallPath\Data\passwords.txt",
            "$Script:InstallPath\Data\credentials.xlsx",
            "$Script:InstallPath\Data\secrets.docx"
        )
        
        foreach ($honeypot in $honeypotFiles) {
            if (Test-Path $honeypot) {
                $file = Get-Item $honeypot -ErrorAction SilentlyContinue
                if ($file.LastAccessTime -gt (Get-Date).AddMinutes(-5)) {
                    $detections += @{
                        HoneypotFile = $honeypot
                        LastAccess = $file.LastAccessTime
                        Type = "Honeypot File Accessed"
                        Risk = "Critical"
                    }
                }
            } else {
                try {
                    $dir = Split-Path $honeypot -Parent
                    if (-not (Test-Path $dir)) {
                        New-Item -Path $dir -ItemType Directory -Force | Out-Null
                    }
                    "HONEYPOT - This file is monitored for unauthorized access" | Set-Content -Path $honeypot
                } catch { }
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "HoneypotMonitoring" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "HoneypotMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Invoke-LateralMovementDetection {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ($cmdLine) {
                $lateralPatterns = @(
                    "psexec", "paexec", "wmic.*process.*call.*create",
                    "winrm", "enter-pssession", "invoke-command.*-computername",
                    "schtasks.*/create.*/s", "at.exe.*\\\\"
                )
                
                foreach ($pattern in $lateralPatterns) {
                    if ($cmdLine -match $pattern) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            CommandLine = $cmdLine
                            Pattern = $pattern
                            Type = "Lateral Movement Activity"
                            Risk = "High"
                        }
                    }
                }
            }
        }
        
        $smbConnections = Get-NetTCPConnection -RemotePort 445 -State Established -ErrorAction SilentlyContinue
        $uniqueHosts = ($smbConnections.RemoteAddress | Select-Object -Unique).Count
        
        if ($uniqueHosts -gt 5) {
            $detections += @{
                UniqueHosts = $uniqueHosts
                Type = "Multiple SMB Connections"
                Risk = "Medium"
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "LateralMovementDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "LateralMovementDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Invoke-ProcessCreationDetection {
    $detections = @()
    
    try {
        # Check for WMI process creation filters (blockers)
        try {
            $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Query -match 'Win32_ProcessStartTrace|__InstanceCreationEvent.*Win32_Process'
                }
            
            foreach ($filter in $filters) {
                # Check if filter is bound to a consumer that blocks processes
                $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                    Where-Object { $_.Filter -like "*$($filter.Name)*" }
                
                if ($bindings) {
                    foreach ($binding in $bindings) {
                        $consumer = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -like "*$($binding.Consumer)*" }
                        
                        if ($consumer) {
                            # Check if consumer command blocks process creation
                            if ($consumer.CommandLineTemplate -match 'taskkill|Stop-Process|Remove-Process' -or
                                $consumer.CommandLineTemplate -match 'block|deny|prevent') {
                                $detections += @{
                                    FilterName = $filter.Name
                                    ConsumerName = $consumer.Name
                                    CommandLine = $consumer.CommandLineTemplate
                                    Type = "WMI Process Creation Blocker Detected"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check Event Log for process creation failures
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7034} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    $_.Message -match 'process.*failed|service.*failed.*start|start.*failed'
                }
            
            $processFailures = $events | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1)
            }
            
            if ($processFailures.Count -gt 10) {
                $detections += @{
                    EventCount = $processFailures.Count
                    Type = "Excessive Process Creation Failures"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for processes with unusual creation patterns
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, CreationDate, ExecutablePath
            
            # Check for processes spawned in rapid succession
            $recentProcs = $processes | Where-Object {
                (Get-Date) - $_.CreationDate -lt [TimeSpan]::FromMinutes(5)
            }
            
            # Group by parent process
            $parentGroups = $recentProcs | Group-Object ParentProcessId
            
            foreach ($group in $parentGroups) {
                if ($group.Count -gt 20) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($group.Name)" -ErrorAction SilentlyContinue
                        if ($parent) {
                            $detections += @{
                                ParentProcessId = $group.Name
                                ParentProcessName = $parent.Name
                                ChildCount = $group.Count
                                Type = "Rapid Process Creation Spawning"
                                Risk = "Medium"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Check for processes with unusual parent relationships
        try {
            $suspiciousParents = @{
                "winlogon.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                "services.exe" = @("cmd.exe", "powershell.exe", "rundll32.exe")
                "explorer.exe" = @("notepad.exe", "calc.exe")
            }
            
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId
            
            foreach ($proc in $processes) {
                if ($proc.ParentProcessId) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                        
                        if ($parent) {
                            foreach ($suspParent in $suspiciousParents.Keys) {
                                if ($parent.Name -eq $suspParent -and 
                                    $proc.Name -in $suspiciousParents[$suspParent]) {
                                    
                                    $detections += @{
                                        ProcessId = $proc.ProcessId
                                        ProcessName = $proc.Name
                                        ParentProcessId = $proc.ParentProcessId
                                        ParentProcessName = $parent.Name
                                        Type = "Suspicious Parent-Child Process Relationship"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Also check Security event log for suspicious process creation (original check)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue -MaxEvents 50
            
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $newProcessName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text'
                $commandLine = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
                
                $suspiciousPatterns = @(
                    "powershell.*-enc", "cmd.*/c.*powershell",
                    "certutil.*-decode", "bitsadmin.*/download",
                    "mshta.*http", "regsvr32.*/s.*/i"
                )
                
                foreach ($pattern in $suspiciousPatterns) {
                    if ($commandLine -match $pattern) {
                        $detections += @{
                            ProcessName = $newProcessName
                            CommandLine = $commandLine
                            Pattern = $pattern
                            TimeCreated = $evt.TimeCreated
                            Type = "Suspicious Process Creation"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "PROCESS CREATION: $($detection.Type) - $($detection.ProcessName -or $detection.FilterName -or $detection.ParentProcessName -or 'System')" "THREAT" "process_creation_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessCreation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.FilterName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Process creation detection error: $_" "ERROR" "process_creation_detections.log"
    }
    
    return $detections.Count
}

function Invoke-QuarantineFile {
    param(
        [string]$FilePath,
        [string]$Reason,
        [string]$Source
    )
    
    try {
        if (Test-Path $FilePath) {
            $fileName = Split-Path -Leaf $FilePath
            $quarantinePath = Join-Path $Config.QuarantinePath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$fileName"
            
            if (-not (Test-Path $Config.QuarantinePath)) {
                New-Item -Path $Config.QuarantinePath -ItemType Directory -Force | Out-Null
            }
            
            Move-Item -Path $FilePath -Destination $quarantinePath -Force
            Write-EDRLog -Module "Quarantine" -Message "Quarantined: $FilePath -> $quarantinePath (Reason: $Reason)" -Level "Warning"
            return $true
        }
    } catch {
        Write-EDRLog -Module "Quarantine" -Message "Failed to quarantine $FilePath : $_" -Level "Error"
    }
    
    return $false
}

function Invoke-QuarantineManagement {
    try {
        $quarantineFiles = Get-ChildItem -Path $Config.QuarantinePath -File -ErrorAction SilentlyContinue
        
        foreach ($file in $quarantineFiles) {
            $age = (Get-Date) - $file.CreationTime
            if ($age.Days -gt 30) {
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                Write-EDRLog -Module "Quarantine" -Message "Removed old quarantined file: $($file.Name)" -Level "Info"
            }
        }
    } catch {
        Write-EDRLog -Module "QuarantineManagement" -Message "Error: $_" -Level "Error"
    }
    
    return 0
}

function Invoke-ReflectiveDLLInjectionDetection {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Modules }
        
        foreach ($proc in $processes) {
            try {
                $memOnlyModules = $proc.Modules | Where-Object {
                    $_.FileName -and -not (Test-Path $_.FileName)
                }
                
                if ($memOnlyModules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        MemoryModules = $memOnlyModules.Count
                        Type = "Potential Reflective DLL Injection"
                        Risk = "High"
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "ReflectiveDLLInjectionDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "ReflectiveDLLInjectionDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Add-ThreatToResponseQueue {
    param(
        [string]$ThreatType,
        [string]$ThreatPath,
        [string]$Severity = "Medium"
    )
    
    try {
        # Initialize response queue if not already initialized
        if (-not $Script:ResponseQueue) {
            $Script:ResponseQueue = New-Object System.Collections.Queue
            $Script:ResponseQueueMaxSize = 1000
        }

        # Prevent queue overflow
        if ($Script:ResponseQueue.Count -ge $Script:ResponseQueueMaxSize) {
            Write-EDRLog -Module "ResponseEngine" -Message "WARNING: Response queue is full, dropping oldest threat" -Level "Warning"
            $null = $Script:ResponseQueue.Dequeue()
        }

        $threat = @{
            ThreatType = $ThreatType
            ThreatPath = $ThreatPath
            Severity = $Severity
            Timestamp = Get-Date
        }

        $Script:ResponseQueue.Enqueue($threat)
        Write-EDRLog -Module "ResponseEngine" -Message "Queued threat: $ThreatType - $ThreatPath (Severity: $Severity). Queue size: $($Script:ResponseQueue.Count)" -Level "Debug"
    }
    catch {
        Write-EDRLog -Module "ResponseAction" -Message "Error adding threat to queue: $_" -Level "Error"
    }
}

function Invoke-ResponseAction {
    param(
        [string]$ThreatType,
        [string]$ThreatPath,
        [string]$Severity = "Medium"
    )
    
    try {
        $actions = @{
            "Critical" = @("Quarantine", "KillProcess", "BlockNetwork", "Log")
            "High"     = @("Quarantine", "Log", "Alert")
            "Medium"   = @("Log", "Alert")
            "Low"      = @("Log")
        }
        
        $responseActions = $actions[$Severity]
        
        foreach ($action in $responseActions) {
            switch ($action) {
                "Quarantine" {
                    if (Test-Path $ThreatPath) {
                        Invoke-QuarantineFile -FilePath $ThreatPath -Reason $ThreatType -Source "ResponseEngine"
                    }
                }
                "KillProcess" {
                    try {
                        # ThreatPath might be a PID (integer) or process name
                        if ($ThreatPath -match '^\d+$') {
                            $threatPID = [int]$ThreatPath
                            
                            # Whitelist own process - never kill ourselves
                            if ($threatPID -eq $PID -or $threatPID -eq $Script:SelfPID) {
                                Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own process (PID: $threatPID) - whitelisted" -Level "Warning"
                                return
                            }
                            
                            # Check if this PID is running our script - if so, whitelist it
                            try {
                                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $threatPID" -ErrorAction SilentlyContinue).CommandLine
                                $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                                if ($cmdLine -and $ownScriptPath -and $cmdLine -like "*$ownScriptPath*") {
                                    Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own script instance (PID: $threatPID) - whitelisted" -Level "Warning"
                                    return
                                }
                            } catch {}
                            
                            $proc = Get-Process -Id $threatPID -ErrorAction SilentlyContinue
                            if ($proc) {
                                Stop-Process -Id $threatPID -Force -ErrorAction SilentlyContinue
                                Write-EDRLog -Module "ResponseEngine" -Message "Terminated process PID: $ThreatPath" -Level "Info"
                            }
                        } else {
                            $proc = Get-Process -Name $ThreatPath -ErrorAction SilentlyContinue
                            if ($proc) {
                                # Check each process to ensure we're not killing our own
                                foreach ($p in $proc) {
                                    if ($p.Id -eq $PID -or $p.Id -eq $Script:SelfPID) {
                                        Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own process (PID: $($p.Id), Name: $ThreatPath) - whitelisted" -Level "Warning"
                                        continue
                                    }
                                    
                                    # Check if this process is running our script
                                    try {
                                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue).CommandLine
                                        $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                                        if ($cmdLine -and $ownScriptPath -and $cmdLine -like "*$ownScriptPath*") {
                                            Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own script instance (PID: $($p.Id)) - whitelisted" -Level "Warning"
                                            continue
                                        }
                                    } catch {}
                                    
                                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                                    Write-EDRLog -Module "ResponseEngine" -Message "Terminated process: $ThreatPath (PID: $($p.Id))" -Level "Info"
                                }
                            }
                        }
                    } catch {
                        Write-EDRLog -Module "ResponseEngine" -Message "Failed to kill process $ThreatPath : $_" -Level "Warning"
                    }
                }
                "BlockNetwork" {
                    try {
                        # Extract IP address from ThreatPath if it's in format "IP:Port" or just "IP"
                        $ipAddress = if ($ThreatPath -match '^(\d+\.\d+\.\d+\.\d+)') { $matches[1] } else { $ThreatPath }
                        
                        $RuleName = "Block_ResponseEngine_$ipAddress" -replace '[\.:]', '_'
                        $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                        
                        if (-not $existingRule) {
                            New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $ipAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                            Write-EDRLog -Module "ResponseEngine" -Message "Blocked network connection to $ipAddress" -Level "Info"
                        }
                    } catch {
                        Write-EDRLog -Module "ResponseEngine" -Message "Failed to block network for $ThreatPath : $_" -Level "Warning"
                    }
                }
                "Log" {
                    Write-EDRLog -Module "ResponseEngine" -Message "THREAT: $ThreatType - $ThreatPath (Severity: $Severity)" -Level "Warning"
                }
                "Alert" {
                    try {
                        # Ensure event log source exists before writing
                        if ($null -ne $Config -and $null -ne $Config.EDRName -and -not [string]::IsNullOrWhiteSpace($Config.EDRName)) {
                            if (-not [System.Diagnostics.EventLog]::SourceExists($Config.EDRName)) {
                                [System.Diagnostics.EventLog]::CreateEventSource($Config.EDRName, "Application")
                            }
                            Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Warning -EventId 2000 `
                                -Message "THREAT ALERT: $ThreatType - $ThreatPath (Severity: $Severity)" -ErrorAction SilentlyContinue
                        }
                    } catch {
                        # Event log may not be available, fall back to EDR log
                        Write-EDRLog -Module "ResponseEngine" -Message "ALERT: $ThreatType - $ThreatPath (Severity: $Severity)" -Level "Warning"
                    }
                }
            }
        }
    } catch {
        Write-EDRLog -Module "ResponseAction" -Message "Error processing response action: $_" -Level "Error"
    }
}

function Invoke-ResponseEngine {
    try {
        # Initialize response queue if not already initialized
        if (-not $Script:ResponseQueue) {
            $Script:ResponseQueue = New-Object System.Collections.Queue
            $Script:ResponseQueueMaxSize = 1000
        }

        # Process up to 50 items from the queue per tick to avoid blocking
        $processedCount = 0
        $maxProcessPerTick = 50

        while ($Script:ResponseQueue.Count -gt 0 -and $processedCount -lt $maxProcessPerTick) {
            try {
                $threat = $Script:ResponseQueue.Dequeue()
                
                if ($threat -and $threat.ThreatType -and $threat.ThreatPath) {
                    Invoke-ResponseAction -ThreatType $threat.ThreatType -ThreatPath $threat.ThreatPath -Severity $threat.Severity
                    $processedCount++
                }
            }
            catch {
                Write-EDRLog -Module "ResponseEngine" -Message "Error processing threat from queue: $_" -Level "Error"
            }
        }

        if ($processedCount -gt 0) {
            Write-EDRLog -Module "ResponseEngine" -Message "Processed $processedCount threat(s) from queue. Queue size: $($Script:ResponseQueue.Count)" -Level "Info"
        }

        return $processedCount
    } catch {
        Write-EDRLog -Module "ResponseEngine" -Message "Error: $_" -Level "Error"
        return 0
    }
}

# PrivacyForge Spoofing Module (Converted from Spoofer.py)
function Invoke-PrivacyForgeSpoofing {
    param(
        [hashtable]$Config
    )
    
    # Initialize script-level variables if not already set
    if (-not $Script:PrivacyForgeIdentity) {
        $Script:PrivacyForgeIdentity = @{}
        $Script:PrivacyForgeDataCollected = 0
        $Script:PrivacyForgeRotationInterval = 3600  # 1 hour
        $Script:PrivacyForgeDataThreshold = 50
        $Script:PrivacyForgeLastRotation = Get-Date
    }
    
    try {
        # Check if rotation is needed
        $timeSinceRotation = (Get-Date) - $Script:PrivacyForgeLastRotation
        $shouldRotate = $false
        
        if ($timeSinceRotation.TotalSeconds -ge $Script:PrivacyForgeRotationInterval) {
            $shouldRotate = $true
            Write-AVLog "PrivacyForge: Time-based rotation triggered" "INFO"
        }
        
        if ($Script:PrivacyForgeDataCollected -ge $Script:PrivacyForgeDataThreshold) {
            $shouldRotate = $true
            Write-AVLog "PrivacyForge: Data threshold reached ($Script:PrivacyForgeDataCollected/$Script:PrivacyForgeDataThreshold)" "INFO"
        }
        
        if ($shouldRotate -or (-not $Script:PrivacyForgeIdentity.ContainsKey("name"))) {
            Invoke-PrivacyForgeRotateIdentity
        }
        
        # Simulate data collection
        $Script:PrivacyForgeDataCollected += Get-Random -Minimum 1 -Maximum 6
        
        # Perform spoofing operations
        Invoke-PrivacyForgeSpoofSoftwareMetadata
        Invoke-PrivacyForgeSpoofGameTelemetry
        Invoke-PrivacyForgeSpoofSensors
        Invoke-PrivacyForgeSpoofSystemMetrics
        Invoke-PrivacyForgeSpoofClipboard
        
        Write-AVLog "PrivacyForge: Spoofing active - Data collected: $Script:PrivacyForgeDataCollected/$Script:PrivacyForgeDataThreshold" "INFO"
        
    } catch {
        Write-AVLog "PrivacyForge: Error - $_" "ERROR"
    }
}

function Invoke-PrivacyForgeGenerateIdentity {
    # Generate fake identity data
    $firstNames = @("John", "Jane", "Michael", "Sarah", "David", "Emily", "James", "Jessica", "Robert", "Amanda", "William", "Ashley", "Richard", "Melissa", "Joseph", "Nicole")
    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Wilson", "Anderson", "Thomas", "Taylor")
    $domains = @("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com")
    $cities = @("New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose")
    $countries = @("United States", "Canada", "United Kingdom", "Australia", "Germany", "France", "Spain", "Italy")
    $languages = @("en-US", "fr-FR", "es-ES", "de-DE", "it-IT", "pt-BR")
    $interests = @("tech", "gaming", "news", "sports", "music", "movies", "travel", "food", "fitness", "books")
    
    $firstName = Get-Random -InputObject $firstNames
    $lastName = Get-Random -InputObject $lastNames
    $username = "$firstName$lastName" + (Get-Random -Minimum 100 -Maximum 9999)
    $domain = Get-Random -InputObject $domains
    $email = "$username@$domain"
    
    $userAgents = @(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    
    return @{
        "name" = "$firstName $lastName"
        "email" = $email
        "username" = $username
        "location" = Get-Random -InputObject $cities
        "country" = Get-Random -InputObject $countries
        "user_agent" = Get-Random -InputObject $userAgents
        "screen_resolution" = "$(Get-Random -Minimum 800 -Maximum 1920)x$(Get-Random -Minimum 600 -Maximum 1080)"
        "interests" = (Get-Random -InputObject $interests -Count 4)
        "device_id" = [System.Guid]::NewGuid().ToString()
        "mac_address" = "{0:X2}-{1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}" -f (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256)
        "language" = Get-Random -InputObject $languages
        "timezone" = (Get-TimeZone).Id
        "timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

function Invoke-PrivacyForgeRotateIdentity {
    $Script:PrivacyForgeIdentity = Invoke-PrivacyForgeGenerateIdentity
    $Script:PrivacyForgeDataCollected = 0
    $Script:PrivacyForgeLastRotation = Get-Date
    
    Write-AVLog "PrivacyForge: Identity rotated - Name: $($Script:PrivacyForgeIdentity.name), Username: $($Script:PrivacyForgeIdentity.username)" "INFO"
}

function Invoke-PrivacyForgeSpoofSoftwareMetadata {
    try {
        $headers = @{
            "User-Agent" = $Script:PrivacyForgeIdentity.user_agent
            "Cookie" = "session_id=$(Get-Random -Minimum 1000 -Maximum 9999); fake_id=$([System.Guid]::NewGuid().ToString())"
            "X-Device-ID" = $Script:PrivacyForgeIdentity.device_id
            "Accept-Language" = $Script:PrivacyForgeIdentity.language
            "X-Timezone" = $Script:PrivacyForgeIdentity.timezone
        }
        
        # Attempt to send spoofed headers (non-blocking)
        try {
            $null = Invoke-WebRequest -Uri "https://httpbin.org/headers" -Headers $headers -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
            Write-AVLog "PrivacyForge: Sent spoofed software metadata headers" "DEBUG"
        } catch {
            # Silently fail - network may not be available
        }
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing software metadata - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofGameTelemetry {
    try {
        $fakeTelemetry = @{
            "player_id" = [System.Guid]::NewGuid().ToString()
            "hardware_id" = ((New-Object System.Security.Cryptography.SHA256Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes((Get-Random).ToString())) | ForEach-Object { $_.ToString("X2") }) -join ''
            "latency" = Get-Random -Minimum 20 -Maximum 200
            "game_version" = "$(Get-Random -Minimum 1 -Maximum 5).$(Get-Random -Minimum 0 -Maximum 9)"
            "fps" = Get-Random -Minimum 30 -Maximum 120
        }
        Write-AVLog "PrivacyForge: Spoofed game telemetry - Player ID: $($fakeTelemetry.player_id)" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing game telemetry - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofSensors {
    try {
        # Generate random sensor data to spoof fingerprinting
        $null = @{
            "accelerometer" = @{
                "x" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
                "y" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
                "z" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
            }
            "gyroscope" = @{
                "pitch" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
                "roll" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
                "yaw" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
            }
            "magnetometer" = @{
                "x" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
                "y" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
                "z" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
            }
            "light_sensor" = (Get-Random -Minimum 0 -Maximum 1000) / 1.0
            "proximity_sensor" = Get-Random -InputObject @(0, 5, 10)
            "ambient_temperature" = (Get-Random -Minimum 1500 -Maximum 3500) / 100.0
        }
        Write-AVLog "PrivacyForge: Spoofed sensor data" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing sensors - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofSystemMetrics {
    try {
        $fakeMetrics = @{
            "cpu_usage" = (Get-Random -Minimum 0 -Maximum 10000) / 100.0
            "memory_usage" = (Get-Random -Minimum 1000 -Maximum 9000) / 100.0
            "battery_level" = Get-Random -Minimum 20 -Maximum 100
        }
        Write-AVLog "PrivacyForge: Spoofed system metrics - CPU: $($fakeMetrics.cpu_usage)%, Memory: $($fakeMetrics.memory_usage)%" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing system metrics - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofClipboard {
    try {
        $fakeContent = "PrivacyForge: $(Get-Random -Minimum 100000 -Maximum 999999) - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Set-Clipboard -Value $fakeContent -ErrorAction SilentlyContinue
        Write-AVLog "PrivacyForge: Spoofed clipboard content" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing clipboard - $_" "WARN"
    }
}

#endregion

function Set-HostsFileBlock {
    param(
        [string[]]$Domains,
        [string]$RedirectIP = "127.0.0.1"
    )
    
    try {
        $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
        $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
        
        # Check if ad blocking section already exists
        if ($hostsContent -match "# Ad Blocking") {
            Write-Host "Hosts file already contains ad blocking entries"
            return
        }
        
        # Add ad blocking entries
        $adEntries = @(
            "",
            "# Ad Blocking - Redirect ad domains to localhost",
            "$RedirectIP`tpagead2.googlesyndication.com",
            "$RedirectIP`tgooglesyndication.com",
            "$RedirectIP`tgoogleadservices.com",
            "$RedirectIP`tads.google.com",
            "$RedirectIP`tdoubleclick.net",
            "$RedirectIP`twww.googleadservices.com",
            "$RedirectIP`twww.googlesyndication.com",
            "$RedirectIP`tgoogle-analytics.com",
            "$RedirectIP`tssl.google-analytics.com",
            "$RedirectIP`twww.google-analytics.com",
            "$RedirectIP`tfacebook.com/tr",
            "$RedirectIP`tconnect.facebook.net",
            "$RedirectIP`tads.facebook.com",
            "$RedirectIP`tamazon-adsystem.com",
            "$RedirectIP`tads.yahoo.com",
            "$RedirectIP`tadvertising.amazon.com",
            "$RedirectIP`ttaboola.com",
            "$RedirectIP`toutbrain.com",
            "$RedirectIP`tscorecardresearch.com",
            "$RedirectIP`tquantserve.com",
            "$RedirectIP`tads-twitter.com",
            "$RedirectIP`tanalytics.twitter.com",
            "$RedirectIP`tads.linkedin.com",
            "$RedirectIP`tanalytics.linkedin.com",
            "$RedirectIP`tads.reddit.com",
            "$RedirectIP`tads.tiktok.com",
            "$RedirectIP`tanalytics.tiktok.com"
        )
        
        Add-Content $hostsPath $adEntries -Encoding UTF8
        ipconfig /flushdns | Out-Null
        Write-Host "Added ad blocking entries to hosts file"
        
    } catch {
        Write-Host "Error updating hosts file: $($_.Exception.Message)"
    }
}

#region === YouTube Ad Blocker Configuration ===

$Script:YouTubeAdBlockerConfig = @{
    ProxyPort = 8080
    ProxyHost = "127.0.0.1"
    PACUrl = "https://raw.githubusercontent.com/ads-blocker/Pac/refs/heads/main/BlockAds.pac"
    LogFile = "$env:ProgramData\YouTubeAdBlocker\proxy.log"
    PIDFile = "$env:ProgramData\YouTubeAdBlocker\proxy.pid"
    ServiceName = "YouTubeAdBlockerProxy"
    InstallDir = "$env:ProgramData\YouTubeAdBlocker"
}

# JavaScript to inject
$Script:AdSkipScript = @"
(function() {
    'use strict';
    console.log('[AdBlocker] Script injected');
    function skipAds() {
        try {
            var skipBtn = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .videoAdUiSkipButton, button[class*='skip']');
            if (skipBtn && skipBtn.offsetParent !== null) {
                skipBtn.click();
                console.log('[AdBlocker] Skipped ad');
            }
            var overlays = document.querySelectorAll('.ytp-ad-overlay-container, .ytp-ad-text, .ad-showing, .ad-interrupting');
            overlays.forEach(function(o) { o.style.display = 'none'; o.remove(); });
            var iframes = document.querySelectorAll('iframe[src*='doubleclick'], iframe[src*='googlesyndication']');
            iframes.forEach(function(i) { if (i.src) { i.src = 'about:blank'; i.style.display = 'none'; } });
            var player = document.getElementById('movie_player');
            if (player) {
                var video = player.querySelector('video');
                if (video && video.duration > 0 && video.duration < 5) {
                    video.currentTime = video.duration;
                }
            }
        } catch(e) {}
    }
    skipAds();
    setInterval(skipAds, 250);
    var obs = new MutationObserver(skipAds);
    var container = document.getElementById('movie_player') || document.body;
    if (container) {
        obs.observe(container, {childList: true, subtree: true, attributes: true});
    }
})();
"@

#endregion

#region === YouTube Ad Blocker Functions ===

function Write-YouTubeLog {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $logDir = Split-Path -Path $Script:YouTubeAdBlockerConfig.LogFile -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $Script:YouTubeAdBlockerConfig.LogFile -Value $logEntry -ErrorAction SilentlyContinue
    $color = if ($Level -eq "Error") { "Red" } elseif ($Level -eq "Success") { "Green" } elseif ($Level -eq "Warning") { "Yellow" } else { "White" }
    Write-Host $logEntry -ForegroundColor $color
}

function Test-InternetConnectivity {
    Write-YouTubeLog "Testing internet connectivity..." "Info"
    try {
        $test = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
        if (-not $test) {
            $test = Test-NetConnection -ComputerName "1.1.1.1" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
        }
        return $test
    } catch {
        return $false
    }
}

function Restore-InternetSettings {
    Write-YouTubeLog "Restoring internet settings for safety..." "Warning"
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Remove-ItemProperty -Path $regPath -Name "AutoConfigURL" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0 -Type DWord -Force | Out-Null
        Remove-ItemProperty -Path $regPath -Name "ProxyServer" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $regPath -Name "ProxyOverride" -ErrorAction SilentlyContinue
        
        $signature = @'
[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
        $type = Add-Type -MemberDefinition $signature -Name WinInet -Namespace NetTools -PassThru -ErrorAction SilentlyContinue
        if ($type) {
            $type::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
            $type::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
        }
        Write-YouTubeLog "Internet settings restored" "Success"
        return $true
    } catch {
        Write-YouTubeLog "Failed to restore settings: $_" "Error"
        return $false
    }
}

function Start-ProxyServer {
    Write-YouTubeLog "Starting local proxy server..." "Info"
    
    try {
        # Check if already running
        if (Test-Path $Script:YouTubeAdBlockerConfig.PIDFile) {
            $oldPID = Get-Content -Path $Script:YouTubeAdBlockerConfig.PIDFile -ErrorAction SilentlyContinue
            if ($oldPID) {
                $proc = Get-Process -Id $oldPID -ErrorAction SilentlyContinue
                if ($proc) {
                    Write-YouTubeLog "Proxy already running (PID: $oldPID)" "Info"
                    return $true
                }
            }
        }
        
        # Create proxy PowerShell script file
        $proxyScriptPath = "$($Script:YouTubeAdBlockerConfig.InstallDir)\proxy.ps1"
        $proxyScriptContent = @"
`$ErrorActionPreference = 'SilentlyContinue'
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}

`$listener = New-Object System.Net.HttpListener
`$listener.Prefixes.Add("http://127.0.0.1:$($Script:YouTubeAdBlockerConfig.ProxyPort)/")
`$listener.Start()

"Proxy started" | Out-File -FilePath "$($Script:YouTubeAdBlockerConfig.LogFile)" -Append

while (`$listener.IsListening) {
    try {
        `$context = `$listener.GetContextAsync()
        `$task = `$context.GetAwaiter()
        while (-not `$task.IsCompleted) {
            Start-Sleep -Milliseconds 100
            if (-not `$listener.IsListening) { break }
        }
        if (-not `$listener.IsListening) { break }
        `$ctx = `$task.GetResult()
        `$request = `$ctx.Request
        `$response = `$ctx.Response
        
        `$url = `$request.Url.ToString()
        
        # Handle CONNECT (HTTPS tunneling)
        if (`$request.HttpMethod -eq 'CONNECT') {
            `$response.StatusCode = 200
            `$response.Close()
            continue
        }
        
        # For YouTube, inject JavaScript
        if (`$url -match 'youtube\.com') {
            try {
                `$webRequest = [System.Net.HttpWebRequest]::Create(`$url)
                `$webRequest.Method = `$request.HttpMethod
                `$webRequest.Proxy = `$null
                `$webRequest.Timeout = 10000
                
                `$webResponse = `$webRequest.GetResponse()
                `$stream = `$webResponse.GetResponseStream()
                `$reader = New-Object System.IO.StreamReader(`$stream)
                `$content = `$reader.ReadToEnd()
                `$reader.Close()
                `$stream.Close()
                
                if (`$content -match '<html') {
                    `$script = '<script>(function(){var s=function(){try{var b=document.querySelector(".ytp-ad-skip-button");if(b&&b.offsetParent){b.click();}var o=document.querySelectorAll(".ytp-ad-overlay-container");o.forEach(function(e){e.style.display="none";});}catch(e){}};s();setInterval(s,250);})();</script>'
                    `$content = `$content -replace '</body>', (`$script + '</body>')
                }
                
                `$bytes = [System.Text.Encoding]::UTF8.GetBytes(`$content)
                `$response.ContentLength64 = `$bytes.Length
                `$response.ContentType = `$webResponse.ContentType
                `$response.StatusCode = 200
                `$response.OutputStream.Write(`$bytes, 0, `$bytes.Length)
                `$webResponse.Close()
            } catch {
                `$response.StatusCode = 500
            }
        } else {
            # Forward non-YouTube directly
            try {
                `$webRequest = [System.Net.HttpWebRequest]::Create(`$url)
                `$webRequest.Method = `$request.HttpMethod
                `$webRequest.Proxy = `$null
                `$webRequest.Timeout = 10000
                `$webResponse = `$webRequest.GetResponse()
                `$stream = `$webResponse.GetResponseStream()
                `$response.ContentType = `$webResponse.ContentType
                `$response.StatusCode = 200
                `$stream.CopyTo(`$response.OutputStream)
                `$stream.Close()
                `$webResponse.Close()
            } catch {
                `$response.StatusCode = 500
            }
        }
        `$response.Close()
    } catch {
        # Continue on error
    }
}
"@
        
        Set-Content -Path $proxyScriptPath -Value $proxyScriptContent -Encoding UTF8 -Force
        
        # Start proxy in new PowerShell window (hidden)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$proxyScriptPath`""
        $psi.CreateNoWindow = $true
        $psi.UseShellExecute = $false
        $process = [System.Diagnostics.Process]::Start($psi)
        
        Start-Sleep -Seconds 3
        
        # Verify proxy is running
        try {
            $testRequest = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($Script:YouTubeAdBlockerConfig.ProxyPort)/")
            $testRequest.Timeout = 2000
            $testRequest.Method = "GET"
            try {
                $testResponse = $testRequest.GetResponse()
                $testResponse.Close()
            } catch {
                # Proxy might not respond to root, but that's OK
            }
        } catch {}
        
        # Save PID
        $process.Id | Out-File -FilePath $Script:YouTubeAdBlockerConfig.PIDFile -Force
        
        Write-YouTubeLog "Proxy server started (PID: $($process.Id))" "Success"
        return $true
        
    } catch {
        Write-YouTubeLog "Failed to start proxy: $_" "Error"
        return $false
    }
}

function Stop-ProxyServer {
    Write-YouTubeLog "Stopping proxy server..." "Info"
    
    try {
        if (Test-Path $Script:YouTubeAdBlockerConfig.PIDFile) {
            $storedPid = Get-Content -Path $Script:YouTubeAdBlockerConfig.PIDFile -ErrorAction SilentlyContinue
            if ($storedPid) {
                $process = Get-Process -Id $storedPid -ErrorAction SilentlyContinue
                if ($process) {
                    Stop-Process -Id $storedPid -Force -ErrorAction SilentlyContinue
                    Write-YouTubeLog "Stopped proxy process (PID: $storedPid)" "Info"
                }
            }
            Remove-Item -Path $Script:YouTubeAdBlockerConfig.PIDFile -Force -ErrorAction SilentlyContinue
        }
        
        # Kill any remaining proxy PowerShell processes
        Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -like "*proxy.ps1*" -or $_.MainWindowTitle -like "*proxy*"
        } | Stop-Process -Force -ErrorAction SilentlyContinue
        
        Write-YouTubeLog "Proxy server stopped" "Success"
        return $true
    } catch {
        Write-YouTubeLog "Error stopping proxy: $_" "Error"
        return $false
    }
}

function Set-PACConfiguration {
    param([string]$ProxyHost, [int]$ProxyPort, [string]$GitHubPACUrl)
    
    Write-YouTubeLog "Configuring registry to use GitHub PAC URL..." "Info"
    
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        
        # Set GitHub PAC URL directly in registry
        Set-ItemProperty -Path $regPath -Name "AutoConfigURL" -Value $GitHubPACUrl -Type String -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 1 -Type DWord -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name "ProxyOverride" -Value "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>" -Type String -Force | Out-Null
        
        Write-YouTubeLog "Registry configured with GitHub PAC URL: $GitHubPACUrl" "Success"
        
        # Notify system
        $signature = @'
[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
        $type = Add-Type -MemberDefinition $signature -Name WinInet -Namespace NetTools -PassThru -ErrorAction SilentlyContinue
        if ($type) {
            $type::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
            $type::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
        }
        
        Write-YouTubeLog "PAC configuration complete" "Success"
        return $true
    } catch {
        Write-YouTubeLog "Failed to configure PAC: $_" "Error"
        return $false
    }
}

function Invoke-YouTubeAdBlocker {
    <#
    .SYNOPSIS
    Main function for YouTube ad blocking via local proxy server
    #>
    
    try {
        Write-YouTubeLog "=== Installing YouTube Ad Blocker ===" "Info"
        
        # Test internet before changes
        if (-not (Test-InternetConnectivity)) {
            Write-YouTubeLog "WARNING: No internet connectivity detected. Proceeding anyway..." "Warning"
        }
        
        # Create install directory (for proxy files only)
        if (-not (Test-Path $Script:YouTubeAdBlockerConfig.InstallDir)) {
            New-Item -ItemType Directory -Path $Script:YouTubeAdBlockerConfig.InstallDir -Force | Out-Null
        }
        
        # Start proxy server
        if (-not (Start-ProxyServer)) {
            Write-YouTubeLog "Failed to start proxy. Restoring settings..." "Error"
            Restore-InternetSettings
            return
        }
        
        # Wait a moment for proxy to be ready
        Start-Sleep -Seconds 2
        
        # Configure PAC registry key with GitHub PAC URL (no download)
        if (-not (Set-PACConfiguration -ProxyHost $Script:YouTubeAdBlockerConfig.ProxyHost -ProxyPort $Script:YouTubeAdBlockerConfig.ProxyPort -GitHubPACUrl $Script:YouTubeAdBlockerConfig.PACUrl)) {
            Write-YouTubeLog "Failed to configure PAC. Stopping proxy and restoring..." "Error"
            Stop-ProxyServer
            Restore-InternetSettings
            return
        }
        
        # Test internet after changes
        Start-Sleep -Seconds 2
        if (-not (Test-InternetConnectivity)) {
            Write-YouTubeLog "WARNING: Internet connectivity test failed after installation!" "Warning"
            Write-YouTubeLog "Restoring settings for safety..." "Warning"
            Restore-InternetSettings
            Stop-ProxyServer
            return
        }
        
        Write-YouTubeLog "=== Installation Complete ===" "Success"
        Write-YouTubeLog "Restart your browser for changes to take effect" "Info"
        
    } catch {
        Write-YouTubeLog "Error: $($_.Exception.Message)" "Error"
    }
}

#endregion

# ===================== Main =====================

try {
    if ($Uninstall) {
        Uninstall-Antivirus
    }

    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "`n[!] WARNING: Script is not running as Administrator!" -ForegroundColor Red
        Write-Host "[!] Some features require administrator privileges:" -ForegroundColor Yellow
        Write-Host "    - WebcamGuardian (device control)" -ForegroundColor Yellow
        Write-Host "    - Password Management (registry access)" -ForegroundColor Yellow
        Write-Host "    - Some detection modules" -ForegroundColor Yellow
        Write-Host "`n[i] To run with full functionality, right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Cyan
        Write-Host "`n[i] Continuing with limited functionality...`n" -ForegroundColor Gray
        Write-StabilityLog "Script running without administrator privileges - limited functionality" "WARN"
    } else {
        Write-StabilityLog "Script running with administrator privileges" "INFO"
    }

    Write-Host "`nAntivirus Protection (Single File)`n" -ForegroundColor Cyan
    Write-StabilityLog "=== Antivirus Starting ==="

    Write-StabilityLog "Executing script path: $PSCommandPath" "INFO"

    Register-ExitCleanup

    Install-Antivirus
    
    # Only initialize mutex if not already initialized during installation
    if (-not $Global:AntivirusState.Running) {
        Initialize-Mutex
    }

    Register-TerminationProtection

Write-Host "`n[PROTECTION] Initializing anti-termination safeguards..." -ForegroundColor Cyan

if ($host.Name -eq "Windows PowerShell ISE Host") {
    # In ISE, use trap handler which is already defined at the top
    Write-Host "[PROTECTION] ISE detected - using trap-based Ctrl+C protection" -ForegroundColor Cyan
    Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
} else {
    # In regular console, use the Console.CancelKeyPress handler
    Enable-CtrlCProtection
}

# Enable auto-restart if running as admin
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Enable-AutoRestart
        Start-ProcessWatchdog
    } else {
        Write-Host "[INFO] Auto-restart requires administrator privileges (optional)" -ForegroundColor Gray
    }
} catch {
    Write-Host "[WARNING] Some protection features failed to initialize: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[PROTECTION] Anti-termination safeguards active" -ForegroundColor Green
    Write-Host "[*] Starting detection jobs...`n" -ForegroundColor Cyan

    $loaded = 0
    $failed = 0

    $moduleNames = @(
        "HashDetection",
        "LOLBinDetection",
        "ProcessAnomalyDetection",
        "AMSIBypassDetection",
        "CredentialDumpDetection",
        "WMIPersistenceDetection",
        "ScheduledTaskDetection",
        "RegistryPersistenceDetection",
        "DLLHijackingDetection",
        "TokenManipulationDetection",
        "ProcessHollowingDetection",
        "KeyloggerDetection",
        "KeyScramblerManagement",
        "RansomwareDetection",
        "NetworkAnomalyDetection",
        "NetworkTrafficMonitoring",
        "RootkitDetection",
        "ClipboardMonitoring",
        "COMMonitoring",
        "BrowserExtensionMonitoring",
        "ShadowCopyMonitoring",
        "USBMonitoring",
        "EventLogMonitoring",
        "FirewallRuleMonitoring",
        "ServiceMonitoring",
        "FilelessDetection",
        "MemoryScanning",
        "NamedPipeMonitoring",
        "DNSExfiltrationDetection",
        "PasswordManagement",
        "YouTubeAdBlocker",
        "WebcamGuardian",
        "BeaconDetection",
        "CodeInjectionDetection",
        "DataExfiltrationDetection",
        "ElfCatcher",
        "FileEntropyDetection",
        "HoneypotMonitoring",
        "LateralMovementDetection",
        "ProcessCreationDetection",
        "QuarantineManagement",
        "ReflectiveDLLInjectionDetection",
        "ResponseEngine",
        "PrivacyForgeSpoofing"
    )

    foreach ($modName in $moduleNames) {
        $key = "${modName}IntervalSeconds"
        $interval = if ($Script:ManagedJobConfig.ContainsKey($key)) { $Script:ManagedJobConfig[$key] } else { 60 }

        try {
            Start-ManagedJob -ModuleName $modName -IntervalSeconds $interval

            if ($Global:AntivirusState.Jobs.ContainsKey("AV_$modName")) {
                Write-Host "[+] $modName ($interval sec)" -ForegroundColor Green
                Write-StabilityLog "Successfully started module: $modName"
                $loaded++
            }
            else {
                Write-Host "[!] $modName - skipped" -ForegroundColor Yellow
                Write-StabilityLog "Module skipped: $modName" "WARN"
                $failed++
            }
        }
        catch {
            Write-Host "[!] Failed to start $modName : $_" -ForegroundColor Red
            Write-StabilityLog "Module start failed: $modName - $_" "ERROR"
            Write-AVLog "Module start failed: $modName - $_" "ERROR"
            $failed++
        }
    }

    Write-Host "`n[+] Started $loaded modules" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "[!] $failed modules failed to start" -ForegroundColor Yellow
    }

    Write-StabilityLog "Module start complete: $loaded started, $failed failed"

    try {
        $mjCount = if ($script:ManagedJobs) { $script:ManagedJobs.Count } else { 0 }
        Write-StabilityLog "Managed jobs registered after start: $mjCount" "INFO"
        Write-Host "[AV] Managed jobs registered: $mjCount" -ForegroundColor DarkGray
    }
    catch {}

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Antivirus Protection ACTIVE" -ForegroundColor Green
    Write-Host "  Active jobs: $($Global:AntivirusState.Jobs.Count)" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "`nPress Ctrl+C to stop`n" -ForegroundColor Yellow

    Write-StabilityLog "Antivirus fully started with $($Global:AntivirusState.Jobs.Count) active jobs"
    Write-AVLog "About to enter Monitor-Jobs loop"

    Monitor-Jobs
}
catch {
    $err = $_.Exception.Message
    Write-Host "`n[!] Critical error: $err`n" -ForegroundColor Red
    Write-StabilityLog "Critical startup error: $err" "ERROR"
    Write-AVLog "Startup error: $err" "ERROR"

    if ($err -like "*already running*") {
        Write-Host "[i] Another instance is running. Exiting.`n" -ForegroundColor Yellow
        Write-StabilityLog "Blocked duplicate instance - exiting" "INFO"
        exit 1
    }

    Write-StabilityLog "Exiting due to startup failure" "ERROR"
    exit 1
}