#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Unified Antivirus EDR - All-in-One Security Monitoring Script
.DESCRIPTION
    Merged security monitoring script containing 42 detection modules running as managed tick jobs.
    Each module executes at its configured interval, orchestrated by a central tick manager.
.NOTES
    Author: Gorstak
    Version: 1.0
    Requires: Administrator privileges, PowerShell 5.1+
#>

param(
    [Parameter(Mandatory=$false)]
    [string[]]$AllowedDomains = @(),
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoStart,

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall = $false,

    [switch]$Verbose,
    [int]$MainLoopInterval = 5,
    [string]$LogLevel = "Info"
)

#region === CONFIGURATION ===

$script:EDRConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    LogPath = "$env:ProgramData\Antivirus\Logs"
    DataPath = "$env:ProgramData\Antivirus\Data"
    QuarantinePath = "$env:ProgramData\Antivirus\Quarantine"
    EventLogSource = "AntivirusEDR"
}

# Module definitions with tick intervals (in seconds)
$script:ModuleDefinitions = @{
    "Initializer"                  = @{ TickInterval = 10;  Priority = 0;  Function = "Invoke-Initialization" }
    "AMSIBypassDetection"          = @{ TickInterval = 30;  Priority = 1;  Function = "Invoke-AMSIBypassScan" }
    "BeaconDetection"              = @{ TickInterval = 60;  Priority = 2;  Function = "Invoke-BeaconDetection" }
    "BrowserExtensionMonitoring"   = @{ TickInterval = 120; Priority = 3;  Function = "Invoke-BrowserExtensionMonitoring" }
    "ClipboardMonitoring"          = @{ TickInterval = 30;  Priority = 4;  Function = "Invoke-ClipboardMonitoring" }
    "CodeInjectionDetection"       = @{ TickInterval = 30;  Priority = 5;  Function = "Invoke-CodeInjectionDetection" }
    "COMMonitoring"                = @{ TickInterval = 60;  Priority = 6;  Function = "Invoke-COMMonitoring" }
    "CredentialDumpDetection"      = @{ TickInterval = 20;  Priority = 7;  Function = "Invoke-CredentialDumpScan" }
    "DataExfiltrationDetection"    = @{ TickInterval = 30;  Priority = 8;  Function = "Invoke-DataExfiltrationDetection" }
    "DLLHijackingDetection"        = @{ TickInterval = 60;  Priority = 9;  Function = "Invoke-DLLHijackingScan" }
    "DNSExfiltrationDetection"     = @{ TickInterval = 30;  Priority = 10; Function = "Invoke-DNSExfiltrationDetection" }
    "ElfCatcher"                   = @{ TickInterval = 30;  Priority = 11; Function = "Invoke-ElfCatcher" }
    "EventLogMonitoring"           = @{ TickInterval = 60;  Priority = 12; Function = "Invoke-EventLogMonitoring" }
    "FileEntropyDetection"         = @{ TickInterval = 120; Priority = 13; Function = "Invoke-FileEntropyDetection" }
    "FilelessMalwareDetection"     = @{ TickInterval = 20;  Priority = 14; Function = "Invoke-FilelessDetection" }
    "FirewallRuleMonitoring"       = @{ TickInterval = 60;  Priority = 15; Function = "Invoke-FirewallRuleMonitoring" }
    "HashDetection"                = @{ TickInterval = 60;  Priority = 16; Function = "Invoke-HashScan" }
    "HoneypotMonitoring"           = @{ TickInterval = 30;  Priority = 17; Function = "Invoke-HoneypotMonitoring" }
    "KeyloggerDetection"           = @{ TickInterval = 30;  Priority = 18; Function = "Invoke-KeyloggerScan" }
    "KeyScramblerManagement"       = @{ TickInterval = 60;  Priority = 19; Function = "Invoke-KeyScramblerCheck" }
    "LateralMovementDetection"     = @{ TickInterval = 30;  Priority = 20; Function = "Invoke-LateralMovementDetection" }
    "MemoryScanning"               = @{ TickInterval = 60;  Priority = 21; Function = "Invoke-MemoryScanning" }
    "NamedPipeMonitoring"          = @{ TickInterval = 30;  Priority = 22; Function = "Invoke-NamedPipeMonitoring" }
    "NetworkAnomalyDetection"      = @{ TickInterval = 30;  Priority = 23; Function = "Invoke-NetworkAnomalyScan" }
    "NetworkTrafficMonitoring"     = @{ TickInterval = 30;  Priority = 24; Function = "Invoke-NetworkTrafficMonitoring" }
    "PasswordManagement"           = @{ TickInterval = 300; Priority = 25; Function = "Invoke-PasswordManagement" }
    "ProcessAnomalyDetection"      = @{ TickInterval = 20;  Priority = 26; Function = "Invoke-ProcessAnomalyScan" }
    "ProcessCreationDetection"     = @{ TickInterval = 10;  Priority = 27; Function = "Invoke-ProcessCreationDetection" }
    "ProcessHollowingDetection"    = @{ TickInterval = 30;  Priority = 28; Function = "Invoke-ProcessHollowingScan" }
    "QuarantineManagement"         = @{ TickInterval = 300; Priority = 29; Function = "Invoke-QuarantineManagement" }
    "RansomwareDetection"          = @{ TickInterval = 15;  Priority = 30; Function = "Invoke-RansomwareScan" }
    "ReflectiveDLLDetection"       = @{ TickInterval = 30;  Priority = 31; Function = "Invoke-ReflectiveDLLInjectionDetection" }
    "RegistryPersistenceDetection" = @{ TickInterval = 60;  Priority = 32; Function = "Invoke-RegistryPersistenceScan" }
    "ResponseEngine"               = @{ TickInterval = 10;  Priority = 33; Function = "Invoke-ResponseEngine" }
    "RootkitDetection"             = @{ TickInterval = 120; Priority = 34; Function = "Invoke-RootkitScan" }
    "ScheduledTaskDetection"       = @{ TickInterval = 60;  Priority = 35; Function = "Invoke-ScheduledTaskScan" }
    "ServiceMonitoring"            = @{ TickInterval = 60;  Priority = 36; Function = "Invoke-ServiceMonitoring" }
    "ShadowCopyMonitoring"         = @{ TickInterval = 30;  Priority = 37; Function = "Invoke-ShadowCopyMonitoring" }
    "TokenManipulationDetection"   = @{ TickInterval = 30;  Priority = 38; Function = "Invoke-TokenManipulationScan" }
    "USBMonitoring"                = @{ TickInterval = 30;  Priority = 39; Function = "Invoke-USBMonitoring" }
    "WebcamGuardian"               = @{ TickInterval = 20;  Priority = 40; Function = "Invoke-WebcamGuardian" }
    "WMIPersistenceDetection"      = @{ TickInterval = 60;  Priority = 41; Function = "Invoke-WMIPersistenceScan" }
}

# Module state tracking
$script:ModuleStates = @{}
foreach ($moduleName in $script:ModuleDefinitions.Keys) {
    $script:ModuleStates[$moduleName] = @{
        LastTick = [DateTime]::MinValue
        TotalRuns = 0
        TotalDetections = 0
        LastError = $null
        IsEnabled = $true
    }
}

# Shared state for modules that need baselines
$script:BaselineRules = @{}
$script:ServiceBaseline = @{}
$script:HashDatabase = @{}
$script:ThreatHashes = @{}
$script:ProcessedThreats = @{}
$script:Initialized = $false

# Response engine configuration
$script:ResponseActions = @{
    "Critical" = @("Quarantine", "KillProcess", "BlockNetwork", "Log")
    "High"     = @("Quarantine", "Log", "Alert")
    "Medium"   = @("Log", "Alert")
    "Low"      = @("Log")
}

#endregion

#region === LOGGING & UTILITIES ===

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
    $logFile = Join-Path $script:EDRConfig.LogPath "EDR_$(Get-Date -Format 'yyyy-MM-dd').log"
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
        $script:ModuleStates[$Module].TotalDetections += $Count
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

#endregion

#region === INITIALIZATION MODULE ===

function Invoke-Initialization {
    try {
        Write-EDRLog -Module "Initializer" -Message "Starting environment initialization" -Level "Info"
        
        # Create required directories
        $directories = @(
            "$env:ProgramData\Antivirus",
            "$env:ProgramData\Antivirus\Logs",
            "$env:ProgramData\Antivirus\Data",
            "$env:ProgramData\Antivirus\Quarantine",
            "$env:ProgramData\Antivirus\Reports",
            "$env:ProgramData\Antivirus\HashDatabase"
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-EDRLog -Module "Initializer" -Message "Created directory: $dir" -Level "Debug"
            }
        }
        
        # Create Event Log source if it doesn't exist
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("AntivirusEDR")) {
                [System.Diagnostics.EventLog]::CreateEventSource("AntivirusEDR", "Application")
                Write-EDRLog -Module "Initializer" -Message "Created Event Log source: AntivirusEDR" -Level "Info"
            }
        } catch {
            Write-EDRLog -Module "Initializer" -Message "Could not create Event Log source (may require elevation): $_" -Level "Warning"
        }
        
        # Initialize configuration file
        $configFile = "$env:ProgramData\Antivirus\Data\config.json"
        if (-not (Test-Path $configFile)) {
            $defaultConfig = @{
                Version = "1.0"
                Initialized = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                LastUpdate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Settings = @{
                    MaxLogSizeMB = 100
                    QuarantineRetentionDays = 30
                    EnableRealTimeResponse = $true
                    ResponseSeverity = "Medium"
                }
            }
            $defaultConfig | ConvertTo-Json -Depth 3 | Set-Content -Path $configFile
        }
        
        # Initialize module baselines
        Initialize-FirewallBaseline
        Initialize-ServiceBaseline
        Initialize-HashDatabase
        
        $script:Initialized = $true
        Write-EDRLog -Module "Initializer" -Message "Environment initialization completed" -Level "Info"
        return 1
        
    } catch {
        Write-EDRLog -Module "Initializer" -Message "Initialization failed: $_" -Level "Error"
        return 0
    }
}

#endregion

#region === INSTALL MODULE ===

function Install-Antivirus {
    $targetScript = Join-Path $Script:InstallPath $Script:ScriptName
    $currentPath = $PSCommandPath

    if ($currentPath -eq $targetScript) {
        Write-Host "[+] Running from install location" -ForegroundColor Green
        $Global:AntivirusState.Installed = $true
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

    Install-Persistence

    Write-Host "`n[+] Installation complete. Continuing in this instance...`n" -ForegroundColor Green
    $Global:AntivirusState.Installed = $true
    return $true
}

function Install-Persistence {
    Write-Host "`n[*] Setting up persistence for automatic startup...`n" -ForegroundColor Cyan

    try {
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($Script:InstallPath)\$($Script:ScriptName)`""
        $taskTrigger = New-ScheduledTaskTrigger -AtLogon -User $env:USERNAME
        $taskTriggerBoot = New-ScheduledTaskTrigger -AtStartup
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd

        Register-ScheduledTask -TaskName "AntivirusProtection" -Action $taskAction -Trigger $taskTrigger,$taskTriggerBoot -Principal $taskPrincipal -Settings $taskSettings -Force -ErrorAction Stop

        Write-Host "[+] Scheduled task created for automatic startup" -ForegroundColor Green
        Write-StabilityLog "Persistence setup completed - scheduled task created"
    }
    catch {
        Write-Host "[!] Failed to create scheduled task: $_" -ForegroundColor Red
        Write-StabilityLog "Persistence setup failed: $_" "ERROR"

        try {
            $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            $shortcutPath = Join-Path $startupFolder "AntivirusProtection.lnk"

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
            $existingPID = Get-Content $Config.PIDFilePath -ErrorAction Stop
            $existingProcess = Get-Process -Id $existingPID -ErrorAction SilentlyContinue

            if ($existingProcess) {
                Write-StabilityLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                Write-Host "[!] Another instance is already running (PID: $existingPID)" -ForegroundColor Yellow
                Write-AVLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                throw "Another instance is already running (PID: $existingPID)"
            }
            else {
                Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                Write-StabilityLog "Removed stale PID file (process $existingPID not running)"
                Write-AVLog "Removed stale PID file (process $existingPID not running)"
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
            Write-StabilityLog "Failed to acquire mutex - another instance is running" "ERROR"
            Write-Host "[!] Failed to acquire mutex - another instance is running" -ForegroundColor Yellow
            throw "Another instance is already running (mutex locked)"
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
                # CHANGE: Only release mutex if it was acquired
                if ($Global:AntivirusState.Running -and $Global:AntivirusState.Mutex) {
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
            
            # Changed $using: to $Script:
            $errorMsg = "Unhandled exception: $($evtArgs.Exception.ToString())"
            $errorMsg | Out-File "$Script:quarantineFolder\crash_log.txt" -Append
            
            try {
                # Log to security events
                $securityEvent = @{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    EventType = "UnexpectedTermination"
                    Severity = "Critical"
                    Exception = $evtArgs.Exception.ToString()
                    IsTerminating = $evtArgs.IsTerminating
                }
                $securityEvent | ConvertTo-Json -Compress | Out-File "$Script:quarantineFolder\security_events.jsonl" -Append
            } catch {}
            
            # Attempt auto-restart if configured
            if ($Script:AutoRestart -and $evtArgs.IsTerminating) {
                try {
                    Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$Script:SelfPath`"" `
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

#endregion

#region === BASELINE INITIALIZATION FUNCTIONS ===

function Initialize-FirewallBaseline {
    try {
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
    # Load known good hashes (whitelist)
    $whitelistPath = "$env:ProgramData\Antivirus\HashDatabase\whitelist.txt"
    if (Test-Path $whitelistPath) {
        Get-Content $whitelistPath | ForEach-Object {
            if ($_ -match '^([A-F0-9]{64})\|(.+)$') {
                $script:HashDatabase[$matches[1]] = $matches[2]
            }
        }
    }
    
    # Load threat hashes (blacklist)
    $threatPaths = @(
        "$env:ProgramData\Antivirus\HashDatabase\threats.txt",
        "$env:ProgramData\Antivirus\HashDatabase\malware_hashes.txt"
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
}

#endregion

#region === AMSI BYPASS DETECTION ===

function Invoke-AMSIBypassScan {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process | Where-Object { 
            $_.Name -like "*powershell*" -or $_.Name -like "*wscript*" -or $_.Name -like "*cscript*" 
        }
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ([string]::IsNullOrEmpty($cmdLine)) { continue }
            
            $bypassPatterns = @(
                '[Ref].Assembly.GetType.*System.Management.Automation.AmsiUtils',
                'AmsiScanBuffer', 'amsiInitFailed', 'amsi.dll',
                'PatchAmsi', 'DisableAmsi', 'Invoke-AmsiBypass',
                'AMSI.*bypass', 'bypass.*AMSI', '-nop.*-w.*hidden.*-enc'
            )
            
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
        }
        
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
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2004 `
                        -Message "AMSI BYPASS DETECTED: $($detection.ProcessName -or $detection.Type)"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\AMSIBypass_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.BypassPattern -or $_.Path)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "AMSIBypassDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === BEACON DETECTION ===

function Invoke-BeaconDetection {
    $detections = @()
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $connectionGroups = $connections | Group-Object RemoteAddress, RemotePort
        
        foreach ($group in $connectionGroups) {
            # Check for beaconing patterns (multiple connections to same destination)
            if ($group.Count -gt 10) {
                $sample = $group.Group | Select-Object -First 1
                $detections += @{
                    RemoteAddress = $sample.RemoteAddress
                    RemotePort = $sample.RemotePort
                    ConnectionCount = $group.Count
                    Type = "Potential C2 Beaconing"
                    Risk = "High"
                }
            }
        }
        
        # Check for connections to known bad ports
        $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 12345)
        foreach ($conn in $connections) {
            if ($conn.RemotePort -in $suspiciousPorts) {
                $detections += @{
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    LocalPort = $conn.LocalPort
                    ProcessId = $conn.OwningProcess
                    Type = "Suspicious Port Connection"
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\BeaconDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RemoteAddress):$($_.RemotePort)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "BeaconDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === BROWSER EXTENSION MONITORING ===

function Invoke-BrowserExtensionMonitoring {
    $detections = @()
    
    try {
        $extensionPaths = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions",
            "$env:APPDATA\Mozilla\Firefox\Profiles"
        )
        
        foreach ($path in $extensionPaths) {
            if (Test-Path $path) {
                $extensions = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue
                
                foreach ($ext in $extensions) {
                    # Check for recently added extensions
                    if ($ext.CreationTime -gt (Get-Date).AddHours(-24)) {
                        $detections += @{
                            ExtensionPath = $ext.FullName
                            ExtensionId = $ext.Name
                            CreationTime = $ext.CreationTime
                            Type = "New Browser Extension"
                            Risk = "Medium"
                        }
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\BrowserExtension_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ExtensionId)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "BrowserExtensionMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === CLIPBOARD MONITORING ===

function Invoke-ClipboardMonitoring {
    $detections = @()
    
    try {
        # Check for processes accessing clipboard APIs
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                # Check for suspicious processes accessing clipboard
                $suspiciousProcesses = @("keylog", "spy", "capture", "monitor", "hook")
                foreach ($suspicious in $suspiciousProcesses) {
                    if ($proc.ProcessName -like "*$suspicious*") {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            Type = "Suspicious Clipboard Access"
                            Risk = "High"
                        }
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ClipboardMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ClipboardMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === CODE INJECTION DETECTION ===

function Invoke-CodeInjectionDetection {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                if (-not $procObj) { continue }
                
                # Check for unsigned modules in system processes
                if ($proc.Name -in @("svchost.exe", "explorer.exe", "lsass.exe")) {
                    foreach ($module in $procObj.Modules) {
                        if ($module.FileName -and (Test-Path $module.FileName)) {
                            try {
                                $sig = Get-AuthenticodeSignature -FilePath $module.FileName -ErrorAction SilentlyContinue
                                if ($sig.Status -ne "Valid" -and $module.FileName -notlike "$env:SystemRoot\*") {
                                    $detections += @{
                                        ProcessId = $proc.ProcessId
                                        ProcessName = $proc.Name
                                        ModulePath = $module.FileName
                                        Type = "Unsigned Module in System Process"
                                        Risk = "High"
                                    }
                                }
                            } catch { }
                        }
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2005 `
                        -Message "CODE INJECTION: $($detection.ProcessName) - $($detection.ModulePath)"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\CodeInjection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.ModulePath)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "CodeInjectionDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === COM OBJECT MONITORING ===

function Invoke-COMMonitoring {
    $detections = @()
    
    try {
        # Check for suspicious COM object registrations
        $comKeys = @(
            "HKLM:\SOFTWARE\Classes\CLSID",
            "HKCU:\SOFTWARE\Classes\CLSID"
        )
        
        foreach ($comKey in $comKeys) {
            if (Test-Path $comKey) {
                try {
                    $clsids = Get-ChildItem -Path $comKey -ErrorAction SilentlyContinue | Select-Object -First 100
                    
                    foreach ($clsid in $clsids) {
                        $inprocServer = Get-ItemProperty -Path "$($clsid.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
                        if ($inprocServer -and $inprocServer.'(default)') {
                            $serverPath = $inprocServer.'(default)'
                            
                            # Check for DLLs outside system directories
                            if ($serverPath -and (Test-Path $serverPath)) {
                                if ($serverPath -notlike "$env:SystemRoot\*" -and $serverPath -notlike "$env:ProgramFiles*") {
                                    $detections += @{
                                        CLSID = $clsid.PSChildName
                                        ServerPath = $serverPath
                                        Type = "Non-Standard COM Server Location"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        }
                    }
                } catch { }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\COMMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.CLSID)|$($_.ServerPath)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "COMMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === CREDENTIAL DUMP DETECTION ===

function Invoke-CredentialDumpScan {
    $detections = @()
    
    try {
        # Check for LSASS access
        $lsassProc = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
        if ($lsassProc) {
            # Check for processes accessing LSASS memory
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                $cmdLine = $proc.CommandLine
                if ($cmdLine) {
                    # Check for credential dumping tools
                    $dumpPatterns = @(
                        "mimikatz", "sekurlsa", "lsadump", "procdump.*lsass",
                        "comsvcs.*MiniDump", "Out-Minidump", "pypykatz"
                    )
                    
                    foreach ($pattern in $dumpPatterns) {
                        if ($cmdLine -match $pattern) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $cmdLine
                                Pattern = $pattern
                                Type = "Credential Dumping Tool"
                                Risk = "Critical"
                            }
                        }
                    }
                }
            }
        }
        
        # Check Security Event Log for credential access
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656,4663} -ErrorAction SilentlyContinue -MaxEvents 50 |
                Where-Object { $_.Message -match 'lsass|sam|security' }
            
            foreach ($evt in $events) {
                $detections += @{
                    EventId = $evt.Id
                    TimeCreated = $evt.TimeCreated
                    Type = "Credential Access Event"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2006 `
                        -Message "CREDENTIAL DUMP: $($detection.ProcessName -or $detection.Type)"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\CredentialDump_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.EventId)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "CredentialDumpDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === DATA EXFILTRATION DETECTION ===

function Invoke-DataExfiltrationDetection {
    $detections = @()
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        
        # Group by process to find high-volume senders
        $byProcess = $connections | Group-Object OwningProcess
        
        foreach ($group in $byProcess) {
            if ($group.Count -gt 20) {
                $proc = Get-Process -Id $group.Name -ErrorAction SilentlyContinue
                $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                
                # Exclude known browsers and system processes
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
        
        # Check for large outbound transfers
        $networkAdapters = Get-NetAdapterStatistics -ErrorAction SilentlyContinue
        foreach ($adapter in $networkAdapters) {
            if ($adapter.SentBytes -gt 1GB) {
                $detections += @{
                    AdapterName = $adapter.Name
                    SentBytes = $adapter.SentBytes
                    Type = "Large Data Transfer"
                    Risk = "Medium"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\DataExfiltration_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.AdapterName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "DataExfiltrationDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === DLL HIJACKING DETECTION ===

function Invoke-DLLHijackingScan {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Modules }
        
        foreach ($proc in $processes) {
            try {
                foreach ($module in $proc.Modules) {
                    $modulePath = $module.FileName
                    if (-not $modulePath) { continue }
                    
                    # Check for DLLs loaded from suspicious locations
                    $suspiciousLocations = @(
                        "$env:TEMP",
                        "$env:APPDATA",
                        "$env:LOCALAPPDATA\Temp",
                        "C:\Users\Public"
                    )
                    
                    foreach ($location in $suspiciousLocations) {
                        if ($modulePath -like "$location\*") {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                DllPath = $modulePath
                                Type = "DLL Loaded from Suspicious Location"
                                Risk = "High"
                            }
                        }
                    }
                    
                    # Check for unsigned DLLs in trusted process
                    if ($proc.ProcessName -in @("explorer", "svchost", "lsass")) {
                        if (Test-Path $modulePath) {
                            $sig = Get-AuthenticodeSignature -FilePath $modulePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    DllPath = $modulePath
                                    Type = "Unsigned DLL in Trusted Process"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\DLLHijacking_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.DllPath)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "DLLHijackingDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === DNS EXFILTRATION DETECTION ===

function Invoke-DNSExfiltrationDetection {
    $detections = @()
    
    try {
        # Check DNS cache for suspicious queries
        try {
            $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
            
            foreach ($entry in $dnsCache) {
                $name = $entry.Entry
                
                # Check for unusually long domain names (DNS tunneling)
                if ($name.Length -gt 60) {
                    $detections += @{
                        DomainName = $name
                        Type = "Unusually Long DNS Query"
                        Risk = "High"
                    }
                }
                
                # Check for high entropy domain names
                $entropy = ($name.ToCharArray() | Select-Object -Unique).Count / $name.Length
                if ($entropy -gt 0.8 -and $name.Length -gt 30) {
                    $detections += @{
                        DomainName = $name
                        Entropy = $entropy
                        Type = "High Entropy Domain"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check for DNS over HTTPS processes
        $processes = Get-Process -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            if ($proc.ProcessName -match "doh|dns.*over.*https") {
                $detections += @{
                    ProcessId = $proc.Id
                    ProcessName = $proc.ProcessName
                    Type = "DNS over HTTPS Process"
                    Risk = "Low"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\DNSExfiltration_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.DomainName -or $_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "DNSExfiltrationDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === ELF CATCHER (LINUX BINARY DETECTION) ===

function Invoke-ElfCatcher {
    $detections = @()
    
    try {
        # Look for ELF binaries on Windows (WSL or malicious)
        $searchPaths = @(
            "$env:TEMP",
            "$env:APPDATA",
            "$env:LOCALAPPDATA\Temp",
            "C:\Users\Public"
        )
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                $files = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue | 
                    Select-Object -First 100
                
                foreach ($file in $files) {
                    try {
                        # Check for ELF magic bytes
                        $bytes = [System.IO.File]::ReadAllBytes($file.FullName) | Select-Object -First 4
                        if ($bytes.Count -ge 4) {
                            if ($bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46) {
                                $detections += @{
                                    FilePath = $file.FullName
                                    FileSize = $file.Length
                                    Type = "ELF Binary on Windows"
                                    Risk = "High"
                                }
                            }
                        }
                    } catch { }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ElfCatcher_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ElfCatcher" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === EVENT LOG MONITORING ===

function Invoke-EventLogMonitoring {
    $detections = @()
    
    try {
        # Check for cleared event logs
        try {
            $logClearEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue -MaxEvents 10
            
            foreach ($evt in $logClearEvents) {
                if ((Get-Date) - $evt.TimeCreated -lt [TimeSpan]::FromHours(24)) {
                    $detections += @{
                        EventId = $evt.Id
                        TimeCreated = $evt.TimeCreated
                        Type = "Security Log Cleared"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        # Check for disabled audit policies
        try {
            $auditEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719} -ErrorAction SilentlyContinue -MaxEvents 20
            
            foreach ($evt in $auditEvents) {
                if ($evt.Message -match 'disabled|removed') {
                    $detections += @{
                        EventId = $evt.Id
                        TimeCreated = $evt.TimeCreated
                        Type = "Audit Policy Modified"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for failed login attempts
        try {
            $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue -MaxEvents 100
            
            $recentFailures = $failedLogins | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(30)
            }
            
            if ($recentFailures.Count -gt 10) {
                $detections += @{
                    FailureCount = $recentFailures.Count
                    Type = "Multiple Failed Login Attempts"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\EventLogMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.EventId -or $_.FailureCount)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "EventLogMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === FILE ENTROPY DETECTION ===

function Invoke-FileEntropyDetection {
    $detections = @()
    
    try {
        # Check recently modified files for high entropy (encrypted/packed)
        $searchPaths = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop"
        )
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                $recentFiles = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) } |
                    Select-Object -First 20
                
                foreach ($file in $recentFiles) {
                    try {
                        if ($file.Length -gt 1000 -and $file.Length -lt 10MB) {
                            $bytes = [System.IO.File]::ReadAllBytes($file.FullName) | Select-Object -First 1000
                            $uniqueBytes = ($bytes | Select-Object -Unique).Count
                            $entropy = $uniqueBytes / 256
                            
                            if ($entropy -gt 0.9) {
                                $detections += @{
                                    FilePath = $file.FullName
                                    Entropy = [math]::Round($entropy, 3)
                                    FileSize = $file.Length
                                    Type = "High Entropy File"
                                    Risk = "Medium"
                                }
                            }
                        }
                    } catch { }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\FileEntropy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)|Entropy=$($_.Entropy)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "FileEntropyDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === FILELESS MALWARE DETECTION ===

function Invoke-FilelessDetection {
    $detections = @()
    
    try {
        # Check for PowerShell download cradles
        $psProcesses = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*powershell*" }
        
        foreach ($proc in $psProcesses) {
            $cmdLine = $proc.CommandLine
            if ($cmdLine -match '(?i)(downloadstring|downloadfile|webclient|invoke-webrequest).*(http|https|ftp)') {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    CommandLine = $cmdLine
                    Type = "PowerShell Download and Execute"
                    Risk = "Critical"
                }
            }
        }
        
        # Check for WMI event consumers (fileless persistence)
        try {
            $wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
            
            foreach ($consumer in $wmiConsumers) {
                if ($consumer.__CLASS -match 'ActiveScript|CommandLine') {
                    $detections += @{
                        ConsumerName = $consumer.Name
                        ConsumerClass = $consumer.__CLASS
                        Type = "WMI Fileless Persistence"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2026 `
                        -Message "FILELESS DETECTION: $($detection.Type) - $($detection.ProcessName -or $detection.ConsumerName)"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\FilelessDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.ConsumerName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "FilelessMalwareDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === FIREWALL RULE MONITORING ===

function Invoke-FirewallRuleMonitoring {
    $detections = @()
    
    try {
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        
        foreach ($rule in $rules) {
            $key = "$($rule.Name)|$($rule.Direction)|$($rule.Action)"
            
            if (-not $script:BaselineRules.ContainsKey($key)) {
                # New rule detected
                $detections += @{
                    RuleName = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Type = "New Firewall Rule"
                    Risk = "Medium"
                }
                
                $script:BaselineRules[$key] = @{
                    Name = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    FirstSeen = Get-Date
                }
            }
        }
        
        # Check for disabled firewall profiles
        try {
            $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            foreach ($fwProfile in $profiles) {
                if ($fwProfile.Enabled -eq $false) {
                    $detections += @{
                        ProfileName = $fwProfile.Name
                        Type = "Firewall Profile Disabled"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\FirewallRule_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RuleName -or $_.ProfileName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "FirewallRuleMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === HASH-BASED DETECTION ===

function Invoke-HashScan {
    $scannedFiles = 0
    $threatsFound = @()
    
    try {
        $scanPaths = @("$env:TEMP", "$env:APPDATA")
        
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            
            $files = Get-ChildItem -Path $scanPath -File -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { $_.Extension -in @(".exe", ".dll", ".ps1", ".bat", ".cmd") } |
                Select-Object -First 200
            
            foreach ($file in $files) {
                $scannedFiles++
                
                try {
                    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    if (-not $hash) { continue }
                    
                    if ($script:ThreatHashes.ContainsKey($hash.ToUpper())) {
                        $threatsFound += @{
                            File = $file.FullName
                            Hash = $hash
                            Size = $file.Length
                            Type = "Known Malware Hash"
                            Risk = "Critical"
                        }
                        
                        try {
                            Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2001 `
                                -Message "THREAT DETECTED: $($file.FullName) - Hash: $hash"
                        } catch { }
                    }
                } catch { continue }
            }
        }
        
        if ($threatsFound.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\HashDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $threatsFound | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|THREAT|$($_.File)|$($_.Hash)|$($_.Size)" | 
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "HashDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $threatsFound.Count
}

#endregion

#region === HONEYPOT MONITORING ===

function Invoke-HoneypotMonitoring {
    $detections = @()
    
    try {
        # Check honeypot files for access
        $honeypotFiles = @(
            "$env:ProgramData\Antivirus\Data\passwords.txt",
            "$env:ProgramData\Antivirus\Data\credentials.xlsx",
            "$env:ProgramData\Antivirus\Data\secrets.docx"
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
                # Create honeypot file
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
            foreach ($detection in $detections) {
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2050 `
                        -Message "HONEYPOT ALERT: $($detection.HoneypotFile) was accessed!"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Honeypot_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.HoneypotFile)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "HoneypotMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === KEYLOGGER DETECTION ===

function Invoke-KeyloggerScan {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                # Check for keyboard hook DLLs
                $modules = $proc.Modules | Where-Object {
                    $_.ModuleName -match 'hook|key|log|capture|spy'
                }
                
                if ($modules.Count -gt 0) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        SuspiciousModules = ($modules.ModuleName -join ',')
                        Type = "Potential Keylogger"
                        Risk = "High"
                    }
                }
                
                # Check for processes with SetWindowsHookEx
                if ($proc.ProcessName -match 'keylog|hook|spy|capture') {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        Type = "Suspicious Process Name"
                        Risk = "High"
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\Keylogger_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "KeyloggerDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === KEY SCRAMBLER CHECK ===

function Invoke-KeyScramblerCheck {
    $detections = @()
    
    try {
        # Check if KeyScrambler or similar protection is active
        $protectionProcesses = @("KeyScrambler", "Zemana", "SpyShelter")
        $activeProtection = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $protectionProcesses -contains $_.ProcessName
        }
        
        if ($activeProtection.Count -eq 0) {
            $detections += @{
                Type = "No Keystroke Protection Active"
                Risk = "Low"
            }
        }
    } catch {
        Write-EDRLog -Module "KeyScramblerManagement" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === LATERAL MOVEMENT DETECTION ===

function Invoke-LateralMovementDetection {
    $detections = @()
    
    try {
        # Check for PsExec-like activity
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ($cmdLine) {
                # Check for lateral movement tools
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
        
        # Check for SMB connections to multiple hosts
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
            $logPath = "$env:ProgramData\Antivirus\Logs\LateralMovement_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.UniqueHosts)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "LateralMovementDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === MEMORY SCANNING ===

function Invoke-MemoryScanning {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                # Check for processes with unusually high memory
                if ($proc.WorkingSet64 -gt 500MB -and $proc.ProcessName -notin @("chrome", "firefox", "msedge", "Code")) {
                    # Check if it's a legitimate process
                    if ($proc.Path -and -not (Test-Path $proc.Path)) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            MemoryMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                            Type = "High Memory Process Without Valid Path"
                            Risk = "High"
                        }
                    }
                }
                
                # Check for memory-only modules
                $memOnlyModules = $proc.Modules | Where-Object {
                    $_.FileName -and -not (Test-Path $_.FileName)
                }
                
                if ($memOnlyModules.Count -gt 3) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        MemoryModules = $memOnlyModules.Count
                        Type = "Process with Memory-Only Modules"
                        Risk = "High"
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\MemoryScanning_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "MemoryScanning" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === NAMED PIPE MONITORING ===

function Invoke-NamedPipeMonitoring {
    $detections = @()
    
    try {
        # Get named pipes
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Select-Object -First 100
        
        # Known malicious pipe patterns
        $maliciousPipes = @(
            "meterpreter", "beacon", "cobaltstrike", "\\psexec",
            "\\RemCom", "\\isapi", "\\msagent", "\\postex"
        )
        
        foreach ($pipe in $pipes) {
            foreach ($pattern in $maliciousPipes) {
                if ($pipe -match $pattern) {
                    $detections += @{
                        PipeName = $pipe
                        Pattern = $pattern
                        Type = "Suspicious Named Pipe"
                        Risk = "Critical"
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2030 `
                        -Message "SUSPICIOUS NAMED PIPE: $($detection.PipeName)"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\NamedPipe_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.PipeName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "NamedPipeMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === NETWORK ANOMALY DETECTION ===

function Invoke-NetworkAnomalyScan {
    $detections = @()
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        
        # Check for connections to unusual ports
        $unusualPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321)
        foreach ($conn in $connections) {
            if ($conn.RemotePort -in $unusualPorts) {
                $detections += @{
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    ProcessId = $conn.OwningProcess
                    Type = "Unusual Port Connection"
                    Risk = "High"
                }
            }
        }
        
        # Check for excessive connections from single process
        $byProcess = $connections | Group-Object OwningProcess
        foreach ($group in $byProcess) {
            if ($group.Count -gt 50) {
                $proc = Get-Process -Id $group.Name -ErrorAction SilentlyContinue
                if ($proc -and $proc.ProcessName -notin @("chrome", "firefox", "msedge", "svchost")) {
                    $detections += @{
                        ProcessId = $group.Name
                        ProcessName = $proc.ProcessName
                        ConnectionCount = $group.Count
                        Type = "Excessive Connections"
                        Risk = "Medium"
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\NetworkAnomaly_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RemoteAddress -or $_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === NETWORK TRAFFIC MONITORING ===

function Invoke-NetworkTrafficMonitoring {
    $detections = @()
    
    try {
        # Check for listening ports
        $listeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        
        foreach ($port in $listeningPorts) {
            $proc = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue
            
            # Check for suspicious listening ports
            if ($port.LocalPort -in @(4444, 5555, 6666, 7777, 8888, 9999)) {
                $detections += @{
                    LocalPort = $port.LocalPort
                    ProcessId = $port.OwningProcess
                    ProcessName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                    Type = "Suspicious Listening Port"
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\NetworkTraffic_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|Port=$($_.LocalPort)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "NetworkTrafficMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === PASSWORD MANAGEMENT ===

function Invoke-PasswordManagement {
    $detections = @()
    
    try {
        # Check for plaintext passwords in common locations
        $searchPaths = @(
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Documents"
        )
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                $files = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match 'password|credential|secret|key' } |
                    Select-Object -First 10
                
                foreach ($file in $files) {
                    $detections += @{
                        FilePath = $file.FullName
                        FileName = $file.Name
                        Type = "Potential Password File"
                        Risk = "Medium"
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\PasswordManagement_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "PasswordManagement" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === PROCESS ANOMALY DETECTION ===

function Invoke-ProcessAnomalyScan {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            # Check for processes running from temp directories
            if ($proc.ExecutablePath -like "*\Temp\*" -or $proc.ExecutablePath -like "*\AppData\Local\Temp\*") {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    Path = $proc.ExecutablePath
                    Type = "Process Running from Temp"
                    Risk = "Medium"
                }
            }
            
            # Check for processes with no parent
            if ($proc.ParentProcessId -eq 0 -and $proc.Name -notin @("System", "Idle")) {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    Type = "Orphaned Process"
                    Risk = "Medium"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessAnomaly_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.Path)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ProcessAnomalyDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === PROCESS CREATION DETECTION ===

function Invoke-ProcessCreationDetection {
    $detections = @()
    
    try {
        # Check recent process creation events
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue -MaxEvents 50
            
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $newProcessName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text'
                $commandLine = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
                
                # Check for suspicious command lines
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
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessCreation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.Pattern)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ProcessCreationDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === PROCESS HOLLOWING DETECTION ===

function Invoke-ProcessHollowingScan {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Modules }
        
        foreach ($proc in $processes) {
            try {
                # Check for processes where memory doesn't match disk
                if ($proc.Path -and (Test-Path $proc.Path)) {
                    $fileSize = (Get-Item $proc.Path).Length
                    $memorySize = $proc.WorkingSet64
                    
                    # Significant difference might indicate hollowing
                    if ($memorySize -gt ($fileSize * 10) -and $fileSize -lt 1MB) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            FileSize = $fileSize
                            MemorySize = $memorySize
                            Type = "Potential Process Hollowing"
                            Risk = "High"
                        }
                    }
                }
                
                # Check for unsigned main module
                if ($proc.Path) {
                    $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
                    if ($sig.Status -ne "Valid" -and $proc.ProcessName -in @("svchost", "explorer", "rundll32")) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            Path = $proc.Path
                            Type = "Unsigned System Process"
                            Risk = "Critical"
                        }
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessHollowing_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ProcessHollowingDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === QUARANTINE MANAGEMENT ===

function Invoke-QuarantineFile {
    param(
        [string]$FilePath,
        [string]$Reason,
        [string]$Source
    )
    
    try {
        if (Test-Path $FilePath) {
            $quarantinePath = "$env:ProgramData\Antivirus\Quarantine"
            $fileName = Split-Path $FilePath -Leaf
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $quarantineFile = Join-Path $quarantinePath "$timestamp`_$fileName.quarantine"
            
            # Move file to quarantine
            Move-Item -Path $FilePath -Destination $quarantineFile -Force
            
            # Log quarantine action
            $logPath = "$env:ProgramData\Antivirus\Logs\Quarantine_$(Get-Date -Format 'yyyy-MM-dd').log"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|QUARANTINE|$FilePath|$Reason|$Source" |
                Add-Content -Path $logPath -ErrorAction SilentlyContinue
            
            return $true
        }
    } catch {
        Write-EDRLog -Module "QuarantineManagement" -Message "Failed to quarantine $FilePath`: $_" -Level "Error"
    }
    
    return $false
}

function Invoke-QuarantineManagement {
    $detections = 0
    
    try {
        $quarantinePath = "$env:ProgramData\Antivirus\Quarantine"
        if (Test-Path $quarantinePath) {
            # Clean up old quarantine files (older than 30 days)
            $oldFiles = Get-ChildItem -Path $quarantinePath -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) }
            
            foreach ($file in $oldFiles) {
                try {
                    Remove-Item -Path $file.FullName -Force
                    Write-EDRLog -Module "QuarantineManagement" -Message "Cleaned up old quarantine file: $($file.Name)" -Level "Debug"
                } catch { }
            }
        }
    } catch {
        Write-EDRLog -Module "QuarantineManagement" -Message "Error: $_" -Level "Error"
    }
    
    return $detections
}

#endregion

#region === RANSOMWARE DETECTION ===

function Invoke-RansomwareScan {
    $detections = @()
    
    try {
        # Check for rapid file modifications
        $monitorPaths = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop"
        )
        
        foreach ($path in $monitorPaths) {
            if (Test-Path $path) {
                $recentMods = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) }
                
                # Check for ransomware indicators
                $ransomwareExtensions = @(".encrypted", ".locked", ".crypt", ".locky", ".cerber", ".zepto", ".wannacry")
                foreach ($file in $recentMods) {
                    foreach ($ext in $ransomwareExtensions) {
                        if ($file.Extension -eq $ext) {
                            $detections += @{
                                FilePath = $file.FullName
                                Extension = $ext
                                Type = "Ransomware Extension Detected"
                                Risk = "Critical"
                            }
                        }
                    }
                }
                
                # Check for mass file modifications (ransomware behavior)
                if ($recentMods.Count -gt 50) {
                    $detections += @{
                        Path = $path
                        ModifiedFiles = $recentMods.Count
                        Type = "Mass File Modification"
                        Risk = "Critical"
                    }
                }
            }
        }
        
        # Check for ransom notes
        $ransomNotePatterns = @("readme*.txt", "*ransom*", "*decrypt*", "*recover*files*")
        foreach ($path in $monitorPaths) {
            if (Test-Path $path) {
                foreach ($pattern in $ransomNotePatterns) {
                    $ransomNotes = Get-ChildItem -Path $path -Filter $pattern -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-24) }
                    
                    foreach ($note in $ransomNotes) {
                        $detections += @{
                            FilePath = $note.FullName
                            Type = "Potential Ransom Note"
                            Risk = "Critical"
                        }
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2099 `
                        -Message "RANSOMWARE ALERT: $($detection.Type) - $($detection.FilePath -or $detection.Path)"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Ransomware_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath -or $_.Path)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "RansomwareDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === REFLECTIVE DLL INJECTION DETECTION ===

function Invoke-ReflectiveDLLInjectionDetection {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Modules }
        
        foreach ($proc in $processes) {
            try {
                # Check for modules not backed by files
                foreach ($module in $proc.Modules) {
                    if ($module.FileName) {
                        if (-not (Test-Path $module.FileName)) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                ModuleName = $module.ModuleName
                                ModulePath = $module.FileName
                                Type = "Module Not Backed by File"
                                Risk = "Critical"
                            }
                        }
                    }
                }
                
                # Check for RWX memory regions (common in reflective injection)
                # Note: Full implementation would require P/Invoke
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ReflectiveDLL_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.ModulePath)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ReflectiveDLLDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === REGISTRY PERSISTENCE DETECTION ===

function Invoke-RegistryPersistenceScan {
    $detections = @()
    
    try {
        $persistenceKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        )
        
        foreach ($key in $persistenceKeys) {
            if (Test-Path $key) {
                try {
                    $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                    $props = $values.PSObject.Properties | Where-Object {
                        $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
                    }
                    
                    foreach ($prop in $props) {
                        $value = $prop.Value
                        
                        # Check for suspicious values
                        if ($value -match 'powershell.*-enc|cmd.*/c|mshta|wscript|cscript') {
                            $detections += @{
                                RegistryKey = $key
                                ValueName = $prop.Name
                                Value = $value
                                Type = "Suspicious Registry Persistence"
                                Risk = "High"
                            }
                        }
                        
                        # Check for executables in non-standard locations
                        if ($value -like "*\Temp\*" -or $value -like "*\AppData\Local\Temp\*") {
                            $detections += @{
                                RegistryKey = $key
                                ValueName = $prop.Name
                                Value = $value
                                Type = "Persistence from Temp Location"
                                Risk = "High"
                            }
                        }
                    }
                } catch { }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\RegistryPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RegistryKey)|$($_.ValueName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "RegistryPersistenceDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === RESPONSE ENGINE ===

function Invoke-ResponseAction {
    param(
        [hashtable]$Detection,
        [string]$Severity
    )
    
    $actions = $script:ResponseActions[$Severity]
    if (-not $actions) { $actions = @("Log") }
    
    $results = @()
    
    foreach ($action in $actions) {
        try {
            switch ($action) {
                "Quarantine" {
                    if ($Detection.FilePath -or $Detection.DllPath) {
                        $filePath = if ($Detection.FilePath) { $Detection.FilePath } else { $Detection.DllPath }
                        if (Test-Path $filePath) {
                            $result = Invoke-QuarantineFile -FilePath $filePath -Reason "Threat: $($Detection.Type)" -Source $Detection.ModuleName
                            if ($result) { $results += "Quarantined: $filePath" }
                        }
                    }
                }
                "KillProcess" {
                    if ($Detection.ProcessId) {
                        try {
                            Stop-Process -Id $Detection.ProcessId -Force -ErrorAction Stop
                            $results += "Killed process PID: $($Detection.ProcessId)"
                        } catch {
                            $results += "Failed to kill process PID: $($Detection.ProcessId)"
                        }
                    }
                }
                "BlockNetwork" {
                    if ($Detection.RemoteAddress) {
                        try {
                            $ruleName = "Block_Threat_$($Detection.RemoteAddress.Replace('.', '_'))"
                            $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                            if (-not $existing) {
                                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress $Detection.RemoteAddress -Action Block -ErrorAction SilentlyContinue | Out-Null
                                $results += "Blocked network to: $($Detection.RemoteAddress)"
                            }
                        } catch { }
                    }
                }
                "Alert" {
                    try {
                        $alertMsg = "ALERT: $($Detection.Type) - Severity: $Severity"
                        Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2100 -Message $alertMsg
                        $results += "Alert sent"
                    } catch { }
                }
                "Log" {
                    $logPath = "$env:ProgramData\Antivirus\Logs\ResponseEngine_$(Get-Date -Format 'yyyy-MM-dd').log"
                    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$Severity|$($Detection.Type)|$($Detection.ProcessName -or $Detection.FilePath)"
                    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
                    $results += "Logged"
                }
            }
        } catch {
            $results += "Error in action $action`: $_"
        }
    }
    
    return $results
}

function Invoke-ResponseEngine {
    $responses = 0
    
    try {
        # Check all module detection logs for new threats
        $logPath = "$env:ProgramData\Antivirus\Logs"
        if (Test-Path $logPath) {
            $today = Get-Date -Format 'yyyy-MM-dd'
            $logFiles = Get-ChildItem -Path $logPath -Filter "*_$today.log" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne "ResponseEngine_$today.log" -and $_.Name -ne "EDR_$today.log" }
            
            foreach ($logFile in $logFiles) {
                try {
                    $logEntries = Get-Content -Path $logFile.FullName -ErrorAction SilentlyContinue | Select-Object -Last 20
                    
                    foreach ($entry in $logEntries) {
                        if ($entry -match '\|') {
                            $parts = $entry -split '\|'
                            if ($parts.Length -ge 3) {
                                $risk = $parts[2]
                                $detectionHash = $entry.GetHashCode()
                                
                                if (-not $script:ProcessedThreats.ContainsKey($detectionHash)) {
                                    $script:ProcessedThreats[$detectionHash] = $true
                                    
                                    if ($risk -in @("Critical", "High")) {
                                        $detection = @{
                                            Type = $parts[1]
                                            Risk = $risk
                                            Details = if ($parts.Length -gt 3) { $parts[3] } else { "" }
                                        }
                                        
                                        Invoke-ResponseAction -Detection $detection -Severity $risk | Out-Null
                                        $responses++
                                    }
                                }
                            }
                        }
                    }
                } catch { }
            }
        }
    } catch {
        Write-EDRLog -Module "ResponseEngine" -Message "Error: $_" -Level "Error"
    }
    
    return $responses
}

#endregion

#region === ROOTKIT DETECTION ===

function Invoke-RootkitScan {
    $detections = @()
    
    try {
        # Check for hidden processes
        $wmiProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessId
        $psProcesses = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
        
        $hiddenProcesses = $wmiProcesses | Where-Object { $_ -notin $psProcesses }
        foreach ($processId in $hiddenProcesses) {
            $detections += @{
                ProcessId = $processId
                Type = "Hidden Process (WMI vs PS mismatch)"
                Risk = "Critical"
            }
        }
        
        # Check for hidden services
        $wmiServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        $scServices = Get-Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        
        $hiddenServices = $wmiServices | Where-Object { $_ -notin $scServices }
        foreach ($svc in $hiddenServices) {
            $detections += @{
                ServiceName = $svc
                Type = "Hidden Service"
                Risk = "Critical"
            }
        }
        
        # Check for SSDT hooks (simplified check)
        try {
            $kernelModules = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                Where-Object { $_.PathName -notlike "$env:SystemRoot\*" -and $_.State -eq "Running" }
            
            foreach ($module in $kernelModules) {
                $detections += @{
                    DriverName = $module.Name
                    DriverPath = $module.PathName
                    Type = "Non-Standard Kernel Driver"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2080 `
                        -Message "ROOTKIT DETECTION: $($detection.Type)"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Rootkit_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessId -or $_.ServiceName -or $_.DriverName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "RootkitDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === SCHEDULED TASK DETECTION ===

function Invoke-ScheduledTaskScan {
    $detections = @()
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" }
        
        foreach ($task in $tasks) {
            try {
                $actions = $task.Actions
                
                foreach ($action in $actions) {
                    if ($action.Execute) {
                        $execute = $action.Execute
                        $arguments = $action.Arguments
                        
                        # Check for suspicious task actions
                        $suspiciousPatterns = @(
                            "powershell.*-enc", "cmd.*/c", "mshta", "wscript", "cscript",
                            "certutil", "bitsadmin", "regsvr32"
                        )
                        
                        foreach ($pattern in $suspiciousPatterns) {
                            if ("$execute $arguments" -match $pattern) {
                                $detections += @{
                                    TaskName = $task.TaskName
                                    TaskPath = $task.TaskPath
                                    Execute = $execute
                                    Arguments = $arguments
                                    Pattern = $pattern
                                    Type = "Suspicious Scheduled Task"
                                    Risk = "High"
                                }
                            }
                        }
                        
                        # Check for tasks running from temp
                        if ($execute -like "*\Temp\*" -or $arguments -like "*\Temp\*") {
                            $detections += @{
                                TaskName = $task.TaskName
                                Execute = $execute
                                Type = "Scheduled Task from Temp"
                                Risk = "High"
                            }
                        }
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ScheduledTask_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.TaskName)|$($_.Pattern)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ScheduledTaskDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === SERVICE MONITORING ===

function Invoke-ServiceMonitoring {
    $detections = @()
    
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        
        foreach ($service in $services) {
            $key = $service.Name
            
            if (-not $script:ServiceBaseline.ContainsKey($key)) {
                # New service detected
                $detections += @{
                    ServiceName = $service.Name
                    DisplayName = $service.DisplayName
                    PathName = $service.PathName
                    Type = "New Service"
                    Risk = "Medium"
                }
                
                $script:ServiceBaseline[$key] = @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    PathName = $service.PathName
                    StartMode = $service.StartMode
                    State = $service.State
                    FirstSeen = Get-Date
                }
            } else {
                # Check for service binary path changes
                $baseline = $script:ServiceBaseline[$key]
                if ($service.PathName -ne $baseline.PathName) {
                    $detections += @{
                        ServiceName = $service.Name
                        OldPath = $baseline.PathName
                        NewPath = $service.PathName
                        Type = "Service Binary Changed"
                        Risk = "High"
                    }
                    
                    $baseline.PathName = $service.PathName
                }
            }
            
            # Check for services running from suspicious locations
            if ($service.PathName -like "*\Temp\*" -or $service.PathName -like "*\AppData\*") {
                $detections += @{
                    ServiceName = $service.Name
                    PathName = $service.PathName
                    Type = "Service from Suspicious Location"
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ServiceMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ServiceName)|$($_.PathName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ServiceMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === SHADOW COPY MONITORING ===

function Invoke-ShadowCopyMonitoring {
    $detections = @()
    
    try {
        $shadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        
        if ($shadowCopies.Count -eq 0) {
            $detections += @{
                Type = "No Shadow Copies Found"
                ShadowCopyCount = 0
                Risk = "Medium"
            }
        }
        
        # Check for VSSAdmin manipulation
        $processes = Get-CimInstance Win32_Process | 
            Where-Object { $_.Name -eq "vssadmin.exe" -or $_.CommandLine -like "*vssadmin*" }
        
        foreach ($proc in $processes) {
            if ($proc.CommandLine -match 'delete.*shadows|resize.*shadowstorage') {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    CommandLine = $proc.CommandLine
                    Type = "VSSAdmin Shadow Copy Manipulation"
                    Risk = "Critical"
                }
            }
        }
        
        # Check VSS service status
        $vssService = Get-CimInstance Win32_Service -Filter "Name='VSS'" -ErrorAction SilentlyContinue
        if ($vssService -and $vssService.State -ne "Running") {
            $detections += @{
                ServiceState = $vssService.State
                Type = "VSS Service Not Running"
                Risk = "High"
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ShadowCopy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessId -or $_.ServiceState)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "ShadowCopyMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === TOKEN MANIPULATION DETECTION ===

function Invoke-TokenManipulationScan {
    $detections = @()
    
    try {
        # Check for token manipulation tools
        $tokenTools = @("incognito", "mimikatz", "invoke-tokenmanipulation", "getsystem")
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            foreach ($tool in $tokenTools) {
                if ($proc.ProcessName -like "*$tool*" -or ($proc.Path -and $proc.Path -like "*$tool*")) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        Tool = $tool
                        Type = "Token Manipulation Tool"
                        Risk = "Critical"
                    }
                }
            }
        }
        
        # Check for processes running as SYSTEM from non-Windows paths
        $wmiProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($proc in $wmiProcesses) {
            if ($proc.ExecutablePath -and $proc.ExecutablePath -notlike "$env:SystemRoot\*") {
                try {
                    $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($owner.User -eq "SYSTEM") {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            Path = $proc.ExecutablePath
                            Type = "SYSTEM Token on Non-Windows Executable"
                            Risk = "High"
                        }
                    }
                } catch { }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\TokenManipulation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.Tool)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "TokenManipulationDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === USB MONITORING ===

function Invoke-USBMonitoring {
    $detections = @()
    
    try {
        $usbDevices = Get-CimInstance Win32_USBControllerDevice -ErrorAction SilentlyContinue
        
        foreach ($usbDevice in $usbDevices) {
            try {
                $device = Get-CimInstance -InputObject $usbDevice.Dependent -ErrorAction SilentlyContinue
                if ($device) {
                    $deviceType = $device.DeviceID
                    
                    # Check for HID devices (potential keyloggers)
                    if ($deviceType -match "HID" -and $deviceType -notmatch "keyboard|mouse") {
                        $detections += @{
                            DeviceId = $device.DeviceID
                            DeviceName = $device.Name
                            Type = "Unknown HID Device"
                            Risk = "Medium"
                        }
                    }
                }
            } catch { continue }
        }
        
        # Check for USB autorun enabled
        $autorunKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (Test-Path $autorunKey) {
            $noDriveAutorun = Get-ItemProperty -Path $autorunKey -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            if ($noDriveAutorun -and $noDriveAutorun.NoDriveTypeAutoRun -eq 0) {
                $detections += @{
                    Type = "USB Autorun Enabled"
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\USBMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.DeviceName -or 'System')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "USBMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === WEBCAM GUARDIAN ===

function Invoke-WebcamGuardian {
    $detections = @()
    
    try {
        # Check for webcam devices
        $webcamDevices = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'camera|webcam|video|imaging' }
        
        if ($webcamDevices.Count -gt 0) {
            # Check for processes accessing webcam
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'vidcap|camera|webcam|avicap'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Exclude known legitimate apps
                        $legitApps = @("chrome", "firefox", "msedge", "teams", "zoom", "skype")
                        if ($proc.ProcessName -notin $legitApps) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                Type = "Unknown Webcam Access"
                                Risk = "High"
                            }
                        }
                    }
                } catch { continue }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\WebcamGuardian_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "WebcamGuardian" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === WMI PERSISTENCE DETECTION ===

function Invoke-WMIPersistenceScan {
    $detections = @()
    
    try {
        # Check for WMI event subscriptions
        $eventFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        $eventConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
        
        foreach ($filter in $eventFilters) {
            $detections += @{
                FilterName = $filter.Name
                Query = $filter.Query
                Type = "WMI Event Filter"
                Risk = "High"
            }
        }
        
        foreach ($consumer in $eventConsumers) {
            $consumerType = $consumer.__CLASS
            
            # ActiveScript and CommandLine consumers are suspicious
            if ($consumerType -match 'ActiveScript|CommandLine') {
                $detections += @{
                    ConsumerName = $consumer.Name
                    ConsumerType = $consumerType
                    Type = "Suspicious WMI Consumer"
                    Risk = "Critical"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2070 `
                        -Message "WMI PERSISTENCE: $($detection.Type) - $($detection.FilterName -or $detection.ConsumerName)"
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\WMIPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilterName -or $_.ConsumerName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-EDRLog -Module "WMIPersistenceDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

#endregion

#region === TICK MANAGER (MAIN ORCHESTRATOR) ===

function Start-TickManager {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Unified Antivirus EDR v$($script:EDRConfig.Version)" -ForegroundColor Green
    Write-Host "  Starting Tick Manager..." -ForegroundColor Green
    Write-Host "  Modules: $($script:ModuleDefinitions.Count)" -ForegroundColor Green
    Write-Host "  Press Ctrl+C to stop" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    $tickCount = 0
    
    while ($true) {
        $tickCount++
        $now = Get-Date
        $modulesRun = 0
        
        # Sort modules by priority
        $sortedModules = $script:ModuleDefinitions.GetEnumerator() | Sort-Object { $_.Value.Priority }
        
        foreach ($module in $sortedModules) {
            $moduleName = $module.Key
            $moduleConfig = $module.Value
            $moduleState = $script:ModuleStates[$moduleName]
            
            if (-not $moduleState.IsEnabled) { continue }
            
            $timeSinceLastTick = ($now - $moduleState.LastTick).TotalSeconds
            
            if ($timeSinceLastTick -ge $moduleConfig.TickInterval) {
                try {
                    # Get the function and invoke it
                    $functionName = $moduleConfig.Function
                    $detectionCount = & $functionName
                    
                    # Update state
                    $moduleState.LastTick = $now
                    $moduleState.TotalRuns++
                    
                    if ($detectionCount -gt 0) {
                        Write-Detection -Module $moduleName -Count $detectionCount
                    }
                    
                    $modulesRun++
                    
                } catch {
                    $moduleState.LastError = $_.Exception.Message
                    Write-EDRLog -Module $moduleName -Message "Error during scan: $_" -Level "Error"
                }
            }
        }
        
        # Status update every 60 ticks
        if ($tickCount % 60 -eq 0) {
            $totalDetections = ($script:ModuleStates.Values | Measure-Object -Property TotalDetections -Sum).Sum
            $runtime = (Get-Date) - $script:EDRConfig.StartTime
            Write-EDRLog -Module "TickManager" -Message "Runtime: $([math]::Round($runtime.TotalMinutes, 1)) min | Total Detections: $totalDetections" -Level "Info"
        }
        
        Start-Sleep -Seconds $MainLoopInterval
    }
}

#endregion

#region === MAIN ENTRY POINT ===

# Run initialization first
$initResult = Invoke-Initialization
if ($initResult -gt 0) {
    Write-EDRLog -Module "Main" -Message "Initialization successful, starting tick manager" -Level "Info"
    Start-TickManager
} else {
    Write-EDRLog -Module "Main" -Message "Initialization failed, cannot start" -Level "Error"
    exit 1
}

#endregion
