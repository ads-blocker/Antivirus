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
}

$Script:LoopCounter = 0
$script:ManagedJobs = @{}

# Termination protection variables
$Script:TerminationAttempts = 0
$Script:MaxTerminationAttempts = 5
$Script:AutoRestart = $true
$Script:SelfPID = $PID

function Write-AVLog {
    param([string]$Message, [string]$Level = "INFO")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    $logFile = Join-Path $Config.LogPath "antivirus_log.txt"

    if (!(Test-Path $Config.LogPath)) {
        New-Item -ItemType Directory -Path $Config.LogPath -Force | Out-Null
    }

    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue

    $eid = switch ($Level) {
        "ERROR" { 1001 }
        "WARN" { 1002 }
        "THREAT" { 1003 }
        default { 1000 }
    }

    Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Information -EventId $eid -Message $Message -ErrorAction SilentlyContinue
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
            $pid = Get-Content -Path $Script:YouTubeAdBlockerConfig.PIDFile -ErrorAction SilentlyContinue
            if ($pid) {
                $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($process) {
                    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
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
        $hostsContent = Get-Content $hostsPath
        $cleanContent = $hostsContent | Where-Object { $_ -notmatch "# Ad Blocking" -and $_ -notmatch "127\.0\.0\.1.*ads?" -and $_ -notmatch "127\.0\.0\.1.*doubleclick" -and $_ -notmatch "127\.0\.0\.1.*googleads" }
        Set-Content $hostsPath $cleanContent -Encoding UTF8
        ipconfig /flushdns | Out-Null
    }
    catch {}
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

        $cmd = Get-Command $FunctionName -ErrorAction Stop
        $paramNames = @($cmd.Parameters.Keys)
        $bound = @{}
        foreach ($k in $Cfg.Keys) {
            if ($paramNames -contains $k) {
                $bound[$k] = $Cfg[$k]
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

            $Entropy = Measure-FileEntropy -FilePath $File.FullName
            if ($Entropy -gt 7.5 -and $File.Length -lt 1MB) {
                Write-Output "[HashDetection] High entropy detected: $($File.FullName) | Entropy: $([Math]::Round($Entropy, 2))"
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
    param(
        [bool]$AutoKillThreats = $true
    )

    $LOLBins = @{
        "certutil.exe" = @("-decode", "-urlcache", "-split", "http")
        "powershell.exe" = @("-enc", "-EncodedCommand", "bypass", "hidden", "downloadstring", "iex", "invoke-expression")
        "cmd.exe" = @("/c echo", "powershell", "certutil")
        "mshta.exe" = @("http", "javascript:", "vbscript:")
        "rundll32.exe" = @("javascript:", "http", ".dat,", "comsvcs")
        "regsvr32.exe" = @("/s /u /i:http", "scrobj.dll")
        "wscript.exe" = @(".vbs", ".js", "http")
        "cscript.exe" = @(".vbs", ".js", "http")
        "bitsadmin.exe" = @("/transfer", "/download", "http")
        "msiexec.exe" = @("/quiet", "/qn", "http")
        "wmic.exe" = @("process call create", "shadowcopy delete")
        "regasm.exe" = @("/U", "http")
        "regsvcs.exe" = @("/U", "http")
        "installutil.exe" = @("/logfile=", "/U")
    }

    $Processes = Get-Process | Where-Object { $_.Path }

    foreach ($Process in $Processes) {
        $ProcessName = $Process.ProcessName + ".exe"

        if ($LOLBins.ContainsKey($ProcessName)) {
            try {
                $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine

                if ($CommandLine) {
                    foreach ($Indicator in $LOLBins[$ProcessName]) {
                        if ($CommandLine -match [regex]::Escape($Indicator)) {
                            Write-Output "[LOLBinDetection] THREAT: $ProcessName | PID: $($Process.Id) | CommandLine: $CommandLine"

                            if ($AutoKillThreats) {
                                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                                Write-Output "[LOLBinDetection] Terminated process: $ProcessName (PID: $($Process.Id))"
                            }
                            break
                        }
                    }
                }
            } catch {}
        }
    }
}

function Invoke-ProcessAnomalyDetection {
    param(
        [bool]$AutoKillThreats = $true
    )

    $Processes = Get-Process | Where-Object { $_.Path }

    foreach ($Process in $Processes) {
        $Score = 0
        $Reasons = @()

        if ($Process.Path -notmatch "^C:\\(Windows|Program Files)" -and $Process.ProcessName -match "^(svchost|lsass|csrss|services|smss|wininit)$") {
            $Score += 40
            $Reasons += "System process in non-system location"
        }

        try {
            $ParentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop |
                Select-Object -ExpandProperty ParentProcessId
            $Parent = Get-Process -Id $ParentProcess -ErrorAction SilentlyContinue

            if ($Parent -and $Parent.ProcessName -match "^(winword|excel|outlook|powerpnt)$" -and $Process.ProcessName -match "^(powershell|cmd|wscript|cscript)$") {
                $Score += 35
                $Reasons += "Script launched from Office"
            }
        } catch {}

        if ($Process.Threads.Count -gt 100) {
            $Score += 15
            $Reasons += "Excessive threads: $($Process.Threads.Count)"
        }

        if ($Process.WorkingSet64 -gt 1GB) {
            $Score += 10
            $Reasons += "High memory usage: $([Math]::Round($Process.WorkingSet64/1GB, 2)) GB"
        }

        try {
            $Connections = Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue
            if ($Connections.Count -gt 50) {
                $Score += 20
                $Reasons += "Excessive connections: $($Connections.Count)"
            }
        } catch {}

        if ($Score -ge 50) {
            Write-Output "[ProcessAnomaly] THREAT: $($Process.ProcessName) | PID: $($Process.Id) | Score: $Score | Reasons: $($Reasons -join ', ')"

            if ($AutoKillThreats) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                Write-Output "[ProcessAnomaly] Terminated: $($Process.ProcessName) (PID: $($Process.Id))"
            }
        }
    }
}

function Invoke-AMSIBypassDetection {
    param(
        [bool]$AutoKillThreats = $true
    )

    $AMSIBypassPatterns = @(
        "amsiInitFailed",
        "AmsiScanBuffer",
        "amsi.dll",
        "[Ref].Assembly.GetType",
        "System.Management.Automation.AmsiUtils"
    )

    $Processes = Get-Process | Where-Object { $_.ProcessName -match "powershell|pwsh" }

    foreach ($Process in $Processes) {
        try {
            $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine

            foreach ($Pattern in $AMSIBypassPatterns) {
                if ($CommandLine -match [regex]::Escape($Pattern)) {
                    Write-Output "[AMSIBypass] THREAT: AMSI bypass detected | PID: $($Process.Id) | Pattern: $Pattern"

                    if ($AutoKillThreats) {
                        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                        Write-Output "[AMSIBypass] Terminated process (PID: $($Process.Id))"
                    }
                    break
                }
            }
        } catch {}
    }
}

function Invoke-CredentialDumpDetection {
    param(
        [bool]$AutoKillThreats = $true
    )

    $SensitiveProcesses = @("lsass", "csrss", "services")
    $SuspiciousTools = @("mimikatz", "procdump", "dumpert", "nanodump", "pypykatz")

    $Processes = Get-Process | Where-Object { $_.Path }

    foreach ($Process in $Processes) {
        if ($SuspiciousTools -contains $Process.ProcessName.ToLower()) {
            Write-Output "[CredDump] THREAT: Known credential dumping tool detected | Process: $($Process.ProcessName) | PID: $($Process.Id)"

            if ($AutoKillThreats) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                Write-Output "[CredDump] Terminated: $($Process.ProcessName)"
            }
        }

        try {
            $Handles = Get-Process -Id $Process.Id -ErrorAction Stop | Select-Object -ExpandProperty Handles
            if ($Handles -gt 1000) {
                foreach ($SensitiveProc in $SensitiveProcesses) {
                    $Target = Get-Process -Name $SensitiveProc -ErrorAction SilentlyContinue
                    if ($Target) {
                        Write-Output "[CredDump] SUSPICIOUS: $($Process.ProcessName) has excessive handles ($Handles) while $SensitiveProc is running"
                    }
                }
            }
        } catch {}
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
        $Action = $Task.Actions[0].Execute
        if ($Action -match "powershell|cmd|wscript|cscript|mshta") {
            Write-Output "[ScheduledTask] SUSPICIOUS: $($Task.TaskName) | Action: $Action | User: $($Task.Principal.UserId)"
        }
    }
}

function Invoke-RegistryPersistenceDetection {
    $RunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($Key in $RunKeys) {
        if (Test-Path $Key) {
            $Values = Get-ItemProperty -Path $Key
            foreach ($Property in $Values.PSObject.Properties) {
                if ($Property.Name -notmatch "^PS" -and $Property.Value -match "powershell|cmd|http|\\.vbs|\\.js") {
                    Write-Output "[Registry] SUSPICIOUS: $Key | Name: $($Property.Name) | Value: $($Property.Value)"
                }
            }
        }
    }
}

function Invoke-DLLHijackingDetection {
    $Processes = Get-Process | Where-Object { $_.Path }

    foreach ($Process in $Processes) {
        try {
            $Modules = $Process.Modules | Where-Object { $_.FileName -notmatch "^C:\\Windows" }
            foreach ($Module in $Modules) {
                $Signature = Get-AuthenticodeSignature -FilePath $Module.FileName -ErrorAction SilentlyContinue
                if ($Signature.Status -ne "Valid") {
                    Write-Output "[DLLHijack] SUSPICIOUS: Unsigned DLL loaded | Process: $($Process.ProcessName) | DLL: $($Module.FileName)"
                }
            }
        } catch {}
    }
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
    $Processes = Get-Process | Where-Object { $_.Path }

    foreach ($Process in $Processes) {
        try {
            $Modules = $Process.Modules
            if ($Modules.Count -eq 0) {
                Write-Output "[ProcessHollow] THREAT: Process with no modules | Process: $($Process.ProcessName) | PID: $($Process.Id)"
            }
        } catch {}
    }
}

function Invoke-KeyloggerDetection {
    $Hooks = Get-Process | Where-Object {
        try {
            $_.Modules.ModuleName -match "user32.dll" -and $_.ProcessName -notmatch "explorer|chrome|firefox"
        } catch { $false }
    }

    foreach ($Process in $Hooks) {
        Write-Output "[Keylogger] SUSPICIOUS: Potential keylogger | Process: $($Process.ProcessName) | PID: $($Process.Id)"
    }
}

function Invoke-RansomwareDetection {
    param([bool]$AutoKillThreats = $true)

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
                    Write-Output "[Ransomware] THREAT: Ransomware behavior detected | Process: $($Process.ProcessName) | PID: $($Process.Id) | Command: $CommandLine"

                    if ($AutoKillThreats) {
                        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                        Write-Output "[Ransomware] Terminated: $($Process.ProcessName)"
                    }
                    break
                }
            }
        } catch {}
    }
}

function Invoke-NetworkAnomalyDetection {
    $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

    foreach ($Conn in $Connections) {
        if ($Conn.RemotePort -in @(4444, 5555, 8080, 1337, 31337)) {
            Write-Output "[Network] SUSPICIOUS: Connection to suspicious port | Remote: $($Conn.RemoteAddress):$($Conn.RemotePort) | PID: $($Conn.OwningProcess)"
        }
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
    $Drivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue

    foreach ($Driver in $Drivers) {
        if ($Driver.ProviderName -notmatch "Microsoft" -and $Driver.ClassName -eq "System") {
            Write-Output "[Rootkit] SUSPICIOUS: Third-party system driver | Driver: $($Driver.DriverName) | Provider: $($Driver.ProviderName)"
        }
    }
}

function Invoke-ClipboardMonitoring {
    try {
        $ClipboardText = Get-Clipboard -Format Text -ErrorAction SilentlyContinue
        if ($ClipboardText -match "password|api[_-]?key|token|secret") {
            Write-Output "[Clipboard] WARNING: Sensitive data detected in clipboard"
        }
    } catch {}
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
    $ExtensionPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    )

    foreach ($Path in $ExtensionPaths) {
        if (Test-Path $Path) {
            $Extensions = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
            foreach ($Ext in $Extensions) {
                $ManifestPath = Join-Path $Ext.FullName "manifest.json"
                if (Test-Path $ManifestPath) {
                    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $DangerousPermissions = @("tabs", "webRequest", "cookies", "history", "downloads", "clipboardWrite")

                    $HasDangerous = $false
                    foreach ($Perm in $Manifest.permissions) {
                        if ($DangerousPermissions -contains $Perm) {
                            $HasDangerous = $true
                            break
                        }
                    }

                    if ($HasDangerous) {
                        Write-Output "[BrowserExt] SUSPICIOUS: Extension with dangerous permissions | Name: $($Manifest.name) | Permissions: $($Manifest.permissions -join ', ')"
                    }
                }
            }
        }
    }
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
    $USBDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue

    foreach ($Device in $USBDevices) {
        if ($Device.FriendlyName -match "Keyboard|HID") {
            Write-Output "[USB] ALERT: USB HID device connected | Device: $($Device.FriendlyName) | InstanceId: $($Device.InstanceId)"
        }

        if ($Device.FriendlyName -match "Mass Storage") {
            $RemovableDrives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue

            foreach ($Drive in $RemovableDrives) {
                $AutoRunPath = "$($Drive.DeviceID)\autorun.inf"
                if (Test-Path $AutoRunPath) {
                    Write-Output "[USB] THREAT: Autorun.inf detected on removable drive | Path: $AutoRunPath"
                }
            }
        }
    }
}

function Invoke-EventLogMonitoring {
    $ClearedLogs = Get-WinEvent -FilterHashtable @{LogName='Security';ID=1102} -MaxEvents 10 -ErrorAction SilentlyContinue

    foreach ($Event in $ClearedLogs) {
        Write-Output "[EventLog] THREAT: Security log cleared | Time: $($Event.TimeCreated) | User: $($Event.Properties[1].Value)"
    }

    $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue
    $RecentFailed = $FailedLogons | Group-Object {$_.Properties[5].Value} | Where-Object {$_.Count -gt 5}

    foreach ($Account in $RecentFailed) {
        Write-Output "[EventLog] THREAT: Brute force attempt detected | Account: $($Account.Name) | Attempts: $($Account.Count)"
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
    if (-not $Global:BaselineServices) {
        $Global:BaselineServices = Get-Service | Select-Object -ExpandProperty Name
    }

    $CurrentServices = Get-Service | Select-Object -ExpandProperty Name
    $NewServices = $CurrentServices | Where-Object { $_ -notin $Global:BaselineServices }

    foreach ($ServiceName in $NewServices) {
        $Service = Get-Service -Name $ServiceName
        $ServiceDetails = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue

        if ($ServiceDetails.PathName -notmatch "^C:\\Windows") {
            Write-Output "[Service] NEW SERVICE: $($Service.DisplayName) | Status: $($Service.Status) | Path: $($ServiceDetails.PathName)"
        }
    }

    $Global:BaselineServices = $CurrentServices
}

function Invoke-FilelessDetection {
    $PSProcesses = Get-Process | Where-Object { $_.ProcessName -match "powershell|pwsh" }

    foreach ($Process in $PSProcesses) {
        try {
            $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
            if ($CommandLine -match "-enc|-EncodedCommand") {
                Write-Output "[Fileless] THREAT: Encoded PowerShell detected | PID: $($Process.Id)"
            }
        } catch {}
    }
}

function Invoke-MemoryScanning {
    param([bool]$AutoKillThreats = $true)

    $Processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 100MB }

    foreach ($Process in $Processes) {
        try {
            if ($Process.PrivateMemorySize64 -gt $Process.WorkingSet64 * 2) {
                Write-Output "[MemoryScan] SUSPICIOUS: Memory anomaly | Process: $($Process.ProcessName) | PID: $($Process.Id) | Private: $([Math]::Round($Process.PrivateMemorySize64/1MB)) MB"
            }
        } catch {}
    }
}

function Invoke-NamedPipeMonitoring {
    $Pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
    $SuspiciousPipes = @("msagent_", "mojo", "crashpad", "mypipe", "evil")

    foreach ($Pipe in $Pipes) {
        foreach ($Pattern in $SuspiciousPipes) {
            if ($Pipe -match $Pattern) {
                Write-Output "[NamedPipe] SUSPICIOUS: $Pipe"
            }
        }
    }
}

function Invoke-DNSExfiltrationDetection {
    $DNSCache = Get-DnsClientCache -ErrorAction SilentlyContinue

    foreach ($Entry in $DNSCache) {
        if ($Entry.Name.Length -gt 50 -and $Entry.Name -match "[0-9a-f]{32,}") {
            Write-Output "[DNSExfil] SUSPICIOUS: Long subdomain detected | Domain: $($Entry.Name)"
        }
    }
}

function Invoke-PasswordManagement {
    param(
        [bool]$EnablePasswordRotation = $true,
        [int]$RotationMinutes = 10,
        [bool]$ResetOnShutdown = $true
    )

    Write-Output "[Password] Starting password management monitoring..."

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")) {
        Write-Output "[Password] WARNING: Not running as Administrator - limited functionality"
        $IsAdmin = $false
    }
    else {
        $IsAdmin = $true
        Write-Output "[Password] Running with Administrator privileges"
    }

    # Initialize password rotation functions if not already done
    if (-not $script:PasswordRotationInitialized) {
        $script:PasswordRotationInitialized = $true
        $script:PasswordScriptPath = "$env:ProgramData\PasswordTasks.ps1"
        
        # Create helper functions file
        $passwordFunctions = @'
function Generate-RandomPassword {
    $all = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
    ($all | Get-Random -Count 16) -join ''
}
function Set-NewRandomPassword {
    param([string]$Username = $env:USERNAME)
    try {
        $new = Generate-RandomPassword
        Set-LocalUser -Name $Username -Password (ConvertTo-SecureString $new -AsPlainText -Force) -ErrorAction Stop
        Write-Output "[Password] Successfully set new random password for $Username"
        return $true
    } catch {
        Write-Output "[Password] ERROR: Failed to set new password: $_"
        return $false
    }
}
function Reset-ToBlank {
    param([string]$Username = $env:USERNAME)
    try {
        Set-LocalUser -Name $Username -Password (ConvertTo-SecureString "" -AsPlainText -Force) -ErrorAction Stop
        Write-Output "[Password] Successfully reset password to blank for $Username"
        return $true
    } catch {
        Write-Output "[Password] ERROR: Failed to reset password: $_"
        return $false
    }
}
'@
        Set-Content -Path $script:PasswordScriptPath -Value $passwordFunctions -Force -ErrorAction SilentlyContinue
        
        # Register shutdown script if ResetOnShutdown is enabled
        if ($ResetOnShutdown -and $IsAdmin) {
            try {
                $shutdownScript = {
                    $scriptPath = "$env:ProgramData\PasswordTasks.ps1"
                    if (Test-Path $scriptPath) {
                        . $scriptPath
                        Reset-ToBlank
                    }
                }
                $shutdownJob = Register-EngineEvent -SourceIdentifier PowerShell.OnLogoff -Action $shutdownScript -SupportEvent -ErrorAction SilentlyContinue
                $shutdownJob2 = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $shutdownScript -SupportEvent -ErrorAction SilentlyContinue
                if ($shutdownJob -or $shutdownJob2) {
                    Write-Output "[Password] Shutdown event handlers registered - password will reset to blank on shutdown/restart"
                }
            } catch {
                Write-Output "[Password] WARNING: Could not register shutdown handlers: $_"
            }
        }
    }
    
    # Execute password rotation if enabled and enough time has passed
    if ($IsAdmin) {
        # Initialize last rotation time tracking
        if (-not $script:PasswordLastRotation) {
            $script:PasswordLastRotation = @{}
        }
        
        $rotationKey = "LastRotation_$env:USERNAME"
        $lastRotation = if ($script:PasswordLastRotation.ContainsKey($rotationKey)) { 
            $script:PasswordLastRotation[$rotationKey] 
        } else { 
            [DateTime]::MinValue 
        }
        
        $timeSinceRotation = (Get-Date) - $lastRotation
        $rotationInterval = [TimeSpan]::FromMinutes($RotationMinutes)
        
        # Rotate if enabled and enough time has passed since last rotation
        if ($EnablePasswordRotation -and ($timeSinceRotation -ge $rotationInterval)) {
            try {
                if (Test-Path $script:PasswordScriptPath) {
                    . $script:PasswordScriptPath
                    Set-NewRandomPassword
                    $script:PasswordLastRotation[$rotationKey] = Get-Date
                    Write-Output "[Password] Password rotation executed - new random password set"
                } else {
                    Write-Output "[Password] WARNING: Password functions script not found at $script:PasswordScriptPath"
                }
            } catch {
                Write-Output "[Password] ERROR: Password rotation failed: $_"
            }
        } elseif ($EnablePasswordRotation) {
            $minutesRemaining = [math]::Round(($rotationInterval - $timeSinceRotation).TotalMinutes, 1)
            Write-Output "[Password] Password rotation enabled - next rotation in $minutesRemaining minutes"
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
            # Find all imaging devices (webcams)
            $script:WebcamGuardianState.WebcamDevices = Get-PnpDevice -Class "Camera","Image" -Status "OK" -ErrorAction SilentlyContinue
            
            if ($script:WebcamGuardianState.WebcamDevices.Count -eq 0) {
                # Try alternative method
                $script:WebcamGuardianState.WebcamDevices = Get-PnpDevice | Where-Object {
                    $_.Class -match "Camera|Image" -or 
                    $_.FriendlyName -match "Camera|Webcam|Video"
                } -ErrorAction SilentlyContinue
            }
            
            if ($script:WebcamGuardianState.WebcamDevices.Count -gt 0) {
                Write-AVLog "[WebcamGuardian] Found $($script:WebcamGuardianState.WebcamDevices.Count) webcam device(s)" "INFO"
                
                # Disable all webcams by default
                foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                    try {
                        Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                        Write-AVLog "[WebcamGuardian] Disabled webcam: $($device.FriendlyName)" "INFO"
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
                    
                    # Disable webcam if no other processes are using it
                    if ($script:WebcamGuardianState.CurrentlyAllowedProcesses.Count -eq 0) {
                        foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                            Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
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
                    # User allowed - enable webcam
                    foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                        Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
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
        foreach ($pid in $script:WebcamGuardianState.CurrentlyAllowedProcesses.Keys) {
            if (-not (Get-Process -Id $pid -ErrorAction SilentlyContinue)) {
                $deadProcesses += $pid
            }
        }
        
        foreach ($pid in $deadProcesses) {
            $script:WebcamGuardianState.CurrentlyAllowedProcesses.Remove($pid)
        }
        
        # Disable webcam if no processes are allowed
        if ($script:WebcamGuardianState.CurrentlyAllowedProcesses.Count -eq 0) {
            $now = Get-Date
            # Only disable every 30 seconds to avoid excessive device operations
            if (($now - $script:WebcamGuardianState.LastCheck).TotalSeconds -ge 30) {
                foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                    $status = Get-PnpDevice -InstanceId $device.InstanceId -ErrorAction SilentlyContinue
                    if ($status -and $status.Status -eq "OK") {
                        Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
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

                foreach ($Event in $RecentChanges) {
                    $EventType = switch ($Event.Id) {
                        4723 { "Password change attempted" }
                        4724 { "Password reset attempted" }
                        4738 { "Account policy modified" }
                        default { "Unknown event" }
                    }
                    Write-Output "[Password]   - $EventType at $($Event.TimeCreated)"
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

        if ($EnablePasswordRotation -and $IsAdmin) {
            Write-Output "[Password] Password rotation enabled - every $RotationMinutes minutes"
            Write-Output "[Password] INFO: Password rotation requires scheduled task setup"
        }

        try {
            $RegKeys = @(
                "HKLM:\SAM\SAM\Domains\Account\Users",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            )

            foreach ($RegKey in $RegKeys) {
                if (Test-Path $RegKey) {
                    $RecentChanges = Get-ChildItem $RegKey -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) }

                    if ($RecentChanges.Count -gt 0) {
                        Write-Output "[Password] WARNING: Recent registry changes in password-related areas"
                        foreach ($Change in $RecentChanges) {
                            Write-Output "[Password]   - $($Change.PSPath) modified at $($Change.LastWriteTime)"
                        }
                    }
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

        Console.WriteLine("KeyScrambler ACTIVE — invisible mode ON");
        Console.WriteLine("You see only your real typing • Keyloggers blinded");

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
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $connectionGroups = $connections | Group-Object RemoteAddress, RemotePort
        
        foreach ($group in $connectionGroups) {
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
            Write-Detection -Module "BeaconDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "BeaconDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Invoke-CodeInjectionDetection {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                if (-not $procObj) { continue }
                
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
            Write-Detection -Module "CodeInjectionDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "CodeInjectionDetection" -Message "Error: $_" -Level "Error"
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

function Invoke-ElfCatcher {
    $detections = @()
    
    try {
        $searchPaths = @("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp", "C:\Users\Public")
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                $files = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 100
                
                foreach ($file in $files) {
                    try {
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
            Write-Detection -Module "ElfCatcher" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "ElfCatcher" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Invoke-FileEntropyDetection {
    $detections = @()
    
    try {
        $searchPaths = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")
        
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
            Write-Detection -Module "FileEntropyDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "FileEntropyDetection" -Message "Error: $_" -Level "Error"
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
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "ProcessCreationDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "ProcessCreationDetection" -Message "Error: $_" -Level "Error"
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
                        $proc = Get-Process -Id $ThreatPath -ErrorAction SilentlyContinue
                        if ($proc) {
                            Stop-Process -Id $ThreatPath -Force -ErrorAction SilentlyContinue
                        }
                    } catch { }
                }
                "Log" {
                    Write-EDRLog -Module "ResponseEngine" -Message "THREAT: $ThreatType - $ThreatPath" -Level "Warning"
                }
                "Alert" {
                    try {
                        Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Warning -EventId 2000 `
                            -Message "THREAT ALERT: $ThreatType - $ThreatPath"
                    } catch { }
                }
            }
        }
    } catch {
        Write-EDRLog -Module "ResponseAction" -Message "Error: $_" -Level "Error"
    }
}

function Invoke-ResponseEngine {
    try {
        # Process pending response actions
        # This is a placeholder - actual implementation would process a queue
        Write-EDRLog -Module "ResponseEngine" -Message "Response engine tick" -Level "Debug"
        return 0
    } catch {
        Write-EDRLog -Module "ResponseEngine" -Message "Error: $_" -Level "Error"
        return 0
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
            $pid = Get-Content -Path $Script:YouTubeAdBlockerConfig.PIDFile -ErrorAction SilentlyContinue
            if ($pid) {
                $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($process) {
                    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                    Write-YouTubeLog "Stopped proxy process (PID: $pid)" "Info"
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

    Write-Host "`nAntivirus Protection (Single File)`n" -ForegroundColor Cyan
    Write-StabilityLog "=== Antivirus Starting ==="

    Write-StabilityLog "Executing script path: $PSCommandPath" "INFO"

    Register-ExitCleanup

    Install-Antivirus
    Initialize-Mutex

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
        "ResponseEngine"
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
