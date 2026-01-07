#Requires -Version 5.1
# Enterprise EDR Antivirus Orchestrator
# Production-Ready with Hot-Swap Module Support

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$TickInterval = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$ModulesPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$ProgramDataPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$RunAsService,
    
    [Parameter(Mandatory=$false)]
    [switch]$Install,
    
    [Parameter(Mandatory=$false)]
    [switch]$Uninstall,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoInstall
)

#region Global Variables
$Script:ModuleJobs = @{}
$Script:ModuleHealth = @{}
$Script:ModuleLastError = @{}
$Script:ModuleStats = @{}
$Script:IsRunning = $true
$Script:LockObject = New-Object System.Object
$Script:InstallPath = "$env:ProgramData\Antivirus"
$Script:ScriptName = Split-Path -Leaf $PSCommandPath

# Initialize paths - use install location if script is running from there, otherwise use PSScriptRoot
$targetScript = Join-Path $Script:InstallPath $Script:ScriptName
if (Test-Path $targetScript -ErrorAction SilentlyContinue) {
    # Running from install location or installed version exists
    if ([string]::IsNullOrEmpty($ModulesPath)) {
        $ModulesPath = "$Script:InstallPath\Modules"
    }
    if ([string]::IsNullOrEmpty($ProgramDataPath)) {
        $ProgramDataPath = "$Script:InstallPath\Modules"
    }
    if ([string]::IsNullOrEmpty($LogPath)) {
        $LogPath = "$Script:InstallPath\Logs"
    }
} else {
    # Running from source location
    if ([string]::IsNullOrEmpty($ModulesPath)) {
        $ModulesPath = "$PSScriptRoot\modules"
    }
    if ([string]::IsNullOrEmpty($ProgramDataPath)) {
        $ProgramDataPath = "$env:ProgramData\Antivirus\Modules"
    }
    if ([string]::IsNullOrEmpty($LogPath)) {
        $LogPath = "$env:ProgramData\Antivirus\Logs"
    }
}

$Script:Configuration = @{
    TickInterval = $TickInterval
    MaxConcurrentModules = 50
    ModuleTimeout = 300
    HealthCheckInterval = 60
    ErrorThreshold = 3
    EnableDetailedLogging = $true
}
#endregion

#region Logging Functions
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Debug')]
        [string]$Level = 'Info',
        [string]$ModuleName = 'Orchestrator'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] [$ModuleName] $Message"
    
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    $logFile = Join-Path $LogPath "Antivirus_$(Get-Date -Format 'yyyy-MM-dd').log"
    
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue
        if ($Level -eq 'Error' -or $Configuration.EnableDetailedLogging) {
            Write-Host $logEntry -ForegroundColor $(switch($Level){
                'Error'{'Red'}
                'Warning'{'Yellow'}
                'Debug'{'Gray'}
                default{'White'}
            })
        }
    } catch {
        Write-Host "Failed to write log: $_" -ForegroundColor Red
    }
}

function Write-EventLog {
    param(
        [string]$Message,
        [ValidateSet('Information','Warning','Error')]
        [string]$EntryType = 'Information'
    )
    
    try {
        $source = "AntivirusEDR"
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            New-EventLog -LogName Application -Source $source -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source $source -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        # Event log may not be available, continue silently
    }
}
#endregion

#region Module Management
function Copy-ModulesToProgramData {
    param(
        [string]$SourcePath,
        [string]$DestinationPath
    )
    
    Write-Log "Starting module deployment from $SourcePath to $DestinationPath" -Level Info
    
    if (-not (Test-Path $SourcePath)) {
        Write-Log "Source path does not exist: $SourcePath" -Level Error
        return $false
    }
    
    try {
        if (-not (Test-Path $DestinationPath)) {
            New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
            Write-Log "Created destination directory: $DestinationPath" -Level Info
        }
        
        $modules = Get-ChildItem -Path $SourcePath -Filter "*.ps1" -File
        
        if ($modules.Count -eq 0) {
            Write-Log "No PS1 modules found in source path" -Level Warning
            return $false
        }
        
        $copiedCount = 0
        foreach ($module in $modules) {
            try {
                $destPath = Join-Path $DestinationPath $module.Name
                # Only copy if source and destination are different
                if ($module.FullName -ne $destPath) {
                    Copy-Item -Path $module.FullName -Destination $destPath -Force
                    Write-Log "Copied module: $($module.Name)" -Level Debug
                } else {
                    Write-Log "Module already in place: $($module.Name)" -Level Debug
                }
                $copiedCount++
            } catch {
                Write-Log "Failed to copy $($module.Name): $_" -Level Error
            }
        }
        
        Write-Log "Deployed $copiedCount modules to ProgramData" -Level Info
        return $true
    } catch {
        Write-Log "Module deployment failed: $_" -Level Error
        return $false
    }
}

function Get-AvailableModules {
    param([string]$ModulePath)
    
    $modules = @()
    if (Test-Path $ModulePath) {
        $moduleFiles = Get-ChildItem -Path $ModulePath -Filter "*.ps1" -File
        
        foreach ($module in $moduleFiles) {
            try {
                $content = Get-Content $module.FullName -Raw -ErrorAction Stop
                if ($content -match 'function\s+Start-Module\s*\(' -or 
                    $content -match 'function\s+Invoke-Module\s*\(' -or
                    $content -match '\$ModuleConfig') {
                    $modules += @{
                        Name = $module.BaseName
                        Path = $module.FullName
                        LastModified = $module.LastWriteTime
                    }
                }
            } catch {
                Write-Log "Error analyzing module $($module.Name): $_" -Level Warning
            }
        }
    }
    
    return $modules
}

function Start-ModuleJob {
    param(
        [hashtable]$ModuleInfo,
        [hashtable]$Config
    )
    
    $moduleName = $ModuleInfo.Name
    $modulePath = $ModuleInfo.Path
    
    try {
        # Check if module is already running
        if ($Script:ModuleJobs.ContainsKey($moduleName)) {
            $existingJob = $Script:ModuleJobs[$moduleName]
            if ($existingJob.State -eq 'Running') {
                Write-Log "Module $moduleName is already running" -Level Warning
                return $false
            }
        }
        
        # Create module scriptblock with error handling
        $scriptBlock = {
            param($ModulePath, $ModuleName, $Config)
            
            $ErrorActionPreference = 'Continue'
            $Error.Clear()
            
            try {
                # Import and execute module
                . $ModulePath
                
                # Try to invoke Start-Module if it exists
                if (Get-Command -Name 'Start-Module' -ErrorAction SilentlyContinue) {
                    Start-Module -Config $Config
                }
                # Try Invoke-Module as alternative
                elseif (Get-Command -Name 'Invoke-Module' -ErrorAction SilentlyContinue) {
                    Invoke-Module -Config $Config
                }
                # Execute main logic if module config exists
                elseif (Test-Path variable:ModuleConfig) {
                    $ModuleConfig = $Config
                    . $ModulePath
                }
                # Fallback: execute module file
                else {
                    . $ModulePath
                }
            } catch {
                Write-Output "MODULE_ERROR:$ModuleName`:$_"
            }
        }
        
        # Create job with timeout and better resource management
        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $modulePath, $moduleName, $Config -Name "AV_$moduleName"
        
        [System.Threading.Monitor]::Enter($Script:LockObject)
        try {
            $Script:ModuleJobs[$moduleName] = $job
            $Script:ModuleHealth[$moduleName] = @{
                Status = 'Running'
                StartTime = Get-Date
                LastCheck = Get-Date
                ErrorCount = 0
                TickCount = 0
            }
            $Script:ModuleStats[$moduleName] = @{
                Detections = 0
                Errors = 0
                LastDetection = $null
            }
        } finally {
            [System.Threading.Monitor]::Exit($Script:LockObject)
        }
        
        Write-Log "Started module job: $moduleName (Job ID: $($job.Id))" -Level Info
        Write-EventLog "Module $moduleName started successfully" -EntryType Information
        
        return $true
    } catch {
        Write-Log "Failed to start module $moduleName`: $_" -Level Error
        Write-EventLog "Failed to start module $moduleName`: $_" -EntryType Error
        return $false
    }
}

function Stop-ModuleJob {
    param([string]$ModuleName)
    
    try {
        if ($Script:ModuleJobs.ContainsKey($ModuleName)) {
            $job = $Script:ModuleJobs[$ModuleName]
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            
            [System.Threading.Monitor]::Enter($Script:LockObject)
            try {
                $Script:ModuleJobs.Remove($ModuleName)
                if ($Script:ModuleHealth.ContainsKey($ModuleName)) {
                    $Script:ModuleHealth[$ModuleName].Status = 'Stopped'
                }
            } finally {
                [System.Threading.Monitor]::Exit($Script:LockObject)
            }
            
            Write-Log "Stopped module: $moduleName" -Level Info
            return $true
        }
        return $false
    } catch {
        Write-Log "Error stopping module $moduleName`: $_" -Level Error
        return $false
    }
}

function Update-ModuleHealth {
    param([string]$ModuleName)
    
    if (-not $Script:ModuleHealth.ContainsKey($ModuleName)) {
        return
    }
    
    $health = $Script:ModuleHealth[$ModuleName]
    $job = $Script:ModuleJobs[$ModuleName]
    
    try {
        $health.LastCheck = Get-Date
        
        if ($null -eq $job) {
            $health.Status = 'NotRunning'
            $health.ErrorCount++
            return
        }
        
        # Check job state
        if ($job.State -eq 'Failed' -or $job.State -eq 'Stopped') {
            $health.Status = $job.State
            $health.ErrorCount++
            
            # Collect error output
            $output = Receive-Job -Job $job
            if ($output -match 'MODULE_ERROR:(.+?):(.+)') {
                $Script:ModuleLastError[$ModuleName] = $matches[2]
                Write-Log "Module $ModuleName error: $($matches[2])" -Level Error -ModuleName $ModuleName
            }
            
            # Restart if error count is below threshold
            if ($health.ErrorCount -lt $Script:Configuration.ErrorThreshold) {
                Write-Log "Restarting module $ModuleName (error count: $($health.ErrorCount))" -Level Warning
                Stop-ModuleJob -ModuleName $ModuleName
                Start-Sleep -Seconds 5
                $moduleInfo = Get-AvailableModules -ModulePath $Script:ProgramDataPath | Where-Object { $_.Name -eq $ModuleName } | Select-Object -First 1
                if ($moduleInfo) {
                    Start-ModuleJob -ModuleInfo $moduleInfo -Config $Script:Configuration
                }
            } else {
                Write-Log "Module $ModuleName exceeded error threshold, disabling" -Level Error
                Write-EventLog "Module $ModuleName disabled due to repeated failures" -EntryType Error
            }
        } elseif ($job.State -eq 'Running') {
            $health.Status = 'Running'
            
            # Check for timeout
            $runtime = (Get-Date) - $health.StartTime
            if ($runtime.TotalSeconds -gt $Script:Configuration.ModuleTimeout) {
                Write-Log "Module $ModuleName timed out, restarting" -Level Warning
                Stop-ModuleJob -ModuleName $ModuleName
                $moduleInfo = Get-AvailableModules -ModulePath $Script:ProgramDataPath | Where-Object { $_.Name -eq $ModuleName } | Select-Object -First 1
                if ($moduleInfo) {
                    Start-ModuleJob -ModuleInfo $moduleInfo -Config $Script:Configuration
                }
            }
        }
        
        # Increment tick count for running modules
        if ($health.Status -eq 'Running') {
            $health.TickCount++
        }
        
    } catch {
        Write-Log "Error updating health for $ModuleName`: $_" -Level Error
    }
}

function Invoke-HotSwapModules {
    Write-Log "Performing hot-swap module check" -Level Debug
    
    try {
        $sourceModules = Get-AvailableModules -ModulePath $Script:ModulesPath
        $deployedModules = Get-AvailableModules -ModulePath $Script:ProgramDataPath
        
        # Check for new or updated modules
        foreach ($sourceModule in $sourceModules) {
            $deployed = $deployedModules | Where-Object { $_.Name -eq $sourceModule.Name } | Select-Object -First 1
            
            if ($null -eq $deployed -or $sourceModule.LastModified -gt $deployed.LastModified) {
                Write-Log "Hot-swapping module: $($sourceModule.Name)" -Level Info
                
                # Stop existing instance
                if ($Script:ModuleJobs.ContainsKey($sourceModule.Name)) {
                    Stop-ModuleJob -ModuleName $sourceModule.Name
                    Start-Sleep -Seconds 2
                }
                
                # Copy new version
                Copy-Item -Path $sourceModule.Path -Destination (Join-Path $Script:ProgramDataPath "$($sourceModule.Name).ps1") -Force
                Start-Sleep -Seconds 1
                
                # Restart module
                $newModule = @{
                    Name = $sourceModule.Name
                    Path = Join-Path $Script:ProgramDataPath "$($sourceModule.Name).ps1"
                }
                Start-ModuleJob -ModuleInfo $newModule -Config $Script:Configuration
            }
        }
        
        # Check for removed modules
        $deployedNames = $deployedModules | ForEach-Object { $_.Name }
        foreach ($runningModule in $Script:ModuleJobs.Keys) {
            if ($runningModule -notin $deployedNames) {
                Write-Log "Module $runningModule removed from source, stopping" -Level Warning
                Stop-ModuleJob -ModuleName $runningModule
            }
        }
        
    } catch {
        Write-Log "Hot-swap check failed: $_" -Level Error
    }
}
#endregion

#region Installation and Persistence
function Install-Antivirus {
    $targetScript = Join-Path $Script:InstallPath $Script:ScriptName
    $currentPath = $PSCommandPath
    
    # Check if already installed and running from install location
    if ($currentPath -eq $targetScript -and (Test-Path $targetScript)) {
        Write-Log "Running from install location: $targetScript" -Level Info
        
        # Verify persistence is still installed
        $taskName = "AntivirusProtection"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if (-not $existingTask) {
            Write-Log "Persistence not found, reinstalling..." -Level Warning
            Install-Persistence
        }
        
        return $true
    }
    
    Write-Log "=== Installing Antivirus ===" -Level Info
    Write-Host "`n=== Installing Antivirus ===`n" -ForegroundColor Cyan
    
    # Create installation directories
    $directories = @("Data", "Logs", "Quarantine", "Reports", "Modules")
    foreach ($dir in $directories) {
        $dirPath = Join-Path $Script:InstallPath $dir
        if (-not (Test-Path $dirPath)) {
            try {
                New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
                Write-Log "Created directory: $dirPath" -Level Info
                Write-Host "[+] Created: $dirPath" -ForegroundColor Green
            } catch {
                Write-Log "Failed to create directory $dirPath`: $_" -Level Error
            }
        }
    }
    
    # Copy main script to install location
    try {
        Copy-Item -Path $PSCommandPath -Destination $targetScript -Force -ErrorAction Stop
        Write-Log "Copied main script to: $targetScript" -Level Info
        Write-Host "[+] Copied main script to $targetScript" -ForegroundColor Green
        
        # Copy modules directory if it exists
        if (Test-Path $ModulesPath) {
            $targetModulesPath = Join-Path $Script:InstallPath "Modules"
            if (-not (Test-Path $targetModulesPath)) {
                New-Item -ItemType Directory -Path $targetModulesPath -Force | Out-Null
            }
            Copy-Item -Path "$ModulesPath\*" -Destination $targetModulesPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Copied modules to: $targetModulesPath" -Level Info
            Write-Host "[+] Copied modules to $targetModulesPath" -ForegroundColor Green
        }
    } catch {
        Write-Log "Failed to copy script to install location: $_" -Level Error
        Write-Host "[!] Failed to copy script: $_" -ForegroundColor Red
        return $false
    }
    
    # Install persistence
    Install-Persistence
    
    Write-Log "Installation complete" -Level Info
    Write-Host "`n[+] Installation complete. Continuing in this instance...`n" -ForegroundColor Green
    Write-EventLog "Antivirus installed successfully" -EntryType Information
    
    return $true
}

function Install-Persistence {
    Write-Log "Setting up persistence for automatic startup" -Level Info
    Write-Host "`n[*] Setting up persistence for automatic startup...`n" -ForegroundColor Cyan
    
    $taskName = "AntivirusProtection"
    $targetScript = Join-Path $Script:InstallPath $Script:ScriptName
    
    # Check if running with admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log "Warning: Not running as Administrator. Scheduled task creation may fail." -Level Warning
        Write-Host "[!] Warning: Not running as Administrator. Scheduled task creation may fail." -ForegroundColor Yellow
    }
    
    try {
        # Remove existing task if it exists
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Log "Removed existing scheduled task: $taskName" -Level Info
        }
        
        # Create scheduled task action
        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`""
        
        # Create triggers (at logon and at startup)
        $taskTriggerLogon = New-ScheduledTaskTrigger -AtLogon -User $env:USERNAME
        $taskTriggerBoot = New-ScheduledTaskTrigger -AtStartup
        
        # Create task principal (run as current user with highest privileges)
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        
        # Create task settings
        $taskSettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RunOnlyIfNetworkAvailable `
            -DontStopOnIdleEnd `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1)
        
        # Register the scheduled task
        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $taskAction `
            -Trigger $taskTriggerLogon, $taskTriggerBoot `
            -Principal $taskPrincipal `
            -Settings $taskSettings `
            -Description "Enterprise EDR Antivirus - Automatic Protection" `
            -Force `
            -ErrorAction Stop
        
        Write-Log "Scheduled task created successfully: $taskName" -Level Info
        Write-Host "[+] Scheduled task created for automatic startup" -ForegroundColor Green
        Write-EventLog "Antivirus persistence installed - scheduled task created" -EntryType Information
        
    } catch {
        Write-Log "Failed to create scheduled task: $_" -Level Error
        Write-Host "[!] Failed to create scheduled task: $_" -ForegroundColor Red
        Write-Host "[*] Attempting fallback: startup shortcut..." -ForegroundColor Yellow
        
        # Fallback: Create startup shortcut
        try {
            $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            
            if (-not (Test-Path $startupFolder)) {
                New-Item -ItemType Directory -Path $startupFolder -Force | Out-Null
            }
            
            $shortcutPath = Join-Path $startupFolder "AntivirusProtection.lnk"
            
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = "powershell.exe"
            $shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`""
            $shortcut.WorkingDirectory = $Script:InstallPath
            $shortcut.WindowStyle = 7  # Minimized
            $shortcut.Save()
            
            Write-Log "Fallback: Created startup shortcut at: $shortcutPath" -Level Info
            Write-Host "[+] Fallback: Created startup shortcut" -ForegroundColor Yellow
            Write-EventLog "Antivirus persistence installed - startup shortcut created" -EntryType Information
            
        } catch {
            Write-Log "Both scheduled task and shortcut failed: $_" -Level Error
            Write-Host "[!] Both scheduled task and shortcut failed: $_" -ForegroundColor Red
            Write-EventLog "Antivirus persistence installation failed: $_" -EntryType Error
        }
    }
}

function Uninstall-Antivirus {
    Write-Log "=== Uninstalling Antivirus ===" -Level Info
    Write-Host "`n=== Uninstalling Antivirus ===`n" -ForegroundColor Cyan
    
    # Remove scheduled task
    try {
        $taskName = "AntivirusProtection"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Log "Removed scheduled task: $taskName" -Level Info
            Write-Host "[+] Removed scheduled task" -ForegroundColor Green
        }
    } catch {
        Write-Log "Failed to remove scheduled task: $_" -Level Warning
    }
    
    # Remove startup shortcut
    try {
        $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        $shortcutPath = Join-Path $startupFolder "AntivirusProtection.lnk"
        if (Test-Path $shortcutPath) {
            Remove-Item -Path $shortcutPath -Force -ErrorAction Stop
            Write-Log "Removed startup shortcut: $shortcutPath" -Level Info
            Write-Host "[+] Removed startup shortcut" -ForegroundColor Green
        }
    } catch {
        Write-Log "Failed to remove startup shortcut: $_" -Level Warning
    }
    
    Write-Log "Uninstallation complete" -Level Info
    Write-Host "[+] Uninstallation complete" -ForegroundColor Green
    Write-EventLog "Antivirus uninstalled" -EntryType Information
}
#endregion

#region Main Execution
function Start-AntivirusOrchestrator {
    Write-Log "=== Antivirus EDR Orchestrator Starting ===" -Level Info
    Write-EventLog "Antivirus EDR Orchestrator starting" -EntryType Information
    
    # Cleanup orphaned processes on startup
    Write-Log "Performing startup cleanup of orphaned processes" -Level Info
    try {
        $currentPID = $PID
        $orphanedProcesses = Get-Process -Name "powershell" -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -ne $currentPID }
        
        foreach ($proc in $orphanedProcesses) {
            try {
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmdLine -and ($cmdLine -match "Antivirus|AV_|Start-Module")) {
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    Write-Log "Startup cleanup: Removed orphaned PowerShell PID: $($proc.Id)" -Level Info
                }
            } catch { }
        }
    } catch {
        Write-Log "Startup cleanup failed: $_" -Level Warning
    }
    
    # Initialize directories
    if (-not (Test-Path $ProgramDataPath)) {
        New-Item -Path $ProgramDataPath -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    # Deploy initial modules
    if (-not (Copy-ModulesToProgramData -SourcePath $ModulesPath -DestinationPath $ProgramDataPath)) {
        Write-Log "Initial module deployment failed, continuing with existing modules" -Level Warning
    }
    
    # Start all available modules
    $modules = Get-AvailableModules -ModulePath $ProgramDataPath
    Write-Log "Found $($modules.Count) modules to start" -Level Info
    
    $startedCount = 0
    $attemptedCount = 0
    foreach ($module in $modules) {
        if ($startedCount -lt $Script:Configuration.MaxConcurrentModules) {
            $attemptedCount++
            Write-Log "Attempting to start module: $($module.Name)" -Level Debug
            if (Start-ModuleJob -ModuleInfo $module -Config $Script:Configuration) {
                $startedCount++
                Write-Log "Successfully started module: $($module.Name)" -Level Info
            } else {
                Write-Log "Failed to start module: $($module.Name)" -Level Warning
            }
            Start-Sleep -Milliseconds 500
        } else {
            Write-Log "Skipping module $($module.Name) - max concurrent limit reached" -Level Warning
        }
    }
    
    Write-Log "Started $startedCount/$attemptedCount modules (limit: $($Script:Configuration.MaxConcurrentModules))" -Level Info
    
    # Main monitoring loop
    $lastHealthCheck = Get-Date
    $lastHotSwap = Get-Date
    
    while ($Script:IsRunning) {
        try {
            $now = Get-Date
            
            # Health check interval
            if (($now - $lastHealthCheck).TotalSeconds -ge $Script:Configuration.HealthCheckInterval) {
                foreach ($moduleName in $Script:ModuleJobs.Keys.Clone()) {
                    Update-ModuleHealth -ModuleName $moduleName
                }
                $lastHealthCheck = $now
                
                # Log summary
                $runningCount = ($Script:ModuleHealth.Values | Where-Object { $_.Status -eq 'Running' }).Count
                Write-Log "Health check complete: $runningCount/$($Script:ModuleJobs.Count) modules running" -Level Debug
            }
            
            # Hot-swap check interval (every 5 minutes)
            if (($now - $lastHotSwap).TotalSeconds -ge 300) {
                Invoke-HotSwapModules
                $lastHotSwap = $now
            }
            
            # Enhanced cleanup of completed jobs and orphaned PowerShell processes
            $completedJobs = $Script:ModuleJobs.GetEnumerator() | Where-Object { $_.Value.State -in @('Completed','Failed','Stopped') }
            foreach ($completed in $completedJobs) {
                try {
                    Remove-Job -Job $completed.Value -Force -ErrorAction SilentlyContinue
                    $Script:ModuleJobs.Remove($completed.Key) | Out-Null
                    Write-Log "Removed completed job: $($completed.Key)" -Level Debug
                } catch { }
            }
            
            # Aggressive cleanup of orphaned PowerShell processes
            try {
                $currentPID = $PID
                $antivirusProcesses = Get-Process -Name "powershell" -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Id -ne $currentPID }
                
                foreach ($proc in $antivirusProcesses) {
                    try {
                        # Check if this is an orphaned antivirus process
                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                        if ($cmdLine -and ($cmdLine -match "Antivirus|AV_" -or $cmdLine -match "Start-Module")) {
                            # Check if process has been running too long (> 10 minutes)
                            if ($proc.StartTime -lt (Get-Date).AddMinutes(-10)) {
                                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                                Write-Log "Cleaned up long-running PowerShell process PID: $($proc.Id)" -Level Debug
                            }
                        }
                    } catch { }
                }
                
                # Also clean up any PowerShell processes using excessive memory (> 100MB)
                $heavyProcesses = Get-Process -Name "powershell" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Id -ne $currentPID -and $_.WorkingSet64 -gt 100MB }
                
                foreach ($proc in $heavyProcesses) {
                    try {
                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                        Write-Log "Cleaned up high-memory PowerShell process PID: $($proc.Id) ($([math]::Round($proc.WorkingSet64/1MB,1))MB)" -Level Debug
                    } catch { }
                }
            } catch { }
            
            Start-Sleep -Seconds $TickInterval
            
        } catch {
            Write-Log "Orchestrator loop error: $_" -Level Error
            Start-Sleep -Seconds 5
        }
    }
}

function Stop-AntivirusOrchestrator {
    Write-Log "=== Antivirus EDR Orchestrator Stopping ===" -Level Info
    $Script:IsRunning = $false
    
    # Stop all module jobs
    foreach ($moduleName in $Script:ModuleJobs.Keys.Clone()) {
        Stop-ModuleJob -ModuleName $moduleName
    }
    
    Write-EventLog "Antivirus EDR Orchestrator stopped" -EntryType Information
}

# Handle termination
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Stop-AntivirusOrchestrator
}

# Trap Ctrl+C
[Console]::TreatControlCAsInput = $false
trap {
    Stop-AntivirusOrchestrator
    break
}

# Handle uninstallation
if ($Uninstall) {
    Uninstall-Antivirus
    exit 0
}

# Automatic installation and persistence on first run
Install-Antivirus

# Start orchestrator
if ($RunAsService) {
    Start-AntivirusOrchestrator
} else {
    Write-Host "Antivirus EDR Orchestrator" -ForegroundColor Cyan
    Write-Host "Install Path: $Script:InstallPath" -ForegroundColor Gray
    Write-Host "Modules Path: $ModulesPath" -ForegroundColor Gray
    Write-Host "ProgramData Path: $ProgramDataPath" -ForegroundColor Gray
    Write-Host "Log Path: $LogPath" -ForegroundColor Gray
    Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
    Write-Host ""
    
    Start-AntivirusOrchestrator
}
#endregion
