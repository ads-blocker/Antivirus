# Initializer Module
# Sets up the Antivirus EDR environment - runs once at startup

param([hashtable]$ModuleConfig)

$ModuleName = "Initializer"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 10 }  # Check every 10 seconds initially
$Initialized = $false

function Invoke-Initialization {
    try {
        Write-Output "STATS:$ModuleName`:Starting environment initialization"
        
        # Create required directories
        $directories = @(
            "$env:ProgramData\Antivirus",
            "$env:ProgramData\Antivirus\Logs",
            "$env:ProgramData\Antivirus\Data",
            "$env:ProgramData\Antivirus\Modules", 
            "$env:ProgramData\Antivirus\Quarantine",
            "$env:ProgramData\Antivirus\Reports"
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-Output "STATS:$ModuleName`:Created directory: $dir"
            }
        }
        
        # Initialize log files with headers
        $logFiles = @(
            "$env:ProgramData\Antivirus\Logs\System_$(Get-Date -Format 'yyyy-MM-dd').log",
            "$env:ProgramData\Antivirus\Logs\Threats_$(Get-Date -Format 'yyyy-MM-dd').log",
            "$env:ProgramData\Antivirus\Logs\Responses_$(Get-Date -Format 'yyyy-MM-dd').log"
        )
        
        foreach ($logFile in $logFiles) {
            if (-not (Test-Path $logFile)) {
                $header = "# Antivirus EDR Log - Created $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n# Format: Timestamp|Module|Action|Details`n"
                Set-Content -Path $logFile -Value $header
                Write-Output "STATS:$ModuleName`:Initialized log: $logFile"
            }
        }
        
        # Create Event Log source if it doesn't exist
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("AntivirusEDR")) {
                [System.Diagnostics.EventLog]::CreateEventSource("AntivirusEDR", "Application")
                Write-Output "STATS:$ModuleName`:Created Event Log source: AntivirusEDR"
            }
        } catch {
            Write-Output "ERROR:$ModuleName`:Failed to create Event Log source: $_"
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
            Write-Output "STATS:$ModuleName`:Created configuration file"
        }
        
        # Create status tracking file
        $statusFile = "$env:ProgramData\Antivirus\Data\agent_status.json"
        if (-not (Test-Path $statusFile)) {
            $statusTemplate = @{
                LastCheck = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                ActiveAgents = @()
                SystemHealth = "Healthy"
                TotalDetections = 0
                TotalResponses = 0
            }
            $statusTemplate | ConvertTo-Json -Depth 3 | Set-Content -Path $statusFile
            Write-Output "STATS:$ModuleName`:Created status tracking file"
        }
        
        # Log initialization completion
        $initLog = "$env:ProgramData\Antivirus\Logs\System_$(Get-Date -Format 'yyyy-MM-dd').log"
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|Initializer|Environment|Antivirus EDR environment initialized successfully" | Add-Content -Path $initLog
        
        Write-Output "DETECTION:$ModuleName`:Environment initialization completed"
        return 1
        
    } catch {
        Write-Output "ERROR:$ModuleName`:Initialization failed: $_"
        return 0
    }
}

function Start-Module {
    param([hashtable]$Config)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                if (-not $Initialized) {
                    $count = Invoke-Initialization
                    if ($count -gt 0) {
                        $Initialized = $true
                        $TickInterval = 3600  # Switch to hourly checks after init
                        Write-Output "STATS:$ModuleName`:Initialization complete - switching to maintenance mode"
                    }
                } else {
                    # Maintenance mode - just check system health
                    $statusFile = "$env:ProgramData\Antivirus\Data\agent_status.json"
                    if (Test-Path $statusFile) {
                        $status = Get-Content $statusFile | ConvertFrom-Json
                        $status.LastCheck = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                        $status | ConvertTo-Json -Depth 3 | Set-Content -Path $statusFile
                        Write-Output "STATS:$ModuleName`:System health check completed"
                    } else {
                        Write-Output "STATS:$ModuleName`:Status file not found, system may need re-initialization"
                    }
                }
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
    Start-Module -Config @{ TickInterval = 10 }
}
