# Process Anomaly Detection Module
# Detects unusual process behavior patterns

param([hashtable]$ModuleConfig)

$ModuleName = "ProcessAnomalyDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 45 }
$BaselineProcesses = @{}
$AnomalyThreshold = 0.8

function Initialize-Baseline {
    try {
        $processes = Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CreationDate, ExecutablePath
        foreach ($proc in $processes) {
            $key = "$($proc.Name)|$($proc.ExecutablePath)"
            if (-not $BaselineProcesses.ContainsKey($key)) {
                $BaselineProcesses[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                    Paths = @{}
                }
            }
            $BaselineProcesses[$key].Count++
            $BaselineProcesses[$key].Paths[$proc.ExecutablePath] = $true
        }
    } catch { }
}

function Test-ProcessAnomaly {
    param($Process)
    
    $anomalies = @()
    
    # Check for unsigned executables in system directories
    if ($Process.ExecutablePath) {
        $systemPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
        foreach ($sysPath in $systemPaths) {
            if ($Process.ExecutablePath -like "$sysPath\*") {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $Process.ExecutablePath -ErrorAction SilentlyContinue
                    if ($sig.Status -ne "Valid") {
                        $anomalies += "Unsigned executable in system directory"
                    }
                } catch { }
            }
        }
    }
    
    # Check parent-child relationship anomalies
    try {
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($parent) {
            $suspiciousPairs = @{
                "explorer.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                "winlogon.exe" = @("cmd.exe", "powershell.exe")
                "services.exe" = @("cmd.exe", "powershell.exe")
            }
            
            if ($suspiciousPairs.ContainsKey($parent.Name)) {
                if ($Process.Name -in $suspiciousPairs[$parent.Name]) {
                    $anomalies += "Suspicious parent-child relationship"
                }
            }
        }
    } catch { }
    
    # Check for process hollowing indicators
    try {
        $procPath = (Get-Process -Id $Process.ProcessId -ErrorAction SilentlyContinue).Path
        $imgPath = $Process.ExecutablePath
        if ($procPath -ne $imgPath -and $procPath -and $imgPath) {
            $anomalies += "Process hollowing suspected - Path mismatch"
        }
    } catch { }
    
    # Check for processes with unusual command lines
    if ($Process.CommandLine) {
        if ($Process.CommandLine -match 'powershell.*-nop.*-w.*hidden' -and $Process.Name -ne "powershell.exe") {
            $anomalies += "PowerShell execution flags in non-PowerShell process"
        }
    }
    
    return $anomalies
}

function Invoke-ProcessAnomalyScan {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate
        foreach ($proc in $processes) {
            $anomalies = Test-ProcessAnomaly -Process $proc
            if ($anomalies.Count -gt 0) {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    ExecutablePath = $proc.ExecutablePath
                    Anomalies = $anomalies
                    CommandLine = $proc.CommandLine
                    Risk = "High"
                }
                
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2003 `
                    -Message "PROCESS ANOMALY: $($proc.Name) (PID: $($proc.ProcessId)) - $($anomalies -join ', ')"
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessAnomaly_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.Anomalies -join ';')" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) process anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    Initialize-Baseline
    Start-Sleep -Seconds 10
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ProcessAnomalyScan
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
    Start-Module -Config @{ TickInterval = 45 }
}
