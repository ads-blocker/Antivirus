# Memory Scanning Module
# Scans process memory for malicious content

param([hashtable]$ModuleConfig)

$ModuleName = "MemoryScanning"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 120 }

function Invoke-MemoryScanning {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.WorkingSet64 -gt 10MB }
        
        foreach ($proc in $processes) {
            try {
                # Check for suspicious memory patterns
                $modules = $proc.Modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*"
                }
                
                if ($modules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        SuspiciousModules = $modules.Count
                        Type = "Process with Many Non-System Modules"
                        Risk = "Medium"
                    }
                }
                
                # Check for processes with unusual memory allocation
                if ($proc.WorkingSet64 -gt 500MB -and $proc.ProcessName -notin @("chrome.exe", "firefox.exe", "msedge.exe", "OUTLOOK.EXE")) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        WorkingSet = $proc.WorkingSet64
                        Type = "Process with Unusual Memory Allocation"
                        Risk = "Low"
                    }
                }
                
                # Check for processes with executable memory regions
                $executableRegions = $proc.Modules | Where-Object {
                    $_.FileName -like "*.exe" -or $_.FileName -like "*.dll"
                }
                
                if ($executableRegions.Count -gt 20) {
                    # Check for unsigned executables in memory
                    $unsignedRegions = $executableRegions | Where-Object {
                        if (Test-Path $_.FileName) {
                            $sig = Get-AuthenticodeSignature -FilePath $_.FileName -ErrorAction SilentlyContinue
                            $sig.Status -ne "Valid"
                        } else {
                            $true
                        }
                    }
                    
                    if ($unsignedRegions.Count -gt 5) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            UnsignedModules = $unsignedRegions.Count
                            Type = "Process with Unsigned Memory Regions"
                            Risk = "High"
                        }
                    }
                }
                
            } catch {
                continue
            }
        }
        
        # Check for processes with code injection indicators
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Check for processes with unusual thread counts
                    if ($procObj.Threads.Count -gt 100) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ThreadCount = $procObj.Threads.Count
                            Type = "Process with Unusual Thread Count"
                            Risk = "Medium"
                        }
                    }
                    
                    # Check for processes with unusual handle counts
                    if ($procObj.HandleCount -gt 1000) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            HandleCount = $procObj.HandleCount
                            Type = "Process with Unusual Handle Count"
                            Risk = "Low"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for suspicious memory patterns in Event Log
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=215} -ErrorAction SilentlyContinue -MaxEvents 50 |
                Where-Object { $_.Message -match 'memory|access.*violation|corruption' }
            
            if ($events.Count -gt 5) {
                $detections += @{
                    EventCount = $events.Count
                    Type = "Excessive Memory Access Violations"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2027 `
                    -Message "MEMORY SCANNING: $($detection.Type) - $($detection.ProcessName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\MemoryScanning_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.ProcessId)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) memory anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Scanned $($processes.Count) processes"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-MemoryScanning
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
    Start-Module -Config @{ TickInterval = 120 }
}
