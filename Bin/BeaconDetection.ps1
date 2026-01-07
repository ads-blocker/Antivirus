# Beacon Detection Module
# Detects C2 beaconing and command & control communication

param([hashtable]$ModuleConfig)

$ModuleName = "BeaconDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }
$ConnectionBaseline = @{}

function Initialize-BeaconBaseline {
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" }
        
        foreach ($conn in $connections) {
            $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $ConnectionBaseline.ContainsKey($key)) {
                $ConnectionBaseline[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                }
            }
            $ConnectionBaseline[$key].Count++
            $ConnectionBaseline[$key].LastSeen = Get-Date
        }
    } catch { }
}

function Invoke-BeaconDetection {
    $detections = @()
    
    try {
        # Monitor for periodic connections (beacon indicator)
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" }
        
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
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2037 `
                    -Message "BEACON DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.RemoteAddress -or $detection.RemoteHost)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\BeaconDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.RemoteAddress -or $_.RemoteHost)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) beacon indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    Initialize-BeaconBaseline
    Start-Sleep -Seconds 10
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-BeaconDetection
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
    Start-Module -Config @{ TickInterval = 20 }
}
