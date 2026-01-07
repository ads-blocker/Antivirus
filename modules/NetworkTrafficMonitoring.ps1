# Network Traffic Monitoring Module
# Monitors all network traffic for suspicious patterns

param([hashtable]$ModuleConfig)

$ModuleName = "NetworkTrafficMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 15 }
$TrafficStats = @{}

function Invoke-NetworkTrafficMonitoring {
    $detections = @()
    
    try {
        # Monitor TCP connections
        $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Established" }
        
        foreach ($conn in $tcpConnections) {
            $key = "$($conn.LocalAddress):$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)"
            
            # Track connection statistics
            if (-not $TrafficStats.ContainsKey($key)) {
                $TrafficStats[$key] = @{
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                    Count = 0
                }
            }
            
            $TrafficStats[$key].LastSeen = Get-Date
            $TrafficStats[$key].Count++
            
            # Check for suspicious patterns
            if ($conn.RemotePort -lt 1024 -and $conn.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
                # Connection to well-known port on public IP
                $detections += @{
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    Type = "Connection to Public Well-Known Port"
                    Risk = "Medium"
                }
            }
            
            # Check for connections to non-standard ports on public IPs
            if ($conn.RemotePort -gt 49152 -and $conn.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
                $detections += @{
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    Type = "Connection to Public Ephemeral Port"
                    Risk = "Low"
                }
            }
        }
        
        # Monitor UDP traffic
        try {
            $udpConnections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
            
            foreach ($conn in $udpConnections) {
                # Check for DNS traffic to non-standard servers
                if ($conn.LocalPort -eq 53) {
                    $dnsServer = $conn.LocalAddress
                    $standardDNSServers = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "127.0.0.1")
                    if ($dnsServer -notin $standardDNSServers -and 
                        $dnsServer -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
                        $detections += @{
                            Type = "DNS Query to Non-Standard Server"
                            DNSServer = $dnsServer
                            Risk = "Medium"
                        }
                    }
                }
            }
        } catch { }
        
        # Monitor network adapters
        try {
            $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | 
                Where-Object { $_.Status -eq "Up" }
            
            foreach ($adapter in $adapters) {
                $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
                
                if ($stats) {
                    $bytesPerSec = ($stats.SentBytes + $stats.ReceivedBytes) / [Math]::Max(1, $TickInterval)
                    
                    if ($bytesPerSec -gt 10MB) {
                        $detections += @{
                            Adapter = $adapter.Name
                            BytesPerSecond = $bytesPerSec
                            Type = "High Bandwidth Usage"
                            Risk = "Medium"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes with network activity
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procConnections = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue
                    
                    if ($procConnections.Count -gt 0) {
                        $remoteIPs = $procConnections.RemoteAddress | Select-Object -Unique
                        
                        # Check for connections to many different IPs
                        if ($remoteIPs.Count -gt 10) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                ConnectionCount = $procConnections.Count
                                UniqueIPs = $remoteIPs.Count
                                Type = "Process Connecting to Many IPs"
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
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Information -EventId 2016 `
                    -Message "NETWORK TRAFFIC: $($detection.Type) - $($detection.ProcessName -or $detection.RemoteAddress -or $detection.Adapter)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\NetworkTraffic_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.RemoteAddress)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) traffic anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Active connections=$($tcpConnections.Count)"
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
                $count = Invoke-NetworkTrafficMonitoring
                $LastTick = $now
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{ TickInterval = 15 }
}
