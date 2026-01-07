# Event Log Monitoring Module
# Monitors Event Log for security events and anomalies

param([hashtable]$ModuleConfig)

$ModuleName = "EventLogMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-EventLogMonitoring {
    $detections = @()
    
    try {
        # Monitor Security Event Log
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'} -ErrorAction SilentlyContinue -MaxEvents 500
            
            # Check for failed logon attempts
            $failedLogons = $securityEvents | Where-Object {
                $_.Id -eq 4625 -or $_.Message -match 'failed.*logon|logon.*failure'
            }
            
            if ($failedLogons.Count -gt 10) {
                $detections += @{
                    EventCount = $failedLogons.Count
                    Type = "Excessive Failed Logon Attempts"
                    Risk = "High"
                }
            }
            
            # Check for privilege escalation
            $privilegeEvents = $securityEvents | Where-Object {
                $_.Id -in @(4672, 4673, 4674) -or
                $_.Message -match 'privilege|SeDebugPrivilege|SeTcbPrivilege'
            }
            
            foreach ($event in $privilegeEvents) {
                $detections += @{
                    EventId = $event.Id
                    TimeCreated = $event.TimeCreated
                    Message = $event.Message
                    Type = "Privilege Escalation Event"
                    Risk = "High"
                }
            }
            
            # Check for account lockouts
            $lockoutEvents = $securityEvents | Where-Object {
                $_.Id -eq 4740 -or $_.Message -match 'account.*lockout|lockout.*account'
            }
            
            if ($lockoutEvents.Count -gt 0) {
                foreach ($event in $lockoutEvents) {
                    $detections += @{
                        EventId = $event.Id
                        TimeCreated = $event.TimeCreated
                        Type = "Account Lockout"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Monitor System Event Log
        try {
            $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'} -ErrorAction SilentlyContinue -MaxEvents 500
            
            # Check for service start failures
            $serviceFailures = $systemEvents | Where-Object {
                $_.Id -eq 7023 -or $_.Message -match 'service.*failed|failed.*start.*service'
            }
            
            if ($serviceFailures.Count -gt 5) {
                $detections += @{
                    EventCount = $serviceFailures.Count
                    Type = "Multiple Service Start Failures"
                    Risk = "Medium"
                }
            }
            
            # Check for driver load failures
            $driverFailures = $systemEvents | Where-Object {
                $_.Id -in @(219, 7000, 7001) -or
                $_.Message -match 'driver.*failed|failed.*load.*driver'
            }
            
            if ($driverFailures.Count -gt 5) {
                $detections += @{
                    EventCount = $driverFailures.Count
                    Type = "Multiple Driver Load Failures"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Monitor Application Event Log
        try {
            $appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'} -ErrorAction SilentlyContinue -MaxEvents 500
            
            # Check for application crashes
            $crashes = $appEvents | Where-Object {
                $_.LevelDisplayName -eq "Error" -and
                $_.Message -match 'crash|exception|fault|error.*application'
            }
            
            if ($crashes.Count -gt 10) {
                $detections += @{
                    EventCount = $crashes.Count
                    Type = "Excessive Application Crashes"
                    Risk = "Low"
                }
            }
        } catch { }
        
        # Check for Event Log clearing
        try {
            $logClearingEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue -MaxEvents 10
            
            foreach ($event in $logClearingEvents) {
                if ((Get-Date) - $event.TimeCreated -lt [TimeSpan]::FromHours(24)) {
                    $detections += @{
                        EventId = $event.Id
                        TimeCreated = $event.TimeCreated
                        LogName = $event.LogName
                        Type = "Event Log Cleared"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        # Check for PowerShell execution events
        try {
            $psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object {
                    $_.Message -match '-encodedcommand|-nop|-w.*hidden|bypass'
                }
            
            foreach ($event in $psEvents) {
                $detections += @{
                    EventId = $event.Id
                    TimeCreated = $event.TimeCreated
                    Message = $event.Message
                    Type = "Suspicious PowerShell Execution"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2023 `
                    -Message "EVENT LOG MONITORING: $($detection.Type) - Event ID: $($detection.EventId -or 'Multiple')"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\EventLogMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.EventId -or $_.EventCount)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) event log anomalies"
        }
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
                $count = Invoke-EventLogMonitoring
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
    Start-Module -Config @{ TickInterval = 30 }
}
