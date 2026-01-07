# Hash-based Malware Detection Module
# Managed Tick Job for Enterprise EDR

param(
    [hashtable]$ModuleConfig
)

$ModuleName = "HashDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }
$HashDatabase = @{}
$ThreatHashes = @{}
$ScanPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:ProgramFiles", "$env:ProgramFiles(x86)")
$DetectionCount = 0

function Initialize-HashDatabase {
    # Load known good hashes (whitelist)
    $whitelistPath = "$env:ProgramData\Antivirus\HashDatabase\whitelist.txt"
    if (Test-Path $whitelistPath) {
        Get-Content $whitelistPath | ForEach-Object {
            if ($_ -match '^([A-F0-9]{64})\|(.+)$') {
                $HashDatabase[$matches[1]] = $matches[2]
            }
        }
    }
    
    # Load threat hashes (blacklist) from multiple sources
    $threatPaths = @(
        "$env:ProgramData\Antivirus\HashDatabase\threats.txt",
        "$env:ProgramData\Antivirus\HashDatabase\malware_hashes.txt"
    )
    
    foreach ($threatPath in $threatPaths) {
        if (Test-Path $threatPath) {
            Get-Content $threatPath | ForEach-Object {
                if ($_ -match '^([A-F0-9]{32,64})$') {
                    $ThreatHashes[$matches[1].ToUpper()] = $true
                }
            }
        }
    }
}

function Get-FileHash {
    param([string]$FilePath)
    
    try {
        if (Test-Path $FilePath) {
            $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            return $hash.Hash
        }
    } catch {
        return $null
    }
}

function Test-ThreatHash {
    param([string]$Hash)
    
    $hashUpper = $Hash.ToUpper()
    
    # Check threat database
    if ($ThreatHashes.ContainsKey($hashUpper)) {
        return $true
    }
    
    # Check against known good hashes
    if ($HashDatabase.ContainsKey($hashUpper)) {
        return $false
    }
    
    # Unknown hash - may be suspicious
    return $null
}

function Invoke-HashScan {
    $scannedFiles = 0
    $threatsFound = @()
    
    foreach ($scanPath in $ScanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        
        try {
            $files = Get-ChildItem -Path $scanPath -File -Recurse -ErrorAction SilentlyContinue | 
                Select-Object -First 1000
            
            foreach ($file in $files) {
                $scannedFiles++
                
                try {
                    $hash = Get-FileHash -FilePath $file.FullName
                    if ($null -eq $hash) { continue }
                    
                    $threatResult = Test-ThreatHash -Hash $hash
                    
                    if ($threatResult -eq $true) {
                        $threatsFound += @{
                            File = $file.FullName
                            Hash = $hash
                            Size = $file.Length
                            LastModified = $file.LastWriteTime
                            Threat = "Known Malware Hash"
                        }
                        
                        # Alert
                        Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2001 `
                            -Message "THREAT DETECTED: $($file.FullName) - Hash: $hash"
                    }
                } catch {
                    continue
                }
            }
        } catch {
            continue
        }
    }
    
    if ($threatsFound.Count -gt 0) {
        $script:DetectionCount += $threatsFound.Count
        Write-Output "DETECTION:$ModuleName`:Found $($threatsFound.Count) hash-based threats"
        
        # Log detailed findings
        $logPath = "$env:ProgramData\Antivirus\Logs\HashDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
        $threatsFound | ForEach-Object {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|THREAT|$($_.File)|$($_.Hash)|$($_.Size)" | 
                Add-Content -Path $logPath
        }
    }
    
    return @{
        ScannedFiles = $scannedFiles
        ThreatsFound = $threatsFound.Count
    }
}

function Start-Module {
    param([hashtable]$Config)
    
    Initialize-HashDatabase
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $result = Invoke-HashScan
                $LastTick = $now
                
                # Update statistics
                Write-Output "STATS:$ModuleName`:Scanned=$($result.ScannedFiles),Threats=$($result.ThreatsFound)"
            }
            
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

# Auto-start if not imported
if (-not $ModuleConfig) {
    Start-Module -Config @{ TickInterval = 60 }
}
