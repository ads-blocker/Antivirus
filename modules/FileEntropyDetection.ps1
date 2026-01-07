# File Entropy Detection Module
# Detects packed/encrypted files through entropy analysis

param([hashtable]$ModuleConfig)

$ModuleName = "FileEntropyDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 120 }
$HighEntropyThreshold = 7.2  # Entropy > 7.2 indicates likely packing/encryption
$ScannedFiles = @{}

function Measure-FileEntropy {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) {
            return $null
        }
        
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        
        # Skip very large files (sample first 4KB for speed)
        $sampleSize = [Math]::Min(4096, $fileInfo.Length)
        
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)[0..($sampleSize - 1)]
        
        if ($bytes.Count -eq 0) {
            return $null
        }
        
        # Calculate byte frequency
        $freq = @{}
        foreach ($byte in $bytes) {
            if ($freq.ContainsKey($byte)) {
                $freq[$byte]++
            } else {
                $freq[$byte] = 1
            }
        }
        
        # Calculate Shannon entropy
        $entropy = 0
        $total = $bytes.Count
        
        foreach ($count in $freq.Values) {
            $p = $count / $total
            if ($p -gt 0) {
                $entropy -= $p * [Math]::Log($p, 2)
            }
        }
        
        return @{
            Entropy = $entropy
            FileSize = $fileInfo.Length
            SampleSize = $sampleSize
        }
    } catch {
        return $null
    }
}

function Invoke-FileEntropyDetection {
    $detections = @()
    
    try {
        # Scan suspicious locations
        $scanPaths = @(
            "$env:APPDATA",
            "$env:LOCALAPPDATA\Temp",
            "$env:TEMP",
            "$env:USERPROFILE\Downloads"
        )
        
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            
            try {
                # Focus on executables and DLLs
                $files = Get-ChildItem -Path $scanPath -Include *.exe,*.dll,*.sys,*.scr -Recurse -File -ErrorAction SilentlyContinue |
                    Select-Object -First 100
                
                foreach ($file in $files) {
                    try {
                        # Skip if already scanned
                        $fileHash = $null
                        if ($file.Length -gt 0) {
                            try {
                                $fileHash = (Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                            } catch { }
                        }
                        
                        if ($fileHash -and $ScannedFiles.ContainsKey($fileHash)) {
                            continue
                        }
                        
                        # Measure entropy
                        $entropyResult = Measure-FileEntropy -FilePath $file.FullName
                        
                        if ($entropyResult -and $entropyResult.Entropy -ge $HighEntropyThreshold) {
                            $detections += @{
                                FilePath = $file.FullName
                                FileName = $file.Name
                                Entropy = [Math]::Round($entropyResult.Entropy, 2)
                                FileSize = $file.Length
                                Type = "High Entropy File (Packed/Encrypted)"
                                Risk = "Medium"
                            }
                            
                            # Mark as scanned
                            if ($fileHash) {
                                $ScannedFiles[$fileHash] = Get-Date
                            }
                        } elseif ($fileHash) {
                            # Mark as scanned even if low entropy
                            $ScannedFiles[$fileHash] = Get-Date
                        }
                    } catch {
                        continue
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check running process executables
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue | 
                Where-Object { $_.Path -and $_.Path -notlike "$env:SystemRoot\*" }
            
            foreach ($proc in $processes) {
                try {
                    if (-not (Test-Path $proc.Path)) { continue }
                    
                    # Skip if already scanned
                    $fileHash = $null
                    try {
                        $fileHash = (Get-FileHash -Path $proc.Path -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                    } catch { }
                    
                    if ($fileHash -and $ScannedFiles.ContainsKey($fileHash)) {
                        continue
                    }
                    
                    $entropyResult = Measure-FileEntropy -FilePath $proc.Path
                    
                    if ($entropyResult -and $entropyResult.Entropy -ge $HighEntropyThreshold) {
                        # Check if it's signed
                        $isSigned = $false
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
                            $isSigned = ($sig.Status -eq "Valid")
                        } catch { }
                        
                        if (-not $isSigned) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                FilePath = $proc.Path
                                Entropy = [Math]::Round($entropyResult.Entropy, 2)
                                Type = "High Entropy Unsigned Executable"
                                Risk = "High"
                            }
                        }
                        
                        # Mark as scanned
                        if ($fileHash) {
                            $ScannedFiles[$fileHash] = Get-Date
                        }
                    } elseif ($fileHash) {
                        $ScannedFiles[$fileHash] = Get-Date
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Cleanup old scanned files (older than 7 days)
        $oldKeys = $ScannedFiles.Keys | Where-Object {
            ((Get-Date) - $ScannedFiles[$_]).TotalDays -gt 7
        }
        foreach ($key in $oldKeys) {
            $ScannedFiles.Remove($key)
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2033 `
                    -Message "FILE ENTROPY: $($detection.Type) - $($detection.FileName -or $detection.ProcessName) - Entropy: $($detection.Entropy)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\FileEntropy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)|Entropy:$($_.Entropy)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) high entropy files"
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
                $count = Invoke-FileEntropyDetection
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
