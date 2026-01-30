#Requires -RunAsAdministrator
# Build Antivirus.ps1 to EXE with Autorun.ico

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceScript = Join-Path $scriptDir 'Antivirus.ps1'
$iconFile   = Join-Path $scriptDir 'Autorun.ico'
$outputExe  = Join-Path $scriptDir 'Antivirus.exe'

if (-not (Test-Path $sourceScript)) { throw "Source script not found: $sourceScript" }
if (-not (Test-Path $iconFile))     { throw "Icon file not found: $iconFile" }

# Install PS2EXE if missing
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installing PS2EXE module...' -ForegroundColor Cyan
    Install-Module -Name ps2exe -Scope CurrentUser -Force
}

Import-Module ps2exe -Force

Write-Host "Compiling: $sourceScript" -ForegroundColor Cyan
Write-Host "Icon:      $iconFile" -ForegroundColor Cyan
Write-Host "Output:    $outputExe" -ForegroundColor Cyan
Write-Host ''

Invoke-ps2exe -inputFile $sourceScript -outputFile $outputExe -iconFile $iconFile -title 'Antivirus Protection'

if (Test-Path $outputExe) {
    Write-Host ''
    Write-Host 'Done. EXE created: ' -NoNewline
    Write-Host $outputExe -ForegroundColor Green
} else {
    throw 'Build failed - output EXE was not created.'
}
