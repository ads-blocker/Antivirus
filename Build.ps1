# Build EDR app (all *.cs) to Antivirus.exe with csc + app.manifest + Autorun.ico
# Optionally downloads yara.exe from VirusTotal/yara releases and copies rules.yar to output.
$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
Set-Location $scriptDir

$icon = 'Autorun.ico'
$out  = 'Antivirus.exe'
$manifest = 'app.manifest'
$rsp  = 'Build.rsp'

# YARA: download win64 zip and extract yara.exe next to output
$yaraZipUrl = 'https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip'
$yaraExeName = 'yara.exe'
$yaraOutPath = Join-Path $scriptDir $yaraExeName
if (-not (Test-Path -LiteralPath $yaraOutPath)) {
    Write-Host 'Downloading YARA (yara.exe)...' -ForegroundColor Cyan
    $tempZip = Join-Path $env:TEMP ('yara-' + [Guid]::NewGuid().ToString('N') + '.zip')
    $tempDir = Join-Path $env:TEMP ('yara-' + [Guid]::NewGuid().ToString('N'))
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $yaraZipUrl -OutFile $tempZip -UseBasicParsing
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force
        $found = Get-ChildItem -Path $tempDir -Filter $yaraExeName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $found) { $found = Get-ChildItem -Path $tempDir -Filter "yara64.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 }
        if ($found) {
            Copy-Item -LiteralPath $found.FullName -Destination $yaraOutPath -Force
            Write-Host "  Copied $([System.IO.Path]::GetFileName($found.FullName)) as $yaraExeName to $scriptDir" -ForegroundColor Gray
        } else {
            Write-Host "  Warning: yara.exe / yara64.exe not found in zip; YARA job will skip if exe missing." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Warning: YARA download failed: $_" -ForegroundColor Yellow
    } finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
} else {
    Write-Host "YARA: $yaraExeName already present." -ForegroundColor Gray
}
# Copy rules.yar to output dir if present
$rulesYar = Join-Path $scriptDir 'rules.yar'
if (Test-Path $rulesYar) {
    Write-Host "Rules: rules.yar present." -ForegroundColor Gray
}

$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$framework = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
$refs = @(
    (Join-Path $framework 'System.Drawing.dll'),
    (Join-Path $framework 'System.Windows.Forms.dll'),
    (Join-Path $framework 'System.Management.dll')
)

foreach ($p in @($icon, $manifest, $csc)) {
    if (-not (Test-Path $p)) { throw "Not found: $p" }
}

$csFiles = Get-ChildItem -Path $scriptDir -Filter '*.cs' | Select-Object -ExpandProperty Name

$optOut = '/out:' + $out
$optIcon = '/win32icon:' + $icon
$optManifest = '/win32manifest:' + $manifest
$optResource = '/resource:' + $icon + ',Autorun.ico'
$rspLines = @(
    '/target:winexe',
    $optOut,
    $optIcon,
    $optManifest,
    $optResource,
    '/nologo'
)
foreach ($r in $refs) { $ro = '/r:' + $r; $rspLines += $ro }
foreach ($f in $csFiles) { $rspLines += $f }

$rspLines | Set-Content -Path $rsp -Encoding ASCII

Write-Host 'Building with csc...' -ForegroundColor Cyan
Write-Host "  Output:  $scriptDir\$out" -ForegroundColor Gray
Write-Host "  Icon:    $scriptDir\$icon" -ForegroundColor Gray
Write-Host "  Manifest: $scriptDir\$manifest" -ForegroundColor Gray
Write-Host "  Sources: $($csFiles.Count) .cs files" -ForegroundColor Gray
& $csc "@$rsp"
if ($LASTEXITCODE -ne 0) {
    Remove-Item -Path $rsp -ErrorAction SilentlyContinue
    throw "csc failed with exit code $LASTEXITCODE"
}
Remove-Item -Path $rsp -ErrorAction SilentlyContinue

$outFull = Join-Path $scriptDir $out
Write-Host ''
Write-Host 'Done. EXE: ' -NoNewline
Write-Host $outFull -ForegroundColor Green
