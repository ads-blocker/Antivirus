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
# Copy VC++ runtime DLLs next to yara.exe so it runs without system install
$vcDlls = @('vcruntime140.dll', 'msvcp140.dll')
$system32 = ${env:SystemRoot} + '\System32'
$vcRedistUrl = 'https://aka.ms/vc14/vc_redist.x64.exe'
foreach ($dll in $vcDlls) {
    $src = Join-Path $system32 $dll
    $dst = Join-Path $scriptDir $dll
    if ((Test-Path $src) -and (Test-Path $yaraOutPath)) {
        Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction SilentlyContinue
        if (Test-Path $dst) { Write-Host "VC++: $dll copied for YARA." -ForegroundColor Gray }
    }
}
if ((Test-Path $yaraOutPath) -and -not (Test-Path (Join-Path $scriptDir 'vcruntime140.dll'))) {
    Write-Host 'VC++ DLLs not in System32. Downloading Redistributable...' -ForegroundColor Cyan
    $vcTemp = Join-Path $env:TEMP ('vc_redist_' + [Guid]::NewGuid().ToString('N') + '.exe')
    $vcExtract = Join-Path $env:TEMP ('vc_extract_' + [Guid]::NewGuid().ToString('N'))
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcTemp -UseBasicParsing
        New-Item -ItemType Directory -Path $vcExtract -Force | Out-Null
        Start-Process -FilePath $vcTemp -ArgumentList "/extract:`"$vcExtract`"", "/passive" -Wait -NoNewWindow -ErrorAction SilentlyContinue
        Get-ChildItem -Path $vcExtract -Filter 'vcruntime140.dll' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { Copy-Item $_.FullName -Destination (Join-Path $scriptDir 'vcruntime140.dll') -Force }
        Get-ChildItem -Path $vcExtract -Filter 'msvcp140.dll' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { Copy-Item $_.FullName -Destination (Join-Path $scriptDir 'msvcp140.dll') -Force }
        if (Test-Path (Join-Path $scriptDir 'vcruntime140.dll')) { Write-Host "VC++: DLLs extracted from Redistributable." -ForegroundColor Gray }
    } catch { Write-Host "  VC++ download/extract failed: $_" -ForegroundColor Yellow }
    finally {
        if (Test-Path $vcTemp) { Remove-Item $vcTemp -Force -ErrorAction SilentlyContinue }
        if (Test-Path $vcExtract) { Remove-Item $vcExtract -Recurse -Force -ErrorAction SilentlyContinue }
    }
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
$rspLines = @(
    '/target:winexe',
    $optOut,
    $optIcon,
    $optManifest,
    ("/resource:$icon,Autorun.ico"),
    '/nologo'
)
# Embed VC++ DLLs, yara.exe, rules.yar for single-file distribution
$embedFiles = @(
    @{file='vcruntime140.dll'; name='vcruntime140'},
    @{file='msvcp140.dll'; name='msvcp140'},
    @{file='yara.exe'; name='yara'},
    @{file='rules.yar'; name='rules'}
)
foreach ($e in $embedFiles) {
    $fp = Join-Path $scriptDir $e.file
    if (Test-Path $fp) { $rspLines += "/resource:$($e.file),$($e.name)" }
}
foreach ($r in $refs) { $ro = '/r:' + $r; $rspLines += $ro }
foreach ($f in $csFiles) { $rspLines += $f }

$rspPath = Join-Path $scriptDir $rsp
$rspLines | Set-Content -Path $rspPath -Encoding ASCII

Write-Host 'Building with csc...' -ForegroundColor Cyan
Write-Host "  Output:  $scriptDir\$out" -ForegroundColor Gray
Write-Host "  Icon:    $scriptDir\$icon" -ForegroundColor Gray
Write-Host "  Manifest: $scriptDir\$manifest" -ForegroundColor Gray
Write-Host "  Sources: $($csFiles.Count) .cs files" -ForegroundColor Gray
& $csc "@$rspPath"
if ($LASTEXITCODE -ne 0) {
    Remove-Item -Path $rspPath -ErrorAction SilentlyContinue
    throw "csc failed with exit code $LASTEXITCODE"
}
Remove-Item -Path $rspPath -ErrorAction SilentlyContinue

$outFull = Join-Path $scriptDir $out
Write-Host ''
Write-Host 'Done. EXE: ' -NoNewline
Write-Host $outFull -ForegroundColor Green
