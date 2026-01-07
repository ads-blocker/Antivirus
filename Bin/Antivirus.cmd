@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Move to the script directory
cd /d %~dp0

:: Step 4: Execute PowerShell (.ps1) files alphabetically
echo Executing PowerShell scripts...
for /f "tokens=*" %%A in ('dir /b /o:n *.ps1') do (
    echo Running %%A...
        start "" /b powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "%%A"
)

echo Script completed successfully.

exit
