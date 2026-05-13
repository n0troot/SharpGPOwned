@echo off
setlocal
cd /d "%~dp0"

set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
set BIN=bin
set SHARED=%BIN%\GPOwned.Shared.dll

if not exist "%SHARED%" (
    echo [-] GPOwned.Shared.dll not found. Run build.bat first.
    exit /b 1
)

echo [*] Building GPOwned.Standalone.exe...
"%CSC%" /target:exe /out:"%BIN%\GPOwned.Standalone.exe" /main:EmbeddedEntry /platform:x64 ^
    /reference:"%SHARED%" ^
    /resource:"%SHARED%",GPOwned.Shared.dll ^
    /resource:"GPOwned\Resources\ScheduledTasks.xml",ScheduledTasks.xml ^
    /resource:"GPOwned\Resources\wsadd.xml",wsadd.xml ^
    "GPOwned\Program.cs" ^
    "GPOwned.Standalone\EmbeddedEntry.cs"
if errorlevel 1 ( echo [-] GPOwned standalone build failed. & exit /b 1 )
echo [+] %BIN%\GPOwned.Standalone.exe

echo [*] Building GPRecon.Standalone.exe...
"%CSC%" /target:exe /out:"%BIN%\GPRecon.Standalone.exe" /main:EmbeddedEntry /platform:x64 ^
    /reference:"%SHARED%" ^
    /resource:"%SHARED%",GPOwned.Shared.dll ^
    "GPRecon\Program.cs" ^
    "GPRecon.Standalone\EmbeddedEntry.cs"
if errorlevel 1 ( echo [-] GPRecon standalone build failed. & exit /b 1 )
echo [+] %BIN%\GPRecon.Standalone.exe

echo.
echo [+] Done.
