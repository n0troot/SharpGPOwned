@echo off
setlocal
set ROOT=%~dp0
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
set BIN=%ROOT%bin
set SHARED=%BIN%\GPOwned.Shared.dll

if not exist "%SHARED%" (
    echo [-] GPOwned.Shared.dll not found in bin\. Run build.bat first.
    exit /b 1
)

echo [*] Building GPOwned.Standalone.exe...
"%CSC%" /target:exe /out:"%BIN%\GPOwned.Standalone.exe" /main:EmbeddedEntry /platform:x64 /reference:"%SHARED%" /resource:"%SHARED%",GPOwned.Shared.dll /resource:"%ROOT%GPOwned\Resources\ScheduledTasks.xml",ScheduledTasks.xml /resource:"%ROOT%GPOwned\Resources\wsadd.xml",wsadd.xml "%ROOT%GPOwned\Program.cs" "%ROOT%GPOwned.Standalone\EmbeddedEntry.cs"
if errorlevel 1 ( echo [-] GPOwned standalone build failed. & exit /b 1 )
echo [+] %BIN%\GPOwned.Standalone.exe

echo [*] Building GPRecon.Standalone.exe...
"%CSC%" /target:exe /out:"%BIN%\GPRecon.Standalone.exe" /main:EmbeddedEntry /platform:x64 /reference:"%SHARED%" /resource:"%SHARED%",GPOwned.Shared.dll "%ROOT%GPRecon\Program.cs" "%ROOT%GPRecon.Standalone\EmbeddedEntry.cs"
if errorlevel 1 ( echo [-] GPRecon standalone build failed. & exit /b 1 )
echo [+] %BIN%\GPRecon.Standalone.exe

echo.
echo [+] Done.
