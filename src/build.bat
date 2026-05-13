@echo off
setlocal
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
set SRC=%~dp0
set BIN=%SRC%bin

if not exist "%BIN%" mkdir "%BIN%"

set REFS=/r:System.dll /r:System.Core.dll /r:System.DirectoryServices.dll /r:System.Management.dll /r:Microsoft.CSharp.dll

echo.
echo [*] Building GPOwned.Shared.dll...
"%CSC%" /target:library /out:"%BIN%\GPOwned.Shared.dll" %REFS% ^
    "%SRC%Shared\Output.cs" ^
    "%SRC%Shared\AdHelper.cs" ^
    "%SRC%Shared\SysvolHelper.cs" ^
    "%SRC%Shared\TaskSchedulerHelper.cs"
if errorlevel 1 ( echo [-] Shared build FAILED & exit /b 1 )
echo [+] GPOwned.Shared.dll built.

echo.
echo [*] Building GPOwned.exe...
"%CSC%" /target:exe /platform:x64 /out:"%BIN%\GPOwned.exe" %REFS% ^
    /r:"%BIN%\GPOwned.Shared.dll" ^
    "/res:%SRC%GPOwned\Resources\ScheduledTasks.xml,ScheduledTasks.xml" ^
    "/res:%SRC%GPOwned\Resources\wsadd.xml,wsadd.xml" ^
    "%SRC%GPOwned\Program.cs"
if errorlevel 1 ( echo [-] GPOwned build FAILED & exit /b 1 )
echo [+] GPOwned.exe built.

echo.
echo [*] Building GPRecon.exe...
"%CSC%" /target:exe /platform:x64 /out:"%BIN%\GPRecon.exe" %REFS% ^
    /r:"%BIN%\GPOwned.Shared.dll" ^
    "%SRC%GPRecon\Program.cs"
if errorlevel 1 ( echo [-] GPRecon build FAILED & exit /b 1 )
echo [+] GPRecon.exe built.

echo.
echo [+] Build complete. Binaries in: %BIN%
echo     - GPOwned.exe          (main exploitation tool)
echo     - GPRecon.exe          (recon tool)
echo     - GPOwned.Shared.dll   (required alongside both EXEs)
echo.
