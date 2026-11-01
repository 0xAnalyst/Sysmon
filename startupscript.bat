@echo off
setlocal EnableExtensions
REM Sysmon deployment: GPO computer startup script.
REM Installs Sysmon when missing, reinstalls when the binary on the share changes, and
REM reapplies the config whenever the copy on the share changes (compared by SHA256).

set "SHARE=\\UNCPATH"
set "EXE=sysmon.exe"
set "CFG=sysmonconfig.xml"
set "DEST=%SystemRoot%"

if not exist "%SHARE%\%EXE%" exit /b 1
if not exist "%SHARE%\%CFG%" exit /b 1

call :hash "%SHARE%\%EXE%" NEW_EXE
call :hash "%DEST%\%EXE%" OLD_EXE
call :hash "%SHARE%\%CFG%" NEW_CFG
call :hash "%DEST%\%CFG%" OLD_CFG

sc query "sysmon" >nul 2>&1
if errorlevel 1 goto install

if /i not "%NEW_EXE%"=="%OLD_EXE%" (
  "%DEST%\%EXE%" -u force
  goto install
)

if /i not "%NEW_CFG%"=="%OLD_CFG%" (
  REM Apply from the share first, keep the local copy only if Sysmon accepted it.
  "%DEST%\%EXE%" -c "%SHARE%\%CFG%" && copy /y "%SHARE%\%CFG%" "%DEST%\%CFG%" >nul
)
exit /b 0

:install
copy /y "%SHARE%\%EXE%" "%DEST%\%EXE%" >nul
copy /y "%SHARE%\%CFG%" "%DEST%\%CFG%" >nul
"%DEST%\%EXE%" -accepteula -i "%DEST%\%CFG%"
exit /b %errorlevel%

:hash
set "%~2="
if not exist "%~1" exit /b 0
for /f "delims=" %%H in ('certutil -hashfile "%~1" SHA256 ^| findstr /v /c:":"') do set "%~2=%%H"
exit /b 0
