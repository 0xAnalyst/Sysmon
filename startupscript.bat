@echo off

SET Configfile="c:\windows\sysmonconfig.xml"
IF EXIST %Configfile% GOTO END

REM you can use sysmon -u in here for future versions to unistall the old version before installing new one
copy /z /y "\\UNCPATH\sysmonconfig.xml" "C:\windows\"
copy /z /y "\\UNCPATH\sysmon.exe" "C:\windows\"


"C:\windows\sysmon.exe" /accepteula -i c:\windows\sysmonconfig.xml

:End
