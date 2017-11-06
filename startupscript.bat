@echo off

SET Configfile="c:\windows\sysmonconfig.xml"
IF EXIST %Configfile% GOTO END

sysmon -u
copy /z /y "\\UNCPATH\sysmonconfig.xml" "C:\windows\"
copy /z /y "\\UNCPATH\sysmon.exe" "C:\windows\"


"C:\windows\sysmon.exe" /accepteula -i c:\windows\sysmonconfigV65.xml

:End
