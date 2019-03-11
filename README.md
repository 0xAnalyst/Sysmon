# Sysmon configuration and scripts
Create a GPO startup script and execute the batch file from it. The script terminates if it finds sysmonconfig.xml in C:\Windows modify it with the new config name.
# Sysmon V9.0
In sysmon v9.0 config file we added some of the detections from JPCERT https://jpcertcc.github.io/ToolAnalysisResultSheet/. 
We also included most of https://github.com/olafhartong/sysmon-modular and also some of https://github.com/Neo23x0/sigma/tree/master/rules/windows/sysmon. 
We will push it to more than 4k Endpoints and a month later would update it/remove noisy stuff. Our target is to map most of the MITRE Att@ck/JPCERT in this sysmon config. You might need to add exclusion for some of the software your enivroment including Antivirus/EDR/Whitelisting...etc. Also some of the events are noisy like pipe related events.
