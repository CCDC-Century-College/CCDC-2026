## Sysmon/Hayabusa (AD & MSSQL)

```
# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Path "C:\Tools" -Force | Out-Null
Set-Location "C:\Tools"

Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile "C:\Tools\Sysmon64.exe"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\sysmonconfig.xml"
.\Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig.xml
```
hayabusa
```
Invoke-WebRequest -Uri "https://github.com/Yamato-Security/hayabusa/releases/download/v4.4.0/hayabusa-4.4.0-win-x64-live-response.zip" -OutFile "C:\Tools\hayabusa.zip"
Expand-Archive -Path "C:\Tools\hayabusa.zip" -DestinationPath "C:\Tools\Hayabusa" -Force

$Exe = Get-ChildItem -Path "C:\Tools\Hayabusa" -Filter "hayabusa*.exe" | Select-Object -First 1
Copy-Item $Exe.FullName "C:\Tools\hayabusa.exe" -Force
```

### Run Hayabusa Live Scan

```
# Scan live event logs for Med/High/Critical lerts
C:\Tools\hayabusa.exe csv-timeline --live-analysis --min-level med --no-wizard --output C:\Tools\alerts.csv

# Display only Timestamp, Level, RuleTitle, and Details in a clean table
Import-Csv C:\Tools\alerts.csv | Select-Object Timestamp, Level, RuleTitle, Details | Format-Table -AutoSize
```

### Back Up Scored Data

```
# [(MSSQL) Water facility SOPs + NTFS permissions (/COPYALL) and subdirs (/E)
robocopy "C:\Shares\SOPs" "C:\Windows\System32\ccdc_sop_backup" /E /COPYALL

# (AD) non-default DNS zones
Get-DnsServerZone | Where-Object {-not $_.IsAutoCreated} | ForEach-Object { Export-DnsServerZone -Name $_.ZoneName -FileName "$($_.ZoneName).bak" }
```

### Network & Listening Ports

```
Get-NetTCPConnection | Where-Object State -in @("Listen","Established") | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
```

### threat hunting

```
# Find active, non Microsoft scheduled tasks and unpack exes/args
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" } | Select-Object TaskName, TaskPath, @{N="Exec";E={$_.Actions.Execute}}, @{N="Args";E={$_.Actions.Arguments}}

# Sticky Keys / Accessibility IFEO registry backdoors (checks for Debugger values)
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | ForEach-Object { Get-ItemProperty $_.PSPath | Where-Object { $_.Debugger -ne $null } | Select-Object PSChildName, Debugger }

Get-ADGroupMember -Identity "Domain Admins"

# demoting
Remove-ADGroupMember -Identity "Domain Admins" -Members "rogue_user" -Confirm:$false

# PS, hashing sus files DONT UPLOAD TO VT
Get-FileHash "C:\path\to\suspect.exe" -Algorithm SHA256
```

kerberos GT reset
```
Add-Type -AssemblyName System.Web
1..2 | ForEach-Object { Set-ADAccountPassword -Identity "krbtgt" -NewPassword (ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(32,8)) -AsPlainText -Force) -Reset; Start-Sleep -Seconds 2 }
```


netlogon
```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
Restart-Service -Name "Netlogon" -Force
```


```
New-Item -ItemType Directory -Path "C:\Program Files\ClamAV", "C:\Tools\ClamAV\db" -Force | Out-Null
Set-Location "C:\Tools"

$ClamUrl = "https://www.clamav.net/downloads/production/clamav-1.5.4.win.x64.zip"
Invoke-WebRequest -Uri $ClamUrl -OutFile "C:\Tools\clamav.zip"
Expand-Archive -Path "C:\Tools\clamav.zip" -DestinationPath "C:\Program Files\ClamAV" -Force

# Config Setup refer 2 docs
Copy-Item "C:\Program Files\ClamAV\conf_examples\freshclam.conf.sample" "C:\Program Files\ClamAV\freshclam.conf"
Copy-Item "C:\Program Files\ClamAV\conf_examples\clamd.conf.sample" "C:\Program Files\ClamAV\clamd.conf"
(Get-Content "C:\Program Files\ClamAV\freshclam.conf") | Where-Object { $_ -ne "Example" } | Set-Content "C:\Program Files\ClamAV\freshclam.conf"
(Get-Content "C:\Program Files\ClamAV\clamd.conf") | Where-Object { $_ -ne "Example" } | Set-Content "C:\Program Files\ClamAV\clamd.conf"

# Run
& "C:\Program Files\ClamAV\clamscan.exe" -r "C:\Users\Public" "C:\Windows\Temp" "C:\inetpub" --log="C:\ccdc\clamav_scan.log"
```
