# NOTE: WORK IN PROGRESS

# Cobalt Strike & Red Team Cheat Sheet

## Enumeration

### Running PowerShell scripts
```
# powershell-import --> Select PowerView.ps1 to import PS1 file in memory
# powershell Get-Module PowerView
# powershell Get-NetUser -Identity testuser -Domain test.lab.local
```

### Running ActiveDirectory module
```
# powershell import --> Select \ADModule\Microsoft.ActiveDirectory.Management.dll  file from https://github.com/samratashok/ADModule
# powershell Get-ADDomainController -Domain test.lab.local
```

### Running Sharphound (.NET version of Bloodhound) for AD data collection
```
Running SharpView in memory (.NET version of PowerView)
# execute-assembly C:\SharpHound.exe --CollectionMethod All --Domain test.lab.local --Stealth --excludedomaincontrollers --windowsonly --OutputDirectory C:\users\testuser\appdata\local\temp\

Just to collect user sessions to determine who is logged in where:
# execute-assembly C:\SharpHound.exe --CollectionMethod Session,LoggedOn --windowsonly --Outputdirectory C:\users\testuser\appdata\local\temp\

Collection methods reference: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html
```
---
## Lateral Movement


# References
Cobalt Strike commands cheat-sheet: https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet
Sharphound: https://github.com/BloodHoundAD/SharpHound3
