# Cobalt Strike & Red Team Cheat Sheet

## Running PowerShell scripts
```
powershell-import --> Select PowerView.ps1 to import PS1 file in memory
powershell Get-Module PowerView
powershell Get-NetUser -Identity testuser
```

## Running ActiveDirectory module
```
powershell import --> Select \ActiveDirectory\ActiveDirectory.psd1 file from https://github.com/samratashok/ADModule
```

## Running Bloodhound/Sharphound for AD data collection
```
# Running SharpView in memory (.NET version of PowerView)
execute-assembly C:\SharpHound.exe --CollectionMethod All --Domain test.lab.local --Stealth --excludedomaincontrollers --windowsonly --OutputDirectory C:\users\testuser\appdata\local\temp\
# Collection methods reference: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html

```


# References
Cobalt Strike commands cheat-sheet: https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet
Sharphound: https://github.com/BloodHoundAD/SharpHound3
