# Cobalt Strike Cheat Sheet

## Running PowerShell scripts
```
powershell-import --> Select PowerView.ps1 to import PS1 file in memory
powershell Get-Module PowerView
powershell Get-NetUser -Identity testuser
```

## Executing .NET binaries (i.e. SharpView and SharpHound)
```
# Running SharpView in memory (.NET version of PowerView)
execute-assembly C:\SharpView.exe ...

# BloodHound collection with SharpHound.exe
# --Stealth will
# --excludedomaincontrollers will 
# --windowsonly will 
execute-assembly C:\SharpHound.exe --CollectionMethod All --Domain test.lab.local --Stealth --excludedomaincontrollers --windowsonly --OutputDirectory C:\users\testuser\appdata\local\temp\
```
