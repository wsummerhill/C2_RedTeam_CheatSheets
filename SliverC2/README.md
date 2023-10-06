# Sliver C2 Cheat Sheet

# TO DO - Work in Progress

## Setup

Sliver client and server can both be downloaded from public [GitHub releases](https://github.com/BishopFox/sliver/releases/), or it can manually be compiled.

### Sliver Server 

The Sliver server can be installed running in "Daemon mode" using the [Linux Install Script](https://github.com/BishopFox/sliver/wiki/Linux-Install-Script). Use a quick Bash script below to help with setting up requirements and installing/running the Sliver server:
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

---
## Usage - Useful CLI Commands Cheat Sheet
```
# Starting HTTP/S Listeners
http -> Start HTTP listener
https -> Start HTTPS listener
https -c cert.pen -k key_decrypted.pem -d domain.com -p -> Start HTTPS listener using a cert/key which only accepts connections from a specific domain (i.e. redirector)

# Managing or stopping listeners
jobs -> View active jobs (aka listeners/stages)
jobs -k <number> -> Kill listener job

# Beacon/Session management
beacons -> List active beacons
sessions -> List active sessions
beacons rm -> Select a beacon to remove
use <ID> -> Interact with a Beacon/Session
background -> Background an active Beacon/Session

# Payloads
implants -> List all created payload builds
implants rm <NAME> -> Remove an implant build
generate ... -> Create Session payload
generate beacon ... -> Create Beacon payload

# Armory (BOFs)
armory -> List all available packages/bundles in armory
armory search <query> -> Search for specific aromory package/bundle
armory install <name> -> Install a new armory package/bundle
armory update -> Update installed packages

# Miscellaneous
hosts -> List all hosts that have had beacons or sessions
update -> Check for Sliver updates
clear -> Clear the screen
loot -> Show captured loot
reaction ... -> Create automatic command upon specific events like a new session
```

---
## Listeners - HTTP(S)

TO DO

---
## Redirectors - HTTP(S)

TO DO

---
## Payloads
### Beacon Payloads

TO DO

### Session Payloads

TO DO

### Debugging Payloads for testing

Sliver can easily create debugging payloads for testing execution or viewing C2 traffic sent by the payload or server. Use the `generate --debug` 
parameter when generating new payloads which will show the debug output in the CLI console. 

---
## OPSEC Tips

- Best practices to modify the default HTTP(S) C2 profile at the local path `/root/.sliver/configs/http-c2.json`
- Always use Sliver Armory wherever you can to execute commands within the current process instead of using commands or tools that spawn new or child processes
