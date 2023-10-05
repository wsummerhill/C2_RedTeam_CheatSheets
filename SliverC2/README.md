# Sliver C2 Cheat Sheet

# TO DO - Work in Progress

## Setup

TO DO

---
## Usage - CLI Useful Commands
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

---
## Payloads
### Beacon Payload

TO DO

### Session Payload

TO DO

### Debugging Payloads for testing

Sliver can easily create debugging payloads for testing execution or viewing C2 traffic sent by the payload or server. Use the `generate --debug` 
parameter when generating new payloads which will show the debug output in the CLI console. 

---
## OPSEC Tips

- Best practices to modify the default HTTP(S) C2 profile at the local path `/root/.sliver/configs/http-c2.json`
