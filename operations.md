# Fox3 Operations Guide — Server & Agent Startup

## Building

### Server (Go)
```bash
cd c:/Users/null/fox3
go build -o fox3_server.exe .
```

### Agent (Rust)
```bash
cd c:/Users/null/fox3/simple_agent
cargo build --release
# Binary: target/release/simple_agent.exe
```

## Starting the Server
```bash
cd c:/Users/null/fox3
# Kill old instance if needed:
taskkill //F //IM fox3_server.exe 2>/dev/null
# Start (REST on :8080, gRPC on :50051):
./fox3_server.exe > server.log 2>&1 &
sleep 3 && tail -5 server.log  # verify startup
```
- Default password: `fox3`
- REST API: `http://127.0.0.1:8080`
- No python3 on this machine — use bash/curl for JSON parsing

## Getting a REST Auth Token
```bash
TOKEN=$(curl -sk -X POST http://127.0.0.1:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"fox3"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "$TOKEN"
```

## Creating Listeners via REST

### Get Default Options for a Protocol
```bash
curl -sk http://127.0.0.1:8080/api/listeners/options/HTTPS \
  -H "Authorization: Bearer $TOKEN"
```
Protocols: `HTTPS`, `WSS`, `DOHDNS`, `TCP`, `SMB`

### Create HTTPS Listener (port 443)
```bash
curl -sk -X POST http://127.0.0.1:8080/api/listeners/create \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
  "Authenticator":"OPAQUE",
  "Description":"HTTPS Listener",
  "Interface":"127.0.0.1",
  "JWTKey":"UlBUak9oQ1hzYnd0cUljbWFhY0VTeG9DaVpxWFJjUG8=",
  "JWTLeeway":"1m",
  "Name":"HTTPS Listener",
  "PSK":"fox3test",
  "Port":"443",
  "Protocol":"HTTPS",
  "Transforms":"jwe,json",
  "URLS":"/"
}'
```
Returns `{"id":"<uuid>", ...}`. Save the listener ID.
**WSS auto-created**: A companion WSS listener is automatically created alongside the HTTPS listener (same PSK, transforms, authenticator, JWTKey). No separate WSS creation needed.

### Create WSS Listener Manually (only for debug/testing separate configs)
```bash
curl -sk -X POST http://127.0.0.1:8080/api/listeners/create \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
  "Authenticator":"OPAQUE",
  "Description":"WSS Listener",
  "Interface":"127.0.0.1",
  "JWTKey":"UlBUak9oQ1hzYnd0cUljbWFhY0VTeG9DaVpxWFJjUG8=",
  "JWTLeeway":"1m",
  "Name":"WSS Listener",
  "PSK":"fox3test",
  "Port":"443",
  "Protocol":"WSS",
  "Transforms":"jwe,json",
  "URLS":"/"
}'
```
**Note**: WSS shares the HTTPS server; both must use the same port/interface.

### Create DoH+DNS Hybrid Listener
```bash
curl -sk -X POST http://127.0.0.1:8080/api/listeners/create \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
  "Protocol":"DOHDNS",
  "Interface":"127.0.0.1",
  "DOHPort":"8443",
  "DNSPort":"5353",
  "PSK":"fox3test",
  "Transforms":"jwe,json",
  "Authenticator":"OPAQUE",
  "Domain":"fox3.local.",
  "Name":"DoH+DNS Listener"
}'
```

### Start a Listener
```bash
curl -sk -X POST http://127.0.0.1:8080/api/listeners/start/<LISTENER_ID> \
  -H "Authorization: Bearer $TOKEN"
```

### List Listeners
```bash
curl -sk http://127.0.0.1:8080/api/listeners \
  -H "Authorization: Bearer $TOKEN"
```

## Starting Agents

### HTTPS/WSS Agent (auto-upgrades to WSS if available)
```bash
cd c:/Users/null/fox3/simple_agent
./target/release/simple_agent.exe \
  --url https://127.0.0.1:443/ \
  --psk fox3test \
  --sleep 30 \
  --jitter 10 \
  --transport http
```

### HTTPS/WSS Agent via Proxy
```bash
./target/release/simple_agent.exe \
  --url https://127.0.0.1:443/ \
  --psk fox3test \
  --sleep 30 \
  --transport http \
  --proxy http://proxy:8080
```

### DoH/DNS Agent
```bash
./target/release/simple_agent.exe \
  --url https://127.0.0.1:8443/dns-query \
  --psk fox3test \
  --sleep 30 \
  --jitter 10 \
  --transport dns \
  --domain fox3.local. \
  --dns-server 127.0.0.1:5353
```

### TCP Agent
```bash
./target/release/simple_agent.exe \
  --url 127.0.0.1:4444 \
  --psk fox3test \
  --sleep 5 \
  --transport tcp
```

**IMPORTANT**: The Rust agent does NOT implement OPAQUE auth (MSG_OPAQUE=2 defined but unhandled).
Always use `"Authenticator":"none"` in listener options when testing with the Rust agent.
OPAQUE listeners will cause the agent to silently fail registration.

### Agent CLI Flags
- `--url` — server URL (https for HTTP/WSS, doh URL for DNS, addr:port for TCP)
- `--psk` — pre-shared key (must match listener)
- `--sleep` — beacon interval in seconds (default 30)
- `--jitter` — jitter percentage 0-50 (default 10)
- `--tunnel-poll` — tunnel fast-poll interval in ms (default 50)
- `--transport` — `http` (default), `dns`, `tcp`, `smb`
- `--domain` — DNS domain (only for dns transport)
- `--dns-server` — DNS server addr:port (only for dns transport)
- `--smb-pipe` — named pipe path (only for smb transport)
- `--proxy` — HTTP proxy URL for http transport (e.g., `http://proxy:8080`); tunnels both HTTPS POST and WSS via CONNECT

## Issuing Commands to Agents

### List Agents
```bash
curl -sk http://127.0.0.1:8080/api/agents \
  -H "Authorization: Bearer $TOKEN"
```

### Send Shell Command
```bash
curl -sk -X POST http://127.0.0.1:8080/api/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
  "type": "cmd",
  "agent_id": "<AGENT_UUID>",
  "payload": "shell whoami"
}'
```

### Get Job Results
```bash
curl -sk http://127.0.0.1:8080/api/jobs/<AGENT_UUID> \
  -H "Authorization: Bearer $TOKEN"
```

## Quick Test Sequence
```bash
# 1. Build & start server
go build -o fox3_server.exe . && ./fox3_server.exe > server.log 2>&1 &
sleep 3

# 2. Get token
TOKEN=$(curl -sk -X POST http://127.0.0.1:8080/api/login -H 'Content-Type: application/json' -d '{"password":"fox3"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# 3. Create + start HTTPS listener (save ID from response)
# 4. Create + start WSS listener (shares same port)
# 5. Start agent with --transport http
# 6. List agents → get agent UUID
# 7. Send command → check results
```
