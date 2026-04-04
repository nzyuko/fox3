# fox3

Post-exploitation C2 teamserver (Go) with React frontend.

## What it does

The command and control server that fox3_agent connects to:

- **REST API + WebSocket** — real-time agent management on `0.0.0.0:8080`
- **gRPC service** — CLI client connectivity on `127.0.0.1:50051`
- **HTTPS listeners** — HTTP/1.1, HTTP/2, H2C, HTTP/3 (QUIC) agent checkin
- **DNS/DoH/WSS/TCP listeners** — additional transport protocols
- **JWE/JWT authentication** — encrypted agent-server communication
- **SQLite database** — agent state, job tracking, audit log
- **React frontend** — agent dashboard, terminal, file browser, listener management
- **Transform pipeline** — pluggable encoding/encryption (JWE, AES, RC4, XOR, base64, hex, JSON, gob)
- **OPAQUE authentication** — optional strong agent authentication

## Build and run

```bash
# Build
go build -o fox3_server.exe .

# Run with defaults (password=fox3, REST=0.0.0.0:8080, gRPC=127.0.0.1:50051)
./fox3_server.exe

# Production
./fox3_server.exe --password <strong-password> --rest 0.0.0.0:8443 --addr 0.0.0.0:50051

# With TLS
./fox3_server.exe --password <pw> --tlsCert cert.pem --tlsKey key.pem
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--password` | `fox3` | REST API + gRPC auth password |
| `--rest` | `0.0.0.0:8080` | REST API listen address |
| `--addr` | `127.0.0.1:50051` | gRPC listen address |
| `--tlsCert` | | TLS certificate file |
| `--tlsKey` | | TLS private key file |
| `--tlsCA` | | Client CA for mutual TLS |
| `--secure` | false | Require client TLS cert |
| `--debug` | false | Debug logging |
| `--trace` | false | Trace logging |

## Creating a listener

After starting the server, open `http://localhost:8080` in a browser. Log in with the password, then create a listener via the UI or WebSocket API:

```json
{
  "action": "listener.create",
  "payload": {
    "Name": "https-443",
    "Protocol": "https",
    "Interface": "0.0.0.0",
    "Port": "443",
    "PSK": "fox3",
    "Transforms": "jwe,json"
  }
}
```

## Agent communication flow

```
fox3_agent                         fox3 server
   │                                    │
   ├─ POST /  ─────────────────────────►│  (JWE-encrypted body)
   │  Auth: Bearer <JWT>                │
   │                                    ├─ Validate JWT (PSK or session key)
   │                                    ├─ Decrypt JWE payload
   │                                    ├─ Process checkin / job results
   │                                    ├─ Queue pending jobs
   │◄──────────────────────────────────-┤  (JWE-encrypted response)
   │                                    │
   └─ Sleep(jitter) ─── loop ──────────►│
```

## Related repos

- **[fox3_agent](https://github.com/nzyuko/fox3_agent)** — PIC C2 beacon that connects to this server
- **[fox3_core](https://github.com/nzyuko/fox3_core)** — indirect syscall engine used by the agent
- **[fox3_injector](https://github.com/nzyuko/fox3_injector)** — JAR-based injector that delivers the agent

## Structure

```
fox3 (this repo)
├── main.go                    Entry point, flag parsing, server startup
├── go.mod                     Module: github.com/nzyuko/fox3/v2
├── pkg/
│   ├── fox3-message/          Vendored message types (Base, AgentInfo, Job, etc.)
│   ├── authenticators/        OPAQUE + none authentication
│   ├── listeners/             HTTP, DNS, DoH, WSS, TCP, UDP, SMB listener factories
│   ├── servers/               Protocol server implementations
│   ├── services/
│   │   ├── rest/              REST API server, WebSocket hub, auth handlers
│   │   ├── rpc/               gRPC service implementation
│   │   ├── agent/             Agent lifecycle management
│   │   ├── job/               Job queue and dispatch
│   │   ├── listeners/         Listener service layer
│   │   └── message/           Inter-service messaging
│   ├── transformer/           Encoding/encryption pipeline (AES, JWE, RC4, XOR, base64, etc.)
│   ├── rpc/                   Protobuf definitions + generated code
│   ├── client/                CLI client types
│   ├── db/                    SQLite database, models, migrations
│   └── logging/               Structured logging
├── frontend/
│   ├── src/                   React 19 + TypeScript + Material UI
│   └── dist/                  Pre-built static assets (served by REST API)
└── simple_agent/              Go reference agent (for testing, not deployed)
```

## How the repos connect

```
                    ┌──────────────────┐
                    │   fox3 (server)  │
                    │   Go + React     │
                    │   Port 443/8080  │
                    └────────▲─────────┘
                             │ HTTPS / DoH / DNS
                             │
                    ┌────────┴─────────┐
                    │  fox3_agent      │
                    │  Rust, no_std    │
                    │  PIC shellcode   │
                    └────────▲─────────┘
                             │ Cargo git dep
                             │
                    ┌────────┴─────────┐
                    │  fox3_core       │
                    │  Syscall engine  │
                    │  Macros + PEB    │
                    └──────────────────┘

      ┌──────────────────┐
      │  fox3_injector   │     Delivers fox3_agent into
      │  JAR + APC       │ ──► target process via module
      │  Module stomp    │     stomping + APC injection
      └──────────────────┘
           (self-contained, no fox3_core dependency)
```
