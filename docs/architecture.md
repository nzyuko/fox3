# Architecture

## Overview

fox3 is a single Go binary that runs two concurrent services sharing in-memory state:

```
┌─────────────────────────────────────────────────────┐
│                    fox3_server                      │
│                                                     │
│  ┌──────────────────────────┐  ┌─────────────────┐  │
│  │  REST + WebSocket        │  │  SQLite DB      │  │
│  │  0.0.0.0:8080            │  │  data/fox3.db   │  │
│  └────────────┬─────────────┘  └─────────────────┘  │
│               │                                     │
│  ┌────────────▼─────────────────────────────────┐   │
│  │         in-memory service layer              │   │
│  │  AgentService  JobService  ListenerService   │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │  Listener goroutines                         │   │
│  │  HTTP/1.1   HTTP/2   HTTP/3   (more coming)  │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

State split:
- **Agents and jobs** — in-memory (fast) + persisted to SQLite (durable across restarts)
- **Listeners** — in-memory only; recreate after restart
- **Credentials, screenshots, pivots** — SQLite

All operator interaction flows through the WebSocket API (`/api/ws`). There is no CLI client or gRPC — the React frontend is the single operator interface.

---

## Agent check-in flow

The critical path from agent network packet to queued response:

```
Agent HTTP POST /
        │
        ▼
pkg/servers/http/handler.go : agentHandler()
        │
        ├─ 1. Reject non-POST (return 404)
        ├─ 2. Check User-Agent for PRISM fingerprint (log warning)
        ├─ 3. Read body (JWE ciphertext)
        ├─ 4. Extract Authorization header (JWT)
        │
        ├─ 5. Validate JWT — two keys tried in order:
        │      a. Server's HTTP interface key  →  authenticated session
        │      b. Listener PSK (SHA-256 hash)  →  new or re-authing agent
        │      c. Both fail                    →  401
        │
        ├─ 6. Identify agent: JWT sub claim = agent UUID
        │
        ├─ 7. listener.Deconstruct(body) — reverse transform pipeline:
        │      "jwe,json" → JWE.Deconstruct → JSON.Deconstruct → messages.Base
        │
        ├─ 8. Route by Base.Type:
        │      ├─ CHECKIN (1) → register/update agent, build AgentInfo response
        │      ├─ JOBS    (3) → job.Handler(jobs) → process results, queue new jobs
        │      └─ other       → log warning
        │
        ├─ 9. Build response messages.Base:
        │      ├─ pending jobs → Base{Type: JOBS, Payload: []Job{…}}
        │      └─ nothing      → Base{Type: IDLE}
        │
        ├─ 10. listener.Construct(response) — forward transform pipeline:
        │       JSON.Construct → JWE.Construct → ciphertext
        │
        └─ 11. HTTP 200, body = ciphertext
               + session JWT in response Base.Token
```

---

## Transform pipeline

Every listener has a pipeline: a slice of `Transformer` interfaces.

```go
type Transformer interface {
    Construct(data []byte) ([]byte, error)    // encode/encrypt (outbound)
    Deconstruct(data []byte) ([]byte, error)  // decode/decrypt (inbound)
}
```

**Outbound** (server → agent): transformers applied left-to-right.
**Inbound** (agent → server): transformers applied right-to-left.

Default pipeline string: `"jwe,json"` — JWE encryption wrapping JSON-encoded `messages.Base`.

- Outbound: `JSON.Construct(Base{})` → JSON bytes → `JWE.Construct(json-bytes)` → wire bytes
- Inbound: `JWE.Deconstruct(wire)` → JSON bytes → `JSON.Deconstruct(json-bytes)` → `Base{}`

`transformer.BuildPipeline(str)` parses a comma-separated string into a `[]Transformer` slice.

---

## Listener / Server relationship

```
┌─────────────────────────────────────────────┐
│ listeners.Listener (interface)              │
│  Construct()   — encode outbound            │
│  Deconstruct() — decode inbound             │
│  Authenticator()                            │
│  Transformers()                             │
│  Server() *servers.ServerInterface          │
└────────────────────┬────────────────────────┘
                     │ has-a
                     ▼
┌─────────────────────────────────────────────┐
│ servers.ServerInterface (interface)         │
│  Listen()  — bind port                      │
│  Start()   — accept loop (blocks)           │
│  Stop()    — shutdown                       │
│  Protocol() / Interface() / Port() / Addr() │
└─────────────────────────────────────────────┘
```

**Working:**
- `pkg/listeners/http` + `pkg/servers/http` — HTTP/1.1, HTTPS, H2C, HTTP/2, HTTP/3

**Coming soon** (packages compile, not yet wired into the factory):
- TCP, UDP, SMB, DNS, DoH, WSS

---

## WebSocket hub

`pkg/services/rest/ws.go` implements a hub-and-spoke model:

```
                 ┌───────────┐
    browser WS ──►           │
    browser WS ──► wsHub     │──► event bus (pkg/events)
    browser WS ──►           │
                 └─────┬─────┘
                       │
               actionHandlers map
               (dispatches to service layer)
```

The hub subscribes to `pkg/events` on startup. When an agent checks in or a job completes, the service layer publishes an event; the hub enriches it with full object data and broadcasts JSON to all connected clients.

HVNC frames are delivered as binary WebSocket messages via a dedicated `hvncFramePusher` goroutine, bypassing the JSON event bus to avoid blocking.

---

## Database schema

SQLite via GORM. Created at `data/fox3.db` relative to the working directory. WAL mode enabled.

```
agents
  id            TEXT PRIMARY KEY      (UUID string)
  alive         BOOLEAN
  authenticated BOOLEAN
  initial       DATETIME
  checkin       DATETIME
  secret        BLOB
  note          TEXT

hosts (1:1 with agents)
  agent_id      TEXT UNIQUE
  name          TEXT                  hostname
  platform      TEXT                  "windows", "linux", etc.
  architecture  TEXT                  "amd64", "arm64", etc.
  ips           TEXT

processes (1:1 with agents)
  agent_id      TEXT UNIQUE
  pid           INTEGER
  name          TEXT
  user_name     TEXT
  domain        TEXT
  integrity     INTEGER               1=Low 2=Medium 3=High 4=System

comms (1:1 with agents)
  agent_id      TEXT UNIQUE
  protocol      TEXT
  sleep         INTEGER               seconds
  jitter        INTEGER               percent
  padding       INTEGER               bytes

credentials
  id / domain / username / password / hash / source / agent_id / created

screenshots
  id / agent_id / data (BLOB) / note / created

pivots
  id / name / parent_agent_id / child_agent_id / protocol / created
```

---

## Job lifecycle

```
job.create (WS action)
        │
        ▼
job.Service.Add(agentID, jobType, args)
        │
        ▼
job.Service.buildJob()
  ├── validate agent exists
  ├── assign job ID + token
  ├── store in jobRepo (in-memory)
  └── log to agent log file

        ↕  (agent polls on sleep interval)

agentHandler receives POST with job results
        │
        ▼
job.Service.Handler([]jobs.Job)
  ├── fast path: SOCKS/rportfwd/HVNC → channel relay (no tracking)
  ├── verify agent known + job token matches
  ├── process by type:
  │     RESULT       → log stdout/stderr, store output, events.Publish
  │     AGENTINFO    → agentService.UpdateAgentInfo
  │     FILETRANSFER → write to data/agents/<id>/
  └── jobInfo.Complete() + events.Publish(EventJobComplete)
```

---

## SOCKS / rportfwd / HVNC tunnel relay

High-frequency tunnel traffic bypasses the normal job path:

```
JobsOut channel (pkg/modules/socks, rportfwd, hvnc)
        │
        ▼
job.Service.tunnelRelay()
  (4 goroutines for SOCKS, 2 each for rportfwd/HVNC)
        │
        ▼
jobRepo.AddFast(job)   — no formatting, no logging, no Info tracking
        │
        ▼
push.Notify(agentID)   — wake agent's pending response if long-polling
```

On inbound, `job.Handler()` routes SOCKS-type jobs directly to:
- `hvnc.In(job)` if conn_id is a known HVNC session
- `rportfwd.In(job)` if conn_id is a known reverse port forward
- `socks.In(job)` otherwise

---

## Authentication layers

| Layer | Mechanism | Key material |
|---|---|---|
| REST login | HMAC-SHA256 JWT, 24h TTL | `--password` flag |
| WebSocket | Same JWT (header or `?token=`) | Same |
| Agent check-in | HMAC-SHA256 JWT | Per-interface server key (session) or SHA-256(PSK) (unauthenticated) |
| Agent payload | JWE AES-256-GCM | Negotiated during check-in |
| OPAQUE (optional) | OPAQUE PAKE | Ephemeral per-agent key |

---

## Module / extension points

`pkg/modules/` — server-side helpers for agent capabilities:

| Package | Purpose |
|---|---|
| `donut` | PE → shellcode conversion |
| `hvnc` | HVNC session registry and frame channel |
| `minidump` | lsass dump orchestration |
| `rportfwd` | Reverse port forward session management |
| `sharpgen` | C# → assembly compilation |
| `shellcode` | Shellcode helpers |
| `socks` | SOCKS5 proxy session management |
| `srdi` | sRDI reflective DLL injection |
| `winapi/createprocess` | Windows CreateProcess wrapper |

---

## Key packages

| Path | Role |
|---|---|
| `main.go` | Entry point; flag parsing; starts REST server |
| `pkg/fox3.go` | Version constant (`2.1.4`) |
| `pkg/fox3-message/` | Vendored message types shared with the agent (must match `protocol.rs`) |
| `pkg/servers/http/` | HTTP/1.1/2/3 server; `agentHandler` |
| `pkg/listeners/http/` | HTTP listener; JWT validation; transform pipeline |
| `pkg/services/listeners/` | Listener factory; in-memory repository management |
| `pkg/services/rest/` | REST server; WebSocket hub; login endpoint |
| `pkg/services/job/` | Job dispatch; result handling; tunnel relay |
| `pkg/services/agent/` | Agent lifecycle; CRUD; check-in update |
| `pkg/transformer/` | Transform pipeline implementations |
| `pkg/db/` | SQLite init; GORM models; auto-migrate |
| `pkg/events/` | In-process pub/sub bus |
| `pkg/push/` | Agent push-notification (long-poll wake) |
| `pkg/authenticators/` | `none` and OPAQUE authenticator implementations |
| `pkg/client/message/` | Internal message bus (used by HTTP handler and job service) |

---

## Known issues (inherited from Merlin)

| Location | Issue | Notes |
|---|---|---|
| `pkg/servers/dns`, `pkg/servers/doh` | `return` copies `sync.Map` (vet) | Needs pointer receivers; low priority while DNS/DoH aren't wired |
| `pkg/servers/dns/memory`, `doh/memory` | Pass/assign `sync.Map` by value (vet) | Same |
| `pkg/authenticators/opaque` | Non-constant format string in `fmt.Errorf` (vet) | Cosmetic |
| `pkg/listeners/*/memory` | Non-constant format string in `fmt.Errorf` (vet) | Cosmetic |
