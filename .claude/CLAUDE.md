# Claude Working Guide — fox3 (server)

## What this repo is

The C2 teamserver. A Go application serving a React frontend, HTTPS listener for agent checkins, WebSocket API for operators, and SQLite database for state. Forked from Merlin v2, fully renamed to fox3/nzyuko. gRPC has been removed — the WebSocket API is the only operator interface.

## Critical rules

1. **Zero merlin references.** The rename is complete. Any "merlin"/"Merlin"/"Ne0nd0g" in .go files is a bug. The protobuf generated code was manually sed-renamed (not protoc-regenerated).

2. **Wire protocol must match the agent.** Types in `pkg/fox3-message/` (Base, AgentInfo, Job, SysInfo, etc.) are JSON-serialized and JWE-encrypted. Changing field names/types here without updating `protocol.rs` in fox3_agent breaks communication.

3. **fox3-message is vendored.** Originally an external module (`github.com/Ne0nd0g/merlin-message`). Now internal at `pkg/fox3-message/`. Its own `go.mod` was removed. All imports: `github.com/nzyuko/fox3/v2/pkg/fox3-message`.

4. **Frontend is pre-built.** `frontend/dist/` has compiled React assets. REST server serves them. Rebuild after src changes: `cd frontend && npm install && npm run build`

## Deep architecture

### Request flow (agent checkin — the critical path)

```
                        Agent HTTP POST /
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ pkg/servers/http/handler.go : agentHandler()                     │
│                                                                  │
│  1. Check method == POST (reject GET/HEAD/OPTIONS with 404)      │
│  2. Check User-Agent for fingerprinting (PRISM detection)        │
│  3. Read request body (JWE-encrypted ciphertext)                 │
│  4. Extract Authorization header                                 │
│                                                                  │
│  5. Validate JWT:                                                │
│     a. Try server's HTTP interface JWT key (authenticated agent) │
│     b. If fail → try listener's PSK (new/re-authing agent)      │
│     c. If both fail → 401 (agent must regenerate JWT)            │
│                                                                  │
│  6. Identify agent from JWT claims (sub = agent UUID)            │
│  7. Pass body to listener.Deconstruct():                         │
│     └─ Transform pipeline in REVERSE order:                      │
│        "jwe,json" → JSON decode → JWE decrypt                   │
│     └─ Returns messages.Base struct                              │
│                                                                  │
│  8. Route by Base.Type:                                          │
│     ├─ CHECKIN (1): register/update agent, build AgentInfo       │
│     ├─ JOBS (3): process job results, queue new jobs             │
│     └─ Other: log warning                                        │
│                                                                  │
│  9. Build response Base (queued jobs or IDLE)                    │
│ 10. listener.Construct():                                        │
│     └─ Transform pipeline in FORWARD order:                      │
│        "jwe,json" → JWE encrypt → JSON encode                   │
│ 11. Return HTTP 200 with encrypted response body                 │
│ 12. Issue session JWT token (in response Base.Token)             │
└──────────────────────────────────────────────────────────────────┘
```

### Transform pipeline (pkg/transformer/)

The pipeline is a slice of `Transformer` interfaces, each with `Construct()` (encode/encrypt) and `Deconstruct()` (decode/decrypt).

**Outbound (server → agent):** Apply transformers in reverse order (last transformer runs first):
```
messages.Base → Transformer[N-1].Construct() → ... → Transformer[0].Construct() → raw bytes
```

**Inbound (agent → server):** Apply transformers in forward order:
```
raw bytes → Transformer[0].Deconstruct() → ... → Transformer[N-1].Deconstruct() → messages.Base
```

**Default pipeline:** `"jwe,json"` = `[JWE, JSON]`
- Outbound: JSON.Construct(Base) → JWE.Construct(json_bytes) → encrypted bytes
- Inbound: JWE.Deconstruct(bytes) → JSON.Deconstruct(plaintext) → Base

**Available transformers:**

| Name | Package | What it does |
|---|---|---|
| `jwe` | `encrypters/jwe` | JWE compact serialization (AES-256-GCM) |
| `aes` | `encrypters/aes` | Raw AES-256-GCM |
| `rc4` | `encrypters/rc4` | RC4 stream cipher |
| `xor` | `encrypters/xor` | XOR with key |
| `json` | `encoders/json` | JSON marshal/unmarshal |
| `base64-byte` | `encoders/base64` | Base64 encode (returns bytes) |
| `base64-string` | `encoders/base64` | Base64 encode (returns string) |
| `hex-byte` | `encoders/hex` | Hex encode (returns bytes) |
| `hex-string` | `encoders/hex` | Hex encode (returns string) |
| `gob-base` | `encoders/gob` | Go gob encoding (Base type) |
| `gob-string` | `encoders/gob` | Go gob encoding (string type) |

`transformer.BuildPipeline("jwe,json")` parses a comma-separated string and returns `[]Transformer`. Used by all non-HTTP listeners (DNS, DoH, WSS, etc.). The HTTP listener manually builds its pipeline in `NewHTTPListener()` with the same switch/case logic.

### Listener architecture

Listeners are **in-memory only** (not persisted to DB). Created/destroyed via WebSocket API.

```
┌─────────────────┐     implements     ┌───────────────────┐
│ listeners.       │ ◄──────────────── │ pkg/listeners/     │
│ Listener         │    interface       │ http/http.go       │
│ (interface)      │                    │ dns/dns.go         │
│                  │                    │ doh/doh.go         │
│ - Construct()    │                    │ wss/wss.go         │
│ - Deconstruct()  │                    │ tcp/              │
│ - Authenticator()│                    │ smb/              │
│ - Transformers() │                    └───────────────────┘
└─────────────────┘
         │ has-a
         ▼
┌─────────────────┐     implements     ┌───────────────────┐
│ servers.         │ ◄──────────────── │ pkg/servers/       │
│ ServerInterface  │    interface       │ http/http.go       │
│                  │                    │ dns/dns.go         │
│ - Listen()       │                    │ doh/doh.go         │
│ - Start()        │                    │ tcp/tcp.go         │
│ - Stop()         │                    └───────────────────┘
│ - Protocol()     │
└─────────────────┘
```

**Listener creation flow:**
1. WebSocket action `listener.create` with options map
2. `listeners.NewListener()` determines protocol type
3. Creates appropriate Server implementation (HTTP/DNS/etc.)
4. Creates appropriate Listener wrapping the Server
5. Listener registers its `agentHandler` on the Server's URL routes
6. `listener.start` → Server.Start() → begins accepting connections

### WebSocket API (pkg/services/rest/ws.go)

All operator interaction flows through a single WebSocket at `/api/ws`.

**Connection flow:**
1. Client connects to `/api/ws`
2. Sends `{"action":"login","payload":{"password":"..."}}`
3. Server validates, returns JWT
4. All subsequent messages include JWT in header

**Action routing in `handleAction()`:**

| Category | Actions |
|---|---|
| **Auth** | `login` |
| **Agents** | `agents.list`, `agents.get`, `agent.delete`, `agent.note`, `agent.cmd` |
| **Listeners** | `listener.create`, `listener.start`, `listener.stop`, `listener.delete`, `listeners.list`, `listeners.options` |
| **Jobs** | `jobs.list`, `job.get`, `job.clear` |

Each action handler: parse payload → call service layer → return response via WebSocket.

### Database (pkg/db/)

SQLite via GORM. Auto-created at `data/fox3.db`.

```
┌─────────────┐     ┌─────────────┐
│   agents     │     │    jobs      │
├─────────────┤     ├─────────────┤
│ id (UUID)    │     │ id (UUID)    │
│ alive        │     │ agent_id     │
│ platform     │     │ type         │
│ architecture │     │ payload (JSON)│
│ username     │     │ status       │
│ hostname     │     │ created_at   │
│ pid          │     │ completed_at │
│ checkin      │     └─────────────┘
│ initial      │
│ version      │
│ build        │
│ proto        │
│ note         │
└─────────────┘
```

`db.InitDB()` + `db.AutoMigrate()` called in `main.go` at startup.

### Frontend (frontend/)

React 19 + TypeScript + Material UI + Tailwind. Vite build.

```
frontend/
├── src/
│   ├── api.ts          Base API URL: http://127.0.0.1:8080/api (or VITE_API_URL)
│   ├── App.tsx         Router: /, /agents, /agents/:id, /listeners
│   ├── components/     Agent cards, terminal, file browser, listener forms
│   └── hooks/          WebSocket hook, auth context
├── dist/               Pre-built (served by REST API)
├── package.json        React 19, MUI, xterm.js, Axios, Vite
└── vite.config.ts
```

The REST server in `server.go` serves `frontend/dist/` as static files at `/`. API routes are under `/api/`.

### Server type constants

**Server protocols** (`pkg/servers/servers.go`):
```
HTTP=1, HTTPS=2, H2C=3, HTTP2=4, HTTP3=5, TCP=6, DNS=7, DOH=8
```

**Listener types** (`pkg/listeners/listeners.go`):
```
UNKNOWN=0, HTTP=1, TCP=2, UDP=3, SMB=4, DNS=5, DOH=6, DOHDNS=7, WSS=8
```

### OPAQUE authentication (optional)

`pkg/authenticators/opaque/` implements the OPAQUE password-authenticated key exchange. When a listener uses `Authenticator: "opaque"`, agents must complete the OPAQUE registration/auth handshake before jobs are accepted. Default is `Authenticator: "none"` (PSK only).

## Build

```bash
go build -o fox3_server.exe .    # Build
go build ./...                   # Check all packages
go vet ./...                     # Lint
./fox3_server.exe --password pw  # Run
```

## Common operations

### Adding a WebSocket action
1. Handler in `pkg/services/rest/ws.go`
2. Case in `handleAction()` switch

### Adding a listener type
1. Constants in `listeners.go` + `servers.go`
2. Implement `listeners.Listener` interface in `pkg/listeners/<type>/`
3. Implement `servers.ServerInterface` in `pkg/servers/<type>/`
4. Wire into `NewListener()` in `pkg/services/listeners/`

### Modifying agent messages
1. Update `pkg/fox3-message/` types
2. **Also update** `protocol.rs` in fox3_agent — must match exactly

## What NOT to do

- Don't reintroduce "merlin"/"Merlin"/"Ne0nd0g"
- Don't re-add gRPC — the WebSocket API is the only operator interface
- Don't remove `pkg/fox3-message/` — it's vendored, not external
- Don't change message types without updating the Rust agent
- Don't commit `fox3_server.exe`, `data/` directory, or `node_modules/`
- Don't edit `frontend/dist/` directly — rebuild from `frontend/src/`

## Known issues (non-blocking, from original Merlin)

- `go vet`: non-constant format strings in opaque/memory packages — cosmetic
- `go vet`: sync.Map copy in DNS/DoH server packages — need pointer refactor once those listeners are wired
- `missile/` is a Rust reference agent for testing, not production
