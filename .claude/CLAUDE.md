# Claude Working Guide — fox3 (server)

## What this repo is

The C2 teamserver. A Go application that:
- Listens for agent checkins via HTTPS (and optionally DNS/DoH/WSS/TCP)
- Serves a React frontend for operator interaction
- Provides a gRPC API for CLI clients
- Manages agent state, job queuing, and listener lifecycle

Forked from Merlin v2, fully renamed to fox3/nzyuko. All Go imports use `github.com/nzyuko/fox3/v2`.

## Critical rules

1. **Zero merlin references.** The rename is complete. If you find "merlin" or "Merlin" or "Ne0nd0g" anywhere in .go files, it's a bug — fix it. The protobuf generated code (`pkg/rpc/rpc_grpc.pb.go`) was manually renamed (no protoc regeneration).

2. **Wire protocol must match the agent.** The agent sends JWE-encrypted JSON that deserializes into types from `pkg/fox3-message/`. If you change message types here, you break the agent. The agent repo's `protocol.rs` must stay in sync.

3. **fox3-message is vendored.** The `pkg/fox3-message/` package was originally an external Go module (`github.com/Ne0nd0g/merlin-message`). It's now vendored internally — its own `go.mod` was removed. All imports use `github.com/nzyuko/fox3/v2/pkg/fox3-message`.

4. **Protobuf code is manually maintained.** `pkg/rpc/rpc.proto` defines the Fox3 service, but we don't have protoc set up. `rpc.pb.go` and `rpc_grpc.pb.go` were generated from the original Merlin proto, then sed-renamed to Fox3 types. If you need to regenerate, install protoc + protoc-gen-go + protoc-gen-go-grpc and run:
   ```bash
   protoc --go_out=. --go-grpc_out=. pkg/rpc/rpc.proto
   ```

5. **Frontend is pre-built.** `frontend/dist/` contains compiled React assets. The REST server serves them as static files. If you modify frontend code in `frontend/src/`, rebuild with:
   ```bash
   cd frontend && npm install && npm run build
   ```

6. **Default password is "fox3".** main.go warns if the default is used. The password is used for REST API JWT auth and gRPC client auth.

## Architecture

### Request flow (agent checkin)

```
Agent POST /
  → HTTP server handler (pkg/servers/http/handler.go:agentHandler)
  → Validate JWT (Authorization header)
    → Try server JWT key (authenticated agents)
    → Fall back to listener PSK (new agents)
  → Decrypt JWE body using listener PSK
  → Deserialize messages.Base
  → Route by message type:
    → MSG_CHECKIN: register/update agent, return queued jobs
    → MSG_JOBS: process job results, return new jobs
    → MSG_IDLE: no-op keepalive
  → Encrypt response as JWE
  → Return HTTP 200
```

### Listener lifecycle

Listeners are in-memory only (not persisted to DB). Created via WebSocket API:

```
WebSocket /api/ws
  → ws.go:handleAction()
  → "listener.create" → listeners.NewListener()
    → Creates HTTP server (pkg/servers/http/)
    → Creates HTTP listener (pkg/listeners/http/)
    → Registers handler for agent URLs
  → "listener.start" → listener.Server.Start()
  → "listener.stop" → listener.Server.Stop()
```

### WebSocket API actions

All operator interaction goes through WebSocket at `/api/ws`:

| Action | Description |
|---|---|
| `listener.create` | Create new listener |
| `listener.start` / `stop` / `delete` | Listener lifecycle |
| `listeners.list` | List all listeners |
| `listeners.options` | Get default options for protocol |
| `agents.list` | List all agents |
| `agents.get` | Get agent details |
| `agent.delete` | Remove agent |
| `agent.note` | Add notes |
| `agent.cmd` | Send command to agent |

### Transform pipeline

Listeners use a configurable transform pipeline for message encoding:

```
Agent → [raw bytes] → Transformer 1 (e.g., JWE decrypt) → Transformer 2 (e.g., JSON decode) → messages.Base
messages.Base → Transformer 2 (JSON encode) → Transformer 1 (JWE encrypt) → [raw bytes] → Agent
```

Available transforms: `aes`, `jwe`, `rc4`, `xor`, `base64-byte`, `base64-string`, `hex-byte`, `hex-string`, `gob-base`, `gob-string`, `json`

Default for HTTPS listeners: `jwe,json`

The `transformer.BuildPipeline()` function (pkg/transformer/transformer.go) parses a comma-separated transform string into a `[]Transformer` slice.

## Build

```bash
# Build server
go build -o fox3_server.exe .

# Check all packages compile
go build ./...

# Vet
go vet ./...

# Run
./fox3_server.exe --password mypassword
```

## Common operations

### Adding a new WebSocket action
1. Add handler function in `pkg/services/rest/ws.go`
2. Add case in `handleAction()` switch
3. Follow existing pattern: parse payload, call service, return response

### Adding a new listener type
1. Define constants in `pkg/listeners/listeners.go` and `pkg/servers/servers.go`
2. Create `pkg/listeners/<type>/` package implementing `listeners.Listener` interface
3. Create `pkg/servers/<type>/` package implementing `servers.ServerInterface`
4. Wire into `pkg/services/listeners/listeners.go:NewListener()`
5. Use `transformer.BuildPipeline()` for transform support

### Modifying the agent message format
1. Update types in `pkg/fox3-message/` (Base, AgentInfo, Job, etc.)
2. **Also update** `protocol.rs` in the fox3_agent repo — they must match exactly
3. Test with an actual agent checkin, not just compilation

### Adding a new agent command
Commands are dispatched server-side in `pkg/services/job/`. The server queues a Job with a command string + args. The agent receives and dispatches locally. To add a new command:
1. No server changes needed for simple commands — just document the command string
2. For commands needing server-side processing (file transfer, SOCKS), add handling in the appropriate service

## What NOT to do

- Don't reintroduce "merlin" or "Merlin" in any Go file
- Don't modify `pkg/rpc/rpc_grpc.pb.go` without understanding it was manually renamed (not protoc-generated from current proto)
- Don't remove `pkg/fox3-message/` thinking it's an external dep — it's vendored internally
- Don't change message type field names without updating the Rust agent's `protocol.rs`
- Don't commit `fox3_server.exe` — it's in .gitignore
- Don't commit `data/` directory — contains SQLite DB at runtime
- Don't modify `frontend/dist/` directly — rebuild from `frontend/src/`
- Don't add external module dependencies without `go mod tidy`

## Known issues (non-blocking, from original Merlin)

- `go vet` reports `non-constant format string` in several packages (opaque, memory repos) — cosmetic
- `go vet` reports `sync.Map copy` issues in DNS/DoH server packages — these server types need refactoring to use pointers
- The `simple_agent/` directory contains a Go reference agent — it's for testing, not production use

## Files you'll touch most often

| File | When |
|---|---|
| `main.go` | Server startup, flag changes |
| `pkg/services/rest/server.go` | REST API routes, static file serving |
| `pkg/services/rest/ws.go` | WebSocket actions (all operator commands) |
| `pkg/servers/http/handler.go` | Agent HTTP handler (checkin processing) |
| `pkg/servers/http/http.go` | HTTPS server config, TLS, listener options |
| `pkg/listeners/http/http.go` | HTTP listener factory, transform pipeline |
| `pkg/services/agent/` | Agent state management |
| `pkg/services/job/` | Job queue and dispatch |
| `pkg/fox3-message/` | Wire protocol types (must match agent) |
| `pkg/transformer/transformer.go` | Transform pipeline builder |
| `pkg/services/listeners/listeners.go` | Listener service (create/start/stop) |
| `frontend/src/` | React frontend (needs `npm run build` after changes) |

## Database

SQLite via `pkg/db/`. Auto-migrated on startup. Tables:
- agents (state, last checkin, platform info)
- jobs (command queue, results)

Database file: `data/fox3.db` (created at runtime, gitignored)
