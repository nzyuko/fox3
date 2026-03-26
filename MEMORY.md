# Fox3 C2 Project Memory

## Environment
- Use `python` not `python3` on this Windows system (`python3` not found)

## Project
- Path: `c:\Users\null\fox3`
- Go module: `fox3`
- Language: Go (server), Rust (test agent at `simple_agent/`)
- Framework: Post-exploitation C2 (Merlin-message protocol)
- **Operations guide**: See [operations.md](operations.md) — server startup, listener creation, agent launch
- **API**: WebSocket-only (no REST endpoints except `/api/login`); all operations via WS actions

## Architecture
- Listeners: HTTP/HTTPS, WSS, DNS, DoH, DoH+DNS hybrid, SMB — each has transformer pipeline + authenticator
- Servers: HTTPS (shared with WSS), DNS, DoH, SMB
- Transformer pipeline default: `jwe,json` (changed from `jwe,gob-base` for cross-lang compat)
- Authenticators: `none` (immediate), `opaque` (PAKE, 4-step)

## Key Files
- `pkg/transformer/transformer.go` — factory `New(name)` + `BuildPipeline(transforms string)`
- `pkg/servers/http/http.go` — HTTPS server; `wssListenerID uuid.UUID` field, `RegisterWSSListener()`
- `pkg/servers/http/handler.go` — `agentHandler`, `checkJWT`, `handleWSS(conn, agentID)` with ping/push
- `pkg/servers/dns/dns.go` — DNS server; `SetListenerID(uuid.UUID)`, `effectiveListenerID()`
- `pkg/servers/doh/doh.go` — DoH server; `SetListenerID(uuid.UUID)`, `effectiveListenerID()`
- `pkg/listeners/wss/wss.go` — WSS listener; own `id uuid.UUID` distinct from HTTPS server ID
- `pkg/listeners/dohdns/dohdns.go` — DoH+DNS hybrid listener (uses `servers.ServerInterface`, NOT concrete types)
- `pkg/listeners/dohdns/memory/memory.go` — in-memory repo for dohdns listeners
- `pkg/services/listeners/listeners.go` — all listener factories + dohdns case
- `pkg/services/job/job.go` — job service with sock_start/sock_stop, portfwd_start/portfwd_stop
- `pkg/modules/socks/socks.go` — SOCKS5 proxy module; exports `IsKnown(uuid.UUID) bool`, `JobsOut`
- `pkg/modules/portfwd/portfwd.go` — local port-forward module; synthetic SOCKS5 handshake
- `pkg/push/push.go` — WSS push signal registry; `Register`, `Unregister`, `Notify`
- `pkg/core/core.go` — `RandStringBytesMaskImprSrc` uses `sync.Mutex` for thread safety

## Wire Protocol
- `messages.Base` JSON tags: `id`, `type`, `payload,omitempty`, `padding`, `token,omitempty`, `delegate,omitempty`
- `jobs.Job` NO JSON tags → PascalCase in JSON: `AgentID`, `ID`, `Token`, `Type`, `Payload`
- `opaque.Opaque` NO JSON tags → PascalCase: `Type`, `Payload`
- Job payloads (Command, Results etc.) have lowercase JSON tags

### JWE Message Body
- alg: `PBES2-HS512+A256KW`, p2c=3000, password=`sha256(PSK)` bytes
- enc: `A256GCM`

### JWT Authorization Header
- Nested: outer JWE(`dir`+`A256GCM`, key=`sha256(PSK)`) containing inner JWS(`HS256`, key=`sha256(PSK)`)
- Claims: `sub`=agentID, `nbf`, `iat`, `exp`
- Format: `Bearer <compact-jwe>`

## Guardrails
- [No external process spawning](feedback_no_external_processes.md) — agent must not auto-spawn processes; everything in-process; user-initiated launches (HVNC buttons) are acceptable
- [Autonomous testing](feedback_autonomous_testing.md) — when user says "test this", run ALL verification via CLI/API/curl autonomously; don't ask user to manually test in browser

## Important Patterns

### DoH-DNS Hybrid Import Cycle Avoidance
`pkg/listeners/dohdns` MUST NOT import `pkg/servers/dns` or `pkg/servers/doh`.
Cycle: `dohdns` → `servers/dns` → `services/message` → `dohdns/memory` → `dohdns`
Fix: `dohdns.go` uses `servers.ServerInterface` fields in `compositeServer`.
Listeners service calls `SetListenerID(hybridID)` on concrete structs BEFORE converting to interface.
Constructor: `NewDoHDNSListener(id uuid.UUID, doh servers.ServerInterface, dns servers.ServerInterface, options map[string]string)`

### WSS Push
`pkg/push` provides `Register(agentID, chan struct{})` / `Notify(agentID)`.
`handler.go` runs push goroutine: wakes on pushCh, calls `ms.Handle(agentID, nil)` to deliver pending jobs.
`job.go` calls `push.Notify(agentID)` from `buildJob()` (all job types) and from `socksJobs()`/`portfwdJobs()`.
Agent `sleep_or_listen()`: when WSS connected, blocks on `try_recv(jittered_duration)` to receive pushes.
Uses absolute deadline to prevent Ping/Pong from extending the per-read SO_RCVTIMEO indefinitely.
`supports_push()` trait method returns true only when `wss_conn.is_some()`; non-WSS transports fall back to `wake.wait()`.

### Port Forward (portfwd) vs SOCKS Routing
Both use `jobs.SOCKS` job type. `job.Handler()` checks `portfwd.IsKnown(id)` first, then `socks.In()`.
`portfwd.JobsOut` and `socks.JobsOut` are separate channels; separate goroutines relay them.

### sock_start / sock_stop / portfwd_start / portfwd_stop
Handled in `job.Add()` — they call the module's `Parse()` directly without creating an agent job.
No job round-trip to agent; server-side only resource management.

## Rust Agent (`simple_agent/`)

### Async Tunnel + Sleep Encryption Architecture
- `simple_agent/src/ekko.rs` — **Ekko sleep encryption**: XOR-encrypts PE image during sleep; page-skip approach; WSAEventSelect for WSS push wake
- `simple_agent/src/socks.rs` — `WakeSignal` (Windows: Event handle, non-Windows: Condvar), `SocksManager`, `SocksConn` state machine, background `tcp_reader` thread
- `simple_agent/src/agent.rs` — `Agent` with three-mode sleep: encrypted (Ekko), tunnel (fast poll), fallback (Condvar)
- `simple_agent/src/protocol.rs` — all payload types with CORRECT lowercase JSON tags (verified against merlin-message@v1.3.0)
- `simple_agent/src/shellcode.rs` — platform-specific injection (Linux: mmap; Windows: VirtualAlloc/CreateRemoteThread/RtlCreateUserThread/QueueUserAPC)
- CLI: `--sleep`, `--jitter` (0-50%), `--tunnel-poll` (ms, default 50)
- Detailed docs: See [sleep_encryption.md](sleep_encryption.md)

### Threading Model
- Main loop sleeps via Ekko encrypted wait (Windows) or `WakeSignal::wait(duration)` (non-Windows)
- `WakeSignal` on Windows: `CreateEventW` auto-reset; `SetEvent` for notify; raw HANDLE exposed for `WaitForMultipleObjectsEx`
- Background `tcp_reader` threads (one per SOCKS connection) push to `Arc<Mutex<Vec<SocksOut>>>`, call `wake.notify()` to interrupt sleep early
- `has_active()` → fast tunnel poll; no active tunnels → jittered encrypted sleep

### Key Borrow Checker Pattern
`make_socks_job` MUST be a **free function**, not a `&self` method.
Reason: called while `conn: &mut SocksConn` borrows `self.conns`; a `&self` method receiver would conflict (E0502).
Signature: `fn make_socks_job(conn_id: Uuid, conn: &mut SocksConn, data: &[u8]) -> Job`

### File Transfer Chunking
1MB chunks; first returned immediately; remaining queued in `pending_results` → keeps `has_active()` true.

## Completed Features
1. Transformer factory, JSON encoder, WSS ID, SOCKS5 module
2. WSS ping/pong heartbeat (15s interval, 5s pong timeout)
3. WSS push goroutine via `pkg/push` signal registry
4. `sock_start`/`sock_stop` lifecycle in job service
5. Local port forwarding: `portfwd_start`/`portfwd_stop` + state machine in `pkg/modules/portfwd`
6. DoH+DNS hybrid listener with `DOHDNS` constant in `pkg/listeners/listeners.go`
7. Import cycle resolved: `dohdns.go` uses `servers.ServerInterface`, listeners service pre-generates UUID
8. `go build ./...` passes cleanly
9. Rust agent async tunnels: SOCKS5 + file transfer run independently of beacon sleep; `cargo build` clean
10. Rust agent shellcode: Windows-only; methods: self, remote, rdll, bof (COFF loader)
11. `Shellcode.bof_args` optional field in protocol
12. TCP listener+server: `pkg/listeners/tcp/`, `pkg/servers/tcp/`; 4-byte LE framed; TCP=9 constant
13. **REMOVED**: Interactive terminal (ConPTY issues; server+agent+frontend all stripped; rethink later)
14. **REPLACED**: SSE event bus replaced by WS push events; `events.go` + all REST handlers deleted
15. **REPLACED**: REST API removed — now WS-only; `pkg/services/rest/` = auth.go, server.go, ws.go, types.go, handlers_hvnc.go
16. Frontend uses WS exclusively via `useWebSocket` hook; no REST/SSE calls
17. **REMOVED** (was: xterm.js TerminalView)
18. Frontend: Fox3 darker theme (bg #080d14, paper #0e1420, secondary #22d3ee), custom scrollbar, MuiTableCell/Drawer overrides
19. Frontend: Topology.tsx rewritten with MUI (no Tailwind), SSE-driven auto-refresh, richer node renderer
20. Frontend: DashboardLayout live stats strip (agents/listeners count via SSE)
21. `message.go:484` — unchecked `j.Payload.(jobs.Command)` hardened with comma-ok + continue
22. `job.Get()` — now marks non-SOCKS jobs as Sent in DB after retrieving; prevents re-delivery on next checkin
23. Credentials now persisted to SQLite via `pkg/credentials/db/repository.go` (CredentialModel added to db/models.go); `pkg/services/credentials/credentials.go` uses DB repo instead of memory
24. Login rate limiter: 5 failures → 15 min lockout per IP in `pkg/services/rest/auth.go`
25. Default password warning at startup in `main.go`; CORS restricted to localhost-only (`isLocalhostOrigin`)
26. Graceful shutdown: SIGINT/SIGTERM → `restServer.Shutdown(ctx)` 10 s timeout; REST uses `http.Server{}` stored in `Server.httpServer`
27. Authorization header redacted in ExtraDebug logs (`redactedHeaders()` in `handler.go`)
28. **REMOVED** (was: Terminal TTL reaper); SSE slow-consumer drop now `slog.Warn`
29. TCP: `SetReadDeadline(30s)` + `SetWriteDeadline(30s)`; `tcpMaxMsgSize = 10<<20`; `"time"` import added
30. DNS: name length guard >253, agent ID label != 32, payload size cap `dnsMaxDecodedBytes=4096`; noisy errors → Debug level
31. Stress test plan + edge cases: `docs/STRESS_TESTING.md` (20 open items, bash test scripts included)
    Top open items: SOCKS no read timeout, JobsOut unbuffered, HTTPS ReadHeaderTimeout missing, pivot beacon latency
32. **REMOVED**: Interactive terminal feature (ConPTY, terminal.rs, TerminalView, terminal service, handlers_terminal.go all deleted)
    - Agent CLI flags: `--url`, `--sleep`, `--jitter`, `--tunnel-poll`, `--psk`, `--transport`, `--smb-pipe`, `--domain`, `--dns-server`, `--proxy` (no `--auth` or `--no-tls-verify`; agent auto-accepts invalid certs)
33. Hybrid HTTPS/WSS transport: `simple_agent/src/transport/http.rs`; auto-upgrades to WSS, falls back to HTTPS POST; WSS listener MUST have `JWTKey` set
34. Hybrid DoH/DNS transport: `simple_agent/src/transport/dns.rs`; tries DoH first, falls back to raw DNS TXT queries over TCP; `doh_failed` AtomicBool flag
35. DNS multi-query chunking: JWE ciphertext (~300+ bytes) exceeds single DNS query capacity (~120 bytes, was 110); payloads split across multiple queries with `m<seq_hex2><total_hex2>` prefix label
    - Server-side: `chunkBuf sync.Map` in both `dns.go` and `doh.go`; `chunkBuffer{mu, chunks, total, created}`; reassembles when all chunks received; ACKs intermediate; TTL reaper 30s
    - Agent-side: `split_payload()` adds chunk markers when `total_chunks > 1`; `build_qname()` prepends `m0003` etc.; single-query messages omit marker for backward compat
    - DNS TCP connection reuse: `dns_tcp_conn: Mutex<Option<TcpStream>>` cached; retry on stale
    - SOCKS tests: DoH 15/15, raw DNS 15/15, HTTPS/WSS 14/15 (portfwd timing), HTTPS-only 15/15
36. WSS push optimization: agent listens for server pushes during idle sleep via `try_recv()` + absolute deadline
    - `supports_push()` on Transporter trait; only HttpTransport overrides (true when wss_conn.is_some())
    - `sleep_or_listen()` replaces `obfuscated_sleep()` for idle; non-WSS falls back to `wake.wait()`
    - `push.Notify(agentID)` added to `buildJob()` for ALL job types (cmd, shell, control, shellcode, etc.)
    - Chunk buffer TTL reaper in `dns.go` + `doh.go`: 10s ticker, 30s expiry, prevents orphaned buffer leak
    - Verified: command pushed to agent within <1s of creation; results sent back inline via WSS
37. WSS auto-start: HTTPS `NewListener()` auto-creates companion WSS listener (same PSK, Transforms, Authenticator, JWTKey, JWTLeeway)
    - `pkg/services/listeners/listeners.go` HTTPS case: auto-creates and registers WSS after HTTPS listener
    - Must include `JWTKey`+`JWTLeeway` in wssOpts — omitting causes `invalid key size for algorithm` on JWT construction
    - Explicit WSS creation endpoint still works (for debug/testing separate configs)
38. HTTP CONNECT proxy: `--proxy http://host:port` CLI flag on Rust agent
    - `simple_agent/src/transport/http.rs`: `proxy_url` field; reqwest `Proxy::all()` for HTTPS POST; manual HTTP CONNECT for WSS
    - `http_connect_proxy()`: TCP connect to proxy → `CONNECT target:port` → validate 200 → return tunneled stream for tungstenite TLS+WS
    - `simple_agent/Cargo.toml`: added `url = "2"` for proxy URL parsing
39. Ekko sleep encryption: `simple_agent/src/ekko.rs`; mandatory on Windows
    - Page-skip: `ekko_core` (`#[inline(never)]`) page excluded from XOR; all other PE image pages encrypted
    - Pre-resolved fn pointers (VirtualProtect, WaitForMultipleObjectsEx) via GetProcAddress; stored on stack → survive image encryption
    - WSS push during encrypted sleep: `WSAEventSelect(socket, event, FD_READ|FD_CLOSE)` → kernel signals event → agent wakes instantly
    - WakeSignal replaced with Windows Event handle (CreateEventW auto-reset); `handle()` method exposes raw HANDLE for Ekko
    - Transport `raw_wss_socket()` trait method extracts SOCKET from tungstenite WsStream for WSAEventSelect
    - Cold section encryption: PE headers, .reloc, .rsrc, .pdata identified at init; `encrypt_cold()`/`decrypt_cold()` (idempotent, persistent key)
    - Sleep paths: interactive (SOCKS/portfwd/transfer/terminal) = zero sleep + cold encrypted; idle = full Ekko encrypted wait; non-Windows = Condvar fallback
    - Interactive mode: `has_interactive` flag checks `socks.has_active() || pending_results || active_terminals > 0`; clear start/stop log markers
    - Normal one-off commands (whoami, dir, shell) do NOT trigger interactive mode — only streaming/bidirectional operations
    - `active_terminals: Arc<AtomicU32>` shared with terminal threads; `TerminalGuard` RAII decrements on relay exit
    - Ekko `[sleep]` debug eprintln still present in `sleep_or_listen()` (useful for debugging; remove for prod)
    - `obfuscated_sleep()` (retry loop path) and `sleep_or_listen()` (main loop path) are DIFFERENT functions; both use Ekko
40. Job result persistence: completed jobs visible via WS `jobs.list`
    - `UpdateOutput(jobID, output)` stored in DB; `GetTableActiveWithResults` returns active + last 50 completed
41. Default listener PSK is "fox3" (set via `--password` at server startup)
    - `"Orphaned Agent JWT detected"` error means agent PSK doesn't match listener PSK
    - Job types: ps/shell/run/exec/shellcode/upload/download/screenshot etc. (use WS `job.create`)

42. Tunnel flow control: HiWM/LoWM backpressure on SOCKS/portfwd connections
43. Reverse port forward (rportfwd): agent binds TCP port, relays through C2 to server forward target
    - Server: `pkg/modules/rportfwd/` — `In()` processes synthetic SOCKS5 from agent; `forwardTargets` map
    - Agent: `simple_agent/src/rportfwd.rs` — `RPortFwdManager` shares `SocksManager` outbound queue; `OnceLock<Mutex<HashMap>>` global conn registry
    - Agent acts as SOCKS5 client (sends greeting+CONNECT); server acts as SOCKS5 server
    - JOB_NATIVE commands: `rportfwd_start` (args=[port]) / `rportfwd_stop`
    - Frontend: `TunnelManager.tsx` rportfwd panel (listen port, forward host:port, start/stop)
44. Screenshot capture & gallery — WS actions: `screenshots.list`, `screenshots.image`, `screenshot.create`, `screenshot.delete`
45. Pivot/link metadata — WS actions: `pivots.list`, `pivot.create`, `pivot.delete`; Topology.tsx renders pivot edges
46. SOCKS5 UDP ASSOCIATE support
    - Server: `pkg/modules/socks/socks.go` — detects CMD=0x03, binds local UDP socket, relays datagrams through JOB_SOCKS
    - Agent: `simple_agent/src/socks.rs` — `UdpEstablished` state, `udp_reader` thread, SOCKS5 UDP datagram encapsulation
47. HVNC (Hidden Virtual Network Computing)
    - Agent: `simple_agent/src/hvnc.rs` — hidden desktop (CreateDesktopW), GDI capture (PrintWindow compositing), GDI+ JPEG encoding, input dispatch (PostMessageW + child window walk), process launch (CreateProcessW with lpDesktop)
    - Server: `pkg/modules/hvnc/hvnc.go` — session mgmt (Register/Unregister/IsKnown), frame buffer, input/control relay via JobsOut
    - Wire protocol over JOB_SOCKS: 0x00=no-change, 0x01=JPEG frame(w,h,data), 0x02=input(msg,wparam,lparam), 0x03=control(action)
    - WS actions: `hvnc.start`, `hvnc.stop`, `hvnc.input`, `hvnc.launch`, `hvnc.quality`, `hvnc.status`
    - Frontend: `HvncViewer.tsx` — canvas viewer, mouse/keyboard capture, quality slider, FPS counter, app launcher menu
    - Job routing: `hvnc.IsKnown()` checked before portfwd/rportfwd/socks in `job.Handler()`
    - Result handling: agent's `hvnc_start` result contains `conn_id=<uuid>`; server parses and calls `hvnc.Register()`

### BOF / rDLL Architecture (shellcode.rs)
- `shellcode::execute(method, data, pid, bof_args)` — public entry point
- `exec_bof(data, bof_args)`: preferred=`bof_args` non-empty (raw COFF + arg buffer); legacy=4-byte length prefix
- `bof_load_and_run(coff, bargs)`: full AMD64 COFF loader; RWX alloc per section; relocations (ADDR64, REL32+addend); extern symbol: `DLLNAME$Func` via LoadLibraryA+GetProcAddress; Beacon API stubs (BeaconOutput, BeaconPrintf, BeaconIsAdmin, BeaconDataParse/Int/Short/Length/Extract); calls `go(args_ptr, args_len)`
- `exec_rdll(data, pid)`: parses PE export table → finds `ReflectiveLoader` RVA → VirtualAlloc RWX → copy → CreateThread (pid=0) or OpenProcess+VirtualAllocEx+WriteProcessMemory+CreateRemoteThread (pid>0)
- Thread-local `BOF_OUTPUT: RefCell<Vec<u8>>` collects Beacon output; returned as String after `go()` returns
- `datap` struct `{ original, buffer, length, size }` for BeaconDataParse/Extract stubs

48. Agent Remove() full cleanup: push.Unregister, socks.CleanupAgent, rportfwd.CleanupAgent, pivotService.RemoveByAgent, screenshotService.RemoveByAgent
49. Frontend UI/UX (borrowed from Adaptix/Havoc): sleep display, agent table view (sortable), right-click context menu (kill/delete/navigate), process tree view
    - `AgentTable.tsx` — sortable columns, localStorage view toggle
    - `AgentContextMenu.tsx` — kill (exit job), delete (remove from DB), interact, browse files, processes, HVNC, set note
    - `ProcessBrowser.tsx` — tree view with `buildTree()` from ppid, expand/collapse
    - Agent `ps` command uses `wmic` for ppid data on Windows
50. **REST API removed** — all operations now WS-only
    - Deleted: handlers_agents.go, handlers_jobs.go, handlers_listeners.go, handlers_credentials.go, handlers_screenshots.go, handlers_pivots.go, handlers_topology.go, handlers_events.go, events.go
    - Kept: server.go (login + ws upgrade), auth.go, ws.go (all actions), types.go (shared types), handlers_hvnc.go
    - HTTP only serves: `POST /api/login` (JWT), `GET /api/ws` (WS upgrade)
    - Added `screenshot.create` WS action (was REST-only)
