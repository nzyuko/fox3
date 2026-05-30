# Fox3 Agent — Architecture Reference

## Overview

The Fox3 agent is a Rust-based implant designed for post-exploitation operations. It communicates with a Go-based C2 server using JWE-encrypted messages over multiple transport protocols. The agent is built around several architecturally unique subsystems that distinguish it from conventional implants.

---

## Core Design Principles

1. **Transport-agnostic protocol** — The same JWE-encrypted message body and JWT authorization header work across all transports (HTTPS, WSS, DNS, DoH, SMB, TCP). The protocol layer never knows which transport carries it.

2. **Zero-dependency crypto** — All cryptographic operations (JWE, JWT, AES-GCM, PBKDF2, HMAC-SHA256) use pure-Rust RustCrypto crates. No OpenSSL, no system crypto providers, no DLL dependencies.

3. **Single-binary, cross-platform** — Compiles to a standalone binary on Windows and Linux with `cfg`-gated platform-specific features. No runtime dependencies, no installers.

---

## Sleep Encryption — Ekko Page-Skip Architecture

### The Problem

Memory scanners detect sleeping implants by scanning the process's PE image for known code patterns, strings, and signatures. A conventional implant's entire `.text`, `.rdata`, and `.data` sections are readable in memory 24/7.

### The Solution: Ekko-Style Page-Skip

The agent XOR-encrypts its own PE image during every sleep cycle. Only decrypted bytes exist while the agent is actively executing code.

```
┌─────────────────────────────────────────────────────┐
│ PE Image in Memory                                   │
│                                                       │
│  ┌──────────┐ ┌──────────────────────────────────┐  │
│  │ Headers  │ │ .text (executable code)            │  │
│  │ (cold)   │ │                                    │  │
│  └──────────┘ │  ┌────────────┐                   │  │
│               │  │ ekko_core  │ ← SKIPPED (4KB)   │  │
│               │  │ page       │   never encrypted  │  │
│               │  └────────────┘                   │  │
│               │                                    │  │
│               └──────────────────────────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ .rdata   │ │ .data    │ │ .reloc   │           │
│  │          │ │          │ │ (cold)   │           │
│  └──────────┘ └──────────┘ └──────────┘           │
└─────────────────────────────────────────────────────┘
```

**Key insight**: The `ekko_core()` function is marked `#[inline(never)]` so the compiler places it at a deterministic address. At initialization, the agent identifies its containing 4KB page and excludes it from encryption. This single page contains the encrypt → wait → decrypt loop.

### The Bootstrap Problem

When the PE image is encrypted, the Import Address Table (IAT) is also encrypted — the agent cannot call any Win32 function through normal imports. Solution:

1. At init, resolve `VirtualProtect` and `WaitForMultipleObjectsEx` via `GetProcAddress`
2. Store these function pointers in an `EkkoParams` struct on the **stack** (outside the PE image)
3. `ekko_core` calls these functions through the stack-based pointers
4. The XOR loop is `#[inline(always)]` within `ekko_core` — pure pointer arithmetic, zero function calls

```
Stack (survives encryption):
  ┌─────────────────────────────┐
  │ EkkoParams                   │
  │   fn_virtual_protect: 0x...  │  ← pre-resolved, works while IAT is encrypted
  │   fn_wait_multiple:   0x...  │
  │   key: [16 bytes]            │  ← random per sleep cycle
  │   regions: [base, size, ...]│  ← which pages to encrypt
  │   handles: [wake, wss, ...]  │  ← events to wait on
  └─────────────────────────────┘
```

### Sleep Flow

```
obfuscated_sleep() / sleep_or_listen()
  │
  ├─ Generate 16-byte random XOR key
  ├─ Get WSS socket handle (if connected)
  ├─ WSAEventSelect(socket, ws_event, FD_READ|FD_CLOSE)
  ├─ Build EkkoParams on stack
  │
  ├─ ekko_core():
  │   ├─ VirtualProtect all regions → RW (via fn pointer)
  │   ├─ XOR encrypt all regions (u64-wide, ~1ms for 6MB)
  │   ├─ WaitForMultipleObjectsEx([wake, wss], timeout)
  │   ├─ XOR decrypt all regions (same key)
  │   └─ VirtualProtect restore original protections
  │
  ├─ WSAEventSelect(socket, ws_event, 0)  // deregister
  ├─ ioctlsocket(FIONBIO, 0)              // restore blocking
  └─ If WSS data arrived: try_recv → decrypt → handle
```

### WSS Push During Encrypted Sleep

**The architectural challenge**: How can the agent receive server-pushed data while its memory is encrypted?

**Solution**: `WSAEventSelect` is a kernel-level mechanism. When data arrives on the WSS socket, the kernel networking stack signals the event object directly — **zero user-mode code executes**. The event is included in `WaitForMultipleObjectsEx`, so the agent wakes instantly, decrypts, and processes the pushed data.

This means:
- Memory CAN be encrypted while waiting for WSS push
- Agent wakes with the same latency as an unencrypted push listener
- After wakeup: `ioctlsocket(FIONBIO, 0)` restores blocking mode for tungstenite

---

## Three-Mode Sleep Architecture

The agent dynamically switches between three sleep modes based on operational state:

| Mode | Condition | Sleep | Encryption |
|------|-----------|-------|-----------|
| **Full Ekko** | Idle (no interactive ops) | Jittered sleep (e.g., 5s ±30%) | Entire PE image XOR-encrypted |
| **Interactive** | SOCKS / portfwd / transfer / terminal active | Zero sleep (tight loop) | Cold PE sections encrypted (headers, .reloc, .rsrc, .pdata) |
| **Fallback** | Non-Windows platform | Condvar wait with jitter | None (future work) |

### Interactive Mode

When streaming operations begin, the agent enters interactive mode:

```
[agent] interactive mode started (SOCKS/portfwd/transfer/terminal active)
  │
  │  Cold sections encrypted (PE headers, .reloc, .rsrc, .pdata)
  │  Zero sleep — network I/O provides natural pacing
  │  Agent continuously polls: drain → POST → handle response → repeat
  │
[agent] interactive mode ended — resuming encrypted sleep
```

**What triggers interactive mode**:
- SOCKS connections (any active tunnel)
- Port forwarding sessions
- File transfer chunks in progress
- Interactive terminal sessions

**What does NOT trigger interactive mode**:
- One-off commands (`whoami`, `dir`, `ps`)
- Control commands (`sleep`, `kill`, `agentInfo`)
- Shellcode execution
- Module commands

This distinction is critical: normal commands complete inline within a single checkin cycle and the agent returns to encrypted sleep. Interactive operations are streaming/bidirectional and need continuous processing.

### Cold Section Encryption

During interactive mode, unused PE sections stay encrypted:

- **PE headers** — DOS header, PE signature, COFF header, section table. Only needed by the loader at process start.
- **.reloc** — Relocation table. Already applied by the loader.
- **.rsrc** — Resources. Not accessed at runtime.
- **.pdata** — Exception handler tables. Registered with the OS at load time.

These are classified at initialization by parsing the PE section table. A persistent XOR key encrypts/decrypts them idempotently on mode transitions.

---

## Hybrid Transport Architecture

### HTTP → WSS Auto-Upgrade

The default transport starts as HTTPS POST and automatically upgrades to WebSocket (WSS):

```
Agent startup
  │
  ├─ First checkin: HTTPS POST to /
  ├─ Server registers agent, returns session JWT
  ├─ Agent attempts WSS upgrade: GET / → 101 Switching Protocols
  │    ├─ Success: switch to persistent WSS connection
  │    │   ├─ Outbound: send via ws.write_message()
  │    │   ├─ Inbound: push via ws.read_message()
  │    │   └─ Heartbeat: Ping/Pong every 15s
  │    └─ Failure: continue with HTTPS POST polling
  └─ Transparent fallback — protocol layer unchanged
```

### DNS/DoH Hybrid

The DNS transport tries DoH (DNS-over-HTTPS) first, falling back to raw DNS TXT queries:

```
send(payload)
  │
  ├─ DoH available?
  │   ├─ Yes: HTTPS POST to /dns-query with application/dns-message
  │   │        Response: standard DNS wire format
  │   └─ No:  Raw DNS TXT queries over TCP
  │            Payload split across multiple queries:
  │            m0003.chunk1.agent-id.domain  (chunk 1 of 3)
  │            m0103.chunk2.agent-id.domain  (chunk 2 of 3)
  │            m0203.chunk3.agent-id.domain  (chunk 3 of 3)
  │            Server reassembles and responds
  └─ Automatic failover: doh_failed flag persists across calls
```

### Transport Abstraction

```rust
pub trait Transporter: Send {
    fn send(&self, auth: &str, body: Vec<u8>) -> Result<Vec<u8>>;
    fn try_recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>>;
    fn supports_push(&self) -> bool;
    fn raw_wss_socket(&self) -> Option<u64>;
}
```

Every transport implements this trait. The agent's protocol layer calls `transport.post()` and `transport.try_recv()` without knowing the underlying mechanism.

---

## Async Tunnel Architecture

### The Problem

SOCKS5 proxying and port forwarding require bidirectional data flow that is independent of the beacon sleep interval. A 30-second sleep would make interactive SSH or web browsing unusable.

### The Solution: Background TCP Reader Threads

```
Main Thread                          Background Threads
    │                                 (one per SOCKS conn)
    │                                      │
    │  ┌─────────────┐                    │
    │  │ Ekko sleep  │ ◄── wake signal ──│
    │  └──────┬──────┘                    │
    │         │                           │  ┌───────────┐
    │         ▼                           │  │ TCP read  │
    │  drain_outbound()                   │  │ 32KB buf  │
    │         │                           │  └─────┬─────┘
    │         ▼                           │        │
    │  POST to server ◄──────────────────│── push to
    │         │           (shared queue)   │   outbound
    │         ▼                           │
    │  handle response                    │
    │  (new SOCKS data                    │
    │   → write to TCP)                   │
    │         │                           │
    │         └─── loop ──────────────────┘
```

Each established SOCKS connection spawns a dedicated reader thread that:
1. Reads from the real TCP target (32KB buffer)
2. Pushes data to a shared `Arc<Mutex<Vec<SocksOut>>>` queue
3. Calls `WakeSignal::notify()` to interrupt the main thread's sleep

The main thread drains this queue on every iteration and includes the data in its next checkin.

### WakeSignal — Cross-Platform Event Primitive

On Windows, `WakeSignal` wraps a kernel Event handle (`CreateEventW`, auto-reset):
- `wait(timeout)` → `WaitForSingleObjectEx(event, ms, TRUE)` (alertable)
- `notify()` → `SetEvent(event)` (auto-resets after wake)
- `handle()` → raw HANDLE exposed for Ekko's `WaitForMultipleObjectsEx`

On non-Windows, it wraps `Condvar` with the same interface.

The same handle serves double duty: background threads call `notify()` to wake the main loop, and Ekko uses it as one of the wait handles during encrypted sleep.

### Terminal Session Tracking

Interactive terminal sessions run asynchronously in background threads. An `Arc<AtomicU32>` counter tracks active sessions:

```rust
// Terminal relay thread starts
active_terminals.fetch_add(1, Ordering::Relaxed);
let _guard = TerminalGuard(active_terminals.clone());

// ... relay PTY ↔ WebSocket ...

// Thread exits → TerminalGuard::drop() → fetch_sub(1)
```

The main loop includes this counter in its interactive mode check:
```rust
let has_interactive = socks.has_active()
    || !pending_results.is_empty()
    || active_terminals.load(Ordering::Relaxed) > 0;
```

---

## Pure-Rust JWE/JWT Crypto Stack

### Why Not a JOSE Library?

Standard JOSE libraries pull in OpenSSL or system crypto. The agent uses a hand-rolled JWE/JWT implementation built entirely on RustCrypto crates:

| Operation | Crate | Algorithm |
|-----------|-------|-----------|
| Message encryption | `aes-gcm` | AES-256-GCM |
| Key wrapping | `aes-kw` | A256KW (RFC 3394) |
| Key derivation | `pbkdf2` | PBKDF2-HMAC-SHA512 |
| JWT signing | `hmac` + `sha2` | HMAC-SHA256 |
| PSK hashing | `sha2` | SHA-256 |
| Base64url encoding | `base64` | URL-safe no-pad |

### Wire Format

**Message body** (JWE compact serialization):
```
alg: PBES2-HS512+A256KW
enc: A256GCM
password: sha256(PSK) bytes
p2c: 3000 iterations
```

**Authorization header** (nested JWT-in-JWE):
```
Outer: JWE(dir + A256GCM, key=sha256(PSK))
Inner: JWS(HS256, key=sha256(PSK))
Claims: sub=agentID, nbf, iat, exp
Format: Bearer <compact-jwe>
```

---

## COFF/BOF Loader

The agent includes a full AMD64 COFF (Common Object File Format) loader for executing Beacon Object Files:

1. **Section allocation** — Each COFF section gets its own `VirtualAlloc` RWX allocation
2. **Relocations** — Supports `IMAGE_REL_AMD64_ADDR64` and `IMAGE_REL_AMD64_REL32` with addend
3. **Symbol resolution** — External symbols follow `DLLNAME$FunctionName` convention, resolved via `LoadLibraryA` + `GetProcAddress`
4. **Beacon API** — Stubs for `BeaconOutput`, `BeaconPrintf`, `BeaconIsAdmin`, `BeaconDataParse/Int/Short/Length/Extract`
5. **Output collection** — Thread-local `BOF_OUTPUT: RefCell<Vec<u8>>` captures Beacon output; returned as String after `go()` returns

---

## File Layout

```
simple_agent/
├── Cargo.toml              # Dependencies (pure-Rust only)
├── ARCHITECTURE.md         # This document
└── src/
    ├── main.rs             # CLI entry point (clap)
    ├── agent.rs            # Main beacon loop, sleep modes, job dispatch
    ├── ekko.rs             # Ekko sleep encryption + cold sections
    ├── socks.rs            # WakeSignal + SOCKS5 state machine
    ├── terminal.rs         # PTY backend detection + session lifecycle
    ├── transport.rs        # Transporter trait + unified Transport handle
    ├── transport_wss.rs    # WebSocket terminal relay
    ├── pipeline.rs         # JWE/JWT encrypt/decrypt/sign/verify
    ├── protocol.rs         # Wire format structs (Base, Job, Command, etc.)
    ├── shellcode.rs        # Shellcode injection + COFF/BOF loader + rDLL
    ├── bof.rs              # BOF argument packing helpers
    ├── rdll.rs             # Reflective DLL loader
    └── transport/
        ├── http.rs         # HTTPS + WSS hybrid transport
        ├── dns.rs          # DoH + raw DNS hybrid transport
        ├── smb.rs          # SMB named pipe transport (Windows)
        └── tcp.rs          # Raw TCP transport
```

---

## Build

```bash
# Release build (optimized for size, stripped)
cargo build --release

# Binary at target/release/simple_agent.exe
# Profile: opt-level = "z", strip = true
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | `https://127.0.0.1:443/` | C2 server URL |
| `--transport` | `http` | Protocol: `http`, `dns`, `smb`, `tcp` |
| `--psk` | `fox3` | Pre-shared key (must match listener) |
| `--sleep` | `5` | Beacon interval in seconds |
| `--jitter` | `0` | Jitter percentage (0–50) |
| `--tunnel-poll` | `50` | Legacy tunnel poll interval (ms) |
| `--proxy` | | HTTP CONNECT proxy URL |
| `--smb-pipe` | | Named pipe path (SMB transport) |
| `--domain` | `fox3.local` | DNS domain (DNS transport) |
| `--dns-server` | `127.0.0.1:5353` | Raw DNS server (DNS transport) |
