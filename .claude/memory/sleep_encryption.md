# Ekko Sleep Encryption — Architecture Reference

## Overview

The Rust agent uses Ekko-style sleep encryption to XOR-encrypt its PE image (.text, .rdata, .data) in memory during every sleep cycle. Only the 4KB page containing the encrypt/wait/decrypt stub remains readable. This defeats memory scanners that look for known code patterns or strings in sleeping processes.

## Key Files

| File | Role |
|------|------|
| `simple_agent/src/ekko.rs` | Sleep encryption + cold sections (Windows: full impl, non-Windows: no-op stub) |
| `simple_agent/src/socks.rs` | `WakeSignal` — Windows: Event handle, non-Windows: Condvar |
| `simple_agent/src/agent.rs` | Integration: `sleep_or_listen()`, interactive mode, `ekko`+`active_terminals` fields |
| `simple_agent/src/terminal.rs` | `TerminalGuard` RAII counter for active terminal sessions |
| `simple_agent/src/transport/http.rs` | `raw_wss_socket()` — extracts SOCKET from WsStream |
| `simple_agent/src/transport.rs` | `raw_wss_socket()` trait method + Transport pass-through |

## Page-Skip Approach

`ekko_core()` is marked `#[inline(never)]` so the compiler places it at a fixed location in .text. At init, its containing 4KB page is identified and excluded from encryption:

```
core_page = (ekko_core as usize) & !0xFFF
```

All other PE image pages are XOR-encrypted with a random 16-byte key per sleep cycle.

## Bootstrap Problem

The encrypt/wait/decrypt code must execute while the rest of .text is encrypted. Solution:
1. `ekko_core` receives ALL function pointers through `EkkoParams` on the stack
2. `VirtualProtect` and `WaitForMultipleObjectsEx` are resolved via `GetProcAddress` at init time
3. The XOR loop is `#[inline(always)]` within `ekko_core` — pure pointer arithmetic, no function calls
4. The IAT (Import Address Table) lives in the PE image and gets encrypted, but stack-based pointers survive

## Sleep Flow

```
obfuscated_sleep() / sleep_or_listen()
  │
  ├─ Ekko available (Windows)?
  │   ├─ Generate 16-byte random XOR key
  │   ├─ Get WSS socket handle (if connected): transport.raw_wss_socket()
  │   ├─ WSAEventSelect(socket, ws_event, FD_READ|FD_CLOSE)  [kernel monitors socket]
  │   ├─ Build EkkoParams on stack
  │   ├─ ekko_core():
  │   │   ├─ VirtualProtect all regions → RW (via fn pointer)
  │   │   ├─ XOR encrypt all regions
  │   │   ├─ WaitForMultipleObjectsEx([wake_event, ws_event], timeout) (via fn pointer)
  │   │   ├─ XOR decrypt all regions
  │   │   └─ VirtualProtect restore original protections (via fn pointer)
  │   ├─ WSAEventSelect(socket, ws_event, 0)  [deregister]
  │   ├─ ioctlsocket(FIONBIO, 0)  [restore blocking mode]
  │   └─ If WSS event fired: try_recv(100ms) → decrypt → handle_response
  │
  └─ No Ekko (non-Windows)?
      └─ wake.wait(duration) or try_recv(duration) [old Condvar path]
```

## WSS + Encrypted Sleep

Key insight: `WSAEventSelect` is purely kernel-side. The networking stack signals the event when data arrives on the socket — no user-mode code executes. This means:
- Memory CAN be encrypted while waiting for WSS push data
- Agent wakes instantly when server pushes data (same latency as before)
- After wakeup and decryption, tungstenite reads the buffered frame normally

After `WSAEventSelect`, the socket is in non-blocking mode. Must call `ioctlsocket(FIONBIO, 0)` to restore blocking mode for tungstenite.

## WakeSignal (Windows)

Replaced Condvar with Windows Event handle:
- `CreateEventW(NULL, FALSE/*auto-reset*/, FALSE, NULL)`
- `wait(timeout)` → `WaitForSingleObjectEx(event, ms, TRUE/*alertable*/)`
- `notify()` → `SetEvent(event)` — auto-reset means next wait blocks again
- `handle()` → returns raw `*mut c_void` HANDLE for Ekko's `WaitForMultipleObjectsEx`
- `clone_ref()` → `Arc::clone()` (same handle, refcounted)
- `Drop` → `CloseHandle(event)`

## Sleep Path Decision Table

| Condition | Method | Encrypted? |
|-----------|--------|-----------|
| Interactive (SOCKS/portfwd/transfer/terminal) | Zero sleep, tight loop | Cold sections only |
| Idle, Windows, Ekko initialized | `ekko.encrypted_wait(...)` | **Full PE image** |
| Idle, non-Windows | `wake.wait(duration)` | No |

## Interactive Mode

When streaming/bidirectional operations are active (SOCKS, portfwd, file transfer, interactive terminal), the agent enters "interactive mode":
- **Zero sleep**: no delay between iterations — network I/O (POST round-trip) provides natural pacing
- **Cold sections encrypted**: PE headers, .reloc, .rsrc, .pdata stay XOR-encrypted via `encrypt_cold()` (persistent key, idempotent)
- **Start/stop markers**: `[agent] interactive mode started` / `[agent] interactive mode ended` logged on transitions
- **Normal commands excluded**: one-off jobs (whoami, dir, shell, agentInfo) do NOT trigger interactive mode
- **Terminal tracking**: `active_terminals: Arc<AtomicU32>` shared with relay threads; `TerminalGuard` RAII decrements on exit
- **Invariant**: `decrypt_cold()` called before `encrypted_wait()` — Ekko encrypts ALL regions including cold ones

`has_interactive` check:
```
socks.has_active() || !pending_results.is_empty() || active_terminals.load() > 0
```

## Cold Section Classification

PE sections parsed at init from section table (COFF header → section headers):
- **Cold** (encrypted during interactive mode): PE headers (base to first section VA), `.reloc`, `.rsrc`, `.pdata`
- **Hot** (must stay decrypted during execution): `.text`, `.rdata`, `.data`, `.bss`

Cold regions are a subset of `regions` — same base addresses but separate `cold_regions` Vec with a persistent `cold_key`.

## PE Image Measurement

```
GetModuleHandleW(NULL) → image_base
*(u32*)(base + 0x3C) → e_lfanew (PE signature offset)
base + e_lfanew + 24 → Optional header
*(u32*)(opt_hdr + 56) → SizeOfImage
```

Region collection: `VirtualQuery` walk from `image_base` to `image_base + SizeOfImage`. Each region's `{BaseAddress, RegionSize, Protect}` is recorded. `PAGE_NOACCESS` and `PAGE_GUARD` regions skipped.

## XOR Performance

- 16-byte key XORed in u64 pairs (two 8-byte words) for speed
- ~100MB PE image encrypted in <1ms on modern hardware
- Typical agent image: 5-10MB → negligible overhead
