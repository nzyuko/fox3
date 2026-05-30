/// Hybrid HTTPS/WSS transport.
///
/// Automatically negotiates the best protocol:
///   1. First `send()` tries a WebSocket upgrade on the HTTPS URL.
///   2. If the server supports WSS (listener registered), all subsequent
///      calls use the persistent WebSocket connection (binary frames).
///   3. If the upgrade fails (503, connection error, etc.), the transport
///      falls back to plain HTTPS POST — identical to the old behavior.
///   4. If an established WSS connection drops, the next `send()` retries
///      the upgrade before falling through to HTTPS.
///
/// Benefits of WSS over HTTPS:
///   - Connection reuse (no TLS handshake per checkin)
///   - Server push: SOCKS/rportfwd jobs delivered immediately via push goroutine
///   - Lower latency for tunnel-mode fast polling

use std::io;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::blocking::Client;
use tungstenite::client::IntoClientRequest;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::Message;

use crate::transport::Transporter;

type WsStream = tungstenite::WebSocket<MaybeTlsStream<TcpStream>>;

pub struct HttpTransport {
    url:        String,
    proxy_url:  String,
    http_client: Client,
    wss_conn:   Mutex<Option<WsStream>>,
    wss_failed: Mutex<bool>,
}

impl HttpTransport {
    pub fn new(url: String, proxy_url: String) -> anyhow::Result<Self> {
        let mut builder = Client::builder()
            .danger_accept_invalid_certs(true);

        if !proxy_url.is_empty() {
            builder = builder.proxy(reqwest::Proxy::all(&proxy_url)?);
        }

        let http_client = builder.build()?;
        Ok(Self {
            url,
            proxy_url,
            http_client,
            wss_conn:   Mutex::new(None),
            wss_failed: Mutex::new(false),
        })
    }

    /// Attempt to establish a WSS connection.  Returns Ok(()) on success.
    fn try_wss_connect(&self, auth: &str) -> anyhow::Result<()> {
        // Derive wss:// URL from the https:// URL
        let wss_url = self.url
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        // Build the WebSocket upgrade request with Authorization header
        let mut request = wss_url.as_str().into_client_request()
            .map_err(|e| anyhow::anyhow!("wss: bad request: {}", e))?;
        request.headers_mut().insert(
            "Authorization",
            auth.parse().map_err(|e| anyhow::anyhow!("wss: bad auth header: {}", e))?,
        );

        // Extract host:port for TCP connection
        let uri = request.uri().clone();
        let host = uri.host().ok_or_else(|| anyhow::anyhow!("wss: no host in URL"))?;
        let port = uri.port_u16().unwrap_or(443);
        let addr = format!("{}:{}", host, port);

        // Open TCP connection (direct or via HTTP CONNECT proxy)
        let tcp = if self.proxy_url.is_empty() {
            TcpStream::connect(&addr)
                .map_err(|e| anyhow::anyhow!("wss: tcp connect to {}: {}", addr, e))?
        } else {
            self.http_connect_proxy(&addr)?
        };
        tcp.set_nodelay(true).ok();

        // Build custom rustls config that accepts self-signed certificates
        let tls_config = dangerous_tls_config();

        // Use tungstenite's built-in TLS + WS handshake with our custom connector
        let connector = tungstenite::Connector::Rustls(Arc::new(tls_config));
        let (ws, _resp) = tungstenite::client_tls_with_config(
            request,
            tcp,
            None,                   // no WebSocket config override
            Some(connector),
        ).map_err(|e| anyhow::anyhow!("wss: upgrade failed: {}", e))?;

        let mut guard = self.wss_conn.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
        *guard = Some(ws);
        Ok(())
    }

    /// Send a message via the established WSS connection.
    /// Returns Ok(response_bytes) or Err if the connection failed.
    fn wss_send(&self, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let mut guard = self.wss_conn.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
        let ws = guard.as_mut().ok_or_else(|| anyhow::anyhow!("wss: no connection"))?;

        // 60-second read timeout prevents indefinite blocking if the server
        // processes the request but fails to deliver a response frame.
        set_ws_read_timeout(ws, Some(Duration::from_secs(60)));

        // Send binary frame
        ws.send(Message::Binary(body))
            .map_err(|e| anyhow::anyhow!("wss: send error: {}", e))?;

        // Read until we get a binary response frame.
        // tungstenite auto-responds to Ping with Pong.
        loop {
            match ws.read() {
                Ok(Message::Binary(data)) => {
                    set_ws_read_timeout(ws, None);
                    return Ok(data);
                }
                Ok(Message::Ping(_)) => {
                    // tungstenite auto-responds with Pong
                }
                Ok(Message::Close(_)) => {
                    *guard = None;
                    anyhow::bail!("wss: server closed connection");
                }
                Ok(_) => {
                    // Skip text frames, pong frames, etc.
                }
                Err(tungstenite::Error::Io(ref e))
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    *guard = None;
                    anyhow::bail!("wss: read timeout — no response within 60s");
                }
                Err(e) => {
                    *guard = None;
                    anyhow::bail!("wss: read error: {}", e);
                }
            }
        }
    }

    /// Non-blocking receive: listen for a server-pushed WSS frame with a timeout.
    /// Returns Ok(Some(data)) if a Binary frame arrived, Ok(None) on timeout/no WSS.
    ///
    /// Uses an absolute deadline to prevent Ping/Pong exchanges from indefinitely
    /// extending the per-read SO_RCVTIMEO timeout.
    pub fn try_recv(&self, timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        use std::time::Instant;

        let mut guard = match self.wss_conn.lock() {
            Ok(g) => g,
            Err(_) => return Ok(None),
        };
        let ws = match guard.as_mut() {
            Some(w) => w,
            None => return Ok(None), // No WSS connection — nothing to receive
        };

        let deadline = Instant::now() + timeout;

        loop {
            // Compute remaining time; if expired, return timeout.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                set_ws_read_timeout(ws, None);
                return Ok(None);
            }

            set_ws_read_timeout(ws, Some(remaining));

            match ws.read() {
                Ok(Message::Binary(data)) => {
                    set_ws_read_timeout(ws, None);
                    return Ok(Some(data));
                }
                Ok(Message::Ping(_)) => {
                    // tungstenite auto-responds with Pong; loop to re-check deadline
                }
                Ok(Message::Close(_)) => {
                    set_ws_read_timeout(ws, None);
                    *guard = None;
                    anyhow::bail!("wss: server closed connection during try_recv");
                }
                Ok(_) => {
                    // Skip text, pong, etc.
                }
                Err(tungstenite::Error::Io(ref e))
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Timeout expired — no data available
                    set_ws_read_timeout(ws, None);
                    return Ok(None);
                }
                Err(e) => {
                    set_ws_read_timeout(ws, None);
                    *guard = None;
                    // Clear wss_failed so next send() retries the upgrade
                    if let Ok(mut f) = self.wss_failed.lock() { *f = false; }
                    anyhow::bail!("wss: try_recv error: {}", e);
                }
            }
        }
    }

    /// Open a TCP stream to `target` (host:port) via an HTTP CONNECT proxy.
    /// Returns the raw TCP stream after the proxy confirms 200.
    fn http_connect_proxy(&self, target: &str) -> anyhow::Result<TcpStream> {
        use std::io::{BufRead, BufReader, Write};
        use base64::Engine as _;

        let proxy_uri: url::Url = self.proxy_url.parse()
            .map_err(|e| anyhow::anyhow!("proxy: bad URL: {}", e))?;
        let proxy_host = proxy_uri.host_str()
            .ok_or_else(|| anyhow::anyhow!("proxy: no host in URL"))?;
        let proxy_port = proxy_uri.port().unwrap_or(8080);
        let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

        let stream = TcpStream::connect(&proxy_addr)
            .map_err(|e| anyhow::anyhow!("proxy: connect to {}: {}", proxy_addr, e))?;

        // Build CONNECT request with optional Basic auth from proxy URL credentials
        let mut writer = stream.try_clone()?;
        let auth_header = if !proxy_uri.username().is_empty() {
            let creds = format!("{}:{}",
                proxy_uri.username(),
                proxy_uri.password().unwrap_or(""));
            format!("Proxy-Authorization: Basic {}\r\n",
                base64::engine::general_purpose::STANDARD.encode(creds))
        } else {
            String::new()
        };
        write!(writer, "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}\r\n", target, target, auth_header)
            .map_err(|e| anyhow::anyhow!("proxy: write CONNECT: {}", e))?;

        // Read response status line
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut status_line = String::new();
        reader.read_line(&mut status_line)
            .map_err(|e| anyhow::anyhow!("proxy: read status: {}", e))?;

        if !status_line.contains("200") {
            anyhow::bail!("proxy: CONNECT failed: {}", status_line.trim());
        }

        // Drain remaining headers until empty line
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.trim().is_empty() { break; }
        }

        Ok(stream)
    }

    /// Send via plain HTTPS POST (fallback path).
    fn https_send(&self, auth: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let resp = self.http_client
            .post(&self.url)
            .header("Content-Type", "application/octet-stream; charset=utf-8")
            .header("Authorization", auth)
            .body(body)
            .send()?;

        let status = resp.status();
        let bytes  = resp.bytes()?.to_vec();

        if !status.is_success() {
            anyhow::bail!("http: server returned {}", status);
        }
        Ok(bytes)
    }
}

impl Transporter for HttpTransport {
    fn send(&self, auth: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        // ── Try WSS if not already marked as failed ────────────────────────
        let wss_failed = *self.wss_failed.lock().unwrap_or_else(|e| e.into_inner());
        let has_conn = self.wss_conn.lock()
            .map(|g| g.is_some())
            .unwrap_or(false);

        if !wss_failed && !has_conn {
            // First call (or reconnect after drop): try WSS upgrade
            match self.try_wss_connect(auth) {
                Ok(()) => {
                    crate::dbg_print!("[transport] WSS upgrade succeeded");
                }
                Err(e) => {
                    crate::dbg_print!("[transport] WSS upgrade failed ({}), using HTTPS", e);
                    if let Ok(mut f) = self.wss_failed.lock() {
                        *f = true;
                    }
                }
            }
        }

        // ── Send via WSS if connected ──────────────────────────────────────
        let has_conn = self.wss_conn.lock()
            .map(|g| g.is_some())
            .unwrap_or(false);

        if has_conn {
            match self.wss_send(body.clone()) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    crate::dbg_print!("[transport] WSS error ({}), falling back to HTTPS", e);
                    // Connection dropped — clear it so next call retries WSS
                    if let Ok(mut g) = self.wss_conn.lock() { *g = None; }
                    if let Ok(mut f) = self.wss_failed.lock() { *f = false; }
                    // Fall through to HTTPS for this call
                }
            }
        }

        // ── Fallback: HTTPS POST ───────────────────────────────────────────
        self.https_send(auth, body)
    }

    fn kind(&self) -> &'static str {
        let has_conn = self.wss_conn.lock()
            .map(|g| g.is_some())
            .unwrap_or(false);
        if has_conn { "wss" } else { "https" }
    }

    fn try_recv(&self, timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        self.try_recv(timeout)
    }

    fn supports_push(&self) -> bool {
        self.wss_conn.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    fn raw_wss_socket(&self) -> Option<u64> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let guard = self.wss_conn.lock().ok()?;
            let ws = guard.as_ref()?;
            let tcp = match ws.get_ref() {
                MaybeTlsStream::Rustls(s) => s.get_ref(),
                MaybeTlsStream::Plain(s) => s,
                _ => return None,
            };
            Some(tcp.as_raw_socket())
        }
        #[cfg(not(windows))]
        { None }
    }

}

// ── WSS read-timeout helper ──────────────────────────────────────────────────

/// Set (or clear) the read timeout on the TCP stream underlying a tungstenite WebSocket.
/// Proven pattern from `transport_wss.rs` — works with both plain and rustls streams.
fn set_ws_read_timeout(ws: &mut WsStream, dur: Option<Duration>) {
    match ws.get_mut() {
        MaybeTlsStream::Plain(s) => { let _ = s.set_read_timeout(dur); }
        MaybeTlsStream::Rustls(s) => { let _ = s.get_ref().set_read_timeout(dur); }
        #[allow(unreachable_patterns)]
        _ => {}
    }
}

// ── TLS configuration (accept self-signed certificates) ─────────────────────

/// Build a rustls ClientConfig that accepts any TLS certificate.
/// Required for the self-signed certs the fox3 server generates.
fn dangerous_tls_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}

/// A rustls certificate verifier that accepts everything.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
