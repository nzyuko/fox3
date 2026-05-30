/// Shared WinAPI FFI helpers used by all command modules.
/// Provides wide string conversion, error formatting, RAII handles,
/// hive mapping, dynamic DLL loading, and common token operations.

#[cfg(windows)]
pub mod win {
    use std::ffi::c_void;
    use std::ptr;

    pub type HANDLE = *mut c_void;
    pub type HKEY = *mut c_void;
    #[allow(non_camel_case_types)]
    pub type SC_HANDLE = *mut c_void;
    pub type HMODULE = *mut c_void;

    pub const INVALID_HANDLE: HANDLE = -1isize as HANDLE;

    // ── Wide string conversion ──────────────────────────────────────────

    /// Convert &str to null-terminated UTF-16 Vec<u16>
    pub fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Convert null-terminated *const u16 to String
    pub fn from_wide(p: *const u16) -> String {
        if p.is_null() { return String::new(); }
        unsafe {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    /// Convert *const u16 with known byte length to String
    pub fn from_wide_bytes(p: *const u16, byte_len: usize) -> String {
        if p.is_null() || byte_len == 0 { return String::new(); }
        let char_len = byte_len / 2;
        unsafe {
            String::from_utf16_lossy(std::slice::from_raw_parts(p, char_len))
        }
    }

    // ── Win32 error formatting ──────────────────────────────────────────

    /// Format a Win32 error code into a human-readable string
    pub fn win32_error_string(code: u32) -> String {
        use windows_sys::Win32::System::Diagnostics::Debug::*;
        use windows_sys::Win32::Foundation::*;
        unsafe {
            let mut buf: *mut u16 = ptr::null_mut();
            let len = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                ptr::null(), code, 0,
                &mut buf as *mut _ as *mut u16, 0, ptr::null(),
            );
            if len == 0 || buf.is_null() {
                return format!("error {}", code);
            }
            let msg = from_wide(buf).trim().to_string();
            LocalFree(buf as HLOCAL);
            format!("{} (error {})", msg, code)
        }
    }

    /// Get last Win32 error as anyhow::Error
    pub fn last_error(context: &str) -> anyhow::Error {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        anyhow::anyhow!("{}: {}", context, win32_error_string(code))
    }

    /// Format NTSTATUS to string
    pub fn ntstatus_string(status: i32) -> String {
        format!("NTSTATUS 0x{:08X}", status as u32)
    }

    // ── RAII Handles ────────────────────────────────────────────────────

    /// RAII wrapper for registry key handles (HKEY)
    pub struct RegKeyHandle(pub HKEY);
    impl Drop for RegKeyHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { windows_sys::Win32::System::Registry::RegCloseKey(self.0); }
            }
        }
    }

    /// RAII wrapper for SC_HANDLE (Service Control Manager)
    pub struct ScHandle(pub SC_HANDLE);
    impl Drop for ScHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { windows_sys::Win32::System::Services::CloseServiceHandle(self.0); }
            }
        }
    }

    /// RAII wrapper for generic HANDLE (CloseHandle)
    pub struct WinHandle(pub HANDLE);
    impl Drop for WinHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0); }
            }
        }
    }

    /// RAII wrapper for NetAPI buffers (NetApiBufferFree)
    pub struct NetApiBuf(pub *mut u8);
    impl Drop for NetApiBuf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree(
                        self.0 as *const _
                    );
                }
            }
        }
    }

    // ── Hive / Registry helpers ─────────────────────────────────────────

    /// Map hive string (e.g. "HKLM") to predefined HKEY handle
    pub fn hive_to_hkey(hive: &str) -> anyhow::Result<HKEY> {
        use windows_sys::Win32::System::Registry::*;
        match hive.to_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => Ok(HKEY_LOCAL_MACHINE),
            "HKCU" | "HKEY_CURRENT_USER" => Ok(HKEY_CURRENT_USER),
            "HKU" | "HKEY_USERS" => Ok(HKEY_USERS),
            "HKCR" | "HKEY_CLASSES_ROOT" => Ok(HKEY_CLASSES_ROOT),
            "HKCC" | "HKEY_CURRENT_CONFIG" => Ok(HKEY_CURRENT_CONFIG),
            _ => anyhow::bail!("Unknown registry hive: {}", hive),
        }
    }

    /// Map registry type string to REG_* constant
    pub fn reg_type_from_str(s: &str) -> anyhow::Result<u32> {
        use windows_sys::Win32::System::Registry::*;
        match s.to_uppercase().as_str() {
            "REG_SZ" => Ok(REG_SZ),
            "REG_EXPAND_SZ" => Ok(REG_EXPAND_SZ),
            "REG_BINARY" => Ok(REG_BINARY),
            "REG_DWORD" => Ok(REG_DWORD),
            "REG_MULTI_SZ" => Ok(REG_MULTI_SZ),
            "REG_QWORD" => Ok(REG_QWORD),
            _ => anyhow::bail!("Unknown registry type: {}. Use: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD", s),
        }
    }

    /// Map REG_* constant to display string
    pub fn reg_type_to_str(t: u32) -> &'static str {
        use windows_sys::Win32::System::Registry::*;
        match t {
            REG_SZ => "REG_SZ",
            REG_EXPAND_SZ => "REG_EXPAND_SZ",
            REG_BINARY => "REG_BINARY",
            REG_DWORD => "REG_DWORD",
            REG_MULTI_SZ => "REG_MULTI_SZ",
            REG_QWORD => "REG_QWORD",
            REG_NONE => "REG_NONE",
            _ => "REG_UNKNOWN",
        }
    }

    /// Encode data string to bytes for RegSetValueExW based on type
    pub fn encode_reg_data(typ: u32, data: &str) -> anyhow::Result<Vec<u8>> {
        use windows_sys::Win32::System::Registry::*;
        match typ {
            REG_SZ | REG_EXPAND_SZ => {
                let wide = to_wide(data);
                Ok(unsafe {
                    std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2).to_vec()
                })
            }
            REG_DWORD => {
                let val: u32 = data.parse().map_err(|_| anyhow::anyhow!("Invalid DWORD: {}", data))?;
                Ok(val.to_le_bytes().to_vec())
            }
            REG_QWORD => {
                let val: u64 = data.parse().map_err(|_| anyhow::anyhow!("Invalid QWORD: {}", data))?;
                Ok(val.to_le_bytes().to_vec())
            }
            REG_BINARY => {
                let hex = data.replace(' ', "");
                let bytes: Result<Vec<u8>, _> = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i+2], 16))
                    .collect();
                bytes.map_err(|_| anyhow::anyhow!("Invalid hex for REG_BINARY: {}", data))
            }
            REG_MULTI_SZ => {
                let mut buf: Vec<u16> = Vec::new();
                for part in data.split("\\0") {
                    buf.extend(part.encode_utf16());
                    buf.push(0);
                }
                buf.push(0);
                Ok(unsafe {
                    std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 2).to_vec()
                })
            }
            _ => anyhow::bail!("Unsupported registry type for encoding"),
        }
    }

    /// Format registry data bytes to display string based on type
    pub fn format_reg_data(typ: u32, data: &[u8]) -> String {
        use windows_sys::Win32::System::Registry::*;
        match typ {
            REG_SZ | REG_EXPAND_SZ => {
                if data.len() >= 2 {
                    let wide: Vec<u16> = data.chunks(2)
                        .filter_map(|c| if c.len() == 2 { Some(u16::from_le_bytes([c[0], c[1]])) } else { None })
                        .collect();
                    let s = String::from_utf16_lossy(&wide);
                    s.trim_end_matches('\0').to_string()
                } else {
                    String::new()
                }
            }
            REG_DWORD => {
                if data.len() >= 4 {
                    let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    format!("0x{:08x} ({})", val, val)
                } else {
                    format!("(invalid dword, {} bytes)", data.len())
                }
            }
            REG_QWORD => {
                if data.len() >= 8 {
                    let val = u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
                    format!("0x{:016x} ({})", val, val)
                } else {
                    format!("(invalid qword, {} bytes)", data.len())
                }
            }
            REG_BINARY => {
                data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
            }
            REG_MULTI_SZ => {
                if data.len() >= 2 {
                    let wide: Vec<u16> = data.chunks(2)
                        .filter_map(|c| if c.len() == 2 { Some(u16::from_le_bytes([c[0], c[1]])) } else { None })
                        .collect();
                    let s = String::from_utf16_lossy(&wide);
                    s.trim_end_matches('\0').replace('\0', " | ")
                } else {
                    String::new()
                }
            }
            _ => {
                data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
            }
        }
    }

    // ── Token / Elevation helpers ───────────────────────────────────────

    /// Check if current process is elevated (running as admin)
    pub fn is_elevated() -> bool {
        use windows_sys::Win32::Security::*;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let _guard = WinHandle(token);
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token, TokenElevation,
                &mut elevation as *mut _ as *mut c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    // ── Dynamic DLL loading ─────────────────────────────────────────────

    /// Load a function from a DLL by name at runtime.
    /// Used for ntdll.dll, dbghelp.dll, dnsapi.dll, crypt32.dll, wldap32.dll, etc.
    ///
    /// # Safety
    /// The caller must ensure T matches the actual function signature.
    pub unsafe fn get_proc<T>(dll: &str, func: &str) -> anyhow::Result<T> {
        use windows_sys::Win32::System::LibraryLoader::*;
        let dll_w = to_wide(dll);
        let hmod = LoadLibraryW(dll_w.as_ptr());
        if hmod.is_null() {
            anyhow::bail!("LoadLibraryW({}) failed: {}", dll, win32_error_string(
                windows_sys::Win32::Foundation::GetLastError()
            ));
        }
        let func_c = std::ffi::CString::new(func)
            .map_err(|_| anyhow::anyhow!("Invalid function name: {}", func))?;
        let addr = GetProcAddress(hmod, func_c.as_ptr() as *const u8);
        match addr {
            Some(f) => Ok(std::mem::transmute_copy(&f)),
            None => anyhow::bail!("GetProcAddress({}, {}) failed", dll, func),
        }
    }

    // ── UNICODE_STRING for ntdll operations ─────────────────────────────

    /// NT UNICODE_STRING structure for NtSetValueKey / NtDeleteValueKey
    #[repr(C)]
    pub struct UnicodeString {
        pub length: u16,
        pub maximum_length: u16,
        pub buffer: *const u16,
    }

    // ── Service state formatting ────────────────────────────────────────

    pub fn service_state_str(state: u32) -> &'static str {
        match state {
            1 => "STOPPED",
            2 => "START_PENDING",
            3 => "STOP_PENDING",
            4 => "RUNNING",
            5 => "CONTINUE_PENDING",
            6 => "PAUSE_PENDING",
            7 => "PAUSED",
            _ => "UNKNOWN",
        }
    }

    pub fn service_start_type_str(st: u32) -> &'static str {
        match st {
            0 => "BOOT_START",
            1 => "SYSTEM_START",
            2 => "AUTO_START",
            3 => "DEMAND_START",
            4 => "DISABLED",
            _ => "UNKNOWN",
        }
    }

    pub fn service_type_str(t: u32) -> &'static str {
        match t {
            1 => "KERNEL_DRIVER",
            2 => "FILE_SYSTEM_DRIVER",
            0x10 => "WIN32_OWN_PROCESS",
            0x20 => "WIN32_SHARE_PROCESS",
            0x110 => "WIN32_OWN_PROCESS (interactive)",
            0x120 => "WIN32_SHARE_PROCESS (interactive)",
            _ => "OTHER",
        }
    }
}
