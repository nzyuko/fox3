/// Process operation commands.
/// Windows: native Win32 API (zero child processes). Linux: /proc or shell fallback.

#[cfg(windows)]
use super::winapi_helpers::win::{
    self, to_wide, WinHandle, HANDLE,
};

// ── procdump ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn procdump(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Threading::OpenProcess;
    use windows_sys::Win32::Foundation::CloseHandle;

    let pid_str = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("procdump: <pid> <outfile> required"))?;
    let outfile = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("procdump: <pid> <outfile> required"))?;
    let pid: u32 = pid_str.parse().map_err(|_| anyhow::anyhow!("procdump: invalid PID"))?;

    // MiniDumpWriteDump from dbghelp.dll
    type MiniDumpWriteDumpFn = unsafe extern "system" fn(
        HANDLE, u32, HANDLE, u32,
        *const std::ffi::c_void, *const std::ffi::c_void, *const std::ffi::c_void,
    ) -> i32;

    let minidump_write: MiniDumpWriteDumpFn = unsafe {
        win::get_proc("dbghelp.dll", "MiniDumpWriteDump")?
    };

    // Open process with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    let hproc = unsafe { OpenProcess(0x0410, 0, pid) };
    if hproc.is_null() {
        return Err(win::last_error(&format!("OpenProcess({})", pid)));
    }
    let _proc_guard = WinHandle(hproc);

    // Create output file
    let file_w = to_wide(outfile);
    let hfile = unsafe {
        windows_sys::Win32::Storage::FileSystem::CreateFileW(
            file_w.as_ptr(),
            0x40000000, // GENERIC_WRITE
            0, std::ptr::null(), 2, // CREATE_ALWAYS
            0x80, // FILE_ATTRIBUTE_NORMAL
            std::ptr::null_mut(),
        )
    };
    if hfile == win::INVALID_HANDLE {
        return Err(win::last_error("CreateFileW"));
    }
    let _file_guard = WinHandle(hfile);

    // MiniDumpWithFullMemory = 2
    let ok = unsafe {
        minidump_write(hproc, pid, hfile, 2, std::ptr::null(), std::ptr::null(), std::ptr::null())
    };
    if ok == 0 {
        return Err(win::last_error("MiniDumpWriteDump"));
    }

    Ok(format!("Process {} dumped to {}", pid, outfile))
}

#[cfg(not(windows))]
pub fn procdump(args: &[String]) -> anyhow::Result<String> {
    let pid = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("procdump: <pid> <outfile> required"))?;
    let outfile = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("procdump: <pid> <outfile> required"))?;
    let (stdout, stderr) = crate::exec::exec("gcore", &["-o".into(), outfile.clone(), pid.clone()]);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(if stdout.is_empty() { format!("Process {} dumped to {}", pid, outfile) } else { stdout })
}

// ── processlisthandles ───────────────────────────────────────────────────────

#[cfg(windows)]
pub fn processlisthandles(args: &[String]) -> anyhow::Result<String> {
    let pid: u32 = args.first()
        .ok_or_else(|| anyhow::anyhow!("processlisthandles: <pid> required"))?
        .parse().map_err(|_| anyhow::anyhow!("processlisthandles: invalid PID"))?;

    // Use NtQuerySystemInformation(SystemHandleInformation=16)
    type NtQuerySystemInformationFn = unsafe extern "system" fn(
        u32, *mut std::ffi::c_void, u32, *mut u32,
    ) -> i32;

    let nt_query: NtQuerySystemInformationFn = unsafe {
        win::get_proc("ntdll.dll", "NtQuerySystemInformation")?
    };

    // Start with 1MB buffer, grow as needed
    let mut buf_size: u32 = 1024 * 1024;
    let mut buf: Vec<u8>;
    let mut status: i32;

    loop {
        buf = vec![0u8; buf_size as usize];
        let mut ret_len: u32 = 0;
        status = unsafe { nt_query(16, buf.as_mut_ptr() as *mut std::ffi::c_void, buf_size, &mut ret_len) };
        if status == 0 { break; }
        if status == -1073741820 /* STATUS_INFO_LENGTH_MISMATCH */ {
            buf_size = ret_len + 4096;
            continue;
        }
        anyhow::bail!("NtQuerySystemInformation: {}", win::ntstatus_string(status));
    }

    // Parse SYSTEM_HANDLE_INFORMATION
    #[repr(C)]
    struct SystemHandleInfo {
        count: u32,
        // followed by SYSTEM_HANDLE_TABLE_ENTRY_INFO array
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct HandleEntry {
        process_id: u16,
        _creator_back_trace_index: u16,
        object_type_index: u8,
        handle_attributes: u8,
        handle_value: u16,
        object: usize,
        granted_access: u32,
    }

    let info = unsafe { &*(buf.as_ptr() as *const SystemHandleInfo) };
    let entries = unsafe {
        std::slice::from_raw_parts(
            (buf.as_ptr() as *const SystemHandleInfo).add(1) as *const HandleEntry,
            info.count as usize,
        )
    };

    let mut out = format!("Handles for PID {}:\n{:<8} {:<6} {:<12} {}\n",
        pid, "Handle", "Type", "Access", "Object");
    out.push_str(&"-".repeat(50));
    out.push('\n');

    let mut handle_count = 0u32;
    for e in entries {
        if e.process_id as u32 == pid {
            out.push_str(&format!("0x{:<6x} {:<6} 0x{:08x}   0x{:x}\n",
                e.handle_value, e.object_type_index, e.granted_access, e.object));
            handle_count += 1;
        }
    }

    out.push_str(&format!("\nTotal handles: {}", handle_count));
    Ok(out)
}

#[cfg(not(windows))]
pub fn processlisthandles(args: &[String]) -> anyhow::Result<String> {
    let pid = args.first()
        .ok_or_else(|| anyhow::anyhow!("processlisthandles: <pid> required"))?;
    let (stdout, stderr) = crate::exec::exec("ls", &["-la".into(), format!("/proc/{}/fd", pid)]);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(stdout)
}

// ── processdestroy ───────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn processdestroy(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, GetCurrentProcess};
    use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_CLOSE_SOURCE};

    let pid_str = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("processdestroy: <pid> [handle_id] required"))?;
    let pid: u32 = pid_str.parse().map_err(|_| anyhow::anyhow!("invalid PID"))?;

    if let Some(handle_str) = args.get(1) {
        // Close specific handle via DuplicateHandle(DUPLICATE_CLOSE_SOURCE)
        let handle_val: usize = if handle_str.starts_with("0x") || handle_str.starts_with("0X") {
            usize::from_str_radix(&handle_str[2..], 16).map_err(|_| anyhow::anyhow!("invalid handle"))?
        } else {
            handle_str.parse().map_err(|_| anyhow::anyhow!("invalid handle"))?
        };

        let hproc = unsafe { OpenProcess(0x0040, 0, pid) }; // PROCESS_DUP_HANDLE
        if hproc.is_null() {
            return Err(win::last_error(&format!("OpenProcess({})", pid)));
        }
        let _guard = WinHandle(hproc);

        let mut dummy: HANDLE = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                hproc, handle_val as HANDLE,
                GetCurrentProcess(), &mut dummy,
                0, 0, DUPLICATE_CLOSE_SOURCE,
            )
        };
        if ok == 0 {
            return Err(win::last_error("DuplicateHandle"));
        }
        // Close our copy
        if !dummy.is_null() {
            unsafe { CloseHandle(dummy) };
        }
        Ok(format!("Closed handle 0x{:x} in PID {}", handle_val, pid))
    } else {
        // Kill entire process
        let hproc = unsafe { OpenProcess(0x0001, 0, pid) }; // PROCESS_TERMINATE
        if hproc.is_null() {
            return Err(win::last_error(&format!("OpenProcess({})", pid)));
        }
        let _guard = WinHandle(hproc);

        if unsafe { TerminateProcess(hproc, 1) } == 0 {
            return Err(win::last_error("TerminateProcess"));
        }
        Ok(format!("Killed PID {}", pid))
    }
}

#[cfg(not(windows))]
pub fn processdestroy(args: &[String]) -> anyhow::Result<String> {
    let pid = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("processdestroy: <pid> required"))?;
    let (stdout, stderr) = crate::exec::exec("kill", &["-9".into(), pid.clone()]);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(if stdout.is_empty() { format!("Killed PID {}", pid) } else { stdout })
}

// ── suspendresume ────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn suspendresume(args: &[String]) -> anyhow::Result<String> {
    let pid: u32 = args.first()
        .ok_or_else(|| anyhow::anyhow!("suspendresume: <pid> required"))?
        .parse().map_err(|_| anyhow::anyhow!("suspendresume: invalid PID"))?;

    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    use windows_sys::Win32::System::Threading::OpenThread;
    use windows_sys::Win32::Foundation::CloseHandle;

    extern "system" {
        fn SuspendThread(h: windows_sys::Win32::Foundation::HANDLE) -> u32;
        fn ResumeThread(h: windows_sys::Win32::Foundation::HANDLE) -> u32;
    }

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap.is_null() || snap == win::INVALID_HANDLE {
            anyhow::bail!("suspendresume: CreateToolhelp32Snapshot failed");
        }

        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        let mut suspended = 0u32;
        let mut resumed = 0u32;

        if Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == pid {
                    let ht = OpenThread(0x0002, 0, te.th32ThreadID);
                    if !ht.is_null() {
                        let prev = SuspendThread(ht);
                        if prev == 0 {
                            suspended += 1;
                        } else if prev != u32::MAX {
                            ResumeThread(ht);
                            ResumeThread(ht);
                            resumed += 1;
                        }
                        CloseHandle(ht);
                    }
                }
                if Thread32Next(snap, &mut te) == 0 { break; }
            }
        }
        CloseHandle(snap);

        if suspended > 0 {
            Ok(format!("Suspended {} threads in PID {}", suspended, pid))
        } else if resumed > 0 {
            Ok(format!("Resumed {} threads in PID {}", resumed, pid))
        } else {
            Ok(format!("No threads found for PID {}", pid))
        }
    }
}

#[cfg(not(windows))]
pub fn suspendresume(args: &[String]) -> anyhow::Result<String> {
    let pid = args.first()
        .ok_or_else(|| anyhow::anyhow!("suspendresume: <pid> required"))?;
    let (stdout, _) = crate::exec::exec("sh", &[
        "-c".into(),
        format!("if grep -q 'T (stopped)' /proc/{}/status 2>/dev/null; then kill -CONT {}; echo 'Resumed PID {}'; else kill -STOP {}; echo 'Suspended PID {}'; fi",
            pid, pid, pid, pid, pid),
    ]);
    Ok(stdout)
}

// ── findloadedmodule ─────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn findloadedmodule(args: &[String]) -> anyhow::Result<String> {
    let module = args.first()
        .ok_or_else(|| anyhow::anyhow!("findloadedmodule: <module_name> [process_name]"))?;
    let proc_filter = args.get(1).map(|s| s.to_lowercase());

    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    use windows_sys::Win32::Foundation::CloseHandle;

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap == win::INVALID_HANDLE {
            anyhow::bail!("findloadedmodule: snapshot failed");
        }

        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut out = String::new();
        let module_lower = module.to_lowercase();

        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                let proc_name = String::from_utf16_lossy(
                    &pe.szExeFile[..pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len())]
                );
                let proc_name_lower = proc_name.to_lowercase();

                if proc_filter.as_ref().map(|f| proc_name_lower.contains(f)).unwrap_or(true) {
                    let mod_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
                    if !mod_snap.is_null() && mod_snap != win::INVALID_HANDLE {
                        let mut me: MODULEENTRY32W = std::mem::zeroed();
                        me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
                        if Module32FirstW(mod_snap, &mut me) != 0 {
                            loop {
                                let mod_name = String::from_utf16_lossy(
                                    &me.szModule[..me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len())]
                                );
                                if mod_name.to_lowercase().contains(&module_lower) {
                                    out.push_str(&format!("PID: {:<8} Process: {:<30} Module: {}\n",
                                        pe.th32ProcessID, proc_name, mod_name));
                                    break;
                                }
                                if Module32NextW(mod_snap, &mut me) == 0 { break; }
                            }
                        }
                        CloseHandle(mod_snap);
                    }
                }
                if Process32NextW(snap, &mut pe) == 0 { break; }
            }
        }
        CloseHandle(snap);

        if out.is_empty() {
            Ok(format!("No processes found with module matching '{}'", module))
        } else {
            Ok(out)
        }
    }
}

#[cfg(not(windows))]
pub fn findloadedmodule(args: &[String]) -> anyhow::Result<String> {
    let module = args.first()
        .ok_or_else(|| anyhow::anyhow!("findloadedmodule: <module_name> required"))?;
    let (stdout, _) = crate::exec::exec("sh", &[
        "-c".into(),
        format!("for pid in /proc/[0-9]*/maps; do if grep -qi '{}' $pid 2>/dev/null; then echo \"PID $(echo $pid | cut -d/ -f3): $(grep -i '{}' $pid | head -1)\"; fi; done", module, module),
    ]);
    Ok(stdout)
}

// ── listmods ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn listmods(args: &[String]) -> anyhow::Result<String> {
    let pid: u32 = args.first()
        .map(|s| s.parse::<u32>())
        .transpose()
        .map_err(|_| anyhow::anyhow!("listmods: invalid PID"))?
        .unwrap_or(std::process::id());

    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    use windows_sys::Win32::Foundation::CloseHandle;

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap.is_null() || snap == win::INVALID_HANDLE {
            anyhow::bail!("listmods: snapshot failed for PID {} (access denied?)", pid);
        }

        let mut me: MODULEENTRY32W = std::mem::zeroed();
        me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        let mut out = format!("Modules for PID {}:\n{:<12} {:<12} {}\n",
            pid, "Base", "Size", "Name");
        out.push_str(&"-".repeat(60));
        out.push('\n');

        if Module32FirstW(snap, &mut me) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &me.szModule[..me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len())]
                );
                let path = String::from_utf16_lossy(
                    &me.szExePath[..me.szExePath.iter().position(|&c| c == 0).unwrap_or(me.szExePath.len())]
                );
                out.push_str(&format!("0x{:08x}   {:<12} {} ({})\n",
                    me.modBaseAddr as usize, me.modBaseSize, name, path));
                if Module32NextW(snap, &mut me) == 0 { break; }
            }
        }
        CloseHandle(snap);
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn listmods(args: &[String]) -> anyhow::Result<String> {
    let pid = args.first().map(|s| s.as_str()).unwrap_or("self");
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))
        .map_err(|e| anyhow::anyhow!("listmods: {}", e))?;
    Ok(maps)
}

// ── windowlist ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn windowlist(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    use windows_sys::Win32::Foundation::HWND;

    let show_all = args.first().map(|s| s == "all").unwrap_or(false);

    // Collect windows using EnumWindows callback
    static mut WINDOWS: Vec<(u32, String, String)> = Vec::new();
    static mut SHOW_ALL_FLAG: bool = false;

    unsafe {
        WINDOWS.clear();
        SHOW_ALL_FLAG = show_all;

        unsafe extern "system" fn enum_callback(hwnd: HWND, _: isize) -> i32 {
            let mut title_buf = vec![0u16; 512];
            let title_len = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), 512);
            let title = if title_len > 0 {
                String::from_utf16_lossy(&title_buf[..title_len as usize])
            } else {
                String::new()
            };

            if !SHOW_ALL_FLAG && title.is_empty() {
                return 1; // continue
            }

            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);

            // Get class name
            let mut class_buf = vec![0u16; 256];
            let class_len = GetClassNameW(hwnd, class_buf.as_mut_ptr(), 256);
            let class = if class_len > 0 {
                String::from_utf16_lossy(&class_buf[..class_len as usize])
            } else {
                String::new()
            };

            WINDOWS.push((pid, class, title));
            1 // continue
        }

        EnumWindows(Some(enum_callback), 0);

        let mut out = format!("{:<8} {:<30} {}\n", "PID", "Class", "Title");
        out.push_str(&"-".repeat(70));
        out.push('\n');
        for (pid, class, title) in &WINDOWS {
            out.push_str(&format!("{:<8} {:<30} {}\n", pid, class, title));
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn windowlist(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("windowlist: Windows only")
}

// ── get_priv ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn get_priv(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::Foundation::LUID;

    let priv_name = args.first()
        .ok_or_else(|| anyhow::anyhow!("get_priv: <privilege> required\n  Examples: SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege"))?;

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return Err(win::last_error("OpenProcessToken"));
        }
        let _guard = WinHandle(token);

        let priv_w = to_wide(priv_name);
        let mut luid = std::mem::zeroed::<LUID>();
        if LookupPrivilegeValueW(std::ptr::null(), priv_w.as_ptr(), &mut luid) == 0 {
            return Err(win::last_error(&format!("LookupPrivilegeValue({})", priv_name)));
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        if AdjustTokenPrivileges(token, 0, &mut tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
            return Err(win::last_error("AdjustTokenPrivileges"));
        }

        // Check if it actually succeeded
        let err = windows_sys::Win32::Foundation::GetLastError();
        if err == 1300 { // ERROR_NOT_ALL_ASSIGNED
            anyhow::bail!("Privilege {} not held by token", priv_name);
        }

        Ok(format!("Enabled: {}", priv_name))
    }
}

#[cfg(not(windows))]
pub fn get_priv(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("get_priv: Windows only")
}
