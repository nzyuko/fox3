/// File and share operation commands.
/// Windows: native Win32 API (zero child processes). Linux: fallback stubs.

#[cfg(windows)]
use super::winapi_helpers::win::{
    self, to_wide, from_wide, win32_error_string, NetApiBuf, HANDLE,
};

// ── cacls ────────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn cacls(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Security::*;

    let path = args.first()
        .ok_or_else(|| anyhow::anyhow!("cacls: <filepath> required"))?;

    let path_w = to_wide(path);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();

    let ret = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(), std::ptr::null_mut(),
            &mut dacl, std::ptr::null_mut(),
            &mut sd,
        )
    };
    if ret != 0 {
        anyhow::bail!("GetNamedSecurityInfoW: {}", win32_error_string(ret));
    }

    // Parse ACL entries
    let mut out = format!("{}\n", path);

    if !dacl.is_null() {
        let acl = unsafe { &*dacl };
        for i in 0..acl.AceCount {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            if unsafe { GetAce(dacl, i as u32, &mut ace) } == 0 {
                continue;
            }

            let ace_header = unsafe { &*(ace as *const ACE_HEADER) };
            let is_allow = ace_header.AceType == 0; // ACCESS_ALLOWED_ACE_TYPE

            // Get SID from ACE (ACCESS_ALLOWED_ACE or ACCESS_DENIED_ACE both start with Header, Mask, SidStart)
            #[repr(C)]
            struct GenericAce {
                header: ACE_HEADER,
                mask: u32,
                sid_start: u32,
            }
            let generic = unsafe { &*(ace as *const GenericAce) };
            let sid = &generic.sid_start as *const u32 as *mut std::ffi::c_void;

            // Lookup SID name
            let mut name_buf = vec![0u16; 256];
            let mut name_len = 256u32;
            let mut domain_buf = vec![0u16; 256];
            let mut domain_len = 256u32;
            let mut sid_use: SID_NAME_USE = 0;

            let name = if unsafe {
                LookupAccountSidW(
                    std::ptr::null(), sid,
                    name_buf.as_mut_ptr(), &mut name_len,
                    domain_buf.as_mut_ptr(), &mut domain_len,
                    &mut sid_use,
                )
            } != 0 {
                let n = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let d = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
                if d.is_empty() { n } else { format!("{}\\{}", d, n) }
            } else {
                format!("(unknown SID)")
            };

            let perm_type = if is_allow { "Allow" } else { "Deny" };
            let perms = format_access_mask(generic.mask);
            out.push_str(&format!("  {} {} ({})\n", perm_type, name, perms));
        }
    }

    // Free security descriptor
    if !sd.is_null() {
        unsafe { windows_sys::Win32::Foundation::LocalFree(sd) };
    }

    Ok(out)
}

#[cfg(not(windows))]
pub fn cacls(args: &[String]) -> anyhow::Result<String> {
    let path = args.first()
        .ok_or_else(|| anyhow::anyhow!("cacls: <filepath> required"))?;
    let (stdout, stderr) = crate::exec::exec("getfacl", &[path.clone()]);
    if !stderr.is_empty() && stdout.is_empty() {
        let (stdout2, _) = crate::exec::exec("ls", &["-la".into(), path.clone()]);
        return Ok(stdout2);
    }
    Ok(stdout)
}

#[cfg(windows)]
fn format_access_mask(mask: u32) -> String {
    let mut perms = Vec::new();
    if mask & 0x001F01FF == 0x001F01FF { return "FullControl".into(); }
    if mask & 0x001301BF == 0x001301BF { return "Modify".into(); }
    if mask & 0x001200A9 == 0x001200A9 { perms.push("ReadAndExecute"); }
    if mask & 0x00000116 != 0 { perms.push("Write"); }
    if mask & 0x00000001 != 0 { perms.push("ReadData"); }
    if mask & 0x00000002 != 0 { perms.push("WriteData"); }
    if mask & 0x00000004 != 0 { perms.push("AppendData"); }
    if mask & 0x00000020 != 0 { perms.push("Execute"); }
    if mask & 0x00010000 != 0 { perms.push("Delete"); }
    if mask & 0x00040000 != 0 { perms.push("WriteDAC"); }
    if mask & 0x00080000 != 0 { perms.push("WriteOwner"); }
    if perms.is_empty() { format!("0x{:08x}", mask) } else { perms.join(",") }
}

// ── dir ──────────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn dir(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::Storage::FileSystem::*;

    let path = args.get(0).map(|s| s.as_str()).unwrap_or(".");
    let recursive = args.iter().any(|a| a == "/s" || a == "-r" || a == "--recursive");

    let mut out = String::new();
    dir_walk(path, recursive, &mut out)?;
    Ok(out)
}

#[cfg(windows)]
fn dir_walk(path: &str, recursive: bool, out: &mut String) -> anyhow::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::Time::FileTimeToSystemTime;

    let pattern = if path.ends_with('\\') || path.ends_with('/') {
        format!("{}*", path)
    } else {
        format!("{}\\*", path)
    };

    let pattern_w = to_wide(&pattern);
    let mut fd: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let h = unsafe { FindFirstFileW(pattern_w.as_ptr(), &mut fd) };
    if h == win::INVALID_HANDLE {
        anyhow::bail!("FindFirstFileW({}): {}", path, win32_error_string(unsafe { GetLastError() }));
    }

    out.push_str(&format!("\n Directory of {}\n\n", path));
    let mut subdirs = Vec::new();

    loop {
        let name = from_wide(fd.cFileName.as_ptr());
        if name != "." && name != ".." {
            let is_dir = fd.dwFileAttributes & 0x10 != 0; // FILE_ATTRIBUTE_DIRECTORY
            let size = ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64;

            // Format FILETIME to date
            let ft = fd.ftLastWriteTime;
            let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
            unsafe { FileTimeToSystemTime(&ft, &mut st) };
            let date = format!("{:02}/{:02}/{:04}  {:02}:{:02}",
                st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute);

            if is_dir {
                out.push_str(&format!("{}    <DIR>          {}\n", date, name));
                if recursive {
                    let sub = format!("{}\\{}", path, name);
                    subdirs.push(sub);
                }
            } else {
                out.push_str(&format!("{} {:>14}  {}\n", date, size, name));
            }
        }
        if unsafe { FindNextFileW(h, &mut fd) } == 0 { break; }
    }
    unsafe { FindClose(h) };

    for sub in subdirs {
        dir_walk(&sub, true, out)?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn dir(args: &[String]) -> anyhow::Result<String> {
    let path = args.get(0).map(|s| s.as_str()).unwrap_or(".");
    let recursive = args.iter().any(|a| a == "/s" || a == "-r" || a == "--recursive");
    let mut cmd_args = vec!["-la".into(), path.into()];
    if recursive { cmd_args = vec!["-laR".into(), path.into()]; }
    let (stdout, stderr) = crate::exec::exec("ls", &cmd_args);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(stdout)
}

// ── netshares ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netshares(args: &[String]) -> anyhow::Result<String> {
    // NetShareEnum / SHARE_INFO_2 not in windows-sys — load dynamically
    type NetShareEnumFn = unsafe extern "system" fn(
        *const u16, u32, *mut *mut u8, u32, *mut u32, *mut u32, *mut u32,
    ) -> u32;

    #[repr(C)]
    struct ShareInfo2 {
        shi2_netname: *const u16,
        shi2_type: u32,
        shi2_remark: *const u16,
        shi2_permissions: u32,
        shi2_max_uses: u32,
        shi2_current_uses: u32,
        shi2_path: *const u16,
        shi2_passwd: *const u16,
    }

    let net_share_enum: NetShareEnumFn = unsafe {
        win::get_proc("netapi32.dll", "NetShareEnum")?
    };

    let server = args.first();
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume: u32 = 0;

    let ret = unsafe {
        net_share_enum(
            server_ptr, 2, &mut buf,
            0xFFFFFFFF, &mut entries_read, &mut total_entries,
            &mut resume,
        )
    };
    if ret != 0 && ret != 234 {
        anyhow::bail!("NetShareEnum: error {}", ret);
    }
    let _guard = NetApiBuf(buf);

    let mut out = format!("{:<20} {:<10} {:<30} {}\n", "Share", "Type", "Path", "Remark");
    out.push_str(&"-".repeat(80));
    out.push('\n');

    let entries = unsafe {
        std::slice::from_raw_parts(buf as *const ShareInfo2, entries_read as usize)
    };
    for e in entries {
        let name = from_wide(e.shi2_netname);
        let path = from_wide(e.shi2_path);
        let remark = from_wide(e.shi2_remark);
        let stype = match e.shi2_type & 0xFF {
            0 => "Disk",
            1 => "Print",
            2 => "Device",
            3 => "IPC",
            _ => "Unknown",
        };
        out.push_str(&format!("{:<20} {:<10} {:<30} {}\n", name, stype, path, remark));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn netshares(args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("smbclient", &["-L".into(), args.first().cloned().unwrap_or("localhost".into()), "-N".into()]);
    Ok(stdout)
}

// ── netuse_add ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netuse_add(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::WNet::*;

    let share = args.first()
        .ok_or_else(|| anyhow::anyhow!("netuse_add: <share> [user] [pass] required"))?;
    let user = args.get(1);
    let pass = args.get(2);

    let remote_w = to_wide(share);
    let user_w = user.map(|u| to_wide(u));
    let pass_w = pass.map(|p| to_wide(p));

    let nr = NETRESOURCEW {
        dwScope: 0,
        dwType: 1, // RESOURCETYPE_DISK
        dwDisplayType: 0,
        dwUsage: 0,
        lpLocalName: std::ptr::null_mut(),
        lpRemoteName: remote_w.as_ptr() as *mut u16,
        lpComment: std::ptr::null_mut(),
        lpProvider: std::ptr::null_mut(),
    };

    let ret = unsafe {
        WNetAddConnection2W(
            &nr,
            pass_w.as_ref().map_or(std::ptr::null(), |p| p.as_ptr()),
            user_w.as_ref().map_or(std::ptr::null(), |u| u.as_ptr()),
            0,
        )
    };
    if ret != 0 {
        anyhow::bail!("WNetAddConnection2W: {}", win32_error_string(ret));
    }
    Ok(format!("Connected to {}", share))
}

#[cfg(not(windows))]
pub fn netuse_add(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("netuse_add: Windows only")
}

// ── netuse_delete ────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netuse_delete(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::WNet::*;

    let share = args.first()
        .ok_or_else(|| anyhow::anyhow!("netuse_delete: <share> required"))?;

    let share_w = to_wide(share);
    let ret = unsafe {
        WNetCancelConnection2W(share_w.as_ptr(), 0, 1) // force=TRUE
    };
    if ret != 0 {
        anyhow::bail!("WNetCancelConnection2W: {}", win32_error_string(ret));
    }
    Ok(format!("Disconnected {}", share))
}

#[cfg(not(windows))]
pub fn netuse_delete(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("netuse_delete: Windows only")
}

// ── netuse_list ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netuse_list(_args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::WNet::*;

    let mut h: HANDLE = std::ptr::null_mut();
    let ret = unsafe {
        WNetOpenEnumW(2, 1, 0, std::ptr::null(), &mut h) // RESOURCE_CONNECTED, RESOURCETYPE_DISK
    };
    if ret != 0 {
        anyhow::bail!("WNetOpenEnumW: {}", win32_error_string(ret));
    }

    let mut out = format!("{:<10} {:<30} {}\n", "Status", "Local", "Remote");
    out.push_str(&"-".repeat(60));
    out.push('\n');

    let mut buf = vec![0u8; 16384];
    let mut count: u32 = 0xFFFFFFFF;
    let mut buf_size: u32 = buf.len() as u32;

    let ret = unsafe {
        WNetEnumResourceW(h, &mut count, buf.as_mut_ptr() as *mut std::ffi::c_void, &mut buf_size)
    };

    if ret == 0 {
        let entries = unsafe {
            std::slice::from_raw_parts(buf.as_ptr() as *const NETRESOURCEW, count as usize)
        };
        for e in entries {
            let local = from_wide(e.lpLocalName);
            let remote = from_wide(e.lpRemoteName);
            out.push_str(&format!("{:<10} {:<30} {}\n", "OK", local, remote));
        }
    }

    unsafe { WNetCloseEnum(h) };
    Ok(out)
}

#[cfg(not(windows))]
pub fn netuse_list(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("netuse_list: Windows only")
}
