/// Domain / user enumeration commands.
/// Windows: Win32 NetAPI + WTS via windows-sys (zero child processes).
/// Linux: fallback stubs (kept).

#[cfg(windows)]
use super::winapi_helpers::win::{
    self, to_wide, from_wide,
    WinHandle, NetApiBuf, HANDLE,
};

// ── netuser ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netuser(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let username = args.first()
        .ok_or_else(|| anyhow::anyhow!("netuser: <username> [server] required"))?;
    let server = args.get(1);

    let user_w = to_wide(username);
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let mut buf: *mut u8 = std::ptr::null_mut();
    let ret = unsafe {
        NetUserGetInfo(server_ptr, user_w.as_ptr(), 2, &mut buf)
    };
    if ret != 0 {
        anyhow::bail!("NetUserGetInfo: error {}", ret);
    }
    let _guard = NetApiBuf(buf);
    let info = unsafe { &*(buf as *const USER_INFO_2) };

    let flags = info.usri2_flags;
    let disabled = if flags & UF_ACCOUNTDISABLE != 0 { "Yes" } else { "No" };
    let locked = if flags & UF_LOCKOUT != 0 { "Yes" } else { "No" };
    let no_pw = if flags & UF_PASSWD_NOTREQD != 0 { "Yes" } else { "No" };
    let pw_cant_change = if flags & UF_PASSWD_CANT_CHANGE != 0 { "Yes" } else { "No" };

    Ok(format!(
        "User name                    {}\n\
         Full name                    {}\n\
         Comment                      {}\n\
         User's comment               {}\n\
         Account disabled             {}\n\
         Account locked out           {}\n\
         Password not required        {}\n\
         Password can't change        {}\n\
         Home directory               {}\n\
         Logon script                 {}\n\
         Last logon                   {}\n\
         Privilege                    {}\n\
         Country/region code          {}\n\
         Bad password count           {}\n\
         Number of logons             {}",
        from_wide(info.usri2_name),
        from_wide(info.usri2_full_name),
        from_wide(info.usri2_comment),
        from_wide(info.usri2_usr_comment),
        disabled, locked, no_pw, pw_cant_change,
        from_wide(info.usri2_home_dir),
        from_wide(info.usri2_script_path),
        info.usri2_last_logon,
        info.usri2_priv,
        info.usri2_country_code,
        info.usri2_bad_pw_count,
        info.usri2_num_logons,
    ))
}

#[cfg(not(windows))]
pub fn netuser(args: &[String]) -> anyhow::Result<String> {
    let username = args.first()
        .ok_or_else(|| anyhow::anyhow!("netuser: <username> required"))?;
    let (stdout, stderr) = crate::exec::exec("getent", &["passwd".into(), username.clone()]);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr); }
    if stdout.is_empty() { Ok(format!("User '{}' not found", username)) } else { Ok(stdout) }
}

// ── netGroupList ─────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn net_group_list(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let server = args.first();
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    let ret = unsafe {
        NetGroupEnum(
            server_ptr, 0, &mut buf,
            0xFFFFFFFF, // MAX_PREFERRED_LENGTH
            &mut entries_read, &mut total_entries,
            std::ptr::null_mut(),
        )
    };
    if ret != 0 && ret != 234 { // 234 = ERROR_MORE_DATA
        anyhow::bail!("NetGroupEnum: error {}", ret);
    }
    let _guard = NetApiBuf(buf);

    let mut out = String::from("Group accounts:\n");
    let entries = unsafe {
        std::slice::from_raw_parts(buf as *const GROUP_INFO_0, entries_read as usize)
    };
    for e in entries {
        out.push_str(&format!("  *{}\n", from_wide(e.grpi0_name)));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn net_group_list(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("getent", &["group".into()]);
    Ok(stdout)
}

// ── netGroupListMembers ──────────────────────────────────────────────────────

#[cfg(windows)]
pub fn net_group_list_members(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let group = args.first()
        .ok_or_else(|| anyhow::anyhow!("netgrouplistmembers: <group> [server] required"))?;
    let server = args.get(1);

    let group_w = to_wide(group);
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    let ret = unsafe {
        NetGroupGetUsers(
            server_ptr, group_w.as_ptr(), 0, &mut buf,
            0xFFFFFFFF, &mut entries_read, &mut total_entries,
            std::ptr::null_mut(),
        )
    };
    if ret != 0 && ret != 234 {
        anyhow::bail!("NetGroupGetUsers: error {}", ret);
    }
    let _guard = NetApiBuf(buf);

    let mut out = format!("Members of {}:\n", group);
    let entries = unsafe {
        std::slice::from_raw_parts(buf as *const GROUP_USERS_INFO_0, entries_read as usize)
    };
    for e in entries {
        out.push_str(&format!("  {}\n", from_wide(e.grui0_name)));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn net_group_list_members(args: &[String]) -> anyhow::Result<String> {
    let group = args.first()
        .ok_or_else(|| anyhow::anyhow!("netgrouplistmembers: <group> required"))?;
    let (stdout, _) = crate::exec::exec("getent", &["group".into(), group.clone()]);
    Ok(stdout)
}

// ── netLocalGroupList ────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn net_local_group_list(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let server = args.first();
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    let ret = unsafe {
        NetLocalGroupEnum(
            server_ptr, 0, &mut buf,
            0xFFFFFFFF, &mut entries_read, &mut total_entries,
            std::ptr::null_mut(),
        )
    };
    if ret != 0 && ret != 234 {
        anyhow::bail!("NetLocalGroupEnum: error {}", ret);
    }
    let _guard = NetApiBuf(buf);

    let mut out = String::from("Local group accounts:\n");
    let entries = unsafe {
        std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_0, entries_read as usize)
    };
    for e in entries {
        out.push_str(&format!("  *{}\n", from_wide(e.lgrpi0_name)));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn net_local_group_list(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("getent", &["group".into()]);
    Ok(stdout)
}

// ── netLocalGroupListMembers ─────────────────────────────────────────────────

#[cfg(windows)]
pub fn net_local_group_list_members(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let group = args.first()
        .ok_or_else(|| anyhow::anyhow!("netlocalgrouplistmembers: <group> [server] required"))?;
    let server = args.get(1);

    let group_w = to_wide(group);
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    let ret = unsafe {
        NetLocalGroupGetMembers(
            server_ptr, group_w.as_ptr(), 3, &mut buf,
            0xFFFFFFFF, &mut entries_read, &mut total_entries,
            std::ptr::null_mut(),
        )
    };
    if ret != 0 && ret != 234 {
        anyhow::bail!("NetLocalGroupGetMembers: error {}", ret);
    }
    let _guard = NetApiBuf(buf);

    let mut out = format!("Members of {} (local):\n", group);
    let entries = unsafe {
        std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_3, entries_read as usize)
    };
    for e in entries {
        out.push_str(&format!("  {}\n", from_wide(e.lgrmi3_domainandname)));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn net_local_group_list_members(args: &[String]) -> anyhow::Result<String> {
    let group = args.first()
        .ok_or_else(|| anyhow::anyhow!("netlocalgrouplistmembers: <group> required"))?;
    let (stdout, _) = crate::exec::exec("getent", &["group".into(), group.clone()]);
    Ok(stdout)
}

// ── netloggedon ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netloggedon(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::RemoteDesktop::*;

    let server = args.first();

    let h_server: HANDLE = if let Some(s) = server {
        let s_w = to_wide(s);
        unsafe { WTSOpenServerW(s_w.as_ptr()) }
    } else {
        0 as HANDLE // WTS_CURRENT_SERVER_HANDLE
    };

    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;

    let ok = unsafe { WTSEnumerateSessionsW(h_server, 0, 1, &mut info, &mut count) };
    if ok == 0 {
        if server.is_some() && !h_server.is_null() {
            unsafe { WTSCloseServer(h_server) };
        }
        return Err(win::last_error("WTSEnumerateSessionsW"));
    }

    let sessions = unsafe { std::slice::from_raw_parts(info, count as usize) };
    let mut out = format!("{:<8} {:<20} {:<15} {}\n", "ID", "Station", "State", "User");
    out.push_str(&"-".repeat(60));
    out.push('\n');

    for s in sessions {
        let station = from_wide(s.pWinStationName);
        let state = wts_state_str(s.State);

        // Get username for this session
        let mut user_buf: *mut u16 = std::ptr::null_mut();
        let mut user_len: u32 = 0;
        let user = unsafe {
            if WTSQuerySessionInformationW(h_server, s.SessionId, WTSUserName, &mut user_buf as *mut _ as *mut *mut u16, &mut user_len) != 0 {
                let u = from_wide(user_buf);
                WTSFreeMemory(user_buf as *mut std::ffi::c_void);
                u
            } else {
                String::new()
            }
        };

        out.push_str(&format!("{:<8} {:<20} {:<15} {}\n", s.SessionId, station, state, user));
    }

    unsafe { WTSFreeMemory(info as *mut std::ffi::c_void) };
    if server.is_some() && !h_server.is_null() {
        unsafe { WTSCloseServer(h_server) };
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn netloggedon(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("who", &[]);
    Ok(stdout)
}

// ── netsession ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netsession(args: &[String]) -> anyhow::Result<String> {
    // NetSessionEnum is not in windows-sys — load dynamically from netapi32.dll
    type NetSessionEnumFn = unsafe extern "system" fn(
        *const u16, *const u16, *const u16, u32, *mut *mut u8,
        u32, *mut u32, *mut u32, *mut u32,
    ) -> u32;

    #[repr(C)]
    struct SessionInfo10 {
        sesi10_cname: *const u16,
        sesi10_username: *const u16,
        sesi10_time: u32,
        sesi10_idle_time: u32,
    }

    let net_session_enum: NetSessionEnumFn = unsafe {
        win::get_proc("netapi32.dll", "NetSessionEnum")?
    };

    let server = args.first();
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume: u32 = 0;

    let ret = unsafe {
        net_session_enum(
            server_ptr,
            std::ptr::null(),
            std::ptr::null(),
            10,
            &mut buf,
            0xFFFFFFFF,
            &mut entries_read,
            &mut total_entries,
            &mut resume,
        )
    };
    if ret != 0 {
        anyhow::bail!("NetSessionEnum: error {}", ret);
    }
    let _guard = NetApiBuf(buf);

    let mut out = format!("{:<30} {:<20} {:<10} {}\n", "Client", "User", "Time", "Idle");
    out.push_str(&"-".repeat(70));
    out.push('\n');

    let entries = unsafe {
        std::slice::from_raw_parts(buf as *const SessionInfo10, entries_read as usize)
    };
    for e in entries {
        out.push_str(&format!("{:<30} {:<20} {:<10} {}\n",
            from_wide(e.sesi10_cname),
            from_wide(e.sesi10_username),
            e.sesi10_time,
            e.sesi10_idle_time,
        ));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn netsession(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("netsession: Windows only")
}

// ── whoami ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn whoami(_args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::System::SystemInformation::*;
    use windows_sys::Win32::Foundation::LUID;

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(win::last_error("OpenProcessToken"));
        }
        let _guard = WinHandle(token);

        let mut out = String::new();

        // ── User ────────────────────────────────────────────────────────
        let mut user_buf = vec![0u8; 256];
        let mut user_len = 256u32;
        if GetTokenInformation(token, TokenUser, user_buf.as_mut_ptr() as *mut std::ffi::c_void, user_len, &mut user_len) != 0 {
            let tu = &*(user_buf.as_ptr() as *const TOKEN_USER);
            let (name, domain) = lookup_sid(tu.User.Sid);
            let sid_str = sid_to_string(tu.User.Sid);
            out.push_str(&format!("USER INFORMATION\n----------------\n{}\\{}\nSID: {}\n\n", domain, name, sid_str));
        }

        // ── Computer names ──────────────────────────────────────────────
        out.push_str("COMPUTER INFORMATION\n--------------------\n");
        for (label, name_type) in &[
            ("NetBIOS Name   ", ComputerNameNetBIOS),
            ("DNS Hostname   ", ComputerNameDnsHostname),
            ("DNS Domain     ", ComputerNameDnsDomain),
            ("DNS FQDN       ", ComputerNameDnsFullyQualified),
        ] {
            let mut buf = vec![0u16; 256];
            let mut len = 256u32;
            if GetComputerNameExW(*name_type, buf.as_mut_ptr(), &mut len) != 0 {
                let val = String::from_utf16_lossy(&buf[..len as usize]);
                if !val.is_empty() {
                    out.push_str(&format!("{}: {}\n", label, val));
                }
            }
        }
        out.push('\n');

        // ── Token elevation & integrity ─────────────────────────────────
        out.push_str("TOKEN INFORMATION\n-----------------\n");

        // Elevation status
        let mut elev: TOKEN_ELEVATION = std::mem::zeroed();
        let mut elev_len = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        if GetTokenInformation(token, TokenElevation,
            &mut elev as *mut _ as *mut std::ffi::c_void,
            elev_len, &mut elev_len) != 0
        {
            out.push_str(&format!("Elevated       : {}\n",
                if elev.TokenIsElevated != 0 { "Yes" } else { "No" }));
        }

        // Elevation type
        let mut elev_type: TOKEN_ELEVATION_TYPE = 0;
        let mut et_len = std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32;
        if GetTokenInformation(token, TokenElevationType,
            &mut elev_type as *mut _ as *mut std::ffi::c_void,
            et_len, &mut et_len) != 0
        {
            let desc = match elev_type {
                1 => "Default (no UAC split token)",
                2 => "Full (elevated admin token)",
                3 => "Limited (filtered standard user token)",
                _ => "Unknown",
            };
            out.push_str(&format!("Elevation Type : {}\n", desc));
        }

        // Integrity level
        let mut il_len = 0u32;
        GetTokenInformation(token, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut il_len);
        if il_len > 0 {
            let mut il_buf = vec![0u8; il_len as usize];
            if GetTokenInformation(token, TokenIntegrityLevel,
                il_buf.as_mut_ptr() as *mut std::ffi::c_void,
                il_len, &mut il_len) != 0
            {
                let tml = &*(il_buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
                let sub_count = *GetSidSubAuthorityCount(tml.Label.Sid);
                if sub_count > 0 {
                    let rid = *GetSidSubAuthority(tml.Label.Sid, (sub_count - 1) as u32);
                    let level = match rid {
                        0x0000 => "Untrusted",
                        0x1000 => "Low",
                        0x2000 => "Medium",
                        0x2100 => "Medium Plus",
                        0x3000 => "High",
                        0x4000 => "System",
                        _      => "Unknown",
                    };
                    out.push_str(&format!("Integrity Level: {} (0x{:04x})\n", level, rid));
                }
            }
        }

        // Session ID
        let mut session_id: u32 = 0;
        let mut sid_len = 4u32;
        if GetTokenInformation(token, TokenSessionId,
            &mut session_id as *mut _ as *mut std::ffi::c_void,
            sid_len, &mut sid_len) != 0
        {
            out.push_str(&format!("Session ID     : {}\n", session_id));
        }

        // Process ID & image
        out.push_str(&format!("Process ID     : {}\n", std::process::id()));
        if let Ok(path) = std::env::current_exe() {
            out.push_str(&format!("Image Path     : {}\n", path.display()));
        }
        out.push('\n');

        // ── Groups ──────────────────────────────────────────────────────
        let mut grp_len = 0u32;
        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut grp_len);
        let mut grp_buf = vec![0u8; grp_len as usize];
        if GetTokenInformation(token, TokenGroups, grp_buf.as_mut_ptr() as *mut std::ffi::c_void, grp_len, &mut grp_len) != 0 {
            let tg = &*(grp_buf.as_ptr() as *const TOKEN_GROUPS);
            let groups = std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize);
            out.push_str("GROUP INFORMATION\n-----------------\n");
            for g in groups {
                let (name, domain) = lookup_sid(g.Sid);
                let attrs = group_attr_str(g.Attributes);
                out.push_str(&format!("{}\\{}  {}\n", domain, name, attrs));
            }
            out.push('\n');
        }

        // ── Privileges ──────────────────────────────────────────────────
        let mut priv_len = 0u32;
        GetTokenInformation(token, TokenPrivileges, std::ptr::null_mut(), 0, &mut priv_len);
        let mut priv_buf = vec![0u8; priv_len as usize];
        if GetTokenInformation(token, TokenPrivileges, priv_buf.as_mut_ptr() as *mut std::ffi::c_void, priv_len, &mut priv_len) != 0 {
            let tp = &*(priv_buf.as_ptr() as *const TOKEN_PRIVILEGES);
            let privs = std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize);
            out.push_str("PRIVILEGES INFORMATION\n----------------------\n");
            for p in privs {
                let mut name_buf = vec![0u16; 128];
                let mut name_len = 128u32;
                if LookupPrivilegeNameW(std::ptr::null(), &p.Luid as *const LUID, name_buf.as_mut_ptr(), &mut name_len) != 0 {
                    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                    let status = if p.Attributes & SE_PRIVILEGE_ENABLED != 0 { "Enabled" } else { "Disabled" };
                    out.push_str(&format!("{:<40} {}\n", name, status));
                }
            }
            out.push('\n');
        }

        // ── Key environment variables (from PEB, no child process) ─────
        out.push_str("ENVIRONMENT\n-----------\n");
        for key in &[
            "USERDOMAIN", "USERDNSDOMAIN", "LOGONSERVER",
            "COMPUTERNAME", "SYSTEMROOT", "USERPROFILE",
            "APPDATA", "TEMP", "OS", "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS", "COMSPEC",
        ] {
            if let Ok(val) = std::env::var(key) {
                out.push_str(&format!("{:<24} = {}\n", key, val));
            }
        }

        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn whoami(_args: &[String]) -> anyhow::Result<String> {
    // Pure API — no child processes
    let mut out = String::new();

    out.push_str("USER INFORMATION\n----------------\n");
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let egid = unsafe { libc::getegid() };

    if let Ok(user) = std::env::var("USER") {
        out.push_str(&format!("User: {}\n", user));
    }
    out.push_str(&format!("UID: {} (EUID: {})\n", uid, euid));
    out.push_str(&format!("GID: {} (EGID: {})\n", gid, egid));

    // Hostname
    let mut host_buf = vec![0u8; 256];
    if unsafe { libc::gethostname(host_buf.as_mut_ptr() as *mut i8, 256) } == 0 {
        let hostname = unsafe { std::ffi::CStr::from_ptr(host_buf.as_ptr() as *const i8) };
        out.push_str(&format!("Hostname: {}\n", hostname.to_string_lossy()));
    }

    out.push_str(&format!("PID: {}\n", std::process::id()));
    if let Ok(path) = std::env::current_exe() {
        out.push_str(&format!("Image: {}\n", path.display()));
    }
    out.push('\n');

    out.push_str("ENVIRONMENT\n-----------\n");
    for key in &["USER", "HOME", "SHELL", "PATH", "LANG", "TERM", "DISPLAY", "SSH_CLIENT"] {
        if let Ok(val) = std::env::var(key) {
            out.push_str(&format!("{:<16} = {}\n", key, val));
        }
    }

    Ok(out)
}

// ── enumLocalSessions ────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn enum_local_sessions(_args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::RemoteDesktop::*;

    let h_server: HANDLE = 0 as HANDLE; // WTS_CURRENT_SERVER_HANDLE
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;

    let ok = unsafe { WTSEnumerateSessionsW(h_server, 0, 1, &mut info, &mut count) };
    if ok == 0 {
        return Err(win::last_error("WTSEnumerateSessionsW"));
    }

    let sessions = unsafe { std::slice::from_raw_parts(info, count as usize) };
    let mut out = format!("{:<8} {:<20} {:<15} {}\n", "ID", "Station", "State", "User");
    out.push_str(&"-".repeat(60));
    out.push('\n');

    for s in sessions {
        let station = from_wide(s.pWinStationName);
        let state = wts_state_str(s.State);

        let mut user_buf: *mut u16 = std::ptr::null_mut();
        let mut user_len: u32 = 0;
        let user = unsafe {
            if WTSQuerySessionInformationW(h_server, s.SessionId, WTSUserName, &mut user_buf as *mut _ as *mut *mut u16, &mut user_len) != 0 {
                let u = from_wide(user_buf);
                WTSFreeMemory(user_buf as *mut std::ffi::c_void);
                u
            } else {
                String::new()
            }
        };

        out.push_str(&format!("{:<8} {:<20} {:<15} {}\n", s.SessionId, station, state, user));
    }

    unsafe { WTSFreeMemory(info as *mut std::ffi::c_void) };
    Ok(out)
}

#[cfg(not(windows))]
pub fn enum_local_sessions(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("who", &[]);
    Ok(stdout)
}

// ── Internal helpers ─────────────────────────────────────────────────────────

#[cfg(windows)]
fn wts_state_str(state: i32) -> &'static str {
    use windows_sys::Win32::System::RemoteDesktop::*;
    match state {
        WTSActive => "Active",
        WTSConnected => "Connected",
        WTSConnectQuery => "ConnectQuery",
        WTSShadow => "Shadow",
        WTSDisconnected => "Disconnected",
        WTSIdle => "Idle",
        WTSListen => "Listen",
        WTSReset => "Reset",
        WTSDown => "Down",
        WTSInit => "Init",
        _ => "Unknown",
    }
}

#[cfg(windows)]
unsafe fn lookup_sid(sid: *mut std::ffi::c_void) -> (String, String) {
    use windows_sys::Win32::Security::*;
    let mut name_buf = vec![0u16; 256];
    let mut name_len = 256u32;
    let mut domain_buf = vec![0u16; 256];
    let mut domain_len = 256u32;
    let mut sid_use: SID_NAME_USE = 0;

    if LookupAccountSidW(
        std::ptr::null(), sid,
        name_buf.as_mut_ptr(), &mut name_len,
        domain_buf.as_mut_ptr(), &mut domain_len,
        &mut sid_use,
    ) != 0 {
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
        (name, domain)
    } else {
        ("?".into(), "?".into())
    }
}

#[cfg(windows)]
unsafe fn sid_to_string(sid: *mut std::ffi::c_void) -> String {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut str_ptr: *mut u16 = std::ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut str_ptr) != 0 && !str_ptr.is_null() {
        let s = from_wide(str_ptr);
        windows_sys::Win32::Foundation::LocalFree(str_ptr as *mut std::ffi::c_void);
        s
    } else {
        "?".into()
    }
}

#[cfg(windows)]
fn group_attr_str(attrs: u32) -> &'static str {
    use windows_sys::Win32::System::SystemServices::{SE_GROUP_ENABLED, SE_GROUP_MANDATORY};
    if attrs & (SE_GROUP_ENABLED as u32) != 0 {
        if attrs & (SE_GROUP_MANDATORY as u32) != 0 {
            "Mandatory group, Enabled by default, Enabled group"
        } else {
            "Enabled group"
        }
    } else {
        "Group used for deny only"
    }
}
