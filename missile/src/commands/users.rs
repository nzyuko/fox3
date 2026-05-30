/// User account management commands.
/// Windows: Win32 NetAPI via windows-sys (zero child processes).
/// Linux: useradd/usermod fallback (kept).

#[cfg(windows)]
use super::winapi_helpers::win::{
    to_wide, NetApiBuf,
};

// ── adduser ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn adduser(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("adduser: <username> <password> [server]"))?;
    let password = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("adduser: <username> <password> required"))?;
    let server = args.get(2);

    let user_w = to_wide(username);
    let pass_w = to_wide(password);
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let info = USER_INFO_1 {
        usri1_name: user_w.as_ptr() as *mut u16,
        usri1_password: pass_w.as_ptr() as *mut u16,
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: std::ptr::null_mut(),
        usri1_comment: std::ptr::null_mut(),
        usri1_flags: UF_SCRIPT | UF_NORMAL_ACCOUNT,
        usri1_script_path: std::ptr::null_mut(),
    };

    let mut parm_err: u32 = 0;
    let ret = unsafe {
        NetUserAdd(server_ptr, 1, &info as *const _ as *const u8, &mut parm_err)
    };
    if ret != 0 {
        anyhow::bail!("NetUserAdd: error {} (parm {})", ret, parm_err);
    }
    Ok(format!("User '{}' created", username))
}

#[cfg(not(windows))]
pub fn adduser(args: &[String]) -> anyhow::Result<String> {
    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("adduser: <username> <password> [server]"))?;
    let password = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("adduser: <username> <password> required"))?;
    let (_, stderr) = crate::exec::exec("useradd", &[username.clone()]);
    if !stderr.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    let (stdout, stderr2) = crate::exec::exec("sh", &[
        "-c".into(), format!("echo '{}:{}' | chpasswd", username, password),
    ]);
    if !stderr2.is_empty() { anyhow::bail!("{}", stderr2.trim()); }
    Ok(if stdout.is_empty() { format!("User '{}' created", username) } else { stdout })
}

// ── enableuser ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn enableuser(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("enableuser: <username> [server]"))?;
    let server = args.get(1);

    set_user_flag(username, server.map(|s| s.as_str()), UF_ACCOUNTDISABLE, false)?;
    Ok(format!("User '{}' enabled", username))
}

#[cfg(not(windows))]
pub fn enableuser(args: &[String]) -> anyhow::Result<String> {
    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("enableuser: <username> [server]"))?;
    let (_, stderr) = crate::exec::exec("usermod", &["--unlock".into(), username.clone()]);
    if !stderr.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    let (_, _) = crate::exec::exec("usermod", &["--expiredate=".into(), username.clone()]);
    Ok(format!("User '{}' enabled", username))
}

// ── disableuser ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn disableuser(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("disableuser: <username> [server]"))?;
    let server = args.get(1);

    set_user_flag(username, server.map(|s| s.as_str()), UF_ACCOUNTDISABLE, true)?;
    Ok(format!("User '{}' disabled", username))
}

#[cfg(not(windows))]
pub fn disableuser(args: &[String]) -> anyhow::Result<String> {
    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("disableuser: <username> [server]"))?;
    let (_, stderr) = crate::exec::exec("usermod", &["--lock".into(), username.clone()]);
    if !stderr.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(format!("User '{}' disabled", username))
}

// ── setuserpass ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn setuserpass(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("setuserpass: <username> <password> [server]"))?;
    let password = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("setuserpass: <username> <password> required"))?;
    let server = args.get(2);

    let user_w = to_wide(username);
    let pass_w = to_wide(password);
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let info = USER_INFO_1003 {
        usri1003_password: pass_w.as_ptr() as *mut u16,
    };

    let ret = unsafe {
        NetUserSetInfo(server_ptr, user_w.as_ptr(), 1003, &info as *const _ as *const u8, std::ptr::null_mut())
    };
    if ret != 0 {
        anyhow::bail!("NetUserSetInfo(1003): error {}", ret);
    }
    Ok(format!("Password set for '{}'", username))
}

#[cfg(not(windows))]
pub fn setuserpass(args: &[String]) -> anyhow::Result<String> {
    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("setuserpass: <username> <password> required"))?;
    let password = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("setuserpass: <username> <password> required"))?;
    let (stdout, stderr) = crate::exec::exec("sh", &[
        "-c".into(), format!("echo '{}:{}' | chpasswd", username, password),
    ]);
    if !stderr.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(if stdout.is_empty() { format!("Password set for '{}'", username) } else { stdout })
}

// ── unexpireuser ─────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn unexpireuser(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("unexpireuser: <username> [server]"))?;
    let server = args.get(1);

    let user_w = to_wide(username);
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    // Set account expiry to TIMEQ_FOREVER (0xFFFFFFFF)
    let info = USER_INFO_1017 {
        usri1017_acct_expires: 0xFFFFFFFF,
    };

    let ret = unsafe {
        NetUserSetInfo(server_ptr, user_w.as_ptr(), 1017, &info as *const _ as *const u8, std::ptr::null_mut())
    };
    if ret != 0 {
        anyhow::bail!("NetUserSetInfo(1017): error {}", ret);
    }

    // Also enable the user
    set_user_flag(username, server.map(|s| s.as_str()), UF_ACCOUNTDISABLE, false)?;
    Ok(format!("User '{}' unexpired and enabled", username))
}

#[cfg(not(windows))]
pub fn unexpireuser(args: &[String]) -> anyhow::Result<String> {
    let username = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("unexpireuser: <username> [server]"))?;
    let (_, stderr) = crate::exec::exec("usermod", &["--expiredate=".into(), "--unlock".into(), username.clone()]);
    if !stderr.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(format!("User '{}' unexpired", username))
}

// ── addusertogroup ───────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn addusertogroup(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let user = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("addusertogroup: <user> <group> [server]"))?;
    let group = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("addusertogroup: <user> <group> required"))?;
    let server = args.get(2);

    let group_w = to_wide(group);
    let user_w = to_wide(user);
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let member = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: user_w.as_ptr() as *mut u16,
    };

    let ret = unsafe {
        NetLocalGroupAddMembers(
            server_ptr, group_w.as_ptr(), 3,
            &member as *const _ as *const u8, 1,
        )
    };
    if ret != 0 {
        // Try domain group
        let ret2 = unsafe {
            NetGroupAddUser(server_ptr, group_w.as_ptr(), user_w.as_ptr())
        };
        if ret2 != 0 {
            anyhow::bail!("NetLocalGroupAddMembers/NetGroupAddUser: errors {}/{}", ret, ret2);
        }
    }
    Ok(format!("Added '{}' to group '{}'", user, group))
}

#[cfg(not(windows))]
pub fn addusertogroup(args: &[String]) -> anyhow::Result<String> {
    let user = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("addusertogroup: <user> <group> required"))?;
    let group = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("addusertogroup: <user> <group> required"))?;
    let (_, stderr) = crate::exec::exec("usermod", &["-aG".into(), group.clone(), user.clone()]);
    if !stderr.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(format!("Added '{}' to group '{}'", user, group))
}

// ── Internal helpers ─────────────────────────────────────────────────────────

#[cfg(windows)]
fn set_user_flag(username: &str, server: Option<&str>, flag: u32, set: bool) -> anyhow::Result<()> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let user_w = to_wide(username);
    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    // Get current info
    let mut buf: *mut u8 = std::ptr::null_mut();
    let ret = unsafe { NetUserGetInfo(server_ptr, user_w.as_ptr(), 1, &mut buf) };
    if ret != 0 {
        anyhow::bail!("NetUserGetInfo: error {}", ret);
    }
    let _guard = NetApiBuf(buf);

    let info = unsafe { &*(buf as *const USER_INFO_1) };
    let new_flags = if set {
        info.usri1_flags | flag
    } else {
        info.usri1_flags & !flag
    };

    let update = USER_INFO_1008 { usri1008_flags: new_flags };
    let ret = unsafe {
        NetUserSetInfo(server_ptr, user_w.as_ptr(), 1008, &update as *const _ as *const u8, std::ptr::null_mut())
    };
    if ret != 0 {
        anyhow::bail!("NetUserSetInfo(1008): error {}", ret);
    }
    Ok(())
}
