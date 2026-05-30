/// Privilege escalation checks — based on PrivKit BOF collection.
/// All Windows only. Each check uses native Win32 API — zero child processes.

// ── privcheck (run all) ─────────────────────────────────────────────────────

pub fn privcheck(_args: &[String]) -> anyhow::Result<String> {
    if !cfg!(windows) { anyhow::bail!("privcheck: Windows only"); }

    let checks: Vec<(&str, fn(&[String]) -> anyhow::Result<String>)> = vec![
        ("AlwaysInstallElevated", alwaysinstallelevated as fn(&[String]) -> anyhow::Result<String>),
        ("Autologon Credentials", autologoncheck),
        ("Credential Manager", credmancheck),
        ("Hijackable PATH", hijackablepathcheck),
        ("Modifiable Autoruns", modifiableautoruncheck),
        ("Modifiable Services", modifiablesvccheck),
        ("Token Privileges", tokenprivcheck),
        ("Unquoted Service Paths", unquotedsvcpathcheck),
        ("PowerShell History", pshistorycheck),
        ("UAC Status", uacstatuscheck),
    ];

    let mut out = String::from("=== Fox3 Privilege Escalation Assessment ===\n\n");
    let empty: Vec<String> = vec![];

    for (name, func) in &checks {
        out.push_str(&format!("--- {} ---\n", name));
        match func(&empty) {
            Ok(result) => {
                out.push_str(&result);
                if !result.ends_with('\n') { out.push('\n'); }
            }
            Err(e) => {
                out.push_str(&format!("Error: {}\n", e));
            }
        }
        out.push('\n');
    }

    out.push_str("=== Assessment Complete ===\n");
    Ok(out)
}

// ── Helper: read a DWORD from registry, returns None if not found ────────────

#[cfg(windows)]
fn reg_read_dword(hive: windows_sys::Win32::System::Registry::HKEY, subkey: &str, value_name: &str) -> Option<u32> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Registry::*;

    let subkey_w = win::to_wide(subkey);
    let mut key: win::HKEY = std::ptr::null_mut();
    let ret = unsafe {
        RegOpenKeyExW(hive, subkey_w.as_ptr(), 0, KEY_READ, &mut key)
    };
    if ret != 0 { return None; }
    let _guard = win::RegKeyHandle(key);

    let name_w = win::to_wide(value_name);
    let mut dtype: u32 = 0;
    let mut val: u32 = 0;
    let mut size = 4u32;
    let ret = unsafe {
        RegQueryValueExW(key, name_w.as_ptr(), std::ptr::null(), &mut dtype, &mut val as *mut u32 as *mut u8, &mut size)
    };
    if ret == 0 { Some(val) } else { None }
}

#[cfg(windows)]
fn reg_read_string(hive: windows_sys::Win32::System::Registry::HKEY, subkey: &str, value_name: &str) -> Option<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Registry::*;

    let subkey_w = win::to_wide(subkey);
    let mut key: win::HKEY = std::ptr::null_mut();
    let ret = unsafe {
        RegOpenKeyExW(hive, subkey_w.as_ptr(), 0, KEY_READ, &mut key)
    };
    if ret != 0 { return None; }
    let _guard = win::RegKeyHandle(key);

    let name_w = win::to_wide(value_name);
    let mut dtype: u32 = 0;
    let mut size: u32 = 0;
    let ret = unsafe {
        RegQueryValueExW(key, name_w.as_ptr(), std::ptr::null(), &mut dtype, std::ptr::null_mut(), &mut size)
    };
    if ret != 0 || size == 0 { return None; }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        RegQueryValueExW(key, name_w.as_ptr(), std::ptr::null(), &mut dtype, buf.as_mut_ptr(), &mut size)
    };
    if ret != 0 { return None; }
    Some(win::format_reg_data(dtype, &buf))
}

// ── alwaysinstallelevated ───────────────────────────────────────────────────

#[cfg(windows)]
pub fn alwaysinstallelevated(_args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Registry::*;

    let hklm_val = reg_read_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated");
    let hkcu_val = reg_read_dword(HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated");

    let hklm_str = match hklm_val {
        Some(1) => "ENABLED [!]",
        Some(v) => return Ok(format!("HKLM AlwaysInstallElevated: {}\nHKCU AlwaysInstallElevated: {}\n[OK] AlwaysInstallElevated is not exploitable.", v, hkcu_val.unwrap_or(0))),
        None => "Not set",
    };
    let hkcu_str = match hkcu_val {
        Some(1) => "ENABLED [!]",
        Some(_) => "Set but not 1",
        None => "Not set",
    };

    let mut out = format!("HKLM AlwaysInstallElevated: {}\nHKCU AlwaysInstallElevated: {}\n", hklm_str, hkcu_str);
    if hklm_val == Some(1) && hkcu_val == Some(1) {
        out.push_str("[VULNERABLE] Both HKLM and HKCU AlwaysInstallElevated are set. Any user can install MSI as SYSTEM.\n");
    } else {
        out.push_str("[OK] AlwaysInstallElevated is not exploitable (both keys must be set to 1).\n");
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn alwaysinstallelevated(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("alwaysinstallelevated: Windows only")
}

// ── autologoncheck ──────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn autologoncheck(_args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Registry::*;

    let winlogon = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    let auto_logon = reg_read_string(HKEY_LOCAL_MACHINE, winlogon, "AutoAdminLogon");
    let def_user = reg_read_string(HKEY_LOCAL_MACHINE, winlogon, "DefaultUserName");
    let def_pass = reg_read_string(HKEY_LOCAL_MACHINE, winlogon, "DefaultPassword");
    let def_domain = reg_read_string(HKEY_LOCAL_MACHINE, winlogon, "DefaultDomainName");
    let alt_user = reg_read_string(HKEY_LOCAL_MACHINE, winlogon, "AltDefaultUserName");
    let alt_pass = reg_read_string(HKEY_LOCAL_MACHINE, winlogon, "AltDefaultPassword");

    let mut out = format!(
        "AutoAdminLogon : {}\nDefaultDomain  : {}\nDefaultUserName: {}\nDefaultPassword: {}\n",
        auto_logon.as_deref().unwrap_or("Not set"),
        def_domain.as_deref().unwrap_or("Not set"),
        def_user.as_deref().unwrap_or("Not set"),
        def_pass.as_deref().unwrap_or("Not set"),
    );

    if alt_user.is_some() || alt_pass.is_some() {
        out.push_str(&format!("AltDefaultUser : {}\nAltDefaultPass : {}\n",
            alt_user.as_deref().unwrap_or("Not set"),
            alt_pass.as_deref().unwrap_or("Not set"),
        ));
    }

    if auto_logon.as_deref() == Some("1") && def_pass.is_some() {
        out.push_str("[VULNERABLE] Autologon enabled with stored plaintext credentials!\n");
    } else if auto_logon.as_deref() == Some("1") {
        out.push_str("[INFO] Autologon enabled but no DefaultPassword found (may use LSA secret).\n");
    } else {
        out.push_str("[OK] Autologon is not enabled.\n");
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn autologoncheck(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("autologoncheck: Windows only")
}

// ── credmancheck ────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn credmancheck(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use std::ffi::c_void;

    // CredEnumerateW, CredFree from advapi32.dll
    type CredEnumerateWFn = unsafe extern "system" fn(
        filter: *const u16,
        flags: u32,
        count: *mut u32,
        credentials: *mut *mut *mut c_void,
    ) -> i32;
    type CredFreeFn = unsafe extern "system" fn(buffer: *mut c_void);

    // CREDENTIAL structure layout
    #[repr(C)]
    #[allow(non_snake_case)]
    struct Credential {
        Flags: u32,
        Type: u32,
        TargetName: *const u16,
        Comment: *const u16,
        LastWritten: u64, // FILETIME
        CredentialBlobSize: u32,
        CredentialBlob: *mut u8,
        Persist: u32,
        AttributeCount: u32,
        Attributes: *mut c_void,
        TargetAlias: *const u16,
        UserName: *const u16,
    }

    let cred_enum: CredEnumerateWFn = unsafe {
        win::get_proc("advapi32.dll", "CredEnumerateW")?
    };
    let cred_free: CredFreeFn = unsafe {
        win::get_proc("advapi32.dll", "CredFree")?
    };

    unsafe {
        let mut count: u32 = 0;
        let mut creds: *mut *mut c_void = std::ptr::null_mut();
        let ret = cred_enum(std::ptr::null(), 0, &mut count, &mut creds);
        if ret == 0 || count == 0 {
            return Ok("[OK] No credentials stored in Credential Manager (or access denied).".into());
        }

        let mut out = format!("Found {} credential(s) in Credential Manager:\n\n", count);
        let ptrs = std::slice::from_raw_parts(creds, count as usize);

        for &ptr in ptrs {
            let cred = &*(ptr as *const Credential);
            let target = if !cred.TargetName.is_null() { win::from_wide(cred.TargetName) } else { "(null)".into() };
            let username = if !cred.UserName.is_null() { win::from_wide(cred.UserName) } else { "(null)".into() };
            let type_str = match cred.Type {
                1 => "Generic",
                2 => "Domain Password",
                3 => "Domain Certificate",
                4 => "Domain Visible Password",
                _ => "Unknown",
            };

            out.push_str(&format!("  Target  : {}\n  Username: {}\n  Type    : {}\n", target, username, type_str));

            if cred.CredentialBlobSize > 0 && !cred.CredentialBlob.is_null() {
                let blob = std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize);
                // Try to interpret as UTF-16
                if blob.len() >= 2 && blob.len() % 2 == 0 {
                    let wide: Vec<u16> = blob.chunks(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let s = String::from_utf16_lossy(&wide);
                    let s = s.trim_end_matches('\0');
                    if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r') {
                        out.push_str(&format!("  Password: {}\n", s));
                    } else {
                        out.push_str(&format!("  Password: (binary, {} bytes)\n", cred.CredentialBlobSize));
                    }
                } else {
                    out.push_str(&format!("  Password: (binary, {} bytes)\n", cred.CredentialBlobSize));
                }
            }
            out.push_str("  ---\n");
        }

        cred_free(creds as *mut _);
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn credmancheck(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("credmancheck: Windows only")
}

// ── hijackablepathcheck ─────────────────────────────────────────────────────

#[cfg(windows)]
pub fn hijackablepathcheck(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Security::*;
    use std::ffi::c_void;

    type GetNamedSecurityInfoWFn = unsafe extern "system" fn(
        name: *const u16, obj_type: u32, info: u32,
        owner: *mut *mut c_void, group: *mut *mut c_void,
        dacl: *mut *mut c_void, sacl: *mut *mut c_void,
        sd: *mut *mut c_void,
    ) -> u32;

    let get_sec_info: GetNamedSecurityInfoWFn = unsafe {
        win::get_proc("advapi32.dll", "GetNamedSecurityInfoW")?
    };

    let path_var = std::env::var("PATH").unwrap_or_default();
    let paths: Vec<&str> = path_var.split(';').filter(|s| !s.is_empty()).collect();

    let mut out = String::new();
    let mut vuln_count = 0;

    // Well-known SIDs for "everyone" and "users"
    let dangerous_sids = ["S-1-1-0", "S-1-5-11", "S-1-5-4", "S-1-5-32-545"]; // Everyone, Authenticated Users, Interactive, Users

    for p in &paths {
        if !std::path::Path::new(p).exists() {
            out.push_str(&format!("  {} -> MISSING (could be created) [!]\n", p));
            vuln_count += 1;
            continue;
        }

        let path_w = win::to_wide(p);
        unsafe {
            let mut dacl: *mut c_void = std::ptr::null_mut();
            let mut sd: *mut c_void = std::ptr::null_mut();
            let ret = get_sec_info(
                path_w.as_ptr(), 1, // SE_FILE_OBJECT
                4, // DACL_SECURITY_INFORMATION
                std::ptr::null_mut(), std::ptr::null_mut(),
                &mut dacl, std::ptr::null_mut(), &mut sd,
            );
            if ret != 0 { continue; }
            let _sd_guard = if !sd.is_null() { Some(sd) } else { None };

            if dacl.is_null() { continue; }

            // Get ACL info
            let acl = dacl as *const ACL;
            let ace_count = (*acl).AceCount as u32;

            for i in 0..ace_count {
                let mut ace_ptr: *mut c_void = std::ptr::null_mut();
                if GetAce(acl as *mut _, i, &mut ace_ptr) == 0 { continue; }

                let ace_header = &*(ace_ptr as *const ACE_HEADER);
                if ace_header.AceType != 0 { continue; } // ACCESS_ALLOWED_ACE_TYPE = 0

                #[repr(C)]
                struct AccessAllowedAce {
                    header: ACE_HEADER,
                    mask: u32,
                    sid_start: u32,
                }
                let ace = &*(ace_ptr as *const AccessAllowedAce);
                let sid = &ace.sid_start as *const u32 as *mut c_void;

                // Check write permissions: FILE_WRITE_DATA (2) | FILE_APPEND_DATA (4) | WRITE_DAC (0x40000) | WRITE_OWNER (0x80000) | GENERIC_WRITE (0x40000000)
                let write_mask = 0x2 | 0x4 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000; // GENERIC_ALL
                if ace.mask & write_mask == 0 { continue; }

                // Convert SID to string
                let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
                if ConvertSidToStringSidW(sid, &mut sid_str_ptr) != 0 && !sid_str_ptr.is_null() {
                    let sid_str = win::from_wide(sid_str_ptr);
                    windows_sys::Win32::Foundation::LocalFree(sid_str_ptr as *mut c_void);

                    for ds in &dangerous_sids {
                        if sid_str == *ds {
                            out.push_str(&format!("  {} -> WRITABLE by {} (mask: 0x{:08x}) [!]\n", p, sid_str, ace.mask));
                            vuln_count += 1;
                            break;
                        }
                    }
                }
            }

            if !sd.is_null() {
                windows_sys::Win32::Foundation::LocalFree(sd);
            }
        }
    }

    if vuln_count == 0 {
        out.push_str("[OK] No writable directories found in PATH.\n");
    } else {
        out.push_str(&format!("\n[VULNERABLE] {} writable PATH director(ies) found. DLL hijacking possible.\n", vuln_count));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn hijackablepathcheck(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("hijackablepathcheck: Windows only")
}

// ── modifiableautoruncheck ──────────────────────────────────────────────────

#[cfg(windows)]
pub fn modifiableautoruncheck(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Registry::*;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Security::*;
    use std::ffi::c_void;

    let autorun_keys: &[(windows_sys::Win32::System::Registry::HKEY, &str)] = &[
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ];

    type GetNamedSecurityInfoWFn = unsafe extern "system" fn(
        *const u16, u32, u32, *mut *mut c_void, *mut *mut c_void,
        *mut *mut c_void, *mut *mut c_void, *mut *mut c_void,
    ) -> u32;
    let get_sec_info: GetNamedSecurityInfoWFn = unsafe {
        win::get_proc("advapi32.dll", "GetNamedSecurityInfoW")?
    };

    let dangerous_sids = ["S-1-1-0", "S-1-5-11", "S-1-5-4", "S-1-5-32-545"];
    let mut out = String::new();
    let mut vuln_count = 0;

    for (hive, subkey) in autorun_keys {
        let subkey_w = win::to_wide(subkey);
        let mut key: win::HKEY = std::ptr::null_mut();
        let ret = unsafe {
            RegOpenKeyExW(*hive, subkey_w.as_ptr(), 0, KEY_READ, &mut key)
        };
        if ret != 0 { continue; }
        let _guard = win::RegKeyHandle(key);

        // Enumerate values
        let mut idx: u32 = 0;
        loop {
            let mut name_buf = [0u16; 512];
            let mut name_len = 512u32;
            let mut data_type: u32 = 0;
            let mut data_size: u32 = 0;

            let ret = unsafe {
                RegEnumValueW(key, idx, name_buf.as_mut_ptr(), &mut name_len,
                    std::ptr::null_mut(), &mut data_type, std::ptr::null_mut(), &mut data_size)
            };
            if ret != 0 { break; }

            name_len = 512;
            let mut data_buf = vec![0u8; data_size as usize];
            let ret = unsafe {
                RegEnumValueW(key, idx, name_buf.as_mut_ptr(), &mut name_len,
                    std::ptr::null_mut(), &mut data_type, data_buf.as_mut_ptr(), &mut data_size)
            };
            idx += 1;
            if ret != 0 { continue; }

            let val_str = win::format_reg_data(data_type, &data_buf);

            // Extract executable path
            let exe_path = if val_str.starts_with('"') {
                val_str[1..].split('"').next().unwrap_or("").to_string()
            } else {
                val_str.split_whitespace().next().unwrap_or("").to_string()
            };

            if exe_path.is_empty() || !std::path::Path::new(&exe_path).exists() { continue; }

            // Check ACL on executable
            let path_w = win::to_wide(&exe_path);
            unsafe {
                let mut dacl: *mut c_void = std::ptr::null_mut();
                let mut sd: *mut c_void = std::ptr::null_mut();
                let ret = get_sec_info(path_w.as_ptr(), 1, 4,
                    std::ptr::null_mut(), std::ptr::null_mut(),
                    &mut dacl, std::ptr::null_mut(), &mut sd);
                if ret != 0 || dacl.is_null() { continue; }

                let acl = dacl as *const ACL;
                let ace_count = (*acl).AceCount as u32;
                let write_mask = 0x2 | 0x4 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000;

                for i in 0..ace_count {
                    let mut ace_ptr: *mut c_void = std::ptr::null_mut();
                    if GetAce(acl as *mut _, i, &mut ace_ptr) == 0 { continue; }
                    let ace_header = &*(ace_ptr as *const ACE_HEADER);
                    if ace_header.AceType != 0 { continue; }

                    #[repr(C)]
                    struct Aaa { header: ACE_HEADER, mask: u32, sid_start: u32 }
                    let ace = &*(ace_ptr as *const Aaa);
                    if ace.mask & write_mask == 0 { continue; }

                    let sid = &ace.sid_start as *const u32 as *mut c_void;
                    let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
                    if ConvertSidToStringSidW(sid, &mut sid_str_ptr) != 0 && !sid_str_ptr.is_null() {
                        let sid_str = win::from_wide(sid_str_ptr);
                        windows_sys::Win32::Foundation::LocalFree(sid_str_ptr as *mut c_void);
                        for ds in &dangerous_sids {
                            if sid_str == *ds {
                                let val_name = win::from_wide(name_buf.as_ptr());
                                out.push_str(&format!("  [!] {}\\{}\n      Path: {}\n      Writable by: {} (mask: 0x{:08x})\n",
                                    subkey, val_name, exe_path, sid_str, ace.mask));
                                vuln_count += 1;
                                break;
                            }
                        }
                    }
                }

                if !sd.is_null() {
                    windows_sys::Win32::Foundation::LocalFree(sd);
                }
            }
        }
    }

    if vuln_count == 0 {
        out.push_str("[OK] No modifiable autorun executables found.\n");
    } else {
        out.push_str(&format!("\n[VULNERABLE] {} modifiable autorun executable(s) found. Binary replacement possible.\n", vuln_count));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn modifiableautoruncheck(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("modifiableautoruncheck: Windows only")
}

// ── modifiablesvccheck ──────────────────────────────────────────────────────

#[cfg(windows)]
pub fn modifiablesvccheck(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Services::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use std::ffi::c_void;

    const READ_CONTROL_ACCESS: u32 = 0x00020000;

    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            anyhow::bail!("OpenSCManagerW failed: {}", win::win32_error_string(
                windows_sys::Win32::Foundation::GetLastError()));
        }
        let _scm_guard = win::ScHandle(scm);

        // Enumerate services
        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        let mut resume: u32 = 0;
        EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, std::ptr::null_mut(), 0, &mut needed, &mut returned, &mut resume, std::ptr::null());

        let mut buf = vec![0u8; needed as usize];
        let ret = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, buf.as_mut_ptr(), needed, &mut needed, &mut returned, &mut resume, std::ptr::null());
        if ret == 0 {
            anyhow::bail!("EnumServicesStatusExW failed");
        }

        let entries = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, returned as usize
        );

        let mut out = String::new();
        let mut vuln_count = 0;

        let dangerous_sids = ["S-1-1-0", "S-1-5-11", "S-1-5-4", "S-1-5-32-545"];

        for entry in entries {
            let svc_name = win::from_wide(entry.lpServiceName);
            let display_name = win::from_wide(entry.lpDisplayName);

            let svc = OpenServiceW(scm, entry.lpServiceName, READ_CONTROL_ACCESS);
            if svc.is_null() { continue; }
            let _svc_guard = win::ScHandle(svc);

            // QueryServiceObjectSecurity for DACL
            let mut sd_size: u32 = 0;
            QueryServiceObjectSecurity(svc, 4,
                std::ptr::null_mut() as *mut c_void, 0, &mut sd_size);
            if sd_size == 0 { continue; }

            let mut sd_buf = vec![0u8; sd_size as usize];
            let ret = QueryServiceObjectSecurity(svc, 4,
                sd_buf.as_mut_ptr() as *mut c_void, sd_size, &mut sd_size);
            if ret == 0 { continue; }

            // Get DACL from SD
            let mut dacl_present: i32 = 0;
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut defaulted: i32 = 0;
            if GetSecurityDescriptorDacl(
                sd_buf.as_ptr() as *const c_void as *mut c_void,
                &mut dacl_present, &mut dacl, &mut defaulted,
            ) == 0 || dacl_present == 0 || dacl.is_null() {
                continue;
            }

            let ace_count = (*dacl).AceCount as u32;
            let dangerous_mask: u32 = 0x2 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000;

            for i in 0..ace_count {
                let mut ace_ptr: *mut c_void = std::ptr::null_mut();
                if GetAce(dacl as *mut _, i, &mut ace_ptr) == 0 { continue; }
                let header = &*(ace_ptr as *const ACE_HEADER);
                if header.AceType != 0 { continue; }

                #[repr(C)]
                struct Aaa { header: ACE_HEADER, mask: u32, sid_start: u32 }
                let ace = &*(ace_ptr as *const Aaa);
                if ace.mask & dangerous_mask == 0 { continue; }

                let sid = &ace.sid_start as *const u32 as *mut c_void;
                let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
                if ConvertSidToStringSidW(sid, &mut sid_str_ptr) != 0 && !sid_str_ptr.is_null() {
                    let sid_str = win::from_wide(sid_str_ptr);
                    windows_sys::Win32::Foundation::LocalFree(sid_str_ptr as *mut c_void);
                    for ds in &dangerous_sids {
                        if sid_str == *ds {
                            out.push_str(&format!("  [!] {}\n      Display: {}\n      SID: {} -> Perms: 0x{:08x}\n",
                                svc_name, display_name, sid_str, ace.mask));
                            vuln_count += 1;
                            break;
                        }
                    }
                }
            }
        }

        if vuln_count == 0 {
            out.push_str("[OK] No services with overly permissive DACLs found.\n");
        } else {
            out.push_str(&format!("\n[VULNERABLE] {} service(s) with modifiable DACLs found.\n", vuln_count));
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn modifiablesvccheck(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("modifiablesvccheck: Windows only")
}

// ── tokenprivcheck ──────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn tokenprivcheck(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use std::ffi::c_void;

    let interesting_privs = [
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeDebugPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege",
        "SeTcbPrivilege",
        "SeCreateTokenPrivilege",
        "SeManageVolumePrivilege",
    ];

    unsafe {
        let mut token: win::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            anyhow::bail!("OpenProcessToken failed");
        }
        let _guard = win::WinHandle(token);

        // Get token privileges
        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenPrivileges, std::ptr::null_mut(), 0, &mut needed);
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(token, TokenPrivileges, buf.as_mut_ptr() as *mut c_void, needed, &mut needed) == 0 {
            anyhow::bail!("GetTokenInformation(TokenPrivileges) failed");
        }

        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let privs = std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize);

        let mut out = format!("{:<40} {}\n", "Privilege", "State");
        out.push_str(&"-".repeat(55));
        out.push('\n');

        let mut found_interesting = Vec::new();

        for priv_entry in privs {
            let mut name_buf = [0u16; 128];
            let mut name_len = 128u32;
            if LookupPrivilegeNameW(std::ptr::null(), &priv_entry.Luid, name_buf.as_mut_ptr(), &mut name_len) == 0 {
                continue;
            }
            let name = win::from_wide(name_buf.as_ptr());
            let enabled = priv_entry.Attributes & SE_PRIVILEGE_ENABLED != 0;
            let state = if enabled { "Enabled" } else { "Disabled" };

            out.push_str(&format!("{:<40} {}\n", name, state));

            for ip in &interesting_privs {
                if name == *ip {
                    found_interesting.push((name.clone(), enabled));
                    break;
                }
            }
        }

        if !found_interesting.is_empty() {
            out.push_str("\n[INFO] Interesting privileges found:\n");
            for (name, enabled) in &found_interesting {
                let state = if *enabled { "ENABLED" } else { "Disabled" };
                out.push_str(&format!("  [!] {} ({})\n", name, state));
            }
            let names: Vec<&str> = found_interesting.iter().map(|(n, _)| n.as_str()).collect();
            if names.iter().any(|n| *n == "SeImpersonatePrivilege" || *n == "SeAssignPrimaryTokenPrivilege") {
                out.push_str("  -> Potato-style attacks (JuicyPotato, PrintSpoofer, GodPotato) may be possible.\n");
            }
            if names.iter().any(|n| *n == "SeDebugPrivilege") {
                out.push_str("  -> Process injection / memory dumping possible (e.g., LSASS).\n");
            }
            if names.iter().any(|n| *n == "SeBackupPrivilege" || *n == "SeRestorePrivilege") {
                out.push_str("  -> Can read/write any file (SAM/SYSTEM hive extraction).\n");
            }
        }

        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn tokenprivcheck(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("tokenprivcheck: Windows only")
}

// ── unquotedsvcpathcheck ────────────────────────────────────────────────────

#[cfg(windows)]
pub fn unquotedsvcpathcheck(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Services::*;

    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            anyhow::bail!("OpenSCManagerW failed");
        }
        let _scm_guard = win::ScHandle(scm);

        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        let mut resume: u32 = 0;
        EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, std::ptr::null_mut(), 0, &mut needed, &mut returned, &mut resume, std::ptr::null());

        let mut buf = vec![0u8; needed as usize];
        let ret = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, buf.as_mut_ptr(), needed, &mut needed, &mut returned, &mut resume, std::ptr::null());
        if ret == 0 {
            anyhow::bail!("EnumServicesStatusExW failed");
        }

        let entries = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, returned as usize
        );

        let mut out = String::new();
        let mut vuln_count = 0;

        for entry in entries {
            let svc_name = win::from_wide(entry.lpServiceName);
            let display_name = win::from_wide(entry.lpDisplayName);

            // Query config for binary path
            let svc = OpenServiceW(scm, entry.lpServiceName, SERVICE_QUERY_CONFIG);
            if svc.is_null() { continue; }
            let _svc_guard = win::ScHandle(svc);

            let mut cfg_needed: u32 = 0;
            QueryServiceConfigW(svc, std::ptr::null_mut(), 0, &mut cfg_needed);
            if cfg_needed == 0 { continue; }

            let mut cfg_buf = vec![0u8; cfg_needed as usize];
            let ret = QueryServiceConfigW(svc, cfg_buf.as_mut_ptr() as *mut _, cfg_needed, &mut cfg_needed);
            if ret == 0 { continue; }

            let cfg = &*(cfg_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
            if cfg.lpBinaryPathName.is_null() { continue; }
            let bin_path = win::from_wide(cfg.lpBinaryPathName);

            // Skip quoted paths
            if bin_path.starts_with('"') { continue; }
            // Skip paths without spaces
            let exe_part = bin_path.split_whitespace().next().unwrap_or("");
            if !bin_path.contains(' ') || exe_part.contains(' ') == false { continue; }
            // Skip System32/SysWOW64 and .sys
            let lower = bin_path.to_lowercase();
            if lower.contains("\\system32\\") || lower.contains("\\syswow64\\") || lower.ends_with(".sys") { continue; }

            let start_mode = match cfg.dwStartType {
                0 => "Boot", 1 => "System", 2 => "Auto", 3 => "Manual", 4 => "Disabled", _ => "Unknown",
            };

            out.push_str(&format!("  [!] {}\n      Display: {}\n      Path   : {}\n      Start  : {}\n",
                svc_name, display_name, bin_path, start_mode));
            vuln_count += 1;
        }

        if vuln_count == 0 {
            out.push_str("[OK] No unquoted service paths with spaces found.\n");
        } else {
            out.push_str(&format!("\n[VULNERABLE] {} service(s) with unquoted paths containing spaces.\n", vuln_count));
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn unquotedsvcpathcheck(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("unquotedsvcpathcheck: Windows only")
}

// ── pshistorycheck ──────────────────────────────────────────────────────────

pub fn pshistorycheck(_args: &[String]) -> anyhow::Result<String> {
    // Pure Rust — no child process needed
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    if appdata.is_empty() {
        return Ok("[OK] APPDATA not set, cannot check PS history.".into());
    }

    let history_path = format!("{}\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", appdata);
    let path = std::path::Path::new(&history_path);

    if !path.exists() {
        return Ok(format!("[OK] No PSReadLine history file found at {}", history_path));
    }

    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();

    let content = std::fs::read_to_string(path).unwrap_or_default();
    let line_count = content.lines().count();

    let mut out = format!("PSReadLine history found: {}\nSize: {:.2} KB ({} bytes)\nTotal lines: {}\n\n",
        history_path, size as f64 / 1024.0, size, line_count);

    // Check for sensitive patterns
    let patterns: &[(&str, &str)] = &[
        ("Passwords", r"(?i)(password|passwd|pwd)\s*[=:]"),
        ("Credentials", r"(?i)(credential|cred|secret|token|apikey|api_key)"),
        ("Net use", r"(?i)net\s+use\s"),
        ("SecureString", r"(?i)ConvertTo-SecureString"),
        ("PSCredential", r"(?i)PSCredential"),
        ("Invoke-Command", r"(?i)Invoke-Command.*-Credential"),
        ("SSH/RDP", r"(?i)(ssh\s|mstsc|Enter-PSSession)"),
    ];

    let mut sensitive_found = false;
    for (name, pattern_str) in patterns {
        // Simple substring match (no regex crate needed for common patterns)
        let keywords: Vec<&str> = match *name {
            "Passwords" => vec!["password", "passwd", "pwd"],
            "Credentials" => vec!["credential", "cred", "secret", "token", "apikey", "api_key"],
            "Net use" => vec!["net use"],
            "SecureString" => vec!["convertto-securestring"],
            "PSCredential" => vec!["pscredential"],
            "Invoke-Command" => vec!["invoke-command"],
            "SSH/RDP" => vec!["ssh ", "mstsc", "enter-pssession"],
            _ => vec![pattern_str],
        };

        let mut matches: Vec<(usize, &str)> = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let lower = line.to_lowercase();
            for kw in &keywords {
                if lower.contains(kw) {
                    matches.push((i + 1, line));
                    break;
                }
            }
        }

        if !matches.is_empty() {
            if !sensitive_found {
                out.push_str("Sensitive patterns found:\n");
                sensitive_found = true;
            }
            out.push_str(&format!("  [{}] {} occurrence(s)\n", name, matches.len()));
            for (line_num, line) in matches.iter().take(3) {
                let trimmed = line.trim();
                let display = if trimmed.len() > 100 { &trimmed[..100] } else { trimmed };
                out.push_str(&format!("    Line {}: {}\n", line_num, display));
            }
        }
    }

    if !sensitive_found {
        out.push_str("[OK] No obvious sensitive patterns found in history.\n");
    }
    Ok(out)
}

// ── uacstatuscheck ──────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn uacstatuscheck(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Registry::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use std::ffi::c_void;

    let pol_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    let enable_lua = reg_read_dword(HKEY_LOCAL_MACHINE, pol_path, "EnableLUA");
    let consent_admin = reg_read_dword(HKEY_LOCAL_MACHINE, pol_path, "ConsentPromptBehaviorAdmin");
    let prompt_secure = reg_read_dword(HKEY_LOCAL_MACHINE, pol_path, "PromptOnSecureDesktop");
    let filter_admin = reg_read_dword(HKEY_LOCAL_MACHINE, pol_path, "FilterAdministratorToken");

    let mut out = String::from("UAC Configuration:\n");
    out.push_str(&format!("  EnableLUA                 : {}\n", match enable_lua {
        Some(1) => "Enabled",
        Some(0) => "DISABLED [!]",
        _ => "Not set (default: Enabled)",
    }));
    out.push_str(&format!("  ConsentPromptBehaviorAdmin: {}\n", match consent_admin {
        Some(0) => "Elevate without prompt [!]",
        Some(1) => "Prompt for credentials on secure desktop",
        Some(2) => "Prompt for consent on secure desktop",
        Some(3) => "Prompt for credentials",
        Some(4) => "Prompt for consent",
        Some(5) => "Prompt for consent for non-Windows binaries (default)",
        _ => "Not set",
    }));
    out.push_str(&format!("  PromptOnSecureDesktop     : {}\n", match prompt_secure {
        Some(1) => "Enabled (default)",
        Some(0) => "DISABLED [!]",
        _ => "Not set",
    }));
    out.push_str(&format!("  FilterAdministratorToken  : {}\n", match filter_admin {
        Some(1) => "Enabled",
        _ => "Disabled (default)",
    }));

    // Check current integrity level and admin status
    unsafe {
        let mut token: win::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0 {
            let _guard = win::WinHandle(token);

            // Get integrity level
            let mut needed: u32 = 0;
            GetTokenInformation(token, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut needed);
            if needed > 0 {
                let mut il_buf = vec![0u8; needed as usize];
                if GetTokenInformation(token, TokenIntegrityLevel, il_buf.as_mut_ptr() as *mut c_void, needed, &mut needed) != 0 {
                    let til = &*(il_buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
                    let sub_auth_count = *(til.Label.Sid as *const u8).add(1) as usize;
                    let sub_auth_ptr = (til.Label.Sid as *const u8).add(8) as *const u32;
                    if sub_auth_count > 0 {
                        let level = *sub_auth_ptr.add(sub_auth_count - 1);
                        let level_str = match level {
                            l if l >= 0x4000 => "System",
                            l if l >= 0x3000 => "High (Administrator)",
                            l if l >= 0x2000 => "Medium",
                            l if l >= 0x1000 => "Low",
                            _ => "Untrusted",
                        };
                        out.push_str(&format!("\nCurrent Process:\n  Integrity Level: {}\n", level_str));

                        // Check if in Administrators group via token groups
                        let mut grp_needed: u32 = 0;
                        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut grp_needed);
                        let mut grp_buf = vec![0u8; grp_needed as usize];
                        let is_admin = if GetTokenInformation(token, TokenGroups, grp_buf.as_mut_ptr() as *mut c_void, grp_needed, &mut grp_needed) != 0 {
                            let groups = &*(grp_buf.as_ptr() as *const TOKEN_GROUPS);
                            let group_arr = std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
                            // Administrators SID: S-1-5-32-544
                            let admin_sid = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]; // S-1-5-32-544
                            group_arr.iter().any(|g| {
                                EqualSid(g.Sid, admin_sid.as_ptr() as *mut c_void) != 0
                            })
                        } else {
                            false
                        };

                        let elevated = win::is_elevated();
                        out.push_str(&format!("  Is Admin       : {}\n  Is Elevated    : {}\n", is_admin, elevated));

                        // Vulnerability assessment
                        if enable_lua == Some(0) {
                            out.push_str("\n[VULNERABLE] UAC is disabled. All admin tokens are full (high integrity).\n");
                        } else if consent_admin == Some(0) {
                            out.push_str("\n[VULNERABLE] UAC set to auto-elevate without prompt.\n");
                        } else if is_admin && level < 0x3000 {
                            out.push_str("\n[INFO] In Administrators group but running at Medium integrity. UAC bypass may be possible.\n");
                            out.push_str("  Techniques: fodhelper, eventvwr, computerdefaults, sdclt\n");
                        } else {
                            out.push_str("\n[OK] UAC appears properly configured.\n");
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}

#[cfg(not(windows))]
pub fn uacstatuscheck(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("uacstatuscheck: Windows only")
}
