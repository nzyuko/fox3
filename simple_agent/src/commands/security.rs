/// Security and audit commands.
/// Windows: native Win32 API + registry reads. Linux: fallback to /etc files.

// ── adv_audit_policies ───────────────────────────────────────────────────────

#[cfg(windows)]
pub fn adv_audit_policies(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;

    // AuditQuerySystemPolicy from advapi32.dll
    // GUID for subcategories + per-subcategory audit flags

    // We'll read audit policies from registry as a more reliable in-process approach:
    // HKLM\SECURITY\Policy\PolAdtEv — but that requires SYSTEM privileges.
    // Alternative: use AuditEnumerateSubCategories + AuditQuerySystemPolicy from advapi32.dll

    type AuditEnumerateSubCategoriesFn = unsafe extern "system" fn(
        audit_category_guid: *const [u8; 16], // GUID ptr, null = all
        retrieve_all: i32,
        sub_category_guids: *mut *mut [u8; 16],
        sub_count: *mut u32,
    ) -> u8; // BOOLEAN

    type AuditQuerySystemPolicyFn = unsafe extern "system" fn(
        sub_category_guids: *const [u8; 16],
        count: u32,
        policy: *mut *mut AuditPolicyInfo,
    ) -> u8;

    type AuditLookupCategoryNameWFn = unsafe extern "system" fn(
        guid: *const [u8; 16],
        name: *mut *mut u16,
    ) -> u8;

    type AuditLookupSubCategoryNameWFn = unsafe extern "system" fn(
        guid: *const [u8; 16],
        name: *mut *mut u16,
    ) -> u8;

    type AuditFreeFn = unsafe extern "system" fn(*mut std::ffi::c_void);

    #[repr(C)]
    struct AuditPolicyInfo {
        sub_category_guid: [u8; 16],
        auditing_information: u32,
    }

    // Category GUIDs (Windows standard 9 categories)
    let categories: &[([u8; 16], &str)] = &[
        (hex_guid("69979848-797a-11d9-bed3-505054503030"), "System"),
        (hex_guid("6997984a-797a-11d9-bed3-505054503030"), "Logon/Logoff"),
        (hex_guid("6997984c-797a-11d9-bed3-505054503030"), "Object Access"),
        (hex_guid("6997984e-797a-11d9-bed3-505054503030"), "Privilege Use"),
        (hex_guid("69979850-797a-11d9-bed3-505054503030"), "Detailed Tracking"),
        (hex_guid("69979852-797a-11d9-bed3-505054503030"), "Policy Change"),
        (hex_guid("69979854-797a-11d9-bed3-505054503030"), "Account Management"),
        (hex_guid("69979856-797a-11d9-bed3-505054503030"), "DS Access"),
        (hex_guid("69979858-797a-11d9-bed3-505054503030"), "Account Logon"),
    ];

    let audit_enum_sub: AuditEnumerateSubCategoriesFn = unsafe {
        win::get_proc("advapi32.dll", "AuditEnumerateSubCategories")?
    };
    let audit_query: AuditQuerySystemPolicyFn = unsafe {
        win::get_proc("advapi32.dll", "AuditQuerySystemPolicy")?
    };
    let audit_lookup_sub_name: AuditLookupSubCategoryNameWFn = unsafe {
        win::get_proc("advapi32.dll", "AuditLookupSubCategoryNameW")?
    };
    let audit_free: AuditFreeFn = unsafe {
        win::get_proc("advapi32.dll", "AuditFree")?
    };

    let mut out = format!("{:<40} {:<20} {}\n", "Category", "Subcategory", "Setting");
    out.push_str(&"-".repeat(80));
    out.push('\n');

    for (cat_guid, cat_name) in categories {
        // Enumerate subcategories for this category
        let mut sub_guids: *mut [u8; 16] = std::ptr::null_mut();
        let mut sub_count: u32 = 0;

        unsafe {
            let ok = audit_enum_sub(cat_guid as *const _, 0, &mut sub_guids, &mut sub_count);
            if ok == 0 || sub_guids.is_null() || sub_count == 0 {
                continue;
            }

            let subs = std::slice::from_raw_parts(sub_guids, sub_count as usize);

            for sub_guid in subs {
                // Query policy for this subcategory
                let mut policy_ptr: *mut AuditPolicyInfo = std::ptr::null_mut();
                let ok = audit_query(sub_guid as *const _, 1, &mut policy_ptr);
                if ok == 0 || policy_ptr.is_null() {
                    continue;
                }

                let info = &*policy_ptr;
                let setting = match info.auditing_information {
                    0 => "No Auditing",
                    1 => "Success",
                    2 => "Failure",
                    3 => "Success and Failure",
                    _ => "Unknown",
                };

                // Get subcategory name
                let mut sub_name_ptr: *mut u16 = std::ptr::null_mut();
                let ok = audit_lookup_sub_name(sub_guid as *const _, &mut sub_name_ptr);
                let sub_name = if ok != 0 && !sub_name_ptr.is_null() {
                    let n = win::from_wide(sub_name_ptr);
                    audit_free(sub_name_ptr as *mut _);
                    n
                } else {
                    format!("{:?}", sub_guid)
                };

                out.push_str(&format!("{:<40} {:<20} {}\n", cat_name, sub_name, setting));
                audit_free(policy_ptr as *mut _);
            }

            audit_free(sub_guids as *mut _);
        }
    }

    Ok(out)
}

#[cfg(windows)]
fn hex_guid(s: &str) -> [u8; 16] {
    // Parse GUID string "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" to bytes in Windows GUID layout
    let clean: String = s.replace('-', "");
    let bytes: Vec<u8> = (0..32).step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i+2], 16).unwrap_or(0))
        .collect();
    if bytes.len() < 16 { return [0u8; 16]; }

    // Windows GUID is: u32 LE, u16 LE, u16 LE, then 8 bytes raw
    let mut guid = [0u8; 16];
    // Data1: bytes[0..4] → LE u32
    guid[0] = bytes[3]; guid[1] = bytes[2]; guid[2] = bytes[1]; guid[3] = bytes[0];
    // Data2: bytes[4..6] → LE u16
    guid[4] = bytes[5]; guid[5] = bytes[4];
    // Data3: bytes[6..8] → LE u16
    guid[6] = bytes[7]; guid[7] = bytes[6];
    // Data4: bytes[8..16] → raw
    guid[8..16].copy_from_slice(&bytes[8..16]);
    guid
}

#[cfg(not(windows))]
pub fn adv_audit_policies(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("adv_audit_policies: Windows only")
}

// ── list_firewall_rules ──────────────────────────────────────────────────────

#[cfg(windows)]
pub fn list_firewall_rules(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Registry::*;

    // Read firewall rules from registry instead of netsh:
    // HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
    let subkey = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
    let subkey_w = win::to_wide(subkey);

    let mut key: win::HKEY = std::ptr::null_mut();
    let ret = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr(), 0, KEY_READ, &mut key)
    };
    if ret != 0 {
        anyhow::bail!("Failed to open FirewallRules key: error {}", ret);
    }
    let _guard = win::RegKeyHandle(key);

    // Enumerate values — each value is a firewall rule
    let mut out = String::from("=== Windows Firewall Rules ===\n\n");
    let mut idx: u32 = 0;
    let mut count: u32 = 0;

    loop {
        let mut name_buf = [0u16; 512];
        let mut name_len = 512u32;
        let mut data_type: u32 = 0;
        let mut data_size: u32 = 0;

        // First call to get data size
        let ret = unsafe {
            RegEnumValueW(
                key, idx, name_buf.as_mut_ptr(), &mut name_len,
                std::ptr::null_mut(), &mut data_type, std::ptr::null_mut(), &mut data_size,
            )
        };
        if ret != 0 { break; }

        // Read data
        name_len = 512;
        let mut data_buf = vec![0u8; data_size as usize];
        let ret = unsafe {
            RegEnumValueW(
                key, idx, name_buf.as_mut_ptr(), &mut name_len,
                std::ptr::null_mut(), &mut data_type, data_buf.as_mut_ptr(), &mut data_size,
            )
        };
        idx += 1;
        if ret != 0 { continue; }

        let rule_str = win::format_reg_data(data_type, &data_buf);

        // Parse the pipe-delimited rule format
        let mut rule_name = String::new();
        let mut action = String::new();
        let mut direction = String::new();
        let mut protocol = String::new();
        let mut local_port = String::new();
        let mut remote_port = String::new();
        let mut app = String::new();
        let mut enabled = String::new();

        for part in rule_str.split('|') {
            if let Some(val) = part.strip_prefix("Name=") { rule_name = val.to_string(); }
            else if let Some(val) = part.strip_prefix("Action=") {
                action = match val { "Allow" => "Allow".into(), "Block" => "Block".into(), _ => val.to_string() };
            }
            else if let Some(val) = part.strip_prefix("Dir=") {
                direction = match val { "In" => "Inbound".into(), "Out" => "Outbound".into(), _ => val.to_string() };
            }
            else if let Some(val) = part.strip_prefix("Protocol=") { protocol = val.to_string(); }
            else if let Some(val) = part.strip_prefix("LPort=") { local_port = val.to_string(); }
            else if let Some(val) = part.strip_prefix("RPort=") { remote_port = val.to_string(); }
            else if let Some(val) = part.strip_prefix("App=") { app = val.to_string(); }
            else if let Some(val) = part.strip_prefix("Active=") {
                enabled = if val == "TRUE" { "Enabled".into() } else { "Disabled".into() };
            }
        }

        if !rule_name.is_empty() {
            out.push_str(&format!("[{}] {} | {} | {} | Proto={} | LPort={} | RPort={} | App={}\n",
                enabled, rule_name, direction, action, protocol, local_port, remote_port, app));
            count += 1;
        }
    }

    out.push_str(&format!("\nTotal: {} firewall rules", count));
    Ok(out)
}

#[cfg(not(windows))]
pub fn list_firewall_rules(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("list_firewall_rules: Windows only")
}

// ── get_password_policy ──────────────────────────────────────────────────────

#[cfg(windows)]
pub fn get_password_policy(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let server_w: Option<Vec<u16>> = args.first().map(|s| win::to_wide(s));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let ret = NetUserModalsGet(server_ptr, 0, &mut buf);
        if ret != 0 {
            anyhow::bail!("NetUserModalsGet failed: error {}", ret);
        }
        let _guard = win::NetApiBuf(buf);

        let info = &*(buf as *const USER_MODALS_INFO_0);

        let max_age_days = if info.usrmod0_max_passwd_age == u32::MAX {
            "Never expires".to_string()
        } else {
            format!("{} days", info.usrmod0_max_passwd_age / 86400)
        };
        let min_age_days = format!("{} days", info.usrmod0_min_passwd_age / 86400);

        let target = args.first().map(|s| s.as_str()).unwrap_or("localhost");
        Ok(format!(
            "Password Policy for {}\n\
             Min password length : {}\n\
             Max password age    : {}\n\
             Min password age    : {}\n\
             Force logoff        : {}\n\
             Password history    : {} passwords remembered",
            target,
            info.usrmod0_min_passwd_len,
            max_age_days,
            min_age_days,
            if info.usrmod0_force_logoff == u32::MAX { "Never".to_string() }
            else { format!("{} seconds", info.usrmod0_force_logoff) },
            info.usrmod0_password_hist_len,
        ))
    }
}

#[cfg(not(windows))]
pub fn get_password_policy(_args: &[String]) -> anyhow::Result<String> {
    let mut out = String::new();
    if let Ok(defs) = std::fs::read_to_string("/etc/login.defs") {
        for line in defs.lines() {
            let l = line.trim();
            if l.starts_with('#') || l.is_empty() { continue; }
            if l.starts_with("PASS_") || l.starts_with("LOGIN_") || l.starts_with("FAIL") {
                out.push_str(l);
                out.push('\n');
            }
        }
    }
    if out.is_empty() {
        out.push_str("No password policy found in /etc/login.defs");
    }
    Ok(out)
}
