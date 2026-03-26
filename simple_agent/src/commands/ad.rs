/// Active Directory / LDAP commands.
/// Windows: wldap32.dll FFI + COM WMI + token queries. No child processes.

// ── LDAP helpers via wldap32.dll ────────────────────────────────────────────

#[cfg(windows)]
pub(super) mod ldap_ffi {
    use super::super::winapi_helpers::win;
    use std::ffi::c_void;
    use std::ptr;

    pub type LDAP = *mut c_void;
    pub type LDAPMessage = *mut c_void;

    // Function types from wldap32.dll
    type LdapInitWFn = unsafe extern "C" fn(host: *const u16, port: u32) -> LDAP;
    type LdapBindSWFn = unsafe extern "C" fn(ld: LDAP, dn: *const u16, cred: *const u16, method: u32) -> u32;
    type LdapSearchSWFn = unsafe extern "C" fn(
        ld: LDAP, base: *const u16, scope: u32,
        filter: *const u16, attrs: *mut *mut u16,
        attrsonly: u32, res: *mut LDAPMessage,
    ) -> u32;
    type LdapCountEntriesFn = unsafe extern "C" fn(ld: LDAP, res: LDAPMessage) -> u32;
    type LdapFirstEntryFn = unsafe extern "C" fn(ld: LDAP, res: LDAPMessage) -> LDAPMessage;
    type LdapNextEntryFn = unsafe extern "C" fn(ld: LDAP, entry: LDAPMessage) -> LDAPMessage;
    type LdapFirstAttributeWFn = unsafe extern "C" fn(ld: LDAP, entry: LDAPMessage, ber: *mut *mut c_void) -> *mut u16;
    type LdapNextAttributeWFn = unsafe extern "C" fn(ld: LDAP, entry: LDAPMessage, ber: *mut c_void) -> *mut u16;
    type LdapGetValuesWFn = unsafe extern "C" fn(ld: LDAP, entry: LDAPMessage, attr: *const u16) -> *mut *mut u16;
    type LdapCountValuesWFn = unsafe extern "C" fn(vals: *mut *mut u16) -> u32;
    type LdapValueFreeWFn = unsafe extern "C" fn(vals: *mut *mut u16) -> u32;
    type LdapMsgfreeFn = unsafe extern "C" fn(res: LDAPMessage) -> u32;
    type LdapUnbindFn = unsafe extern "C" fn(ld: LDAP) -> u32;
    type BerFreeFn = unsafe extern "C" fn(ber: *mut c_void, freebuf: i32);

    const LDAP_AUTH_NEGOTIATE: u32 = 0x0486; // LDAP_AUTH_SSPI/Negotiate
    const LDAP_SCOPE_SUBTREE: u32 = 2;
    const LDAP_SUCCESS: u32 = 0;

    pub struct LdapConn {
        ld: LDAP,
        unbind: LdapUnbindFn,
    }

    impl Drop for LdapConn {
        fn drop(&mut self) {
            if !self.ld.is_null() {
                unsafe { (self.unbind)(self.ld); }
            }
        }
    }

    pub struct LdapFuncs {
        search: LdapSearchSWFn,
        count_entries: LdapCountEntriesFn,
        first_entry: LdapFirstEntryFn,
        next_entry: LdapNextEntryFn,
        first_attr: LdapFirstAttributeWFn,
        next_attr: LdapNextAttributeWFn,
        get_values: LdapGetValuesWFn,
        count_values: LdapCountValuesWFn,
        value_free: LdapValueFreeWFn,
        msgfree: LdapMsgfreeFn,
        ber_free: BerFreeFn,
    }

    pub fn connect(server: Option<&str>) -> anyhow::Result<(LdapConn, LdapFuncs)> {
        unsafe {
            let init: LdapInitWFn = win::get_proc("wldap32.dll", "ldap_initW")?;
            let bind: LdapBindSWFn = win::get_proc("wldap32.dll", "ldap_bind_sW")?;
            let unbind: LdapUnbindFn = win::get_proc("wldap32.dll", "ldap_unbind")?;

            let host_w: Option<Vec<u16>> = server.map(|s| win::to_wide(s));
            let host_ptr = host_w.as_ref().map_or(ptr::null(), |v| v.as_ptr());

            let ld = init(host_ptr, 389);
            if ld.is_null() {
                anyhow::bail!("ldap_initW failed");
            }

            let ret = bind(ld, ptr::null(), ptr::null(), LDAP_AUTH_NEGOTIATE);
            if ret != LDAP_SUCCESS {
                unbind(ld);
                anyhow::bail!("ldap_bind_sW failed: error {}", ret);
            }

            let funcs = LdapFuncs {
                search: win::get_proc("wldap32.dll", "ldap_search_sW")?,
                count_entries: win::get_proc("wldap32.dll", "ldap_count_entries")?,
                first_entry: win::get_proc("wldap32.dll", "ldap_first_entry")?,
                next_entry: win::get_proc("wldap32.dll", "ldap_next_entry")?,
                first_attr: win::get_proc("wldap32.dll", "ldap_first_attributeW")?,
                next_attr: win::get_proc("wldap32.dll", "ldap_next_attributeW")?,
                get_values: win::get_proc("wldap32.dll", "ldap_get_valuesW")?,
                count_values: win::get_proc("wldap32.dll", "ldap_count_valuesW")?,
                value_free: win::get_proc("wldap32.dll", "ldap_value_freeW")?,
                msgfree: win::get_proc("wldap32.dll", "ldap_msgfree")?,
                ber_free: win::get_proc("wldap32.dll", "ber_free")?,
            };

            Ok((LdapConn { ld, unbind }, funcs))
        }
    }

    pub fn search(conn: &LdapConn, funcs: &LdapFuncs, base: &str, filter: &str, attrs: Option<&str>) -> anyhow::Result<String> {
        let base_w = win::to_wide(base);
        let filter_w = win::to_wide(filter);

        // Build attribute array
        let attr_wides: Vec<Vec<u16>>;
        let mut attr_ptrs: Vec<*mut u16>;
        let attrs_ptr = if let Some(a) = attrs {
            attr_wides = a.split(',').map(|s| win::to_wide(s.trim())).collect();
            attr_ptrs = attr_wides.iter().map(|w| w.as_ptr() as *mut u16).collect();
            attr_ptrs.push(ptr::null_mut());
            attr_ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };

        unsafe {
            let mut res: LDAPMessage = ptr::null_mut();
            let ret = (funcs.search)(
                conn.ld, base_w.as_ptr(), LDAP_SCOPE_SUBTREE,
                filter_w.as_ptr(), attrs_ptr, 0, &mut res,
            );
            if ret != LDAP_SUCCESS {
                anyhow::bail!("ldap_search_sW failed: error {}", ret);
            }

            let count = (funcs.count_entries)(conn.ld, res);
            let mut out = String::new();

            let mut entry = (funcs.first_entry)(conn.ld, res);
            while !entry.is_null() {
                let mut ber: *mut c_void = ptr::null_mut();
                let mut attr = (funcs.first_attr)(conn.ld, entry, &mut ber);

                while !attr.is_null() {
                    let attr_name = win::from_wide(attr);
                    let vals = (funcs.get_values)(conn.ld, entry, attr);
                    if !vals.is_null() {
                        let val_count = (funcs.count_values)(vals);
                        for i in 0..val_count {
                            let val = *vals.add(i as usize);
                            if !val.is_null() {
                                let val_str = win::from_wide(val);
                                out.push_str(&format!("{}: {}\n", attr_name, val_str));
                            }
                        }
                        (funcs.value_free)(vals);
                    }
                    attr = (funcs.next_attr)(conn.ld, entry, ber);
                }

                if !ber.is_null() {
                    (funcs.ber_free)(ber, 0);
                }

                out.push_str("---\n");
                entry = (funcs.next_entry)(conn.ld, entry);
            }

            out.push_str(&format!("Total: {} entries", count));
            (funcs.msgfree)(res);
            Ok(out)
        }
    }
}

// ── ldapsearch ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn ldapsearch(args: &[String]) -> anyhow::Result<String> {
    let query = args.first()
        .ok_or_else(|| anyhow::anyhow!("ldapsearch: <query> [attributes] [server] required"))?;
    let attrs = args.get(1).map(|s| s.as_str());
    let server = args.get(2).map(|s| s.as_str());

    let (conn, funcs) = ldap_ffi::connect(server)?;

    // Get default naming context via RootDSE
    let base = get_default_naming_context(&conn, &funcs)?;
    ldap_ffi::search(&conn, &funcs, &base, query, attrs)
}

#[cfg(windows)]
pub(super) fn get_default_naming_context(conn: &ldap_ffi::LdapConn, funcs: &ldap_ffi::LdapFuncs) -> anyhow::Result<String> {
    let result = ldap_ffi::search(conn, funcs, "", "(objectClass=*)", Some("defaultNamingContext"))?;
    // Parse "defaultNamingContext: DC=..." from the result
    for line in result.lines() {
        if let Some(val) = line.strip_prefix("defaultNamingContext: ") {
            return Ok(val.to_string());
        }
    }
    // Fallback: try USERDNSDOMAIN env var
    if let Ok(domain) = std::env::var("USERDNSDOMAIN") {
        let parts: Vec<&str> = domain.split('.').collect();
        let dn = parts.iter().map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",");
        return Ok(dn);
    }
    anyhow::bail!("Cannot determine default naming context")
}

#[cfg(not(windows))]
pub fn ldapsearch(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("ldapsearch: Windows only (use ldapsearch binary on Linux)")
}

// ── adcs_enum ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn adcs_enum(_args: &[String]) -> anyhow::Result<String> {
    let (conn, funcs) = ldap_ffi::connect(None)?;

    // Get configurationNamingContext
    let config_result = ldap_ffi::search(&conn, &funcs, "", "(objectClass=*)", Some("configurationNamingContext"))?;
    let config_nc = config_result.lines()
        .find_map(|l| l.strip_prefix("configurationNamingContext: "))
        .ok_or_else(|| anyhow::anyhow!("Cannot find configurationNamingContext"))?
        .to_string();

    let mut out = String::from("=== Certificate Authorities ===\n");

    // Search Enrollment Services
    let es_base = format!("CN=Enrollment Services,CN=Public Key Services,CN=Services,{}", config_nc);
    let es_result = ldap_ffi::search(&conn, &funcs, &es_base,
        "(objectClass=pKIEnrollmentService)",
        Some("cn,dNSHostName,certificateTemplates"))?;
    out.push_str(&es_result);

    // Search Certificate Templates
    out.push_str("\n=== Certificate Templates ===\n");
    let ct_base = format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,{}", config_nc);
    let ct_result = ldap_ffi::search(&conn, &funcs, &ct_base,
        "(objectClass=pKICertificateTemplate)",
        Some("cn,displayName"))?;
    out.push_str(&ct_result);

    Ok(out)
}

#[cfg(not(windows))]
pub fn adcs_enum(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("adcs_enum: Windows only")
}

// ── wmi_query ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn wmi_query(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use std::ffi::c_void;
    use std::ptr;

    let query = args.first()
        .ok_or_else(|| anyhow::anyhow!("wmi_query: <WQL query> [server] [namespace] required"))?;
    let _server = args.get(1).map(|s| s.as_str());
    let namespace = args.get(2).map(|s| s.as_str()).unwrap_or("root\\cimv2");

    // COM WMI: CoCreateInstance(CLSID_WbemLocator) → IWbemLocator::ConnectServer → IWbemServices::ExecQuery
    type CoInitializeExFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    type CoCreateInstanceFn = unsafe extern "system" fn(
        *const [u8; 16], *mut c_void, u32, *const [u8; 16], *mut *mut c_void,
    ) -> i32;
    type CoInitializeSecurityFn = unsafe extern "system" fn(
        *mut c_void, i32, *mut c_void, *mut c_void, u32, u32, *mut c_void, u32, *mut c_void,
    ) -> i32;
    type SysAllocStringFn = unsafe extern "system" fn(*const u16) -> *mut u16;
    type SysFreeStringFn = unsafe extern "system" fn(*mut u16);

    let co_init: CoInitializeExFn = unsafe { win::get_proc("ole32.dll", "CoInitializeEx")? };
    let co_create: CoCreateInstanceFn = unsafe { win::get_proc("ole32.dll", "CoCreateInstance")? };
    let co_init_sec: CoInitializeSecurityFn = unsafe { win::get_proc("ole32.dll", "CoInitializeSecurity")? };
    let sys_alloc: SysAllocStringFn = unsafe { win::get_proc("oleaut32.dll", "SysAllocString")? };
    let _sys_free: SysFreeStringFn = unsafe { win::get_proc("oleaut32.dll", "SysFreeString")? };

    // CLSID_WbemLocator = {4590f811-1d3a-11d0-891f-00aa004b2e24}
    let clsid_locator: [u8; 16] = [0x11, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24];
    // IID_IWbemLocator = {dc12a687-737f-11cf-884d-00aa004b2e24}
    let iid_locator: [u8; 16] = [0x87, 0xa6, 0x12, 0xdc, 0x7f, 0x73, 0xcf, 0x11, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24];

    unsafe {
        let hr = co_init(ptr::null_mut(), 0);
        if hr < 0 && hr != 1 { anyhow::bail!("CoInitializeEx failed: 0x{:08x}", hr as u32); }

        // Initialize COM security
        co_init_sec(
            ptr::null_mut(), -1, ptr::null_mut(), ptr::null_mut(),
            0, // RPC_C_AUTHN_LEVEL_DEFAULT
            3, // RPC_C_IMP_LEVEL_IMPERSONATE
            ptr::null_mut(), 0, // EOAC_NONE
            ptr::null_mut(),
        );

        let mut locator: *mut c_void = ptr::null_mut();
        let hr = co_create(&clsid_locator, ptr::null_mut(), 1, &iid_locator, &mut locator);
        if hr < 0 || locator.is_null() {
            anyhow::bail!("CoCreateInstance(WbemLocator) failed: 0x{:08x}", hr as u32);
        }

        // IWbemLocator::ConnectServer (vtable index 3)
        let ns_str = format!("\\\\{}\\{}", _server.unwrap_or("."), namespace);
        let ns_bstr = sys_alloc(win::to_wide(&ns_str).as_ptr());

        let mut services: *mut c_void = ptr::null_mut();
        let vtable = *(locator as *const *const usize);
        let connect_server: unsafe extern "system" fn(
            *mut c_void, *mut u16, *mut u16, *mut u16, *mut u16, i32, *mut u16, *mut c_void, *mut *mut c_void,
        ) -> i32 = std::mem::transmute(*vtable.add(3));
        let hr = connect_server(locator, ns_bstr, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut(), &mut services);
        if hr < 0 || services.is_null() {
            anyhow::bail!("IWbemLocator::ConnectServer failed: 0x{:08x}", hr as u32);
        }

        // IWbemServices::ExecQuery (vtable index 20)
        let wql_bstr = sys_alloc(win::to_wide("WQL").as_ptr());
        let query_bstr = sys_alloc(win::to_wide(query).as_ptr());

        let mut enumerator: *mut c_void = ptr::null_mut();
        let svc_vtable = *(services as *const *const usize);
        let exec_query: unsafe extern "system" fn(
            *mut c_void, *mut u16, *mut u16, i32, *mut c_void, *mut *mut c_void,
        ) -> i32 = std::mem::transmute(*svc_vtable.add(20));
        let hr = exec_query(services, wql_bstr, query_bstr,
            0x10 | 0x20, // WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY
            ptr::null_mut(), &mut enumerator);
        if hr < 0 || enumerator.is_null() {
            anyhow::bail!("ExecQuery failed: 0x{:08x}", hr as u32);
        }

        // IEnumWbemClassObject::Next
        let mut out = String::new();
        let mut obj_count = 0u32;
        let enum_vtable = *(enumerator as *const *const usize);
        let next: unsafe extern "system" fn(
            *mut c_void, i32, u32, *mut *mut c_void, *mut u32,
        ) -> i32 = std::mem::transmute(*enum_vtable.add(4));

        loop {
            let mut obj: *mut c_void = ptr::null_mut();
            let mut returned: u32 = 0;
            let hr = next(enumerator, 5000, 1, &mut obj, &mut returned); // 5s timeout
            if hr != 0 || returned == 0 || obj.is_null() { break; }

            // IWbemClassObject::GetObjectText (vtable 17)
            let obj_vtable = *(obj as *const *const usize);
            let get_text: unsafe extern "system" fn(
                *mut c_void, i32, *mut *mut u16,
            ) -> i32 = std::mem::transmute(*obj_vtable.add(17));
            let mut text_bstr: *mut u16 = ptr::null_mut();
            let hr = get_text(obj, 0, &mut text_bstr);
            if hr >= 0 && !text_bstr.is_null() {
                let text = win::from_wide(text_bstr);
                out.push_str(&text);
                out.push_str("\n---\n");
            }

            // Release object
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(*obj_vtable.add(2));
            release(obj);
            obj_count += 1;
        }

        out.push_str(&format!("Total: {} objects", obj_count));

        // Cleanup
        let release_fn = |p: *mut c_void| {
            if !p.is_null() {
                let vt = *(p as *const *const usize);
                let rel: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(*vt.add(2));
                rel(p);
            }
        };
        release_fn(enumerator);
        release_fn(services);
        release_fn(locator);

        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn wmi_query(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("wmi_query: Windows only")
}

// ── get_session_info ─────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn get_session_info(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use std::ffi::c_void;

    let mut out = String::new();

    // Env vars
    out.push_str(&format!("Username   : {}\n", std::env::var("USERNAME").unwrap_or_default()));
    out.push_str(&format!("Domain     : {}\n", std::env::var("USERDOMAIN").unwrap_or_default()));
    out.push_str(&format!("LogonServer: {}\n", std::env::var("LOGONSERVER").unwrap_or_default()));

    unsafe {
        let mut token: win::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            out.push_str("(Cannot open process token)\n");
            return Ok(out);
        }
        let _guard = win::WinHandle(token);

        // IsAdmin
        out.push_str(&format!("IsAdmin    : {}\n", win::is_elevated()));

        // Token groups
        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
        if needed > 0 {
            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(token, TokenGroups, buf.as_mut_ptr() as *mut c_void, needed, &mut needed) != 0 {
                let groups = &*(buf.as_ptr() as *const TOKEN_GROUPS);
                let group_arr = std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
                out.push_str("Groups:\n");
                for g in group_arr {
                    let mut name_buf = [0u16; 256];
                    let mut name_len = 256u32;
                    let mut domain_buf = [0u16; 256];
                    let mut domain_len = 256u32;
                    let mut sid_use: i32 = 0;
                    if LookupAccountSidW(
                        std::ptr::null(), g.Sid,
                        name_buf.as_mut_ptr(), &mut name_len,
                        domain_buf.as_mut_ptr(), &mut domain_len,
                        &mut sid_use,
                    ) != 0 {
                        let domain = win::from_wide(domain_buf.as_ptr());
                        let name = win::from_wide(name_buf.as_ptr());
                        if domain.is_empty() {
                            out.push_str(&format!("  {}\n", name));
                        } else {
                            out.push_str(&format!("  {}\\{}\n", domain, name));
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}

#[cfg(not(windows))]
pub fn get_session_info(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("id", &[]);
    let mut out = stdout;
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        out.push_str(&format!("Hostname: {}", hostname.trim()));
    }
    Ok(out)
}
