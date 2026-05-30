/// Network enumeration commands.
/// Windows: native Win32 API via windows-sys + dynamic DLL loading. Linux: fallback to shell.

use std::net::TcpStream;
use std::time::Duration;

// ── arp ──────────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn arp(_args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use std::net::Ipv4Addr;

    unsafe {
        let mut size: u32 = 0;
        GetIpNetTable(std::ptr::null_mut(), &mut size, 0);
        if size == 0 {
            return Ok("No ARP entries found.".into());
        }

        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let table = buf.as_mut_ptr() as *mut MIB_IPNETTABLE;
        let ret = GetIpNetTable(table, &mut size, 1);
        if ret != 0 {
            anyhow::bail!("GetIpNetTable failed: error {}", ret);
        }

        let num = (*table).dwNumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num);

        let mut out = format!("{:<18} {:<20} {:<6} {}\n", "IP Address", "MAC Address", "Type", "IfIndex");
        out.push_str(&"-".repeat(60));
        out.push('\n');

        for row in rows {
            let ip = Ipv4Addr::from(row.dwAddr.to_ne_bytes());
            let mac_len = row.dwPhysAddrLen as usize;
            let mac = if mac_len > 0 {
                row.bPhysAddr[..mac_len].iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":")
            } else {
                "(incomplete)".into()
            };
            let entry_type = match row.Anonymous.dwType {
                1 => "Other",
                2 => "Invalid",
                3 => "Dynamic",
                4 => "Static",
                _ => "Unknown",
            };
            out.push_str(&format!("{:<18} {:<20} {:<6} {}\n", ip, mac, entry_type, row.dwIndex));
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn arp(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, stderr) = crate::exec::exec("arp", &["-a".into()]);
    if !stderr.is_empty() { anyhow::bail!("{}", stderr); }
    Ok(stdout)
}

// ── routeprint ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn routeprint(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use std::net::Ipv4Addr;

    // GetIpForwardTable from iphlpapi.dll — not in windows-sys
    type GetIpForwardTableFn = unsafe extern "system" fn(
        table: *mut u8, size: *mut u32, order: i32,
    ) -> u32;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct MibIpForwardRow {
        dwForwardDest: u32,
        dwForwardMask: u32,
        dwForwardPolicy: u32,
        dwForwardNextHop: u32,
        dwForwardIfIndex: u32,
        dwForwardType: u32,     // union but we just read the u32
        dwForwardProto: u32,
        dwForwardAge: u32,
        dwForwardNextHopAS: u32,
        dwForwardMetric1: u32,
        dwForwardMetric2: u32,
        dwForwardMetric3: u32,
        dwForwardMetric4: u32,
        dwForwardMetric5: u32,
    }

    let get_ip_fwd: GetIpForwardTableFn = unsafe {
        win::get_proc("iphlpapi.dll", "GetIpForwardTable")?
    };

    unsafe {
        let mut size: u32 = 0;
        get_ip_fwd(std::ptr::null_mut(), &mut size, 0);
        if size == 0 {
            return Ok("No routes found.".into());
        }

        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let ret = get_ip_fwd(buf.as_mut_ptr(), &mut size, 1);
        if ret != 0 {
            anyhow::bail!("GetIpForwardTable failed: error {}", ret);
        }

        // Layout: u32 dwNumEntries followed by array of MibIpForwardRow
        let num = *(buf.as_ptr() as *const u32) as usize;
        let rows_ptr = buf.as_ptr().add(4) as *const MibIpForwardRow;
        let rows = std::slice::from_raw_parts(rows_ptr, num);

        let mut out = format!("{:<18} {:<18} {:<18} {:<8} {}\n",
            "Destination", "Netmask", "Gateway", "Metric", "IfIndex");
        out.push_str(&"-".repeat(72));
        out.push('\n');

        for row in rows {
            let dest = Ipv4Addr::from(row.dwForwardDest.to_ne_bytes());
            let mask = Ipv4Addr::from(row.dwForwardMask.to_ne_bytes());
            let gw = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
            let metric = row.dwForwardMetric1;
            let ifidx = row.dwForwardIfIndex;
            let route_type = match row.dwForwardType {
                1 => " (other)",
                2 => " (invalid)",
                3 => " (direct)",
                4 => " (indirect)",
                _ => "",
            };
            out.push_str(&format!("{:<18} {:<18} {:<18} {:<8} {}{}\n",
                dest, mask, gw, metric, ifidx, route_type));
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn routeprint(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, stderr) = crate::exec::exec("ip", &["route".into()]);
    if !stderr.is_empty() && stdout.is_empty() {
        let (stdout2, _) = crate::exec::exec("netstat", &["-rn".into()]);
        return Ok(stdout2);
    }
    Ok(stdout)
}

// ── probe ────────────────────────────────────────────────────────────────────

pub fn probe(args: &[String]) -> anyhow::Result<String> {
    let host = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("probe: <host> <port> required"))?;
    let port: u16 = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("probe: <host> <port> required"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("probe: invalid port"))?;

    let addr_str = format!("{}:{}", host, port);

    let sock_addr = if let Ok(a) = addr_str.parse::<std::net::SocketAddr>() {
        a
    } else {
        use std::net::ToSocketAddrs;
        addr_str.to_socket_addrs()
            .ok()
            .and_then(|mut i| i.next())
            .ok_or_else(|| anyhow::anyhow!("probe: cannot resolve {}", host))?
    };

    match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5)) {
        Ok(_) => Ok(format!("{}:{} - OPEN", host, port)),
        Err(e) => Ok(format!("{}:{} - CLOSED ({})", host, port, e)),
    }
}

// ── listdns ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn listdns(_args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;
    use std::ptr;

    // DnsGetCacheDataTable from dnsapi.dll — not in windows-sys
    #[repr(C)]
    struct DnsCacheEntry {
        next: *mut DnsCacheEntry,
        name: *const u16,  // PWSTR
        r#type: u16,
        data_length: u16,
        flags: u32,
    }

    type DnsGetCacheDataTableFn = unsafe extern "system" fn(*mut *mut DnsCacheEntry) -> i32;

    let dns_get_cache: DnsGetCacheDataTableFn = unsafe {
        win::get_proc("dnsapi.dll", "DnsGetCacheDataTable")?
    };

    unsafe {
        let mut head: *mut DnsCacheEntry = ptr::null_mut();
        let ret = dns_get_cache(&mut head);
        if ret == 0 || head.is_null() {
            return Ok("No DNS cache entries found.".into());
        }

        let mut out = format!("{:<50} {:<8} {}\n", "Name", "Type", "DataLen");
        out.push_str(&"-".repeat(66));
        out.push('\n');

        let mut entry = head;
        while !entry.is_null() {
            let name = if !(*entry).name.is_null() {
                win::from_wide((*entry).name)
            } else {
                "(null)".into()
            };
            let type_str = match (*entry).r#type {
                1 => "A",
                2 => "NS",
                5 => "CNAME",
                6 => "SOA",
                12 => "PTR",
                15 => "MX",
                16 => "TXT",
                28 => "AAAA",
                33 => "SRV",
                _ => "OTHER",
            };
            out.push_str(&format!("{:<50} {:<8} {}\n", name, type_str, (*entry).data_length));
            entry = (*entry).next;
        }

        // Free — DnsFree is available but entries are typically leaked by this API
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn listdns(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("resolvectl", &["statistics".into()]);
    if stdout.is_empty() {
        Ok("listdns: no DNS cache available on this platform".into())
    } else {
        Ok(stdout)
    }
}

// ── nettime ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn nettime(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;

    // NetRemoteTOD from netapi32.dll
    type NetRemoteTODFn = unsafe extern "system" fn(
        server: *const u16,
        buf: *mut *mut u8,
    ) -> u32;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct TimeOfDayInfo {
        tod_elapsedt: u32,
        tod_msecs: u32,
        tod_hours: u32,
        tod_mins: u32,
        tod_secs: u32,
        tod_hunds: u32,
        tod_timezone: i32,
        tod_tinterval: u32,
        tod_day: u32,
        tod_month: u32,
        tod_year: u32,
        tod_weekday: u32,
    }

    let net_remote_tod: NetRemoteTODFn = unsafe {
        win::get_proc("netapi32.dll", "NetRemoteTOD")?
    };

    let server_w: Option<Vec<u16>> = args.first().map(|s| {
        let unc = format!("\\\\{}", s);
        win::to_wide(&unc)
    });
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let ret = net_remote_tod(server_ptr, &mut buf);
        if ret != 0 {
            anyhow::bail!("NetRemoteTOD failed: error {}", ret);
        }
        let _guard = win::NetApiBuf(buf);
        let tod = &*(buf as *const TimeOfDayInfo);

        let weekday = match tod.tod_weekday {
            0 => "Sunday", 1 => "Monday", 2 => "Tuesday", 3 => "Wednesday",
            4 => "Thursday", 5 => "Friday", 6 => "Saturday", _ => "Unknown",
        };

        let target = if let Some(s) = args.first() { s.as_str() } else { "localhost" };
        Ok(format!(
            "Current time at {}: {}, {:04}-{:02}-{:02} {:02}:{:02}:{:02} (UTC offset: {} min)\nUptime: {} seconds",
            target, weekday,
            tod.tod_year, tod.tod_month, tod.tod_day,
            tod.tod_hours, tod.tod_mins, tod.tod_secs,
            tod.tod_timezone,
            tod.tod_elapsedt
        ))
    }
}

#[cfg(not(windows))]
pub fn nettime(args: &[String]) -> anyhow::Result<String> {
    if let Some(host) = args.first() {
        let (stdout, stderr) = crate::exec::exec("rdate", &["-p".into(), host.clone()]);
        if !stderr.is_empty() && stdout.is_empty() {
            anyhow::bail!("nettime: {}", stderr);
        }
        Ok(stdout)
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?;
        Ok(format!("Local time: {} (unix epoch)", now.as_secs()))
    }
}

// ── netuptime ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netuptime(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;

    // NetStatisticsGet from netapi32.dll
    type NetStatisticsGetFn = unsafe extern "system" fn(
        server: *const u16,
        service: *const u16,
        level: u32,
        options: u32,
        buf: *mut *mut u8,
    ) -> u32;

    let net_stats_get: NetStatisticsGetFn = unsafe {
        win::get_proc("netapi32.dll", "NetStatisticsGet")?
    };

    let server_w: Option<Vec<u16>> = args.first().map(|s| {
        let unc = format!("\\\\{}", s);
        win::to_wide(&unc)
    });
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let service_w = win::to_wide("LanmanServer");

    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let ret = net_stats_get(server_ptr, service_w.as_ptr(), 0, 0, &mut buf);
        if ret != 0 {
            anyhow::bail!("NetStatisticsGet failed: error {}", ret);
        }
        let _guard = win::NetApiBuf(buf);

        // STAT_SERVER_0: first field is sts0_start (u32, seconds since 1970-01-01)
        let start_time = *(buf as *const u32);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let uptime_secs = now.saturating_sub(start_time);
        let days = uptime_secs / 86400;
        let hours = (uptime_secs % 86400) / 3600;
        let mins = (uptime_secs % 3600) / 60;
        let secs = uptime_secs % 60;

        let target = if let Some(s) = args.first() { s.as_str() } else { "localhost" };
        Ok(format!(
            "Server {} has been up for {}d {}h {}m {}s (since Unix epoch: {})",
            target, days, hours, mins, secs, start_time
        ))
    }
}

#[cfg(not(windows))]
pub fn netuptime(_args: &[String]) -> anyhow::Result<String> {
    let (stdout, _) = crate::exec::exec("uptime", &[]);
    Ok(stdout)
}

// ── netview ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn netview(args: &[String]) -> anyhow::Result<String> {
    use super::winapi_helpers::win;

    // NetServerEnum from netapi32.dll
    type NetServerEnumFn = unsafe extern "system" fn(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        servertype: u32,
        domain: *const u16,
        resume_handle: *mut u32,
    ) -> u32;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct ServerInfo101 {
        sv101_platform_id: u32,
        sv101_name: *const u16,
        sv101_version_major: u32,
        sv101_version_minor: u32,
        sv101_type: u32,
        sv101_comment: *const u16,
    }

    let net_server_enum: NetServerEnumFn = unsafe {
        win::get_proc("netapi32.dll", "NetServerEnum")?
    };

    let domain_w: Option<Vec<u16>> = args.first().map(|s| win::to_wide(s));
    let domain_ptr = domain_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    const SV_TYPE_ALL: u32 = 0xFFFFFFFF;
    const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let ret = net_server_enum(
            std::ptr::null(), 101, &mut buf, MAX_PREFERRED_LENGTH,
            &mut entries_read, &mut total_entries,
            SV_TYPE_ALL, domain_ptr, std::ptr::null_mut(),
        );

        if ret != 0 && ret != 234 { // 234 = ERROR_MORE_DATA
            if !buf.is_null() {
                win::NetApiBuf(buf);
            }
            anyhow::bail!("NetServerEnum failed: error {}", ret);
        }
        let _guard = win::NetApiBuf(buf);

        let entries = std::slice::from_raw_parts(buf as *const ServerInfo101, entries_read as usize);
        let mut out = format!("{:<24} {:<12} {}\n", "Server Name", "Version", "Comment");
        out.push_str(&"-".repeat(60));
        out.push('\n');

        for e in entries {
            let name = win::from_wide(e.sv101_name);
            let comment = win::from_wide(e.sv101_comment);
            let ver = format!("{}.{}", e.sv101_version_major, e.sv101_version_minor);
            let mut type_flags = Vec::new();
            if e.sv101_type & 0x00000001 != 0 { type_flags.push("Workstation"); }
            if e.sv101_type & 0x00000002 != 0 { type_flags.push("Server"); }
            if e.sv101_type & 0x00000008 != 0 { type_flags.push("DC"); }
            if e.sv101_type & 0x00000010 != 0 { type_flags.push("BDC"); }
            if e.sv101_type & 0x00000800 != 0 { type_flags.push("PrintServer"); }
            if e.sv101_type & 0x00002000 != 0 { type_flags.push("NT"); }
            let types = if type_flags.is_empty() { String::new() } else {
                format!(" [{}]", type_flags.join(", "))
            };
            out.push_str(&format!("{:<24} {:<12} {}{}\n", name, ver, comment, types));
        }
        out.push_str(&format!("\nTotal: {} servers enumerated", total_entries));
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn netview(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("netview: Windows only")
}
