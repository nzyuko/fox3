/// Service management commands via Win32 Service Control Manager API.
/// Windows: native windows-sys FFI (zero child processes).
/// Linux: systemctl fallback (kept — no WinAPI equivalent).

#[cfg(windows)]
use super::winapi_helpers::win::{
    self, to_wide, from_wide,
    ScHandle,
};

// ── sc_query ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_query(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let svc = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_query: <service> [server]"))?;
    let server = args.get(1);

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let svc_w = to_wide(svc);
    let h = unsafe { OpenServiceW(scm.0, svc_w.as_ptr(), SERVICE_QUERY_STATUS) };
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", svc)));
    }
    let _guard = ScHandle(h);

    // QueryServiceStatusEx
    let mut buf = vec![0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
    let mut needed: u32 = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            h, SC_STATUS_PROCESS_INFO,
            buf.as_mut_ptr(), buf.len() as u32, &mut needed,
        )
    };
    if ok == 0 {
        return Err(win::last_error("QueryServiceStatusEx"));
    }
    let status = unsafe { &*(buf.as_ptr() as *const SERVICE_STATUS_PROCESS) };

    Ok(format!(
        "SERVICE_NAME: {}\n  TYPE               : 0x{:x} {}\n  STATE              : {} {}\n  WIN32_EXIT_CODE    : {}\n  SERVICE_EXIT_CODE  : {}\n  CHECKPOINT         : 0x{:x}\n  WAIT_HINT          : 0x{:x}\n  PID                : {}\n  FLAGS              : 0x{:x}",
        svc,
        status.dwServiceType, win::service_type_str(status.dwServiceType),
        status.dwCurrentState, win::service_state_str(status.dwCurrentState),
        status.dwWin32ExitCode,
        status.dwServiceSpecificExitCode,
        status.dwCheckPoint,
        status.dwWaitHint,
        status.dwProcessId,
        status.dwServiceFlags,
    ))
}

#[cfg(not(windows))]
pub fn sc_query(args: &[String]) -> anyhow::Result<String> {
    let mut cmd_args = vec!["status".into()];
    if let Some(svc) = args.first() {
        cmd_args.push(svc.clone());
    } else {
        cmd_args = vec!["list-units".into(), "--type=service".into(), "--all".into()];
    }
    let (stdout, stderr) = crate::exec::exec("systemctl", &cmd_args);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr); }
    Ok(stdout)
}

// ── sc_qc ────────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_qc(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let svc = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_qc: <service> [server]"))?;
    let server = args.get(1);

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let svc_w = to_wide(svc);
    let h = unsafe { OpenServiceW(scm.0, svc_w.as_ptr(), SERVICE_QUERY_CONFIG) };
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", svc)));
    }
    let _guard = ScHandle(h);

    // Two-call pattern: first gets needed size
    let mut needed: u32 = 0;
    unsafe { QueryServiceConfigW(h, std::ptr::null_mut(), 0, &mut needed) };
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        QueryServiceConfigW(h, buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW, needed, &mut needed)
    };
    if ok == 0 {
        return Err(win::last_error("QueryServiceConfigW"));
    }
    let cfg = unsafe { &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW) };

    Ok(format!(
        "SERVICE_NAME: {}\n  TYPE               : 0x{:x} {}\n  START_TYPE         : {} {}\n  ERROR_CONTROL      : {}\n  BINARY_PATH_NAME   : {}\n  LOAD_ORDER_GROUP   : {}\n  TAG                : {}\n  DISPLAY_NAME       : {}\n  DEPENDENCIES       : {}\n  SERVICE_START_NAME : {}",
        svc,
        cfg.dwServiceType, win::service_type_str(cfg.dwServiceType),
        cfg.dwStartType, win::service_start_type_str(cfg.dwStartType),
        cfg.dwErrorControl,
        from_wide(cfg.lpBinaryPathName),
        from_wide(cfg.lpLoadOrderGroup),
        cfg.dwTagId,
        from_wide(cfg.lpDisplayName),
        from_wide(cfg.lpDependencies),
        from_wide(cfg.lpServiceStartName),
    ))
}

#[cfg(not(windows))]
pub fn sc_qc(args: &[String]) -> anyhow::Result<String> {
    let svc = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_qc: <service> [server] required"))?;
    let (stdout, _) = crate::exec::exec("systemctl", &["show".into(), svc.clone()]);
    Ok(stdout)
}

// ── sc_qdescription ──────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_qdescription(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let svc = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_qdescription: <service> [server]"))?;
    let server = args.get(1);

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let svc_w = to_wide(svc);
    let h = unsafe { OpenServiceW(scm.0, svc_w.as_ptr(), SERVICE_QUERY_CONFIG) };
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", svc)));
    }
    let _guard = ScHandle(h);

    let mut needed: u32 = 0;
    unsafe { QueryServiceConfig2W(h, SERVICE_CONFIG_DESCRIPTION, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Ok(format!("{}: (no description)", svc));
    }
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        QueryServiceConfig2W(h, SERVICE_CONFIG_DESCRIPTION, buf.as_mut_ptr(), needed, &mut needed)
    };
    if ok == 0 {
        return Err(win::last_error("QueryServiceConfig2W(DESCRIPTION)"));
    }
    let desc = unsafe { &*(buf.as_ptr() as *const SERVICE_DESCRIPTIONW) };
    let text = from_wide(desc.lpDescription);
    Ok(format!("SERVICE_NAME: {}\n  DESCRIPTION        : {}", svc, text))
}

#[cfg(not(windows))]
pub fn sc_qdescription(args: &[String]) -> anyhow::Result<String> {
    let svc = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_qdescription: <service> [server] required"))?;
    let (stdout, _) = crate::exec::exec("systemctl", &["show".into(), "-p".into(), "Description".into(), svc.clone()]);
    Ok(stdout)
}

// ── sc_qfailure ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_qfailure(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let svc = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_qfailure: <service> [server]"))?;
    let server = args.get(1);

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let svc_w = to_wide(svc);
    let h = unsafe { OpenServiceW(scm.0, svc_w.as_ptr(), SERVICE_QUERY_CONFIG) };
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", svc)));
    }
    let _guard = ScHandle(h);

    let mut needed: u32 = 0;
    unsafe { QueryServiceConfig2W(h, SERVICE_CONFIG_FAILURE_ACTIONS, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Ok(format!("{}: (no failure actions configured)", svc));
    }
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        QueryServiceConfig2W(h, SERVICE_CONFIG_FAILURE_ACTIONS, buf.as_mut_ptr(), needed, &mut needed)
    };
    if ok == 0 {
        return Err(win::last_error("QueryServiceConfig2W(FAILURE_ACTIONS)"));
    }
    let fa = unsafe { &*(buf.as_ptr() as *const SERVICE_FAILURE_ACTIONSW) };

    let mut out = format!("SERVICE_NAME: {}\n  RESET_PERIOD (seconds) : {}\n  REBOOT_MSG             : {}\n  COMMAND_LINE           : {}\n  FAILURE_ACTIONS:\n",
        svc,
        fa.dwResetPeriod,
        from_wide(fa.lpRebootMsg),
        from_wide(fa.lpCommand),
    );

    if !fa.lpsaActions.is_null() && fa.cActions > 0 {
        let actions = unsafe {
            std::slice::from_raw_parts(fa.lpsaActions, fa.cActions as usize)
        };
        for (i, a) in actions.iter().enumerate() {
            let action_str = match a.Type {
                SC_ACTION_NONE => "NONE",
                SC_ACTION_RESTART => "RESTART",
                SC_ACTION_REBOOT => "REBOOT",
                SC_ACTION_RUN_COMMAND => "RUN_COMMAND",
                _ => "UNKNOWN",
            };
            out.push_str(&format!("    #{}: {} -- Delay = {} ms\n", i + 1, action_str, a.Delay));
        }
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn sc_qfailure(args: &[String]) -> anyhow::Result<String> {
    let _ = args;
    anyhow::bail!("sc_qfailure: Windows only")
}

// ── sc_enum ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_enum(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let server = args.first();
    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_ENUMERATE_SERVICE)?;

    // Two-call pattern
    let mut needed: u32 = 0;
    let mut count: u32 = 0;
    let mut resume: u32 = 0;
    unsafe {
        EnumServicesStatusExW(
            scm.0, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_STATE_ALL,
            std::ptr::null_mut(), 0,
            &mut needed, &mut count, &mut resume, std::ptr::null(),
        )
    };

    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        EnumServicesStatusExW(
            scm.0, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_STATE_ALL,
            buf.as_mut_ptr(), buf.len() as u32,
            &mut needed, &mut count, &mut resume, std::ptr::null(),
        )
    };
    if ok == 0 {
        return Err(win::last_error("EnumServicesStatusExW"));
    }

    let entries = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            count as usize,
        )
    };

    let mut out = String::new();
    for e in entries {
        let name = from_wide(e.lpServiceName);
        let display = from_wide(e.lpDisplayName);
        let state = win::service_state_str(e.ServiceStatusProcess.dwCurrentState);
        let stype = win::service_type_str(e.ServiceStatusProcess.dwServiceType);
        out.push_str(&format!(
            "SERVICE_NAME: {}\n  DISPLAY_NAME: {}\n  TYPE: {}\n  STATE: {}\n  PID: {}\n\n",
            name, display, stype, state, e.ServiceStatusProcess.dwProcessId,
        ));
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn sc_enum(args: &[String]) -> anyhow::Result<String> {
    let _ = args;
    let (stdout, _) = crate::exec::exec("systemctl", &["list-units".into(), "--type=service".into(), "--all".into()]);
    Ok(stdout)
}

// ── sc_create ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_create(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let name = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("sc_create: <name> <binpath> [displayname] [start] [server]"))?;
    let binpath = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("sc_create: <name> <binpath> required"))?;

    let display = args.get(2);
    let start_type_str = args.get(3).map(|s| s.as_str()).unwrap_or("demand");
    let server = args.get(4);

    let start_type = match start_type_str.to_lowercase().as_str() {
        "boot" => 0u32,
        "system" => 1,
        "auto" => 2,
        "demand" => 3,
        "disabled" => 4,
        _ => 3,
    };

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CREATE_SERVICE)?;
    let name_w = to_wide(name);
    let display_w = display.map(|d| to_wide(d));
    let binpath_w = to_wide(binpath);

    let h = unsafe {
        CreateServiceW(
            scm.0,
            name_w.as_ptr(),
            display_w.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            SERVICE_ALL_ACCESS,
            0x10, // SERVICE_WIN32_OWN_PROCESS
            start_type,
            1, // SERVICE_ERROR_NORMAL
            binpath_w.as_ptr(),
            std::ptr::null(), // load order group
            std::ptr::null_mut(), // tag id
            std::ptr::null(), // dependencies
            std::ptr::null(), // service start name (LocalSystem)
            std::ptr::null(), // password
        )
    };
    if h.is_null() {
        return Err(win::last_error("CreateServiceW"));
    }
    unsafe { CloseServiceHandle(h) };

    Ok(format!("[SC] CreateService SUCCESS: {}", name))
}

#[cfg(not(windows))]
pub fn sc_create(args: &[String]) -> anyhow::Result<String> {
    let _ = args;
    anyhow::bail!("sc_create: Windows only")
}

// ── sc_delete ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_delete(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let name = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_delete: <name> [server]"))?;
    let server = args.get(1);

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let name_w = to_wide(name);
    let h = unsafe { OpenServiceW(scm.0, name_w.as_ptr(), 0x10000) }; // DELETE
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", name)));
    }
    let _guard = ScHandle(h);

    let ok = unsafe { DeleteService(h) };
    if ok == 0 {
        return Err(win::last_error("DeleteService"));
    }
    Ok(format!("[SC] DeleteService SUCCESS: {}", name))
}

#[cfg(not(windows))]
pub fn sc_delete(args: &[String]) -> anyhow::Result<String> {
    let _ = args;
    anyhow::bail!("sc_delete: Windows only")
}

// ── sc_start ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_start(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let name = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_start: <name> [server]"))?;
    let server = args.get(1);

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let name_w = to_wide(name);
    let h = unsafe { OpenServiceW(scm.0, name_w.as_ptr(), SERVICE_START) };
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", name)));
    }
    let _guard = ScHandle(h);

    let ok = unsafe { StartServiceW(h, 0, std::ptr::null()) };
    if ok == 0 {
        return Err(win::last_error("StartServiceW"));
    }
    Ok(format!("[SC] StartService SUCCESS: {}", name))
}

#[cfg(not(windows))]
pub fn sc_start(args: &[String]) -> anyhow::Result<String> {
    let name = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_start: <name> [server]"))?;
    let (stdout, stderr) = crate::exec::exec("systemctl", &["start".into(), name.clone()]);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr); }
    Ok(if stdout.is_empty() { format!("Started {}", name) } else { stdout })
}

// ── sc_stop ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_stop(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let name = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_stop: <name> [server]"))?;
    let server = args.get(1);

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let name_w = to_wide(name);
    let h = unsafe { OpenServiceW(scm.0, name_w.as_ptr(), 0x20) }; // SERVICE_STOP
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", name)));
    }
    let _guard = ScHandle(h);

    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    let ok = unsafe { ControlService(h, SERVICE_CONTROL_STOP, &mut status) };
    if ok == 0 {
        return Err(win::last_error("ControlService(STOP)"));
    }
    Ok(format!("[SC] StopService SUCCESS: {} (state={})", name, win::service_state_str(status.dwCurrentState)))
}

#[cfg(not(windows))]
pub fn sc_stop(args: &[String]) -> anyhow::Result<String> {
    let name = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_stop: <name> [server]"))?;
    let (stdout, stderr) = crate::exec::exec("systemctl", &["stop".into(), name.clone()]);
    if !stderr.is_empty() && stdout.is_empty() { anyhow::bail!("{}", stderr); }
    Ok(if stdout.is_empty() { format!("Stopped {}", name) } else { stdout })
}

// ── sc_config ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_config(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let name = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("sc_config: <name> <binpath> [start] [server]"))?;
    let binpath = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("sc_config: <name> <binpath> required"))?;
    let start_type_str = args.get(2);
    let server = args.get(3);

    let start_type = if let Some(st) = start_type_str {
        match st.to_lowercase().as_str() {
            "boot" => 0u32,
            "system" => 1,
            "auto" => 2,
            "demand" => 3,
            "disabled" => 4,
            _ => SERVICE_NO_CHANGE,
        }
    } else {
        SERVICE_NO_CHANGE
    };

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let name_w = to_wide(name);
    let h = unsafe { OpenServiceW(scm.0, name_w.as_ptr(), 0x0002) }; // SERVICE_CHANGE_CONFIG
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", name)));
    }
    let _guard = ScHandle(h);

    let binpath_w = to_wide(binpath);
    let ok = unsafe {
        ChangeServiceConfigW(
            h,
            SERVICE_NO_CHANGE, // service type
            start_type,
            SERVICE_NO_CHANGE, // error control
            binpath_w.as_ptr(),
            std::ptr::null(), // load order group
            std::ptr::null_mut(), // tag id
            std::ptr::null(), // dependencies
            std::ptr::null(), // service start name
            std::ptr::null(), // password
            std::ptr::null(), // display name
        )
    };
    if ok == 0 {
        return Err(win::last_error("ChangeServiceConfigW"));
    }
    Ok(format!("[SC] ChangeServiceConfig SUCCESS: {}", name))
}

#[cfg(not(windows))]
pub fn sc_config(args: &[String]) -> anyhow::Result<String> {
    let _ = args;
    anyhow::bail!("sc_config: Windows only")
}

// ── sc_description ───────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_description(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let name = args.get(0)
        .ok_or_else(|| anyhow::anyhow!("sc_description: <name> <description> [server]"))?;
    let desc = args.get(1)
        .ok_or_else(|| anyhow::anyhow!("sc_description: <name> <description> required"))?;
    let server = args.get(2);

    let scm = open_scm(server.map(|s| s.as_str()), SC_MANAGER_CONNECT)?;
    let name_w = to_wide(name);
    let h = unsafe { OpenServiceW(scm.0, name_w.as_ptr(), 0x0002) }; // SERVICE_CHANGE_CONFIG
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", name)));
    }
    let _guard = ScHandle(h);

    let desc_w = to_wide(desc);
    let sd = SERVICE_DESCRIPTIONW { lpDescription: desc_w.as_ptr() as *mut u16 };
    let ok = unsafe {
        ChangeServiceConfig2W(h, SERVICE_CONFIG_DESCRIPTION, &sd as *const _ as *const std::ffi::c_void)
    };
    if ok == 0 {
        return Err(win::last_error("ChangeServiceConfig2W(DESCRIPTION)"));
    }
    Ok(format!("[SC] ChangeServiceConfig2 SUCCESS: {} description set", name))
}

#[cfg(not(windows))]
pub fn sc_description(args: &[String]) -> anyhow::Result<String> {
    let _ = args;
    anyhow::bail!("sc_description: Windows only")
}

// ── sc_failure ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn sc_failure(args: &[String]) -> anyhow::Result<String> {
    use windows_sys::Win32::System::Services::*;

    let name = args.first()
        .ok_or_else(|| anyhow::anyhow!("sc_failure: <name> <reset_secs> <actions: restart/ms[/restart/ms]> [server]"))?;
    let reset_str = args.get(1).map(|s| s.as_str()).unwrap_or("0");
    let actions_str = args.get(2).map(|s| s.as_str()).unwrap_or("");

    // Determine server — last arg if it doesn't contain / or =
    let server = args.get(3).and_then(|s| {
        if !s.contains('/') && !s.contains('=') { Some(s.as_str()) } else { None }
    });

    let reset_period: u32 = reset_str.parse().unwrap_or(0);

    // Parse actions: "restart/60000/restart/60000" or "restart/60000"
    let mut actions: Vec<SC_ACTION> = Vec::new();
    if !actions_str.is_empty() {
        let parts: Vec<&str> = actions_str.split('/').collect();
        for pair in parts.chunks(2) {
            let action_type = match pair[0].to_lowercase().as_str() {
                "restart" => SC_ACTION_RESTART,
                "reboot" => SC_ACTION_REBOOT,
                "run" | "command" => SC_ACTION_RUN_COMMAND,
                _ => SC_ACTION_NONE,
            };
            let delay: u32 = pair.get(1).and_then(|s| s.parse().ok()).unwrap_or(60000);
            actions.push(SC_ACTION { Type: action_type, Delay: delay });
        }
    }

    let scm = open_scm(server, SC_MANAGER_CONNECT)?;
    let name_w = to_wide(name);
    let h = unsafe { OpenServiceW(scm.0, name_w.as_ptr(), 0x0002) }; // SERVICE_CHANGE_CONFIG
    if h.is_null() {
        return Err(win::last_error(&format!("OpenServiceW({})", name)));
    }
    let _guard = ScHandle(h);

    let fa = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: reset_period,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: if actions.is_empty() { std::ptr::null_mut() } else { actions.as_mut_ptr() },
    };

    let ok = unsafe {
        ChangeServiceConfig2W(h, SERVICE_CONFIG_FAILURE_ACTIONS, &fa as *const _ as *const std::ffi::c_void)
    };
    if ok == 0 {
        return Err(win::last_error("ChangeServiceConfig2W(FAILURE_ACTIONS)"));
    }
    Ok(format!("[SC] ChangeServiceConfig2 SUCCESS: {} failure actions set", name))
}

#[cfg(not(windows))]
pub fn sc_failure(args: &[String]) -> anyhow::Result<String> {
    let _ = args;
    anyhow::bail!("sc_failure: Windows only")
}

// ── Internal helpers ─────────────────────────────────────────────────────────

#[cfg(windows)]
fn open_scm(server: Option<&str>, access: u32) -> anyhow::Result<ScHandle> {
    use windows_sys::Win32::System::Services::OpenSCManagerW;

    let server_w = server.map(|s| to_wide(&format!("\\\\{}", s)));
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

    let h = unsafe { OpenSCManagerW(server_ptr, std::ptr::null(), access) };
    if h.is_null() {
        return Err(win::last_error(&format!("OpenSCManagerW({})", server.unwrap_or("local"))));
    }
    Ok(ScHandle(h))
}
