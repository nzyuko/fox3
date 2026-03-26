/// Scheduled task commands via COM Task Scheduler API + registry fallback.
/// Windows only. No child processes.

#[cfg(windows)]
use super::winapi_helpers::win;

// ── COM Task Scheduler raw FFI ──────────────────────────────────────────────

#[cfg(windows)]
mod task_com {
    use super::win;
    use std::ffi::c_void;
    use std::ptr;

    // GUIDs
    const CLSID_TASK_SCHEDULER: [u8; 16] = guid_bytes("0f87369f-a4e5-4cfc-bd3e-73e6154572dd");
    const IID_ITASK_SERVICE: [u8; 16] = guid_bytes("2faba4c7-4da9-4013-9697-20cc3fd40f85");

    const fn guid_bytes(s: &str) -> [u8; 16] {
        // Parse at compile time — simplified, assumes valid lowercase hex GUID
        let b = s.as_bytes();
        let mut out = [0u8; 16];

        // Data1 (LE u32): bytes 0-7
        out[3] = hex2(b[0], b[1]);
        out[2] = hex2(b[2], b[3]);
        out[1] = hex2(b[4], b[5]);
        out[0] = hex2(b[6], b[7]);
        // Data2 (LE u16): bytes 9-12
        out[5] = hex2(b[9], b[10]);
        out[4] = hex2(b[11], b[12]);
        // Data3 (LE u16): bytes 14-17
        out[7] = hex2(b[14], b[15]);
        out[6] = hex2(b[16], b[17]);
        // Data4: bytes 19-22, 24-35
        out[8] = hex2(b[19], b[20]);
        out[9] = hex2(b[21], b[22]);
        out[10] = hex2(b[24], b[25]);
        out[11] = hex2(b[26], b[27]);
        out[12] = hex2(b[28], b[29]);
        out[13] = hex2(b[30], b[31]);
        out[14] = hex2(b[32], b[33]);
        out[15] = hex2(b[34], b[35]);
        out
    }

    const fn hex2(a: u8, b: u8) -> u8 {
        (hexval(a) << 4) | hexval(b)
    }

    const fn hexval(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    // COM function types
    type CoInitializeExFn = unsafe extern "system" fn(reserved: *mut c_void, coinit: u32) -> i32;
    type CoCreateInstanceFn = unsafe extern "system" fn(
        clsid: *const [u8; 16], outer: *mut c_void, ctx: u32,
        iid: *const [u8; 16], ppv: *mut *mut c_void,
    ) -> i32;
    type CoUninitializeFn = unsafe extern "system" fn();
    type SysAllocStringFn = unsafe extern "system" fn(*const u16) -> *mut u16;
    type SysFreeStringFn = unsafe extern "system" fn(*mut u16);

    pub struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe {
                if let Ok(uninit) = win::get_proc::<CoUninitializeFn>("ole32.dll", "CoUninitialize") {
                    uninit();
                }
            }
        }
    }

    pub fn com_init() -> anyhow::Result<ComGuard> {
        let co_init: CoInitializeExFn = unsafe { win::get_proc("ole32.dll", "CoInitializeEx")? };
        let hr = unsafe { co_init(ptr::null_mut(), 0) }; // COINIT_MULTITHREADED
        if hr < 0 && hr != 1 { // S_FALSE (1) means already initialized
            anyhow::bail!("CoInitializeEx failed: HRESULT 0x{:08x}", hr as u32);
        }
        Ok(ComGuard)
    }

    fn bstr(s: &str) -> anyhow::Result<*mut u16> {
        let alloc: SysAllocStringFn = unsafe { win::get_proc("oleaut32.dll", "SysAllocString")? };
        let w = win::to_wide(s);
        let p = unsafe { alloc(w.as_ptr()) };
        if p.is_null() { anyhow::bail!("SysAllocString failed"); }
        Ok(p)
    }

    fn bstr_free(p: *mut u16) {
        if !p.is_null() {
            if let Ok(free) = unsafe { win::get_proc::<SysFreeStringFn>("oleaut32.dll", "SysFreeString") } {
                unsafe { free(p); }
            }
        }
    }

    /// ITaskService vtable offsets (IDispatch-based COM object)
    /// IUnknown: 0=QueryInterface, 1=AddRef, 2=Release
    /// IDispatch: 3=GetTypeInfoCount, 4=GetTypeInfo, 5=GetIDsOfNames, 6=Invoke
    /// ITaskService: 7=GetFolder, 8=GetRunningTasks, 9=NewTask, 10=Connect,
    ///              11=get_Connected, 12=get_TargetServer, 13=get_ConnectedUser,
    ///              14=get_ConnectedDomain, 15=get_HighestVersion

    pub struct TaskService {
        ptr: *mut c_void,
    }

    impl TaskService {
        pub fn new(server: Option<&str>) -> anyhow::Result<Self> {
            let co_create: CoCreateInstanceFn = unsafe { win::get_proc("ole32.dll", "CoCreateInstance")? };

            let mut ptr: *mut c_void = ptr::null_mut();
            let hr = unsafe {
                co_create(
                    &CLSID_TASK_SCHEDULER, ptr::null_mut(),
                    1 | 4, // CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER
                    &IID_ITASK_SERVICE, &mut ptr,
                )
            };
            if hr < 0 || ptr.is_null() {
                anyhow::bail!("CoCreateInstance(TaskScheduler) failed: HRESULT 0x{:08x}", hr as u32);
            }

            let svc = TaskService { ptr };

            // Call Connect (vtable index 10)
            // Connect(serverName, user, domain, password) — all VARIANT, pass empty
            let server_bstr = if let Some(s) = server { bstr(s)? } else { ptr::null_mut() };
            let hr = unsafe {
                let vtable = *(svc.ptr as *const *const usize);
                let connect: unsafe extern "system" fn(
                    *mut c_void, // this
                    [u8; 16], // serverName VARIANT (VT_BSTR)
                    [u8; 16], // user VARIANT (VT_EMPTY)
                    [u8; 16], // domain VARIANT (VT_EMPTY)
                    [u8; 16], // password VARIANT (VT_EMPTY)
                ) -> i32 = std::mem::transmute(*vtable.add(10));

                let server_var = make_bstr_variant(server_bstr);
                let empty_var = [0u8; 16]; // VT_EMPTY
                connect(svc.ptr, server_var, empty_var, empty_var, empty_var)
            };
            if !server_bstr.is_null() { bstr_free(server_bstr); }
            if hr < 0 {
                anyhow::bail!("ITaskService::Connect failed: HRESULT 0x{:08x}", hr as u32);
            }

            Ok(svc)
        }

        pub fn get_folder(&self, path: &str) -> anyhow::Result<TaskFolder> {
            let path_bstr = bstr(path)?;
            let mut folder_ptr: *mut c_void = ptr::null_mut();
            let hr = unsafe {
                let vtable = *(self.ptr as *const *const usize);
                let get_folder: unsafe extern "system" fn(
                    *mut c_void, *mut u16, *mut *mut c_void,
                ) -> i32 = std::mem::transmute(*vtable.add(7));
                get_folder(self.ptr, path_bstr, &mut folder_ptr)
            };
            bstr_free(path_bstr);
            if hr < 0 || folder_ptr.is_null() {
                anyhow::bail!("ITaskService::GetFolder failed: HRESULT 0x{:08x}", hr as u32);
            }
            Ok(TaskFolder { ptr: folder_ptr })
        }
    }

    impl Drop for TaskService {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe {
                    let vtable = *(self.ptr as *const *const usize);
                    let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                        std::mem::transmute(*vtable.add(2));
                    release(self.ptr);
                }
            }
        }
    }

    /// ITaskFolder vtable:
    /// IUnknown(0-2), IDispatch(3-6),
    /// 7=get_Name, 8=get_Path, 9=GetFolder, 10=GetFolders, 11=CreateFolder,
    /// 12=DeleteFolder, 13=GetTask, 14=GetTasks, 15=DeleteTask,
    /// 16=RegisterTask, 17=RegisterTaskDefinition, 18=GetSecurityDescriptor,
    /// 19=SetSecurityDescriptor
    pub struct TaskFolder {
        ptr: *mut c_void,
    }

    impl TaskFolder {
        /// GetTasks(0) → IRegisteredTaskCollection
        pub fn get_tasks(&self) -> anyhow::Result<Vec<TaskInfo>> {
            let mut coll_ptr: *mut c_void = ptr::null_mut();
            let hr = unsafe {
                let vtable = *(self.ptr as *const *const usize);
                let get_tasks: unsafe extern "system" fn(
                    *mut c_void, i32, *mut *mut c_void,
                ) -> i32 = std::mem::transmute(*vtable.add(14));
                get_tasks(self.ptr, 0, &mut coll_ptr)
            };
            if hr < 0 || coll_ptr.is_null() {
                anyhow::bail!("ITaskFolder::GetTasks failed: HRESULT 0x{:08x}", hr as u32);
            }

            // IRegisteredTaskCollection: IUnknown(0-2), IDispatch(3-6), 7=get_Count, 8=get_Item
            let count = unsafe {
                let vtable = *(coll_ptr as *const *const usize);
                let get_count: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32 =
                    std::mem::transmute(*vtable.add(7));
                let mut c: i32 = 0;
                get_count(coll_ptr, &mut c);
                c
            };

            let mut tasks = Vec::new();
            for i in 1..=count {
                let mut task_ptr: *mut c_void = ptr::null_mut();
                let hr = unsafe {
                    let vtable = *(coll_ptr as *const *const usize);
                    // get_Item takes a VARIANT (index), returns IRegisteredTask
                    let get_item: unsafe extern "system" fn(
                        *mut c_void, [u8; 16], *mut *mut c_void,
                    ) -> i32 = std::mem::transmute(*vtable.add(8));
                    let idx_var = make_i4_variant(i);
                    get_item(coll_ptr, idx_var, &mut task_ptr)
                };
                if hr < 0 || task_ptr.is_null() { continue; }

                if let Some(info) = read_task_info(task_ptr) {
                    tasks.push(info);
                }

                // Release
                unsafe {
                    let vtable = *(task_ptr as *const *const usize);
                    let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                        std::mem::transmute(*vtable.add(2));
                    release(task_ptr);
                }
            }

            // Release collection
            unsafe {
                let vtable = *(coll_ptr as *const *const usize);
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(*vtable.add(2));
                release(coll_ptr);
            }

            Ok(tasks)
        }

        pub fn delete_task(&self, name: &str) -> anyhow::Result<()> {
            let name_bstr = bstr(name)?;
            let hr = unsafe {
                let vtable = *(self.ptr as *const *const usize);
                let delete_task: unsafe extern "system" fn(
                    *mut c_void, *mut u16, i32,
                ) -> i32 = std::mem::transmute(*vtable.add(15));
                delete_task(self.ptr, name_bstr, 0)
            };
            bstr_free(name_bstr);
            if hr < 0 {
                anyhow::bail!("DeleteTask failed: HRESULT 0x{:08x}", hr as u32);
            }
            Ok(())
        }

        pub fn get_task(&self, name: &str) -> anyhow::Result<*mut c_void> {
            let name_bstr = bstr(name)?;
            let mut task_ptr: *mut c_void = ptr::null_mut();
            let hr = unsafe {
                let vtable = *(self.ptr as *const *const usize);
                let get_task: unsafe extern "system" fn(
                    *mut c_void, *mut u16, *mut *mut c_void,
                ) -> i32 = std::mem::transmute(*vtable.add(13));
                get_task(self.ptr, name_bstr, &mut task_ptr)
            };
            bstr_free(name_bstr);
            if hr < 0 || task_ptr.is_null() {
                anyhow::bail!("GetTask('{}') failed: HRESULT 0x{:08x}", name, hr as u32);
            }
            Ok(task_ptr)
        }

        /// RegisterTask from XML
        pub fn register_task_xml(&self, name: &str, xml: &str) -> anyhow::Result<()> {
            let name_bstr = bstr(name)?;
            let xml_bstr = bstr(xml)?;
            let mut task_ptr: *mut c_void = ptr::null_mut();
            let hr = unsafe {
                let vtable = *(self.ptr as *const *const usize);
                // RegisterTask(path, xmlText, flags, userId, password, logonType, sddl, ppTask)
                let register: unsafe extern "system" fn(
                    *mut c_void, *mut u16, *mut u16, i32,
                    [u8; 16], [u8; 16], i32, [u8; 16], *mut *mut c_void,
                ) -> i32 = std::mem::transmute(*vtable.add(16));
                let empty = [0u8; 16];
                register(self.ptr, name_bstr, xml_bstr,
                    6, // TASK_CREATE_OR_UPDATE
                    empty, empty,
                    3, // TASK_LOGON_INTERACTIVE_TOKEN
                    empty, &mut task_ptr)
            };
            bstr_free(name_bstr);
            bstr_free(xml_bstr);
            if hr < 0 {
                anyhow::bail!("RegisterTask failed: HRESULT 0x{:08x}", hr as u32);
            }
            if !task_ptr.is_null() {
                unsafe {
                    let vtable = *(task_ptr as *const *const usize);
                    let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                        std::mem::transmute(*vtable.add(2));
                    release(task_ptr);
                }
            }
            Ok(())
        }
    }

    impl Drop for TaskFolder {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe {
                    let vtable = *(self.ptr as *const *const usize);
                    let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                        std::mem::transmute(*vtable.add(2));
                    release(self.ptr);
                }
            }
        }
    }

    pub struct TaskInfo {
        pub name: String,
        pub path: String,
        pub state: String,
        pub last_run: String,
        pub next_run: String,
    }

    /// IRegisteredTask vtable:
    /// 7=get_Name, 8=get_Path, 9=get_State, 10=get_Enabled, 11=Run, 12=RunEx,
    /// 13=GetInstances, 14=get_LastRunTime, 15=get_LastTaskResult,
    /// 16=get_NumberOfMissedRuns, 17=get_NextRunTime, 18=get_Definition,
    /// 19=get_Xml, 20=GetSecurityDescriptor, 21=SetSecurityDescriptor, 22=Stop, 23=GetRunTimes
    fn read_task_info(task_ptr: *mut c_void) -> Option<TaskInfo> {
        unsafe {
            let vtable = *(task_ptr as *const *const usize);

            // get_Name (7)
            let mut name_bstr: *mut u16 = ptr::null_mut();
            let get_name: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> i32 =
                std::mem::transmute(*vtable.add(7));
            get_name(task_ptr, &mut name_bstr);
            let name = if !name_bstr.is_null() {
                let s = win::from_wide(name_bstr);
                bstr_free(name_bstr);
                s
            } else {
                return None;
            };

            // get_Path (8)
            let mut path_bstr: *mut u16 = ptr::null_mut();
            let get_path: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> i32 =
                std::mem::transmute(*vtable.add(8));
            get_path(task_ptr, &mut path_bstr);
            let path = if !path_bstr.is_null() {
                let s = win::from_wide(path_bstr);
                bstr_free(path_bstr);
                s
            } else {
                String::new()
            };

            // get_State (9) → TASK_STATE enum
            let mut state: i32 = 0;
            let get_state: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32 =
                std::mem::transmute(*vtable.add(9));
            get_state(task_ptr, &mut state);
            let state_str = match state {
                0 => "Unknown",
                1 => "Disabled",
                2 => "Queued",
                3 => "Ready",
                4 => "Running",
                _ => "Unknown",
            };

            Some(TaskInfo {
                name,
                path,
                state: state_str.to_string(),
                last_run: String::new(),
                next_run: String::new(),
            })
        }
    }

    /// Run a registered task (IRegisteredTask::Run, vtable 11)
    pub fn run_task(task_ptr: *mut c_void) -> anyhow::Result<()> {
        let hr = unsafe {
            let vtable = *(task_ptr as *const *const usize);
            let run: unsafe extern "system" fn(
                *mut c_void, [u8; 16], *mut *mut c_void,
            ) -> i32 = std::mem::transmute(*vtable.add(11));
            let empty = [0u8; 16]; // VT_EMPTY params
            let mut running: *mut c_void = ptr::null_mut();
            run(task_ptr, empty, &mut running)
        };
        if hr < 0 {
            anyhow::bail!("IRegisteredTask::Run failed: HRESULT 0x{:08x}", hr as u32);
        }
        Ok(())
    }

    /// Stop a registered task (IRegisteredTask::Stop, vtable 22)
    pub fn stop_task(task_ptr: *mut c_void) -> anyhow::Result<()> {
        let hr = unsafe {
            let vtable = *(task_ptr as *const *const usize);
            let stop: unsafe extern "system" fn(*mut c_void, i32) -> i32 =
                std::mem::transmute(*vtable.add(22));
            stop(task_ptr, 0)
        };
        if hr < 0 {
            anyhow::bail!("IRegisteredTask::Stop failed: HRESULT 0x{:08x}", hr as u32);
        }
        Ok(())
    }

    /// Release a COM pointer
    pub fn release(ptr: *mut c_void) {
        if !ptr.is_null() {
            unsafe {
                let vtable = *(ptr as *const *const usize);
                let rel: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(*vtable.add(2));
                rel(ptr);
            }
        }
    }

    // VARIANT helpers (16 bytes on x64)
    fn make_bstr_variant(bstr: *mut u16) -> [u8; 16] {
        let mut v = [0u8; 16];
        // VT_BSTR = 8
        v[0] = 8;
        v[1] = 0;
        // bytes 8..16 = pointer (on x64)
        let ptr_bytes = (bstr as usize).to_le_bytes();
        v[8..16].copy_from_slice(&ptr_bytes);
        v
    }

    fn make_i4_variant(val: i32) -> [u8; 16] {
        let mut v = [0u8; 16];
        // VT_I4 = 3
        v[0] = 3;
        v[1] = 0;
        // bytes 8..12 = i32 value
        let val_bytes = val.to_le_bytes();
        v[8..12].copy_from_slice(&val_bytes);
        v
    }
}

// ── schtasksenum ────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn schtasksenum(args: &[String]) -> anyhow::Result<String> {
    let _com = task_com::com_init()?;
    let server = args.first().map(|s| s.as_str());
    let svc = task_com::TaskService::new(server)?;
    let folder = svc.get_folder("\\")?;
    let tasks = folder.get_tasks()?;

    let mut out = format!("{:<40} {:<12} {}\n", "Task Name", "State", "Path");
    out.push_str(&"-".repeat(70));
    out.push('\n');

    for t in &tasks {
        out.push_str(&format!("{:<40} {:<12} {}\n", t.name, t.state, t.path));
    }
    out.push_str(&format!("\nTotal: {} tasks", tasks.len()));
    Ok(out)
}

#[cfg(not(windows))]
pub fn schtasksenum(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("schtasksenum: Windows only")
}

// ── schtasksquery ───────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn schtasksquery(args: &[String]) -> anyhow::Result<String> {
    let taskpath = args.first()
        .ok_or_else(|| anyhow::anyhow!("schtasksquery: <taskpath> [server] required"))?;
    let server = args.get(1).map(|s| s.as_str());

    let _com = task_com::com_init()?;
    let svc = task_com::TaskService::new(server)?;

    // Split into folder path and task name
    let (folder_path, task_name) = if let Some(pos) = taskpath.rfind('\\') {
        (&taskpath[..pos], &taskpath[pos+1..])
    } else {
        ("\\", taskpath.as_str())
    };
    let folder_path = if folder_path.is_empty() { "\\" } else { folder_path };

    let folder = svc.get_folder(folder_path)?;
    let task_ptr = folder.get_task(task_name)?;

    // Read task XML (vtable 19: get_Xml)
    let xml = unsafe {
        let vtable = *(task_ptr as *const *const usize);
        let mut xml_bstr: *mut u16 = std::ptr::null_mut();
        let get_xml: unsafe extern "system" fn(*mut std::ffi::c_void, *mut *mut u16) -> i32 =
            std::mem::transmute(*vtable.add(19));
        get_xml(task_ptr, &mut xml_bstr);
        let s = if !xml_bstr.is_null() {
            let x = win::from_wide(xml_bstr);
            task_com::release(xml_bstr as *mut _);
            x
        } else {
            "(unable to read XML)".into()
        };
        s
    };
    task_com::release(task_ptr);

    Ok(format!("Task: {}\n\n{}", taskpath, xml))
}

#[cfg(not(windows))]
pub fn schtasksquery(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("schtasksquery: Windows only")
}

// ── schtaskscreate ──────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn schtaskscreate(args: &[String]) -> anyhow::Result<String> {
    if args.len() < 2 {
        anyhow::bail!("schtaskscreate: <taskname> <program> <schedule> [server]\n  Or: <taskname> /xml <xmlpath> [server]");
    }
    let taskname = &args[0];
    let server = if args.get(1).map(|s| s.as_str()) == Some("/xml") {
        args.get(3).map(|s| s.as_str())
    } else {
        args.get(3).map(|s| s.as_str())
    };

    let _com = task_com::com_init()?;
    let svc = task_com::TaskService::new(server)?;
    let folder = svc.get_folder("\\")?;

    let xml = if args.get(1).map(|s| s.as_str()) == Some("/xml") {
        let xmlpath = args.get(2)
            .ok_or_else(|| anyhow::anyhow!("schtaskscreate: /xml requires <xmlpath>"))?;
        std::fs::read_to_string(xmlpath)
            .map_err(|e| anyhow::anyhow!("Failed to read XML file: {}", e))?
    } else {
        let program = &args[1];
        let schedule = args.get(2).map(|s| s.as_str()).unwrap_or("ONCE");
        let trigger = match schedule.to_uppercase().as_str() {
            "DAILY" => "<CalendarTrigger><StartBoundary>2025-01-01T08:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>",
            "LOGON" => "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>",
            "ONCE" => "<TimeTrigger><StartBoundary>2025-01-01T12:00:00</StartBoundary></TimeTrigger>",
            _ => "<TimeTrigger><StartBoundary>2025-01-01T12:00:00</StartBoundary></TimeTrigger>",
        };

        format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>{}</Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
    </Exec>
  </Actions>
</Task>"#, trigger, program)
    };

    folder.register_task_xml(taskname, &xml)?;
    Ok(format!("Task '{}' created successfully", taskname))
}

#[cfg(not(windows))]
pub fn schtaskscreate(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("schtaskscreate: Windows only")
}

// ── schtasksdelete ──────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn schtasksdelete(args: &[String]) -> anyhow::Result<String> {
    let taskname = args.first()
        .ok_or_else(|| anyhow::anyhow!("schtasksdelete: <taskname> [server] required"))?;
    let server = args.get(1).map(|s| s.as_str());

    let _com = task_com::com_init()?;
    let svc = task_com::TaskService::new(server)?;
    let folder = svc.get_folder("\\")?;
    folder.delete_task(taskname)?;

    Ok(format!("Task '{}' deleted successfully", taskname))
}

#[cfg(not(windows))]
pub fn schtasksdelete(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("schtasksdelete: Windows only")
}

// ── schtasksrun ─────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn schtasksrun(args: &[String]) -> anyhow::Result<String> {
    let taskname = args.first()
        .ok_or_else(|| anyhow::anyhow!("schtasksrun: <taskname> [server] required"))?;
    let server = args.get(1).map(|s| s.as_str());

    let _com = task_com::com_init()?;
    let svc = task_com::TaskService::new(server)?;
    let folder = svc.get_folder("\\")?;
    let task_ptr = folder.get_task(taskname)?;
    task_com::run_task(task_ptr)?;
    task_com::release(task_ptr);

    Ok(format!("Task '{}' started", taskname))
}

#[cfg(not(windows))]
pub fn schtasksrun(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("schtasksrun: Windows only")
}

// ── schtasksstop ────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn schtasksstop(args: &[String]) -> anyhow::Result<String> {
    let taskname = args.first()
        .ok_or_else(|| anyhow::anyhow!("schtasksstop: <taskname> [server] required"))?;
    let server = args.get(1).map(|s| s.as_str());

    let _com = task_com::com_init()?;
    let svc = task_com::TaskService::new(server)?;
    let folder = svc.get_folder("\\")?;
    let task_ptr = folder.get_task(taskname)?;
    task_com::stop_task(task_ptr)?;
    task_com::release(task_ptr);

    Ok(format!("Task '{}' stopped", taskname))
}

#[cfg(not(windows))]
pub fn schtasksstop(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("schtasksstop: Windows only")
}
