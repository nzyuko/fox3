/// Screenshot capture for the Fox3 agent.
///
/// Windows: Uses GDI (GetDC, BitBlt, GetDIBits) via direct FFI to capture
/// the primary screen and return raw BMP bytes.
///
/// Non-Windows: Returns an error (not implemented).

/// Capture the primary screen and return BMP image bytes.
pub fn capture() -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        windows_capture()
    }
    #[cfg(not(windows))]
    {
        Err("screenshot: not supported on this platform".to_string())
    }
}

#[cfg(windows)]
fn windows_capture() -> Result<Vec<u8>, String> {
    use std::ffi::c_void;

    const SM_CXSCREEN: i32 = 0;
    const SM_CYSCREEN: i32 = 1;
    const SRCCOPY: u32 = 0x00CC0020;
    const BI_RGB: u32 = 0;
    const DIB_RGB_COLORS: u32 = 0;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct BITMAPINFOHEADER {
        biSize: u32,
        biWidth: i32,
        biHeight: i32,
        biPlanes: u16,
        biBitCount: u16,
        biCompression: u32,
        biSizeImage: u32,
        biXPelsPerMeter: i32,
        biYPelsPerMeter: i32,
        biClrUsed: u32,
        biClrImportant: u32,
    }

    // BITMAPINFO is header + color table (empty for 32-bit)
    #[repr(C)]
    #[allow(non_snake_case)]
    struct BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER,
        bmiColors: [u32; 1], // unused for 32-bit
    }

    extern "system" {
        fn GetDC(hwnd: *mut c_void) -> *mut c_void;
        fn CreateCompatibleDC(hdc: *mut c_void) -> *mut c_void;
        fn CreateCompatibleBitmap(hdc: *mut c_void, cx: i32, cy: i32) -> *mut c_void;
        fn SelectObject(hdc: *mut c_void, h: *mut c_void) -> *mut c_void;
        fn BitBlt(
            dest: *mut c_void, x: i32, y: i32, cx: i32, cy: i32,
            src: *mut c_void, srcx: i32, srcy: i32, rop: u32,
        ) -> i32;
        fn GetDIBits(
            hdc: *mut c_void, hbm: *mut c_void, start: u32, lines: u32,
            bits: *mut u8, bi: *mut BITMAPINFO, usage: u32,
        ) -> i32;
        fn DeleteDC(hdc: *mut c_void) -> i32;
        fn DeleteObject(h: *mut c_void) -> i32;
        fn ReleaseDC(hwnd: *mut c_void, hdc: *mut c_void) -> i32;
        fn GetSystemMetrics(index: i32) -> i32;
    }

    unsafe {
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        if width <= 0 || height <= 0 {
            return Err("screenshot: GetSystemMetrics returned 0".to_string());
        }

        let hdc_screen = GetDC(std::ptr::null_mut());
        if hdc_screen.is_null() {
            return Err("screenshot: GetDC failed".to_string());
        }

        let hdc_mem = CreateCompatibleDC(hdc_screen);
        if hdc_mem.is_null() {
            ReleaseDC(std::ptr::null_mut(), hdc_screen);
            return Err("screenshot: CreateCompatibleDC failed".to_string());
        }

        let hbm = CreateCompatibleBitmap(hdc_screen, width, height);
        if hbm.is_null() {
            DeleteDC(hdc_mem);
            ReleaseDC(std::ptr::null_mut(), hdc_screen);
            return Err("screenshot: CreateCompatibleBitmap failed".to_string());
        }

        let old = SelectObject(hdc_mem, hbm);
        let ok = BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);
        SelectObject(hdc_mem, old);

        if ok == 0 {
            DeleteObject(hbm);
            DeleteDC(hdc_mem);
            ReleaseDC(std::ptr::null_mut(), hdc_screen);
            return Err("screenshot: BitBlt failed".to_string());
        }

        // Extract pixel data as 32-bit BGRA
        let row_bytes = ((width as u32 * 32 + 31) / 32) * 4;
        let pixel_size = row_bytes as usize * height as usize;
        let mut pixels = vec![0u8; pixel_size];

        let mut bi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: height, // positive = bottom-up (BMP standard)
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: pixel_size as u32,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [0],
        };

        let lines = GetDIBits(
            hdc_mem,
            hbm,
            0,
            height as u32,
            pixels.as_mut_ptr(),
            &mut bi,
            DIB_RGB_COLORS,
        );

        DeleteObject(hbm);
        DeleteDC(hdc_mem);
        ReleaseDC(std::ptr::null_mut(), hdc_screen);

        if lines == 0 {
            return Err("screenshot: GetDIBits failed".to_string());
        }

        // Build BMP file: file header (14) + info header (40) + pixels
        let file_size = 14 + 40 + pixel_size;
        let mut bmp = Vec::with_capacity(file_size);

        // BITMAPFILEHEADER (14 bytes)
        bmp.extend_from_slice(b"BM");                           // bfType
        bmp.extend_from_slice(&(file_size as u32).to_le_bytes()); // bfSize
        bmp.extend_from_slice(&0u16.to_le_bytes());              // bfReserved1
        bmp.extend_from_slice(&0u16.to_le_bytes());              // bfReserved2
        bmp.extend_from_slice(&54u32.to_le_bytes());             // bfOffBits

        // BITMAPINFOHEADER (40 bytes)
        bmp.extend_from_slice(&40u32.to_le_bytes());             // biSize
        bmp.extend_from_slice(&width.to_le_bytes());             // biWidth
        bmp.extend_from_slice(&height.to_le_bytes());            // biHeight
        bmp.extend_from_slice(&1u16.to_le_bytes());              // biPlanes
        bmp.extend_from_slice(&32u16.to_le_bytes());             // biBitCount
        bmp.extend_from_slice(&(BI_RGB).to_le_bytes());          // biCompression
        bmp.extend_from_slice(&(pixel_size as u32).to_le_bytes()); // biSizeImage
        bmp.extend_from_slice(&0i32.to_le_bytes());              // biXPelsPerMeter
        bmp.extend_from_slice(&0i32.to_le_bytes());              // biYPelsPerMeter
        bmp.extend_from_slice(&0u32.to_le_bytes());              // biClrUsed
        bmp.extend_from_slice(&0u32.to_le_bytes());              // biClrImportant

        // Pixel data
        bmp.extend_from_slice(&pixels);

        Ok(bmp)
    }
}
