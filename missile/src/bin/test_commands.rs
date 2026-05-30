/// Comprehensive test harness for Fox3 simple_agent WinAPI commands.
///
/// Exercises every one of the 111+ commands via `dispatch()` to verify
/// WinAPI calls succeed or fail gracefully — no child processes, no panics.
///
/// Usage:
///   cargo run --bin test_commands --release
///   (run as admin for Category 4 tests)

// We need access to the crate's dispatch function.
// Since this is a [[bin]] in the same crate, we can use crate-level paths.
use missile::commands::dispatch;

use std::env;
use std::time::Instant;

// ── ANSI colours ─────────────────────────────────────────────────────────────

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

// ── Test framework ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Status {
    Pass,
    Fail,
    Skip,
}

struct TestResult {
    name: String,
    status: Status,
    detail: String,
    elapsed_ms: u128,
}

#[derive(Clone)]
enum Expect {
    /// Ok + output contains substring (case-insensitive)
    OkContains(&'static str),
    /// Ok + output.len() > 0
    OkNonEmpty,
    /// Ok, any output (even empty)
    OkAny,
    /// Err (any error) — command must fail
    ErrAny,
    /// Err + message contains substring (case-insensitive)
    #[allow(dead_code)]
    ErrContains(&'static str),
    /// Either Ok or Err is acceptable (graceful)
    OkOrErr,
    /// Ok + output matches a custom validator fn
    OkCustom(&'static str, fn(&str) -> bool),
}

struct TestCase {
    name: &'static str,
    cmd: &'static str,
    args: Vec<String>,
    expect: Expect,
}

fn run_test(tc: &TestCase) -> TestResult {
    let start = Instant::now();
    let args_ref: Vec<String> = tc.args.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch(tc.cmd, &args_ref)
    }));
    let elapsed = start.elapsed().as_millis();

    match result {
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            TestResult {
                name: tc.name.to_string(),
                status: Status::Fail,
                detail: format!("PANIC: {}", msg),
                elapsed_ms: elapsed,
            }
        }
        Ok(dispatch_result) => {
            match (&tc.expect, &dispatch_result) {
                (Expect::OkContains(sub), Ok(output)) => {
                    if output.to_lowercase().contains(&sub.to_lowercase()) {
                        TestResult {
                            name: tc.name.to_string(),
                            status: Status::Pass,
                            detail: format!("Ok, contains \"{}\" ({} bytes)", sub, output.len()),
                            elapsed_ms: elapsed,
                        }
                    } else {
                        TestResult {
                            name: tc.name.to_string(),
                            status: Status::Fail,
                            detail: format!(
                                "Ok but missing \"{}\". Output (first 200): {}",
                                sub,
                                &output[..output.len().min(200)]
                            ),
                            elapsed_ms: elapsed,
                        }
                    }
                }
                (Expect::OkNonEmpty, Ok(output)) => {
                    if !output.trim().is_empty() {
                        TestResult {
                            name: tc.name.to_string(),
                            status: Status::Pass,
                            detail: format!("Ok, non-empty ({} bytes)", output.len()),
                            elapsed_ms: elapsed,
                        }
                    } else {
                        TestResult {
                            name: tc.name.to_string(),
                            status: Status::Fail,
                            detail: "Ok but output is empty".to_string(),
                            elapsed_ms: elapsed,
                        }
                    }
                }
                (Expect::OkAny, Ok(output)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Pass,
                    detail: format!("Ok ({} bytes)", output.len()),
                    elapsed_ms: elapsed,
                },
                (Expect::ErrAny, Err(e)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Pass,
                    detail: format!("Err as expected: {}", truncate(&e.to_string(), 120)),
                    elapsed_ms: elapsed,
                },
                (Expect::ErrContains(sub), Err(e)) => {
                    let msg = e.to_string();
                    if msg.to_lowercase().contains(&sub.to_lowercase()) {
                        TestResult {
                            name: tc.name.to_string(),
                            status: Status::Pass,
                            detail: format!("Err contains \"{}\": {}", sub, truncate(&msg, 120)),
                            elapsed_ms: elapsed,
                        }
                    } else {
                        TestResult {
                            name: tc.name.to_string(),
                            status: Status::Fail,
                            detail: format!("Err but missing \"{}\": {}", sub, truncate(&msg, 200)),
                            elapsed_ms: elapsed,
                        }
                    }
                }
                (Expect::OkOrErr, Ok(output)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Pass,
                    detail: format!("Ok ({} bytes)", output.len()),
                    elapsed_ms: elapsed,
                },
                (Expect::OkOrErr, Err(e)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Pass,
                    detail: format!("Err (graceful): {}", truncate(&e.to_string(), 120)),
                    elapsed_ms: elapsed,
                },
                (Expect::OkCustom(desc, validator), Ok(output)) => {
                    if validator(output) {
                        TestResult {
                            name: tc.name.to_string(),
                            status: Status::Pass,
                            detail: format!("Ok, {} ({} bytes)", desc, output.len()),
                            elapsed_ms: elapsed,
                        }
                    } else {
                        TestResult {
                            name: tc.name.to_string(),
                            status: Status::Fail,
                            detail: format!(
                                "Ok but failed: {}. Output (first 200): {}",
                                desc,
                                &output[..output.len().min(200)]
                            ),
                            elapsed_ms: elapsed,
                        }
                    }
                }
                // Mismatches
                (Expect::OkContains(sub), Err(e)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Fail,
                    detail: format!(
                        "Expected Ok(contains \"{}\") but got Err: {}",
                        sub,
                        truncate(&e.to_string(), 200)
                    ),
                    elapsed_ms: elapsed,
                },
                (Expect::OkNonEmpty, Err(e)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Fail,
                    detail: format!("Expected Ok(non-empty) but got Err: {}", truncate(&e.to_string(), 200)),
                    elapsed_ms: elapsed,
                },
                (Expect::OkAny, Err(e)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Fail,
                    detail: format!("Expected Ok but got Err: {}", truncate(&e.to_string(), 200)),
                    elapsed_ms: elapsed,
                },
                (Expect::ErrAny, Ok(output)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Fail,
                    detail: format!(
                        "Expected Err but got Ok: {}",
                        truncate(output, 200)
                    ),
                    elapsed_ms: elapsed,
                },
                (Expect::ErrContains(sub), Ok(output)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Fail,
                    detail: format!(
                        "Expected Err(contains \"{}\") but got Ok: {}",
                        sub,
                        truncate(output, 200)
                    ),
                    elapsed_ms: elapsed,
                },
                (Expect::OkCustom(desc, _), Err(e)) => TestResult {
                    name: tc.name.to_string(),
                    status: Status::Fail,
                    detail: format!(
                        "Expected Ok({}) but got Err: {}",
                        desc,
                        truncate(&e.to_string(), 200)
                    ),
                    elapsed_ms: elapsed,
                },
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

fn run_category(name: &str, tests: &[TestCase]) -> Vec<TestResult> {
    println!(
        "\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}"
    );
    println!("{BOLD}{CYAN}  Category: {}{RESET}", name);
    println!(
        "{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}"
    );

    let mut results = Vec::new();
    for tc in tests {
        let tr = run_test(tc);
        let symbol = match tr.status {
            Status::Pass => format!("{GREEN}PASS{RESET}"),
            Status::Fail => format!("{RED}FAIL{RESET}"),
            Status::Skip => format!("{YELLOW}SKIP{RESET}"),
        };
        println!(
            "  [{symbol}] {:<45} {:>6}ms  {}",
            tr.name,
            tr.elapsed_ms,
            truncate(&tr.detail, 80)
        );
        results.push(tr);
    }
    results
}

// ── Admin check ──────────────────────────────────────────────────────────────

#[cfg(windows)]
fn is_admin() -> bool {
    use std::ptr;
    type HANDLE = *mut std::ffi::c_void;
    type BOOL = i32;
    type DWORD = u32;

    #[repr(C)]
    struct TOKEN_ELEVATION {
        token_is_elevated: DWORD,
    }

    extern "system" {
        fn OpenProcessToken(proc: HANDLE, access: DWORD, token: *mut HANDLE) -> BOOL;
        fn GetCurrentProcess() -> HANDLE;
        fn GetTokenInformation(
            token: HANDLE,
            class: u32,
            info: *mut u8,
            len: DWORD,
            ret_len: *mut DWORD,
        ) -> BOOL;
        fn CloseHandle(h: HANDLE) -> BOOL;
    }

    const TOKEN_QUERY: DWORD = 0x0008;
    const TOKEN_ELEVATION_TYPE: u32 = 20; // TokenElevation

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { token_is_elevated: 0 };
        let mut ret_len: DWORD = 0;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION_TYPE,
            &mut elev as *mut _ as *mut u8,
            std::mem::size_of::<TOKEN_ELEVATION>() as DWORD,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elev.token_is_elevated != 0
    }
}

#[cfg(not(windows))]
fn is_admin() -> bool {
    false
}

// ── Validator helpers ────────────────────────────────────────────────────────

fn is_hex(s: &str, expected_len: usize) -> bool {
    s.trim().len() == expected_len && s.trim().chars().all(|c| c.is_ascii_hexdigit())
}

fn extract_hash(output: &str) -> &str {
    // Output format: "ALGO (path) = <hex>"
    if let Some(pos) = output.rfind("= ") {
        output[pos + 2..].trim()
    } else {
        output.trim()
    }
}

fn validate_md5(output: &str) -> bool {
    is_hex(extract_hash(output), 32)
}

fn validate_sha1(output: &str) -> bool {
    is_hex(extract_hash(output), 40)
}

fn validate_sha256(output: &str) -> bool {
    is_hex(extract_hash(output), 64)
}

fn validate_krb_hash_password(output: &str) -> bool {
    // Must contain the RC4/NTLM hash of "password"
    output.to_lowercase().contains("8846f7eaee8fb117ad06bdd830b7586c")
}

fn validate_krb_hash_empty(output: &str) -> bool {
    // Must contain the RC4/NTLM hash of empty string
    output.to_lowercase().contains("31d6cfe0d16ae931b73c59d7e0c089c0")
}

fn validate_krb_hash_with_user(output: &str) -> bool {
    // Must contain RC4 + AES256 + AES128 lines
    let lower = output.to_lowercase();
    lower.contains("rc4") && lower.contains("aes256") && lower.contains("aes128")
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    println!("{BOLD}{CYAN}");
    println!("  ╔═══════════════════════════════════════════════════════╗");
    println!("  ║     Fox3 Simple Agent — WinAPI Command Test Suite    ║");
    println!("  ╚═══════════════════════════════════════════════════════╝");
    println!("{RESET}");

    let admin = is_admin();
    let pid = std::process::id().to_string();
    let temp_dir = env::temp_dir().join("fox3_test");
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_str = temp_dir.to_string_lossy().to_string();

    println!(
        "  Admin: {}{}{RESET}  |  PID: {}  |  Temp: {}",
        if admin { GREEN } else { YELLOW },
        if admin { "Yes" } else { "No" },
        pid,
        temp_str
    );

    let total_start = Instant::now();
    let mut all_results: Vec<TestResult> = Vec::new();

    // ═══════════════════════════════════════════════════════════════════════
    // Category 1: Local Safe
    // ═══════════════════════════════════════════════════════════════════════

    let local_safe = vec![
        TestCase {
            name: "help (no args)",
            cmd: "help",
            args: vec![],
            expect: Expect::OkContains("help"),
        },
        TestCase {
            name: "help (whoami)",
            cmd: "help",
            args: s(&["whoami"]),
            expect: Expect::OkContains("whoami"),
        },
        TestCase {
            name: "md5 notepad.exe",
            cmd: "md5",
            args: s(&["C:\\Windows\\notepad.exe"]),
            expect: Expect::OkCustom("32-char hex", validate_md5),
        },
        TestCase {
            name: "sha1 notepad.exe",
            cmd: "sha1",
            args: s(&["C:\\Windows\\notepad.exe"]),
            expect: Expect::OkCustom("40-char hex", validate_sha1),
        },
        TestCase {
            name: "sha256 notepad.exe",
            cmd: "sha256",
            args: s(&["C:\\Windows\\notepad.exe"]),
            expect: Expect::OkCustom("64-char hex", validate_sha256),
        },
        TestCase {
            name: "arp",
            cmd: "arp",
            args: vec![],
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "routeprint",
            cmd: "routeprint",
            args: vec![],
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "probe 127.0.0.1:445",
            cmd: "probe",
            args: s(&["127.0.0.1", "445"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "listdns",
            cmd: "listdns",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "whoami",
            cmd: "whoami",
            args: vec![],
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "enumlocalsessions",
            cmd: "enumlocalsessions",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "netlocalgrouplist",
            cmd: "netlocalgrouplist",
            args: vec![],
            expect: Expect::OkContains("Administrators"),
        },
        TestCase {
            name: "netlocalgrouplistmembers Administrators",
            cmd: "netlocalgrouplistmembers",
            args: s(&["Administrators"]),
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "netloggedon",
            cmd: "netloggedon",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "netsession",
            cmd: "netsession",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "sc_query Spooler",
            cmd: "sc_query",
            args: s(&["Spooler"]),
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "sc_qc Spooler",
            cmd: "sc_qc",
            args: s(&["Spooler"]),
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "sc_qdescription Spooler",
            cmd: "sc_qdescription",
            args: s(&["Spooler"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "sc_qfailure Spooler",
            cmd: "sc_qfailure",
            args: s(&["Spooler"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "sc_enum",
            cmd: "sc_enum",
            args: vec![],
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "reg_query HKLM ProductName",
            cmd: "reg_query",
            args: s(&[
                "HKLM",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                "ProductName",
            ]),
            expect: Expect::OkContains("Windows"),
        },
        TestCase {
            name: "reg_query HKLM CurrentVersion (all)",
            cmd: "reg_query",
            args: s(&["HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"]),
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "reg_query_recursive Run",
            cmd: "reg_query_recursive",
            args: s(&["HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "schtasksenum",
            cmd: "schtasksenum",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "schtasksquery SynchronizeTime",
            cmd: "schtasksquery",
            args: s(&["\\Microsoft\\Windows\\Time Synchronization\\SynchronizeTime"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "findloadedmodule ntdll.dll",
            cmd: "findloadedmodule",
            args: s(&["ntdll.dll"]),
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "listmods",
            cmd: "listmods",
            args: vec![],
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "windowlist",
            cmd: "windowlist",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "get_priv SeChangeNotifyPrivilege",
            cmd: "get_priv",
            args: s(&["SeChangeNotifyPrivilege"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "cacls cmd.exe",
            cmd: "cacls",
            args: s(&["C:\\Windows\\System32\\cmd.exe"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "dir System32 *.dll",
            cmd: "dir",
            args: s(&["C:\\Windows\\System32", "*.dll"]),
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "netshares",
            cmd: "netshares",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "netuse_list",
            cmd: "netuse_list",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "resources",
            cmd: "resources",
            args: vec![],
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "locale",
            cmd: "locale",
            args: vec![],
            expect: Expect::OkNonEmpty,
        },
        TestCase {
            name: "useridletime",
            cmd: "useridletime",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "driversigs",
            cmd: "driversigs",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "enum_filter_driver",
            cmd: "enum_filter_driver",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "adv_audit_policies",
            cmd: "adv_audit_policies",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "list_firewall_rules",
            cmd: "list_firewall_rules",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "get_password_policy",
            cmd: "get_password_policy",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "get_session_info",
            cmd: "get_session_info",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        // ── Privesc Checks ───────────────────────────────────────────────
        TestCase {
            name: "privcheck",
            cmd: "privcheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "alwaysinstallelevated",
            cmd: "alwaysinstallelevated",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "autologoncheck",
            cmd: "autologoncheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "credmancheck",
            cmd: "credmancheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "hijackablepathcheck",
            cmd: "hijackablepathcheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "modifiableautoruncheck",
            cmd: "modifiableautoruncheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "modifiablesvccheck",
            cmd: "modifiablesvccheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "tokenprivcheck",
            cmd: "tokenprivcheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "unquotedsvcpathcheck",
            cmd: "unquotedsvcpathcheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "pshistorycheck",
            cmd: "pshistorycheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "uacstatuscheck",
            cmd: "uacstatuscheck",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        // ── Process operations (safe subset) ─────────────────────────────
        TestCase {
            name: "processlisthandles (self)",
            cmd: "processlisthandles",
            args: vec![pid.clone()],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "suspendresume (bad args)",
            cmd: "suspendresume",
            args: vec![],
            expect: Expect::ErrAny,
        },
    ];

    all_results.extend(run_category("Local Safe", &local_safe));

    // ═══════════════════════════════════════════════════════════════════════
    // Category 2: Pure Rust Crypto (known test vectors)
    // ═══════════════════════════════════════════════════════════════════════

    let crypto_tests = vec![
        TestCase {
            name: "krb_hash 'password'",
            cmd: "krb_hash",
            args: s(&["password"]),
            expect: Expect::OkCustom("RC4=8846f7ea...", validate_krb_hash_password),
        },
        TestCase {
            name: "krb_hash '' (empty)",
            cmd: "krb_hash",
            args: s(&[""]),
            expect: Expect::OkCustom("RC4=31d6cfe0...", validate_krb_hash_empty),
        },
        TestCase {
            name: "krb_hash with /user /domain",
            cmd: "krb_hash",
            args: s(&["password", "/user:testuser", "/domain:TESTDOMAIN"]),
            expect: Expect::OkCustom("RC4+AES256+AES128", validate_krb_hash_with_user),
        },
        TestCase {
            name: "krb_describe (invalid base64)",
            cmd: "krb_describe",
            args: s(&["invalidbase64!!!"]),
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "krb_describe (empty)",
            cmd: "krb_describe",
            args: vec![],
            expect: Expect::ErrAny,
        },
    ];

    all_results.extend(run_category("Pure Rust Crypto", &crypto_tests));

    // ═══════════════════════════════════════════════════════════════════════
    // Category 3: Domain/Remote Graceful Failure
    // ═══════════════════════════════════════════════════════════════════════

    let domain_tests = vec![
        TestCase {
            name: "netgrouplist (no domain)",
            cmd: "netgrouplist",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "netgrouplistmembers Domain Admins",
            cmd: "netgrouplistmembers",
            args: s(&["Domain Admins"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "netuser nonexistent",
            cmd: "netuser",
            args: s(&["nonexistent_user_xyz123"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "nettime invalid host",
            cmd: "nettime",
            args: s(&["nonexistent.host.invalid"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "netuptime invalid host",
            cmd: "netuptime",
            args: s(&["nonexistent.host.invalid"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "netview",
            cmd: "netview",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "ldapsearch (no domain)",
            cmd: "ldapsearch",
            args: s(&["(objectClass=*)"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "adcs_enum (no domain)",
            cmd: "adcs_enum",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "wmi_query Win32_OperatingSystem",
            cmd: "wmi_query",
            args: s(&["SELECT Caption FROM Win32_OperatingSystem"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_asktgt (no domain)",
            cmd: "krb_asktgt",
            args: s(&["testuser", "FAKE.DOMAIN"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_asktgs (no domain)",
            cmd: "krb_asktgs",
            args: s(&["cifs/fake.host"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_renew (no domain)",
            cmd: "krb_renew",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_s4u (no domain)",
            cmd: "krb_s4u",
            args: s(&["admin", "cifs/fake"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_cross_s4u (no domain)",
            cmd: "krb_cross_s4u",
            args: s(&["admin", "cifs/fake", "OTHER.DOMAIN"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_tgtdeleg (no domain)",
            cmd: "krb_tgtdeleg",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_kerberoasting (no domain)",
            cmd: "krb_kerberoasting",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_asreproasting (no domain)",
            cmd: "krb_asreproasting",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_changepw (no domain)",
            cmd: "krb_changepw",
            args: s(&["fakeuser", "old", "new", "/domain:FAKE"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_ptt (invalid ticket)",
            cmd: "krb_ptt",
            args: s(&["AAAA"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_klist",
            cmd: "krb_klist",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_purge",
            cmd: "krb_purge",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_dump",
            cmd: "krb_dump",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "krb_triage",
            cmd: "krb_triage",
            args: vec![],
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "adcs_request (no CA)",
            cmd: "adcs_request",
            args: s(&["FakeCA", "User"]),
            expect: Expect::OkOrErr,
        },
    ];

    all_results.extend(run_category("Domain/Remote Graceful Failure", &domain_tests));

    // ═══════════════════════════════════════════════════════════════════════
    // Category 4: Registry Round-Trip (safe, uses HKCU temp key)
    // ═══════════════════════════════════════════════════════════════════════

    let reg_tests = vec![
        TestCase {
            name: "reg_set HKCU temp key",
            cmd: "reg_set",
            args: s(&[
                "HKCU",
                "SOFTWARE\\Fox3TestTemp",
                "TestValue",
                "REG_SZ",
                "HelloFox3",
            ]),
            expect: Expect::OkAny,
        },
        TestCase {
            name: "reg_query HKCU temp key",
            cmd: "reg_query",
            args: s(&["HKCU", "SOFTWARE\\Fox3TestTemp", "TestValue"]),
            expect: Expect::OkContains("HelloFox3"),
        },
        TestCase {
            name: "reg_delete HKCU temp key",
            cmd: "reg_delete",
            args: s(&["HKCU", "SOFTWARE\\Fox3TestTemp"]),
            expect: Expect::OkOrErr,
        },
    ];

    all_results.extend(run_category("Registry Round-Trip", &reg_tests));

    // ═══════════════════════════════════════════════════════════════════════
    // Category 5: Admin-Required (skip if not elevated)
    // ═══════════════════════════════════════════════════════════════════════

    if admin {
        let admin_tests = vec![
            TestCase {
                name: "get_priv SeDebugPrivilege",
                cmd: "get_priv",
                args: s(&["SeDebugPrivilege"]),
                expect: Expect::OkOrErr,
            },
            TestCase {
                name: "reg_save HKLM SYSTEM",
                cmd: "reg_save",
                args: vec![
                    "HKLM".into(),
                    "SYSTEM".into(),
                    format!("{}\\test_system.bak", temp_str),
                ],
                expect: Expect::OkOrErr,
            },
            TestCase {
                name: "chromekey",
                cmd: "chromekey",
                args: vec![],
                expect: Expect::OkOrErr,
            },
            TestCase {
                name: "ntfs_read SAM",
                cmd: "ntfs_read",
                args: s(&["C:\\Windows\\System32\\config\\SAM"]),
                expect: Expect::OkOrErr,
            },
            TestCase {
                name: "ntfs_copy SAM to temp",
                cmd: "ntfs_copy",
                args: vec![
                    "C:\\Windows\\System32\\config\\SAM".into(),
                    temp_str.clone(),
                ],
                expect: Expect::OkOrErr,
            },
            TestCase {
                name: "procdump (self)",
                cmd: "procdump",
                args: vec![pid.clone(), format!("{}\\test.dmp", temp_str)],
                expect: Expect::OkOrErr,
            },
            TestCase {
                name: "get_dpapi_system",
                cmd: "get_dpapi_system",
                args: vec![],
                expect: Expect::OkOrErr,
            },
            TestCase {
                name: "sc_start Spooler",
                cmd: "sc_start",
                args: s(&["Spooler"]),
                expect: Expect::OkOrErr,
            },
        ];
        all_results.extend(run_category("Admin-Required", &admin_tests));
    } else {
        println!(
            "\n{YELLOW}  ⚠ Skipping Category: Admin-Required (not elevated){RESET}"
        );
        // Add skip entries for summary
        for name in &[
            "get_priv SeDebugPrivilege",
            "reg_save HKLM SYSTEM",
            "chromekey",
            "ntfs_read SAM",
            "ntfs_copy SAM",
            "procdump (self)",
            "get_dpapi_system",
            "sc_start Spooler",
        ] {
            all_results.push(TestResult {
                name: name.to_string(),
                status: Status::Skip,
                detail: "requires admin".into(),
                elapsed_ms: 0,
            });
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Category 6: Destructive Validation (error paths only)
    // ═══════════════════════════════════════════════════════════════════════

    let destructive_tests = vec![
        TestCase {
            name: "sc_create (no args)",
            cmd: "sc_create",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "sc_delete (nonexistent svc)",
            cmd: "sc_delete",
            args: s(&["nonexistent_svc_xyz123"]),
            expect: Expect::OkOrErr, // may Err with not-found or Ok with error text
        },
        TestCase {
            name: "sc_config (no args)",
            cmd: "sc_config",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "sc_stop (nonexistent svc)",
            cmd: "sc_stop",
            args: s(&["nonexistent_svc_xyz123"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "sc_description (no args)",
            cmd: "sc_description",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "sc_failure (no args)",
            cmd: "sc_failure",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "reg_set (no args)",
            cmd: "reg_set",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "reg_delete (nonexistent key)",
            cmd: "reg_delete",
            args: s(&["HKLM", "SOFTWARE\\NonExistentKey12345\\SubKey"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "reg_hide (no args)",
            cmd: "reg_hide",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "reg_unhide (no args)",
            cmd: "reg_unhide",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "schtaskscreate (no args)",
            cmd: "schtaskscreate",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "schtasksdelete (nonexistent)",
            cmd: "schtasksdelete",
            args: s(&["\\NonExistentTask12345"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "schtasksrun (nonexistent)",
            cmd: "schtasksrun",
            args: s(&["\\NonExistentTask12345"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "schtasksstop (nonexistent)",
            cmd: "schtasksstop",
            args: s(&["\\NonExistentTask12345"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "adduser (no args)",
            cmd: "adduser",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "enableuser (nonexistent)",
            cmd: "enableuser",
            args: s(&["nonexistent_user_xyz123"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "disableuser (nonexistent)",
            cmd: "disableuser",
            args: s(&["nonexistent_user_xyz123"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "setuserpass (no args)",
            cmd: "setuserpass",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "addusertogroup (no args)",
            cmd: "addusertogroup",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "unexpireuser (nonexistent)",
            cmd: "unexpireuser",
            args: s(&["nonexistent_user_xyz123"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "processdestroy (no args)",
            cmd: "processdestroy",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "ghost_task (no args)",
            cmd: "ghost_task",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "ntfs_copy (no args)",
            cmd: "ntfs_copy",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "ntfs_read (no args)",
            cmd: "ntfs_read",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "netuse_add (no args)",
            cmd: "netuse_add",
            args: vec![],
            expect: Expect::ErrAny,
        },
        TestCase {
            name: "netuse_delete (nonexistent)",
            cmd: "netuse_delete",
            args: s(&["Z:"]),
            expect: Expect::OkOrErr,
        },
        TestCase {
            name: "unknown command",
            cmd: "totally_fake_command_xyz",
            args: vec![],
            expect: Expect::ErrAny,
        },
    ];

    all_results.extend(run_category("Destructive Validation (error paths)", &destructive_tests));

    // ═══════════════════════════════════════════════════════════════════════
    // Summary
    // ═══════════════════════════════════════════════════════════════════════

    let total_elapsed = total_start.elapsed();
    let pass_count = all_results.iter().filter(|r| r.status == Status::Pass).count();
    let fail_count = all_results.iter().filter(|r| r.status == Status::Fail).count();
    let skip_count = all_results.iter().filter(|r| r.status == Status::Skip).count();
    let total_count = all_results.len();

    println!("\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}");
    println!("{BOLD}  SUMMARY{RESET}");
    println!("{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}");
    println!(
        "  Total: {}  |  {GREEN}Pass: {}{RESET}  |  {RED}Fail: {}{RESET}  |  {YELLOW}Skip: {}{RESET}",
        total_count, pass_count, fail_count, skip_count
    );
    println!("  Time: {:.1}s", total_elapsed.as_secs_f64());

    if fail_count > 0 {
        println!("\n{BOLD}{RED}  Failed tests:{RESET}");
        for r in &all_results {
            if r.status == Status::Fail {
                println!("    {RED}X{RESET} {}: {}", r.name, r.detail);
            }
        }
    }

    // Cleanup temp dir
    let _ = std::fs::remove_dir_all(&temp_dir);

    println!();
    if fail_count == 0 {
        println!("{BOLD}{GREEN}  ALL TESTS PASSED!{RESET}");
    } else {
        println!("{BOLD}{RED}  {} TEST(S) FAILED{RESET}", fail_count);
    }
    println!();

    std::process::exit(if fail_count == 0 { 0 } else { 1 });
}

// Helper to convert &str slice to Vec<String>
fn s(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| a.to_string()).collect()
}
