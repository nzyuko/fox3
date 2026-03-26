/// Help system for Fox3 agent commands.
/// Static registry of command metadata with descriptions, usage, and guardrails.

pub struct CommandInfo {
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub usage: &'static str,
    pub guardrails: &'static str,
    pub windows_only: bool,
}

pub fn run(args: &[String]) -> anyhow::Result<String> {
    if let Some(cmd) = args.first() {
        // Show help for specific command
        if let Some(info) = COMMANDS.iter().find(|c| c.name.eq_ignore_ascii_case(cmd)) {
            let mut out = format!("=== {} ===\n", info.name);
            out.push_str(&format!("Category   : {}\n", info.category));
            out.push_str(&format!("Description: {}\n", info.description));
            out.push_str(&format!("Usage      : {}\n", info.usage));
            if info.windows_only {
                out.push_str("Platform   : Windows only\n");
            } else {
                out.push_str("Platform   : Cross-platform\n");
            }
            if !info.guardrails.is_empty() {
                out.push_str(&format!("OPSEC      : {}\n", info.guardrails));
            }
            Ok(out)
        } else {
            anyhow::bail!("Unknown command: {}. Type 'help' for list.", cmd)
        }
    } else {
        // Show all commands grouped by category
        let categories = [
            "Built-in", "Network", "Domain/User", "Services", "Registry",
            "Scheduled Tasks", "User Management", "Process", "Files/Shares",
            "Crypto", "System", "Security/Audit", "AD/LDAP",
            "Credentials", "Kerberos", "PrivEsc", "Evasion",
        ];

        let mut out = String::from("=== Fox3 Agent Commands ===\n\n");
        for cat in &categories {
            let cmds: Vec<&CommandInfo> = COMMANDS.iter()
                .filter(|c| c.category == *cat)
                .collect();
            if cmds.is_empty() { continue; }

            out.push_str(&format!("--- {} ---\n", cat));
            for c in cmds {
                let platform = if c.windows_only { " [W]" } else { "" };
                out.push_str(&format!("  {:<28} {}{}\n", c.name, c.description, platform));
            }
            out.push('\n');
        }
        out.push_str("[W] = Windows only. Use 'help <command>' for details.\n");
        Ok(out)
    }
}

static COMMANDS: &[CommandInfo] = &[
    // ── Built-in (existing in agent.rs) ──────────────────────────────────
    CommandInfo { name: "cd", category: "Built-in", description: "Change working directory", usage: "cd <path>", guardrails: "", windows_only: false },
    CommandInfo { name: "pwd", category: "Built-in", description: "Print working directory", usage: "pwd", guardrails: "", windows_only: false },
    CommandInfo { name: "ls", category: "Built-in", description: "List directory contents", usage: "ls [path]", guardrails: "", windows_only: false },
    CommandInfo { name: "env", category: "Built-in", description: "Get/set environment variables", usage: "env [KEY] [VALUE]", guardrails: "", windows_only: false },
    CommandInfo { name: "rm", category: "Built-in", description: "Remove file or directory", usage: "rm <path>", guardrails: "Recursive for directories. Irreversible.", windows_only: false },
    CommandInfo { name: "touch", category: "Built-in", description: "Create empty file", usage: "touch <path>", guardrails: "", windows_only: false },
    CommandInfo { name: "sdelete", category: "Built-in", description: "Secure delete (zero + remove)", usage: "sdelete <path>", guardrails: "Overwrites with zeros before deletion.", windows_only: false },
    CommandInfo { name: "killprocess", category: "Built-in", description: "Kill process by PID", usage: "killprocess <pid>", guardrails: "Forceful termination. Process cannot clean up.", windows_only: false },
    CommandInfo { name: "ifconfig", category: "Built-in", description: "Network interface info", usage: "ifconfig", guardrails: "", windows_only: false },
    CommandInfo { name: "nslookup", category: "Built-in", description: "DNS resolution", usage: "nslookup <hostname>", guardrails: "", windows_only: false },
    CommandInfo { name: "ps", category: "Built-in", description: "List running processes", usage: "ps", guardrails: "", windows_only: false },
    CommandInfo { name: "netstat", category: "Built-in", description: "Network connections", usage: "netstat", guardrails: "", windows_only: false },
    CommandInfo { name: "uptime", category: "Built-in", description: "System uptime", usage: "uptime", guardrails: "", windows_only: false },
    CommandInfo { name: "memory", category: "Built-in", description: "Memory info", usage: "memory", guardrails: "", windows_only: false },
    CommandInfo { name: "pipes", category: "Built-in", description: "Enumerate named pipes", usage: "pipes", guardrails: "", windows_only: false },

    // ── Network Enumeration ──────────────────────────────────────────────
    CommandInfo { name: "arp", category: "Network", description: "List ARP table entries", usage: "arp", guardrails: "", windows_only: false },
    CommandInfo { name: "routeprint", category: "Network", description: "List IPv4 routing table", usage: "routeprint", guardrails: "", windows_only: false },
    CommandInfo { name: "probe", category: "Network", description: "Check if host:port is open", usage: "probe <host> <port>", guardrails: "Creates TCP connection. May be logged by firewall/IDS.", windows_only: false },
    CommandInfo { name: "listdns", category: "Network", description: "List DNS cache entries", usage: "listdns", guardrails: "", windows_only: true },
    CommandInfo { name: "nettime", category: "Network", description: "Display time on remote machine", usage: "nettime [hostname]", guardrails: "", windows_only: false },
    CommandInfo { name: "netuptime", category: "Network", description: "Boot time / uptime of remote host", usage: "netuptime [hostname]", guardrails: "", windows_only: false },
    CommandInfo { name: "netview", category: "Network", description: "List computers in domain", usage: "netview [domain]", guardrails: "Queries domain controller. Network traffic visible.", windows_only: true },

    // ── Domain / User Enumeration ────────────────────────────────────────
    CommandInfo { name: "netuser", category: "Domain/User", description: "Info about domain/local user", usage: "netuser <username> [domain]", guardrails: "", windows_only: false },
    CommandInfo { name: "netgrouplist", category: "Domain/User", description: "List domain groups", usage: "netgrouplist [domain]", guardrails: "Queries domain controller.", windows_only: false },
    CommandInfo { name: "netgrouplistmembers", category: "Domain/User", description: "List members of domain group", usage: "netgrouplistmembers <group> [domain]", guardrails: "", windows_only: false },
    CommandInfo { name: "netlocalgrouplist", category: "Domain/User", description: "List local groups", usage: "netlocalgrouplist [server]", guardrails: "", windows_only: false },
    CommandInfo { name: "netlocalgrouplistmembers", category: "Domain/User", description: "List local group members", usage: "netlocalgrouplistmembers <group> [server]", guardrails: "", windows_only: false },
    CommandInfo { name: "netloggedon", category: "Domain/User", description: "Users logged on (requires admin)", usage: "netloggedon [hostname]", guardrails: "May require admin privileges on remote host.", windows_only: false },
    CommandInfo { name: "netsession", category: "Domain/User", description: "Enumerate sessions on computer", usage: "netsession [computer]", guardrails: "", windows_only: true },
    CommandInfo { name: "whoami", category: "Domain/User", description: "Full whoami /all (token info)", usage: "whoami", guardrails: "", windows_only: false },
    CommandInfo { name: "enumlocalsessions", category: "Domain/User", description: "Enumerate local + RDP sessions", usage: "enumlocalsessions", guardrails: "", windows_only: false },

    // ── Service Management ───────────────────────────────────────────────
    CommandInfo { name: "sc_query", category: "Services", description: "Query service status", usage: "sc_query [service] [server]", guardrails: "", windows_only: false },
    CommandInfo { name: "sc_qc", category: "Services", description: "Query service configuration", usage: "sc_qc <service> [server]", guardrails: "", windows_only: false },
    CommandInfo { name: "sc_qdescription", category: "Services", description: "Query service description", usage: "sc_qdescription <service> [server]", guardrails: "", windows_only: false },
    CommandInfo { name: "sc_qfailure", category: "Services", description: "Query service failure actions", usage: "sc_qfailure <service> [server]", guardrails: "", windows_only: true },
    CommandInfo { name: "sc_enum", category: "Services", description: "Enumerate all services", usage: "sc_enum [server]", guardrails: "", windows_only: false },
    CommandInfo { name: "sc_create", category: "Services", description: "Create a service", usage: "sc_create <name> <binpath> [displayname] [start] [server]", guardrails: "Creates service visible in SCM. High OPSEC risk. Clean up after use.", windows_only: true },
    CommandInfo { name: "sc_delete", category: "Services", description: "Delete a service", usage: "sc_delete <name> [server]", guardrails: "Permanently removes service. Irreversible.", windows_only: true },
    CommandInfo { name: "sc_start", category: "Services", description: "Start a service", usage: "sc_start <name> [server]", guardrails: "", windows_only: false },
    CommandInfo { name: "sc_stop", category: "Services", description: "Stop a service", usage: "sc_stop <name> [server]", guardrails: "May disrupt legitimate services.", windows_only: false },
    CommandInfo { name: "sc_config", category: "Services", description: "Modify service config", usage: "sc_config <name> <binpath> [start] [server]", guardrails: "Modifies service binary path. Persistence technique. High OPSEC.", windows_only: true },
    CommandInfo { name: "sc_description", category: "Services", description: "Set service description", usage: "sc_description <name> <desc> [server]", guardrails: "", windows_only: true },
    CommandInfo { name: "sc_failure", category: "Services", description: "Set service failure actions", usage: "sc_failure <name> <actions...> [server]", guardrails: "Can be used for persistence via failure recovery commands.", windows_only: true },

    // ── Registry Operations ──────────────────────────────────────────────
    CommandInfo { name: "reg_query", category: "Registry", description: "Query registry value or enumerate key", usage: "reg_query [host] <hive> <path> [value]", guardrails: "", windows_only: true },
    CommandInfo { name: "reg_query_recursive", category: "Registry", description: "Recursively enumerate key", usage: "reg_query_recursive [host] <hive> <path>", guardrails: "Large output for deep keys. Consider specific paths.", windows_only: true },
    CommandInfo { name: "reg_set", category: "Registry", description: "Create/set registry value", usage: "reg_set [host] <hive> <key> <value> <type> <data> [--hidden]", guardrails: "Modifies registry. --hidden uses NtSetValueKey with null-byte prefix (SharpHide). Types: REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD.", windows_only: true },
    CommandInfo { name: "reg_delete", category: "Registry", description: "Delete key or value", usage: "reg_delete [host] <hive> <path> [value] [--hidden]", guardrails: "Without [value], deletes all values in key. --hidden targets null-byte prefixed values. Irreversible.", windows_only: true },
    CommandInfo { name: "reg_save", category: "Registry", description: "Save registry hive to file", usage: "reg_save <hive> <path> <outfile>", guardrails: "Writes to disk. Large file for SAM/SECURITY/SYSTEM hives. May trigger AV.", windows_only: true },
    CommandInfo { name: "reg_hide", category: "Registry", description: "Create hidden Run key (SharpHide)", usage: "reg_hide <program> [arguments]", guardrails: "SharpHide technique: NtSetValueKey with null-byte prefix. Invisible to regedit/reg.exe. HKLM if admin, HKCU otherwise. Falls back to normal reg if NT API fails.", windows_only: true },
    CommandInfo { name: "reg_unhide", category: "Registry", description: "Remove hidden Run key", usage: "reg_unhide", guardrails: "Removes the hidden Run key created by reg_hide.", windows_only: true },

    // ── Scheduled Tasks ──────────────────────────────────────────────────
    CommandInfo { name: "schtasksenum", category: "Scheduled Tasks", description: "Enumerate scheduled tasks", usage: "schtasksenum [server]", guardrails: "", windows_only: true },
    CommandInfo { name: "schtasksquery", category: "Scheduled Tasks", description: "Query specific task details", usage: "schtasksquery <taskpath> [server]", guardrails: "", windows_only: true },
    CommandInfo { name: "schtaskscreate", category: "Scheduled Tasks", description: "Create scheduled task", usage: "schtaskscreate <taskname> <program> <schedule> [server]  OR  <taskname> /xml <xmlpath> [server]", guardrails: "Creates scheduled task. Generates Event 4698. Visible in Task Scheduler. Clean up after use.", windows_only: true },
    CommandInfo { name: "schtasksdelete", category: "Scheduled Tasks", description: "Delete scheduled task", usage: "schtasksdelete <taskname> [server]", guardrails: "Generates Event 4699.", windows_only: true },
    CommandInfo { name: "schtasksrun", category: "Scheduled Tasks", description: "Run a task immediately", usage: "schtasksrun <taskname> [server]", guardrails: "", windows_only: true },
    CommandInfo { name: "schtasksstop", category: "Scheduled Tasks", description: "Stop a running task", usage: "schtasksstop <taskname> [server]", guardrails: "", windows_only: true },

    // ── User Account Management ──────────────────────────────────────────
    CommandInfo { name: "adduser", category: "User Management", description: "Add local/domain user", usage: "adduser <username> <password> [server]", guardrails: "Creates user account. Visible in 'net user'. Generates Event 4720. High OPSEC risk.", windows_only: false },
    CommandInfo { name: "enableuser", category: "User Management", description: "Enable + unlock user account", usage: "enableuser <username> [domain]", guardrails: "Generates Event 4722.", windows_only: false },
    CommandInfo { name: "disableuser", category: "User Management", description: "Disable user account", usage: "disableuser <username> [domain]", guardrails: "Generates Event 4725.", windows_only: false },
    CommandInfo { name: "setuserpass", category: "User Management", description: "Set user password", usage: "setuserpass <username> <password> [domain]", guardrails: "Password must meet GPO requirements. Generates Event 4724.", windows_only: false },
    CommandInfo { name: "unexpireuser", category: "User Management", description: "Clear account expiration", usage: "unexpireuser <username> [domain]", guardrails: "", windows_only: false },
    CommandInfo { name: "addusertogroup", category: "User Management", description: "Add user to group", usage: "addusertogroup <user> <group> [server] [domain]", guardrails: "Generates Event 4728 (global) or 4732 (local).", windows_only: false },

    // ── Process Operations ───────────────────────────────────────────────
    CommandInfo { name: "procdump", category: "Process", description: "Dump process memory to file", usage: "procdump <pid> <outfile>", guardrails: "Writes to disk. May trigger AV/EDR. Prefer in-memory extraction. Requires SeDebugPrivilege for LSASS.", windows_only: false },
    CommandInfo { name: "processlisthandles", category: "Process", description: "List open handles in process", usage: "processlisthandles <pid>", guardrails: "Requires adequate process access rights.", windows_only: false },
    CommandInfo { name: "processdestroy", category: "Process", description: "Close handle(s) in process", usage: "processdestroy <pid> [handle_id]", guardrails: "Closing handles can crash target process. Without handle_id, kills process.", windows_only: false },
    CommandInfo { name: "suspendresume", category: "Process", description: "Suspend or resume process threads", usage: "suspendresume <pid>", guardrails: "Toggles: if running, suspends. If suspended, resumes.", windows_only: false },
    CommandInfo { name: "findloadedmodule", category: "Process", description: "Find processes with DLL loaded", usage: "findloadedmodule <module_name> [process_name]", guardrails: "Enumerates all processes. May be slow.", windows_only: false },
    CommandInfo { name: "listmods", category: "Process", description: "List process modules/DLLs", usage: "listmods [pid]", guardrails: "Default: current process. Requires access rights for other PIDs.", windows_only: false },
    CommandInfo { name: "windowlist", category: "Process", description: "List visible windows", usage: "windowlist [all]", guardrails: "", windows_only: true },
    CommandInfo { name: "get_priv", category: "Process", description: "Enable token privilege", usage: "get_priv <privilege>", guardrails: "Examples: SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, SeRestorePrivilege.", windows_only: true },

    // ── File / Share Operations ──────────────────────────────────────────
    CommandInfo { name: "cacls", category: "Files/Shares", description: "List file permissions (DACL)", usage: "cacls <filepath>", guardrails: "", windows_only: false },
    CommandInfo { name: "dir", category: "Files/Shares", description: "Directory listing with wildcards", usage: "dir <path> [/s]", guardrails: "/s for recursive listing.", windows_only: false },
    CommandInfo { name: "netshares", category: "Files/Shares", description: "List shares on computer", usage: "netshares [hostname]", guardrails: "", windows_only: false },
    CommandInfo { name: "netuse_add", category: "Files/Shares", description: "Connect to network share", usage: "netuse_add <share> [user] [pass]", guardrails: "Credentials visible in 'net use' output. Creates network logon event.", windows_only: true },
    CommandInfo { name: "netuse_delete", category: "Files/Shares", description: "Disconnect network share", usage: "netuse_delete <share>", guardrails: "", windows_only: true },
    CommandInfo { name: "netuse_list", category: "Files/Shares", description: "List connected shares", usage: "netuse_list", guardrails: "", windows_only: true },

    // ── Crypto / Hashing ─────────────────────────────────────────────────
    CommandInfo { name: "md5", category: "Crypto", description: "MD5 hash file", usage: "md5 <filepath>", guardrails: "MD5 is cryptographically broken. Use SHA-256 for integrity checks.", windows_only: false },
    CommandInfo { name: "sha1", category: "Crypto", description: "SHA-1 hash file", usage: "sha1 <filepath>", guardrails: "SHA-1 is deprecated. Prefer SHA-256.", windows_only: false },
    CommandInfo { name: "sha256", category: "Crypto", description: "SHA-256 hash file", usage: "sha256 <filepath>", guardrails: "", windows_only: false },

    // ── System Information ───────────────────────────────────────────────
    CommandInfo { name: "resources", category: "System", description: "Disk space + memory info", usage: "resources", guardrails: "", windows_only: false },
    CommandInfo { name: "locale", category: "System", description: "System locale, language, timezone", usage: "locale", guardrails: "", windows_only: false },
    CommandInfo { name: "useridletime", category: "System", description: "User idle time", usage: "useridletime", guardrails: "", windows_only: false },
    CommandInfo { name: "shutdown", category: "System", description: "Shutdown/reboot system", usage: "shutdown [host] [message] [seconds] [reboot:0|1]", guardrails: "Destructive. System will power off or reboot. Cannot undo remotely.", windows_only: false },
    CommandInfo { name: "driversigs", category: "System", description: "Check driver signatures for EDR/AV", usage: "driversigs", guardrails: "", windows_only: true },
    CommandInfo { name: "enum_filter_driver", category: "System", description: "List installed filter drivers", usage: "enum_filter_driver [computer]", guardrails: "", windows_only: true },

    // ── Security / Audit ─────────────────────────────────────────────────
    CommandInfo { name: "adv_audit_policies", category: "Security/Audit", description: "Retrieve advanced audit policies", usage: "adv_audit_policies", guardrails: "", windows_only: true },
    CommandInfo { name: "list_firewall_rules", category: "Security/Audit", description: "List Windows Firewall rules", usage: "list_firewall_rules", guardrails: "Large output. Consider filtering.", windows_only: true },
    CommandInfo { name: "get_password_policy", category: "Security/Audit", description: "Domain password policy + lockouts", usage: "get_password_policy [hostname]", guardrails: "", windows_only: false },

    // ── Active Directory / LDAP ──────────────────────────────────────────
    CommandInfo { name: "ldapsearch", category: "AD/LDAP", description: "LDAP search query", usage: "ldapsearch <filter> [attributes] [server]", guardrails: "Queries domain controller. Example filter: (&(objectClass=user)(sAMAccountName=admin))", windows_only: true },
    CommandInfo { name: "adcs_enum", category: "AD/LDAP", description: "Enumerate CAs + cert templates", usage: "adcs_enum", guardrails: "Queries AD Certificate Services configuration.", windows_only: true },
    CommandInfo { name: "wmi_query", category: "AD/LDAP", description: "Execute WMI query", usage: "wmi_query <WQL> [server] [namespace]", guardrails: "Example: wmi_query \"SELECT * FROM Win32_Process\". Default namespace: root\\cimv2.", windows_only: true },
    CommandInfo { name: "get_session_info", category: "AD/LDAP", description: "Auth package, logon server, groups", usage: "get_session_info", guardrails: "", windows_only: false },

    // ── Credential Operations ────────────────────────────────────────────
    CommandInfo { name: "chromekey", category: "Credentials", description: "Decrypt Chrome DPAPI encryption key", usage: "chromekey", guardrails: "Accesses Chrome Local State. Requires current user context. Key used for cookie/password decryption.", windows_only: true },
    CommandInfo { name: "get_dpapi_system", category: "Credentials", description: "Get DPAPI_SYSTEM key + bootkey", usage: "get_dpapi_system", guardrails: "Requires SYSTEM privileges. Reads LSA secrets from registry.", windows_only: true },
    CommandInfo { name: "adcs_request", category: "Credentials", description: "Request certificate from CA", usage: "adcs_request <CA> [template] [subject] [altname]", guardrails: "Enrollment creates certificate. May be audited. Default template: User.", windows_only: true },

    // ── Kerberos Operations ──────────────────────────────────────────────
    CommandInfo { name: "krb_asktgt", category: "Kerberos", description: "Request TGT for user", usage: "krb_asktgt <user> <domain> <password|/rc4:<hash>|/aes256:<hash>> [/dc:<dc>] [/ptt]", guardrails: "Generates Kerberos AS-REQ. Logged by KDC (Event 4768). /ptt applies to current session.", windows_only: true },
    CommandInfo { name: "krb_asktgs", category: "Kerberos", description: "Request TGS for SPN", usage: "krb_asktgs <SPN> [/dc:<dc>] [/ptt]", guardrails: "Generates TGS-REQ. Logged by KDC (Event 4769).", windows_only: true },
    CommandInfo { name: "krb_renew", category: "Kerberos", description: "Renew current TGT", usage: "krb_renew [/dc:<dc>] [/ptt]", guardrails: "Requires renewable TGT.", windows_only: true },
    CommandInfo { name: "krb_s4u", category: "Kerberos", description: "S4U2Self + S4U2Proxy delegation", usage: "krb_s4u <impersonateUser> <SPN> [/dc:<dc>] [/ptt]", guardrails: "Requires constrained delegation (msDS-AllowedToDelegateTo). Impersonates user to SPN.", windows_only: true },
    CommandInfo { name: "krb_cross_s4u", category: "Kerberos", description: "Cross-domain S4U delegation", usage: "krb_cross_s4u <user> <targetSPN> <targetDomain> [/dc:<dc>] [/ptt]", guardrails: "Requires cross-domain trust + delegation config.", windows_only: true },
    CommandInfo { name: "krb_ptt", category: "Kerberos", description: "Pass-the-Ticket (submit to session)", usage: "krb_ptt <base64_ticket> [/luid:<luid>]", guardrails: "Injects ticket via LSA. May require elevation for other LUIDs.", windows_only: true },
    CommandInfo { name: "krb_purge", category: "Kerberos", description: "Purge Kerberos tickets", usage: "krb_purge [/luid:<luid>]", guardrails: "Destroys cached tickets. New auth will require fresh TGT.", windows_only: true },
    CommandInfo { name: "krb_describe", category: "Kerberos", description: "Parse and describe a ticket", usage: "krb_describe <base64_ticket>", guardrails: "", windows_only: true },
    CommandInfo { name: "krb_klist", category: "Kerberos", description: "List cached Kerberos tickets", usage: "krb_klist [/luid:<luid>] [/all]", guardrails: "/all requires elevation.", windows_only: true },
    CommandInfo { name: "krb_dump", category: "Kerberos", description: "Dump tickets from LSA cache", usage: "krb_dump [/luid:<luid>] [/all] [/service:<svc>]", guardrails: "Reads tickets from memory via LSA. May require elevation.", windows_only: true },
    CommandInfo { name: "krb_triage", category: "Kerberos", description: "Triage tickets across logon sessions", usage: "krb_triage [/luid:<luid>] [/user:<user>] [/service:<svc>]", guardrails: "Enumerates all sessions. Requires elevation for non-current sessions.", windows_only: true },
    CommandInfo { name: "krb_tgtdeleg", category: "Kerberos", description: "TGT delegation trick (extract TGT)", usage: "krb_tgtdeleg [SPN]", guardrails: "Abuses unconstrained delegation to extract usable TGT. Target SPN must be trusted for delegation.", windows_only: true },
    CommandInfo { name: "krb_kerberoasting", category: "Kerberos", description: "Kerberoast SPNs for offline cracking", usage: "krb_kerberoasting [/user:<user>] [/spn:<spn>] [/dc:<dc>] [/outfile:<path>]", guardrails: "Requests TGS for each SPN. Outputs hashcat $krb5tgs$ format. Event 4769 per SPN.", windows_only: true },
    CommandInfo { name: "krb_asreproasting", category: "Kerberos", description: "AS-REP roast (no preauth accounts)", usage: "krb_asreproasting [/user:<user>] [/dc:<dc>] [/outfile:<path>]", guardrails: "Targets accounts with DONT_REQUIRE_PREAUTH. Outputs hashcat $krb5asrep$ format.", windows_only: true },
    CommandInfo { name: "krb_hash", category: "Kerberos", description: "Compute Kerberos keys from password", usage: "krb_hash <password> [/user:<user>] [/domain:<DOMAIN>]", guardrails: "Computes RC4 (NTLM), AES128, AES256 keys. AES requires /user + /domain for salt.", windows_only: true },
    CommandInfo { name: "krb_changepw", category: "Kerberos", description: "Change user password via kpasswd", usage: "krb_changepw <user> <oldpassword> <newpassword> [/dc:<dc>] [/domain:<domain>]", guardrails: "Changes password. Generates Event 4723. Must meet complexity policy.", windows_only: true },

    // ── Privilege Escalation Checks ─────────────────────────────────────
    CommandInfo { name: "privcheck", category: "PrivEsc", description: "Run all privilege escalation checks", usage: "privcheck", guardrails: "Runs 10 checks sequentially. May take several seconds.", windows_only: true },
    CommandInfo { name: "alwaysinstallelevated", category: "PrivEsc", description: "Check AlwaysInstallElevated misconfiguration", usage: "alwaysinstallelevated", guardrails: "Checks HKCU+HKLM for MSI elevation. If both set, any user can install MSI as SYSTEM.", windows_only: true },
    CommandInfo { name: "autologoncheck", category: "PrivEsc", description: "Check for stored Autologon credentials", usage: "autologoncheck", guardrails: "Reads Winlogon registry. May reveal plaintext passwords.", windows_only: true },
    CommandInfo { name: "credmancheck", category: "PrivEsc", description: "Enumerate Credential Manager entries", usage: "credmancheck", guardrails: "Lists stored credentials for current user context.", windows_only: true },
    CommandInfo { name: "hijackablepathcheck", category: "PrivEsc", description: "Find writable directories in PATH", usage: "hijackablepathcheck", guardrails: "Writable PATH dirs enable DLL hijacking / binary planting.", windows_only: true },
    CommandInfo { name: "modifiableautoruncheck", category: "PrivEsc", description: "Find writable autorun executables", usage: "modifiableautoruncheck", guardrails: "Checks Run/RunOnce keys for writable binaries.", windows_only: true },
    CommandInfo { name: "modifiablesvccheck", category: "PrivEsc", description: "Find services with writable DACLs", usage: "modifiablesvccheck", guardrails: "Services with GENERIC_ALL/WRITE or CHANGE_CONFIG allow binary replacement.", windows_only: true },
    CommandInfo { name: "tokenprivcheck", category: "PrivEsc", description: "Enumerate current token privileges", usage: "tokenprivcheck", guardrails: "Shows enabled/disabled privileges. SeImpersonate/SeAssignPrimary enable potato attacks.", windows_only: true },
    CommandInfo { name: "unquotedsvcpathcheck", category: "PrivEsc", description: "Find services with unquoted paths", usage: "unquotedsvcpathcheck", guardrails: "Unquoted paths with spaces allow binary planting in parent directories.", windows_only: true },
    CommandInfo { name: "pshistorycheck", category: "PrivEsc", description: "Check PowerShell history for secrets", usage: "pshistorycheck", guardrails: "PSReadLine history may contain passwords, tokens, or other secrets.", windows_only: true },
    CommandInfo { name: "uacstatuscheck", category: "PrivEsc", description: "Check UAC configuration and status", usage: "uacstatuscheck", guardrails: "Shows EnableLUA, ConsentPrompt, integrity level, admin group membership.", windows_only: true },

    // ── Evasion / Persistence ────────────────────────────────────────────
    CommandInfo { name: "ghost_task", category: "Evasion", description: "Silent schtask via direct registry", usage: "ghost_task <host> <add|delete> <name> <program> [args] [schedule]", guardrails: "Requires SYSTEM. Bypasses Event 4698/4702 but registry artifacts remain in TaskCache.", windows_only: true },

    // ── NTFS Raw Copy ───────────────────────────────────────────────────
    CommandInfo { name: "ntfs_copy", category: "Files/Shares", description: "Copy locked files via raw NTFS read", usage: "ntfs_copy <filepath1> [filepath2 ...] <savedir>", guardrails: "Requires admin. Reads raw disk to bypass OS file locks. Use for SAM/SYSTEM/SECURITY hives.", windows_only: true },
    CommandInfo { name: "ntfs_read", category: "Files/Shares", description: "Read locked file via raw NTFS, return base64", usage: "ntfs_read <filepath>", guardrails: "Requires admin. Reads raw NTFS. Returns base64-encoded file data. 256MB limit.", windows_only: true },
];
