# Fox3 — Production Readiness: Full RT Capability + Simulated Corporate Env Testing

## Context

All 16 phases of the PIC agent rewrite are complete (507KB, 1 section, 0 imports, 139+ native commands). The test harness covers all commands with native-only validation. **Now**: make the agent capable of running **entire RT operations standalone** (no external tooling), validate against simulated mature corporate environments with real EDR telemetry, and harden both agent + teamserver for production use.

**What prompted this**: The agent has strong recon/post-exploitation but **cannot move laterally, manipulate tokens, dump credentials, or evade EDR defenses** — all blockers for a real RT op. The teamserver lacks multi-operator support, reporting, and redirector integration.

**Intended outcome**: Fox3 (agent + server) becomes a self-contained RT platform that can execute full kill chains (initial access → privesc → lateral movement → domain dominance → exfil) in environments defended by top-tier EDRs (Elastic, CrowdStrike, Cortex).

---

## Phase 1: Migration + Bootstrap — COMPLETE

### What Was Done

**Repo structure** (2 repos, not 3 as originally planned):
```
github.com/nzyuko/fox3         → Go teamserver + React frontend
github.com/nzyuko/fox3_agent   → fox3_core (calling engine + injector) + fox3_agent_pic (PIC agent)
```

**Completed tasks**:
- All merlin/Ne0nd0g references renamed to fox3/nzyuko across 120+ files
- merlin-message vendored as `pkg/fox3-message/` (internal, no external Go dep)
- gRPC proto + generated code fully renamed
- `.claude/` context (memory, plans) included in both repos
- DNS/DoH fallback transport added (`dns_transport.rs` — HTTPS → DoH → DNS chain)
- Config struct extended with `dns_domain`, `doh_host`, `doh_path`, `doh_port`, `fail_threshold`
- All pushed to GitHub private repos

**Remaining for new machine**:
1. Clone both repos on 28-core machine
2. Install toolchain:
   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
   winget install Rustlang.Rustup
   winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
   winget install GoLang.Go
   winget install OpenJS.NodeJS.LTS
   winget install Python.Python.3.12
   winget install Git.Git
   winget install GitHub.cli
   rustup default stable-x86_64-pc-windows-msvc
   rustup target add x86_64-pc-windows-msvc
   ```
3. Copy `.claude/` context directory, remap project paths if username differs
4. Verify builds:
   ```bash
   cd fox3_agent/fox3_core && cargo build --release
   cd fox3_agent/fox3_agent_pic && cargo build --release --features pic --lib
   cd fox3 && go build -o fox3_server.exe .
   ```
5. Install Vagrant, Ansible, hashcat:
   ```powershell
   winget install Hashicorp.Vagrant
   pip install ansible pywinrm
   # Hashcat (GPU cracking) — download from https://hashcat.net/hashcat/
   # Extract to C:\tools\hashcat, add to PATH
   # Verify: hashcat -b -m 13100 (krb5tgs benchmark)
   ```

---

## Phase 2: Agent RT Tradecraft (On 28-Core Machine)

All features use `fox3_winapi!` / `fox3_call!` — zero IAT entries, zero child processes.

### 2A: Token Manipulation (foundation for everything else)

| # | Command | Implementation | Notes |
|---|---------|---------------|-------|
| 1 | `steal_token` | NtOpenProcessToken + NtDuplicateToken → ImpersonateLoggedOnUser | Must close handle after |
| 2 | `make_token` | LogonUserW(LOGON32_LOGON_NEW_CREDENTIALS) → ImpersonateLoggedOnUser | Network-only logon, no 4624/10 |
| 3 | `rev2self` | RevertToSelf() | Drop impersonation |
| 4 | `enable_priv` | NtAdjustPrivilegesToken (SeDebugPrivilege, SeImpersonatePrivilege) | |

### 2B: Credential Access (needs token manipulation for SYSTEM)

| # | Command | Implementation | Notes |
|---|---------|---------------|-------|
| 5 | `lsass_dump` | MiniDumpWriteDump callback (no disk) OR NtReadVirtualMemory stream | Dup handle trick avoids SeDebugPrivilege alert |
| 6 | `sam_dump` | NtOpenKey + NtQueryKey on SAM hive (requires SYSTEM) | Registry, no file copy |
| 7 | `vault_enum` | VaultEnumerateVaults + VaultEnumerateItems | Read-only |
| 8 | `dpapi_decrypt` | CryptUnprotectData with user token context | |
| 9 | `dcsync` | MS-DRSR DRS_MSG_GETCHGREQ via RPC | Domain Replication rights required |

### 2C: Lateral Movement (needs creds + tokens)

| # | Command | Implementation | Notes |
|---|---------|---------------|-------|
| 10 | `psexec` | Remote SCM: OpenSCManagerW → CreateServiceW → StartServiceW → DeleteService | Clean up service after |
| 11 | `wmi_exec` | COM IWbemLocator → ConnectServer → Win32_Process.Create | WMI event logs |
| 12 | `dcom_exec` | CoCreateInstance on MMC20 / ShellBrowserWindow CLSIDs | Multiple CLSIDs |
| 13 | `winrm_exec` | WinHTTP SOAP to 5985/5986 | Reuses existing WinHTTP |

### 2D: Defense Evasion (needed before Tier B/C testing)

| # | Feature | Implementation | Why |
|---|---------|---------------|-----|
| 14 | `etw_patch` | Patch EtwEventWrite → `ret` (0xC3) in ntdll | Blinds userland ETW |
| 15 | `amsi_patch` | Patch AmsiScanBuffer → AMSI_RESULT_CLEAN | Before .NET/PS |
| 16 | `unhook_ntdll` | Map fresh ntdll from `\KnownDlls\ntdll.dll`, overwrite .text | Remove EDR hooks |
| 17 | Ekko sleep fix | Fix region detection for PIC memory layout | Encrypt during sleep |
| 18 | Stack spoofing | Desync thread call stack before sleep | Defeat stack scans |

### 2E: Privilege Escalation

| # | Command | Implementation |
|---|---------|---------------|
| 19 | `uac_bypass` | CMSTPLUA COM elevation + fodhelper + eventvwr |
| 20 | `potato` | Named pipe impersonation (SeImpersonatePrivilege → SYSTEM) |
| 21 | Service hijack | Write to modifiable service path → restart |

### 2F: Persistence & Advanced

| # | Feature | Implementation |
|---|---------|---------------|
| 22 | Inline .NET | Host CLR in-process, execute assemblies from memory |
| 23 | `keylogger` | GetAsyncKeyState polling or SetWindowsHookEx |
| 24 | SMB P2P | Complete `smb_transport.rs` stub |
| 25 | Agent failover | Multiple callback URLs in config, rotate on failure |

### Files to Create/Modify

```
fox3_agent_pic/src/
├── commands/token.rs        — NEW: steal_token, make_token, rev2self, enable_priv
├── commands/credentials.rs  — EXTEND: lsass_dump, sam_dump, dcsync, vault_enum, dpapi
├── commands/lateral.rs      — NEW: psexec, wmi_exec, dcom_exec, winrm_exec
├── commands/evasion.rs      — NEW: etw_patch, amsi_patch, unhook_ntdll
├── commands/privesc.rs      — EXTEND: uac_bypass, potato
├── commands/mod.rs          — Add dispatch entries for all new commands
├── agent.rs                 — Agent failover (multiple callback URLs)
├── sleep_encrypt.rs         — Fix Ekko for PIC layout + stack spoofing
└── smb_transport.rs         — Complete P2P transport
```

---

## Phase 3: Lab Environment Setup (Parallel with Phase 2)

### Hardware Budget (28 cores / 56 threads / 32GB RAM / RTX 3060 Ti 8GB)

| VM | vCPU | RAM | Role | OS |
|----|------|-----|------|----|
| DC01 | 4 | 4GB | Primary DC, `corp.local` forest root | Server 2022 |
| DC02 | 2 | 2GB | Child domain DC, `us.corp.local` | Server 2022 |
| SRV01 | 2 | 2GB | File/web server, CA (ADCS) | Server 2022 |
| WS01 | 4 | 4GB | Workstation (target, EDR agent) | Win 11 Enterprise |
| WS02 | 2 | 2GB | Workstation (lateral target) | Win 10 Enterprise |
| EDR-SRV | 4 | 6GB | Elastic Stack (ES + Kibana + Fleet) | Ubuntu 22.04 |
| HOST | 8+ | 12GB+ | Fox3 server + Claude Code + build + GPU | Win 11 (bare metal) |
| **Total VMs** | **18** | **20GB** | | |

**GPU (RTX 3060 Ti 8GB)**:
- **Hashcat**: Offline password cracking for Kerberoasting/AS-REP roasting (~25 GH/s NTLM, ~750 KH/s krb5tgs RC4). Integrated into playbook `post: offline_crack` steps.
- **Local LLM fallback**: For high-frequency deterministic MCP steps (Qwen 2.5 7B Q8 or similar). Reduces API cost during long automated runs. Claude API for decision points only.

### Environment Tiers (Progressive Hardening)

**Tier A — Baseline Corporate** (CRTO-like):
- Single forest `corp.local`, 1 DC, 2 workstations
- Elastic Defend in detect-only mode (no blocking)
- Standard GPO (password policy, audit policy)
- LAPS deployed, local admin randomized
- SMB signing on DCs only
- Goal: Validate full kill chain, identify telemetry signatures

**Tier B — Hardened Corporate** (CRTE-like):
- Multi-domain forest (`corp.local` + `us.corp.local`), trust relationships
- ADCS for certificate-based attacks
- Elastic Defend in **prevent mode**
- PowerShell CLM via WDAC
- Credential Guard on workstations
- SMB signing + LDAP signing enforced
- Sysmon with SwiftOnSecurity config
- Goal: Validate opsec — does Fox3 trigger detections?

**Tier C — Mature SOC** (CRTO-II-like):
- Everything from Tier B, plus:
- EDR aggressive mode (memory scanning, behavior analysis)
- WDAC — only signed binaries
- Network segmentation (VLANs via Hyper-V virtual switches)
- Kerberos armoring (FAST)
- Protected Users group for high-value accounts
- Elastic SIEM correlation rules
- Goal: Full adversary simulation — operate undetected

### Lab Setup

**GOAD-Windows on Hyper-V** (recommended):
1. Download Windows Server 2022 eval ISO + Win 10/11 Enterprise eval ISOs
2. Install GOAD-Windows (Vagrant + Hyper-V provider)
3. Provision Tier A lab (1 DC, 2 workstations, 1 server)
4. Deploy Ubuntu VM for Elastic Stack 8.x
5. Deploy Elastic Defend agent to all Windows VMs via Fleet
6. Deploy Sysmon via GPO (SwiftOnSecurity config)
7. Verify: Fox3 agent checks in from WS01 → server on host

### EDR Stack (Free, Self-Hosted)

| Component | Purpose | Deployment |
|-----------|---------|------------|
| Elastic Stack 8.x | SIEM + EDR | Ubuntu VM (EDR-SRV) |
| Elastic Defend | Endpoint protection | Fleet → all Windows VMs |
| Sysmon | Enhanced telemetry | GPO + SwiftOnSecurity config |
| Windows audit policies | Security events | GPO (advanced audit) |

---

## Phase 4: Teamserver Improvements

### Must-Have

| Feature | Where | Why |
|---------|-------|-----|
| Multi-operator auth | `pkg/services/rest/auth.go` | Per-operator JWT, usernames |
| Operator audit log | New `pkg/audit/` | Who sent what, when, to which agent |
| Credential auto-capture | `pkg/services/job/job.go` | Parse output for creds, auto-store |
| Reporting engine | New `pkg/services/report/` | Timeline + creds + screenshots → JSON/PDF |
| Agent failover | Agent config | Multiple callback URLs |
| Redirector support | `pkg/servers/http/` | X-Forwarded-For, domain fronting |
| Listener profiles | `pkg/listeners/http/` | Custom URI/headers/body (anti-JA3/JA4) |
| Agent builder UI | `frontend/src/pages/` | Configure + build PIC from web UI |
| DNS listener | New listener type | Server-side handler for DNS/DoH transport |

### Nice-to-Have

- Agent task queue visualization
- File browser drag-drop upload
- Screenshot auto-capture on interval
- Team chat between operators

---

## Phase 5: Operator Automation — Claude Code + MCP Servers

### Why Claude Code + MCP (not OpenClaw)

OpenClaw is a **consumer AI chat assistant** (337K stars, TypeScript) — not an RT tool. It has 9+ CVEs in its first 2 months and 42K exposed instances. Wrong tool entirely.

**Claude Code with custom MCP servers** is the right approach because:
- Already running on the machine with full project context
- MCP servers are thin Python wrappers (~100-200 lines each)
- LLM reasoning handles adaptation (SIEM fires alert → pause/pivot/restore)
- Headless mode (`claude -p`) enables full automation
- No browser overhead — direct WebSocket/API calls
- Playbook execution is just a prompt with MCP tools available

### MCP Servers to Build

**`fox3-c2`** — Fox3 teamserver interaction:
- WebSocket connection to Fox3 server
- Tools: `list_agents`, `send_command(agent_id, cmd)`, `get_result(job_id)`, `wait_for_checkin(agent_id)`
- Handles JWE/JWT auth transparently
- Streams job results as they arrive

**`fox3-elastic`** — Elastic SIEM detection monitoring:
- REST client to Elasticsearch API
- Tools: `query_alerts(time_range)`, `get_alert_detail(alert_id)`, `search_events(kql_query)`
- Correlates alerts with agent commands by timestamp
- Returns structured: `{command, alert_name, severity, technique_id}`

**`fox3-hyperv`** — Hyper-V VM lifecycle:
- Wraps PowerShell cmdlets via subprocess
- Tools: `list_vms()`, `snapshot(vm_name)`, `restore(vm_name, snapshot)`, `start_vm(vm_name)`, `stop_vm(vm_name)`
- Snapshot before each scenario, restore on failure

### Operator Workflow

```
Claude Code (headless, with MCP tools)
  ├── fox3-c2:       send commands, read results via WebSocket
  ├── fox3-elastic:   check for detections after each step
  └── fox3-hyperv:    snapshot/restore lab VMs
```

**Playbook execution**: Feed YAML playbook as prompt context. Claude executes step-by-step using MCP tools, checks Elastic after each step, adapts if detected.

**Fallback**: If LLM latency/cost is a problem for high-frequency ops, extract deterministic parts into a standalone Python orchestrator (the MCP server functions become the core).

### Playbook Format (YAML)

```yaml
name: corporate_breach_tier_a
description: Initial access → DA in single-domain environment
target_tier: A
pre_checks:
  - vm_running: [DC01, WS01, WS02]
  - agent_checkin: WS01
  - elastic_clear: true    # no pre-existing alerts

phases:
  - name: situational_awareness
    snapshot: pre_recon
    steps:
      - cmd: agentinfo
      - cmd: whoami
      - cmd: ifconfig
      - cmd: env
      - cmd: hostname
    detection_threshold: low  # OK if these trigger low alerts

  - name: privilege_escalation
    snapshot: pre_privesc
    steps:
      - cmd: privcheck
      - cmd: steal_token {highest_priv_pid}
        on_fail: uac_bypass
      - cmd: whoami  # verify escalation
    detection_threshold: medium

  - name: credential_access
    snapshot: pre_creds
    steps:
      - cmd: krb_kerberoasting
        post: offline_crack  # flag for manual step
      - cmd: make_token {cracked_user} {cracked_pass}
    detection_threshold: high  # expected to trigger

  - name: lateral_movement
    snapshot: pre_lateral
    steps:
      - cmd: psexec {WS02_IP}
        alternatives: [wmi_exec, dcom_exec, winrm_exec]
    detection_threshold: high

  - name: domain_dominance
    snapshot: pre_domain
    steps:
      - cmd: lsass_dump
      - cmd: make_token {da_user} {da_hash}
      - cmd: dcsync
    detection_threshold: high

  - name: collection
    steps:
      - cmd: screenshot
      - cmd: chromekey
      - cmd: vault_enum

  - name: cleanup
    steps:
      - cmd: rev2self
      - cmd: kill

post_run:
  - elastic_report: detection_matrix.csv
  - restore_snapshot: pre_recon
```

---

## Phase 6: Scenario Execution + Hardening Loop

### Scenario 1: "Corporate Breach" (Tier A)

Goal: Initial access → DA in single-domain.
Run the `corporate_breach_tier_a` playbook.
Validation: Check Elastic for detections at each step. Document IOCs.

### Scenario 2: "Hardened Enterprise" (Tier B)

Goal: Operate under Elastic Defend prevent mode + CLM + Credential Guard.
1. Inject into `svchost.exe` (blends better)
2. `etw_patch` + `amsi_patch` before any action
3. Native commands only (no PS, no shell)
4. `adcs_enum` → ESC1/ESC8 cert abuse
5. `krb_ptt` with cert-derived TGT
6. Lateral via `winrm_exec`
7. `dcsync` from DC
8. Persistence via `schtaskscreate`
9. Cleanup

Validation: Steps 2-4 should NOT alert. Steps 5-8 may — document and fix.

### Scenario 3: "Mature SOC" (Tier C)

Goal: Full op under aggressive EDR + WDAC + network segmentation.
Focus: Pure opsec — sleep encryption, stack spoofing, Kerberos-only lateral.
1. Ekko encrypted sleep (memory encrypted between checkins)
2. Stack spoofing before each sleep
3. `unhook_ntdll`
4. Kerberos-only lateral (no NTLM)
5. SOCKS proxy for internal recon
6. Certificate-based auth only
7. Exfil via HTTPS C2 (encrypted, blends with legit)

### Scenario 4: "Multi-Forest Assault" (Tier B extended)

1. Compromise `us.corp.local`
2. Enumerate trust relationships
3. SID history injection or trust key extraction
4. Pivot to `corp.local` forest root

### Scenario 5: "Detection Gap Analysis" (All Tiers)

Systematically trigger every agent command (139+) and catalog Elastic response:
- Categorize: undetected / low-confidence / high-confidence / blocked
- For each detection: can we make it quieter?
- Output: detection matrix CSV (command × EDR response)

---

## Verification Criteria

**Migration verified when** (Phase 1 — DONE on current machine, pending new machine clone):
- Both repos build on new machine
- PIC binary passes `validate_pic.py`
- Test harness connects to server

**Lab verified when** (Phase 3):
- DC01 + WS01 + WS02 domain-joined
- Elastic Defend reporting from all endpoints
- Fox3 agent checks in from WS01

**Agent features verified when** (Phase 2):
- Scenario 1 completes end-to-end (initial access → DA)
- Detection matrix shows <10% high-confidence alerts for native commands

**Automation verified when** (Phase 5):
- Claude Code sends `whoami` via MCP → reads result → checks Elastic
- Full playbook executes headlessly with detection correlation

**Production readiness when** (Phase 6):
- Scenario 3 (Tier C) completes with zero blocked actions
- All new features have test harness coverage
- Teamserver audit log captures every operator action
- Automated playbook run completes with detection report
