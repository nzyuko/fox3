# Agent Commands

Commands are dispatched to an agent via the `job.create` WebSocket action (see [api.md](api.md)). Each command maps to a job type that the agent processes on its next check-in.

## Job types

| Type constant | Description |
|---|---|
| `CONTROL` | Agent-lifecycle control (sleep, exit, changelistener, …) |
| `NATIVE` | Built-in agent commands dispatched agent-side |
| `CMD` | Shell/process execution |
| `MODULE` | Extended capability modules (CLR, shellcode, HVNC, …) |
| `FILETRANSFER` | Upload/download |
| `SHELLCODE` | Raw shellcode injection |
| `SOCKS` | SOCKS5 tunnel traffic (internal, not user-dispatched) |
| `RESULT` | Return path for job output (agent → server) |
| `AGENTINFO` | Agent configuration data (agent → server) |

---

## Command reference

Commands are the strings you pass as `jobType` in `job.create`. Unknown commands are forwarded to the agent as `NATIVE` — the PIC agent has many commands not explicitly listed on the server side.

### Agent management

| Command | Job type | Args | Description |
|---|---|---|---|
| `agentInfo` | CONTROL | — | Request agent to send back its full configuration |
| `exit` | CONTROL | — | Instruct agent to terminate |
| `initialize` | CONTROL | — | Re-initialize agent |
| `sleep` | CONTROL | `<duration>` | Set agent sleep interval (Go duration string, e.g. `30s`) |
| `skew` | CONTROL | `<percent>` | Set jitter percentage applied to sleep |
| `maxretry` | CONTROL | `<count>` | Max consecutive failed check-ins before agent exits |
| `padding` | CONTROL | `<bytes>` | Random padding size added to messages |
| `killdate` | CONTROL | `<date>` | Date/time after which agent terminates |
| `ja3` | CONTROL | `<string>` | Set TLS JA3 fingerprint |
| `parrot` | CONTROL | `<browser>` | Parrot a specific browser's TLS fingerprint |
| `changelistener` | CONTROL | `<command> [args…]` | Change the agent's active listener |
| `connect` | CONTROL | `[args…]` | Connect to a new listener |

### File system

| Command | Job type | Args | Description |
|---|---|---|---|
| `ls` | NATIVE | `[path]` | List directory (defaults to `./`) |
| `pwd` | NATIVE | — | Print working directory |
| `cd` | NATIVE | `<path>` | Change working directory |
| `rm` | NATIVE | `<path>` | Remove a file |
| `touch` | NATIVE | `<path>` | Create or update file timestamp |
| `sdelete` | NATIVE | `<path>` | Secure delete (overwrite then remove) |
| `download` | FILETRANSFER | `<remote-path>` | Download file from agent to `data/agents/<id>/` |
| `upload` | FILETRANSFER | `<local-b64> <remote-path>` | Upload file from server to agent |
| `memfd` | MODULE | `<path>` | Load and execute from an in-memory file descriptor (Linux) |

### Process and system

| Command | Job type | Args | Description |
|---|---|---|---|
| `ps` | MODULE | — | List running processes |
| `env` | NATIVE | `[args…]` | Print environment variables |
| `ifconfig` | NATIVE | — | Print network interface information |
| `nslookup` | NATIVE | `<host>` | DNS lookup |
| `netstat` | MODULE | `[args…]` | Network connections |
| `uptime` | MODULE | — | System uptime |
| `killprocess` | NATIVE | `<pid>` | Kill a process by PID |
| `pipes` | MODULE | — | List named pipes (Windows) |
| `screenshot` | NATIVE | — | Capture screenshot and return to server |

### Execution

| Command | Job type | Args | Description |
|---|---|---|---|
| `run` / `exec` | CMD | `<exe> [args…]` | Run a process directly (no shell) |
| `shell` | CMD | `[args…]` | Run via system shell (`cmd.exe` / `sh`) |
| `CreateProcess` | MODULE | `[args…]` | Create process via Windows API |
| `runas` | MODULE | `[args…]` | Run as a different user (Windows) |
| `ssh` | MODULE | `[args…]` | SSH to a remote host from the agent |

### .NET / CLR (Windows)

| Command | Job type | Args | Description |
|---|---|---|---|
| `load-clr` | MODULE | `<version>` | Load the .NET CLR into the agent process |
| `load-assembly` | MODULE | `<b64> <name> <sha256>` | Load a .NET assembly into the in-process CLR |
| `invoke-assembly` | MODULE | `<name> [args…]` | Execute a previously loaded assembly |
| `list-assemblies` | MODULE | — | List loaded assemblies in the CLR |
| `memory` | MODULE | `[args…]` | Query CLR memory state |

### Shellcode and injection (Windows)

| Command | Job type | Args | Description |
|---|---|---|---|
| `shellcode` | SHELLCODE | `<b64> <method> [pid]` | Inject shellcode. Methods: `self`, `remote`, `rtlcreateuserthread`, `userapc` |
| `Minidump` | MODULE | `[args…]` | Create a memory dump of lsass or another process |
| `token` | MODULE | `[args…]` | Token manipulation (steal, make, list, revoke) |

### Pivoting

| Command | Job type | Args | Description |
|---|---|---|---|
| `link` | MODULE | `[args…]` | Link to a child agent via SMB/TCP pivot |
| `unlink` | MODULE | `[args…]` | Disconnect a child agent |
| `listener` | MODULE | `[args…]` | Manage an in-agent listener for pivot chains |

### Tunnels

| Command | Job type | Args | Description |
|---|---|---|---|
| `rportfwd_start` | NATIVE | `<lport> <rhost> <rport>` | Start reverse port forward through the agent |
| `rportfwd_stop` | NATIVE | `<id>` | Stop a reverse port forward |
| `hvnc_start` | NATIVE | `[args…]` | Start a hidden VNC session (Windows); server registers `conn_id` from response |
| `hvnc_stop` | NATIVE | — | Stop the HVNC session |

### Fallback (pass-through)

Any command not listed above is forwarded to the agent as `NATIVE` with the command string and args passed verbatim. The PIC agent handles many additional commands server-side dispatch doesn't know about. Send `help` to get the agent's own command list.

```json
{
  "action": "job.create",
  "id": "req-x",
  "payload": {
    "agent_id": "<uuid>",
    "type":     "whoami"
  }
}
```

---

## Notes

- All commands are **asynchronous**. `job.create` returns immediately with a job ID. The result arrives as a `job_complete` WebSocket event when the agent checks in.
- File downloads land in `data/agents/<agent-uuid>/` on the server.
- Windows-only commands (`Minidump`, `token`, `pipes`, `runas`, CLR commands, HVNC) will return errors if run against a Linux agent.
- Shellcode injection methods `remote`, `rtlcreateuserthread`, and `userapc` require a target PID as the third argument.
