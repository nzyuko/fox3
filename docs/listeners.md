# Listeners

A listener pairs a **network server** (the transport layer) with a **listener** (the fox3 protocol handler). Listeners are created at runtime via the WebSocket API (`listener.create`) or the browser UI. They are **in-memory only** — they do not persist across server restarts.

## Status

| Protocol | Status | Transport |
|---|---|---|
| `http` | working | HTTP/1.1 plain |
| `https` | working | HTTP/1.1 TLS |
| `h2c` | working | HTTP/2 cleartext |
| `http2` | working | HTTP/2 over TLS |
| `http3` | working | HTTP/3 (QUIC) |
| `tcp` | coming soon | raw TCP |
| `udp` | coming soon | raw UDP |
| `smb` | coming soon | Windows named pipe |
| `dns` | coming soon | DNS |
| `doh` | coming soon | DNS-over-HTTPS |
| `wss` | coming soon | WebSocket Secure |

---

## HTTP family (`http`, `https`, `h2c`, `http2`, `http3`)

All five HTTP variants share the same listener and handler code. The `Protocol` option selects which transport the underlying server starts.

### Options

| Option | Default | Required | Description |
|---|---|---|---|
| `Protocol` | — | yes | One of `http`, `https`, `h2c`, `http2`, `http3` |
| `Name` | `My HTTP Listener` | yes | Human-readable identifier |
| `Interface` | `127.0.0.1` | yes | Bind address |
| `Port` | `80` (http) / `443` (https/h2c/http2/http3) | yes | Bind port |
| `PSK` | `fox3` | yes | Pre-shared key — SHA-256 hashed for agent JWT signing |
| `JWTKey` | _(random 32-byte, base64)_ | no | Explicit JWT signing key; auto-generated if absent |
| `JWTLeeway` | `1m` | no | JWT expiry tolerance (Go duration string, e.g. `30s`) |
| `URLS` | `/` | no | Comma-separated URL paths the agent handler mounts on |
| `X509Cert` | `data/x509/server.crt` | for TLS | PEM certificate path |
| `X509Key` | `data/x509/server.key` | for TLS | PEM private key path |
| `Transforms` | `jwe,json` | no | Comma-separated transform pipeline (see below) |
| `Authenticator` | `NONE` | no | `none` or `opaque` |
| `Description` | `Default HTTP Listener` | no | Free text |

### Example — HTTPS listener (recommended)

```json
{
  "action": "listener.create",
  "id": "req-1",
  "payload": {
    "Protocol":    "https",
    "Name":        "https-443",
    "Interface":   "0.0.0.0",
    "Port":        "443",
    "PSK":         "change-me",
    "X509Cert":    "/etc/ssl/certs/server.crt",
    "X509Key":     "/etc/ssl/private/server.key",
    "Transforms":  "jwe,json",
    "Authenticator": "none"
  }
}
```

Then start it:

```json
{ "action": "listener.start", "id": "req-2", "payload": { "id": "<listener-uuid>" } }
```

### Example — plain HTTP for local testing

```json
{
  "action": "listener.create",
  "id": "req-3",
  "payload": {
    "Protocol":   "http",
    "Name":       "http-8443",
    "Interface":  "0.0.0.0",
    "Port":       "8443",
    "PSK":        "test-psk",
    "Transforms": "jwe,json"
  }
}
```

---

## Transform pipeline

The `Transforms` option is a comma-separated ordered list of encoder/encrypter names applied to agent messages.

**Outbound** (server → agent): transformers applied left-to-right.
**Inbound** (agent → server): transformers applied right-to-left.

| Name | Type | Notes |
|---|---|---|
| `jwe` | encrypter | JWE compact serialization, AES-256-GCM. Default for HTTP. |
| `aes` | encrypter | Raw AES-256-GCM |
| `rc4` | encrypter | RC4 stream cipher |
| `xor` | encrypter | XOR with key |
| `json` | encoder | JSON marshal/unmarshal of `messages.Base` |
| `gob-base` | encoder | Go gob encoding of `messages.Base` |
| `gob-string` | encoder | Go gob encoding of string type |
| `base64-byte` | encoder | Base64 encode → `[]byte` |
| `base64-string` | encoder | Base64 encode → `string` |
| `hex-byte` | encoder | Hex encode → `[]byte` |
| `hex-string` | encoder | Hex encode → `string` |

Default: `jwe,json`
- Outbound: `JSON.Construct(Base)` → `JWE.Construct(json_bytes)` → wire bytes
- Inbound: `JWE.Deconstruct(bytes)` → `JSON.Deconstruct(plaintext)` → `Base`

The agent must use **the same pipeline in the same order**.

---

## Listener lifecycle

```
listener.create  →  listener stored in memory (not yet accepting connections)
listener.start   →  server begins Listen() + Start()
listener.stop    →  server stops accepting new connections
listener.delete  →  server stopped (if running), listener removed from memory
```

Listeners do not survive a server restart. Recreate them after restart or automate with a startup script that calls `listener.create` + `listener.start` via the WebSocket API.

---

## TLS certificates

For HTTPS/HTTP2/HTTP3 listeners you need a certificate and key. Options:

**Self-signed (testing)**

```bash
mkdir -p data/x509
openssl req -x509 -newkey rsa:4096 -keyout data/x509/server.key \
  -out data/x509/server.crt -days 365 -nodes -subj "/CN=fox3"
```

The server looks for these paths by default if `X509Cert`/`X509Key` are not specified.

**Let's Encrypt**

Use Certbot or acme.sh to obtain a cert for your domain, then pass the paths in the listener options.
