# Configuration

All configuration is passed as command-line flags. There is no config file — flags only.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--password` | `fox3` | Password for REST API login and agent listener PSK default |
| `--rest` | `0.0.0.0:8080` | Address the REST API + WebSocket server binds to |
| `--debug` | `false` | Enable debug-level logging |
| `--trace` | `false` | Enable trace-level logging (more verbose than debug) |
| `--extra` | `false` | Enable extra-debug logging (dumps full HTTP connection details per request) |
| `--version` | — | Print version and build stamp, then exit |

## Examples

### Minimal (development)

```bash
./fox3_server
# Uses defaults: password=fox3, REST=0.0.0.0:8080
# Prints a warning about the default password
```

### Production

```bash
./fox3_server --password "s3cr3t-passphrase"
```

### Exposed on a non-default port

```bash
./fox3_server --password "s3cr3t" --rest 0.0.0.0:443
```

### Debug session

```bash
./fox3_server --password "s3cr3t" --debug
# --trace for more verbosity; --extra for full HTTP header dumps
```

## Logging levels

| Flag | What you see |
|---|---|
| _(none)_ | Info, Warn, Error |
| `--debug` | + Debug |
| `--trace` | + Trace |
| `--extra` | + full HTTP headers and TLS details per connection |

## Database

The SQLite database is created automatically at startup:

```
<working-directory>/data/fox3.db
```

Run the server from a consistent working directory, or use a systemd unit with `WorkingDirectory=` set. There is no flag to change the database path.

## REST server TLS

The REST server currently runs plain HTTP. For production, terminate TLS at a reverse proxy (nginx, Caddy) in front of the `--rest` port.

Agent listeners (HTTPS/HTTP2/HTTP3) handle their own TLS independently via the `X509Cert` and `X509Key` options passed at listener-creation time — not through server flags.
