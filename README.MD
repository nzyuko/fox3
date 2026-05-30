# fox3

C2 teamserver. Go backend, React frontend, SQLite state. Agents check in over encrypted HTTP — the browser console is the only operator interface.

> Active development. HTTP/1.1, HTTP/2, H2C, HTTP/3 listeners work. TCP/UDP/SMB/DNS coming. Some modules (HVNC, CLR, Minidump, token) are Windows-only.

## How it works

Agents POST JWE-encrypted messages to a listener. The server decrypts, queues jobs, and returns pending work in the same response. Operators interact through a WebSocket-driven React dashboard — no CLI, no gRPC.

```
agent  ──POST /──►  listener  ──►  server  ──►  operator browser
         JWE               decrypts, queues          WebSocket push
```

## Quick start

**Requires Go 1.24+ and GCC** (GCC is needed to compile the SQLite driver).

```bash
git clone https://github.com/nzyuko/fox3
cd fox3
go build -o fox3_server .
./fox3_server --password <your-password>
```

Open `http://localhost:8080`, log in, create a listener, deploy an agent.

| Flag | Default | |
|---|---|---|
| `--password` | `fox3` | REST API + listener PSK default |
| `--rest` | `0.0.0.0:8080` | Operator console address |
| `--debug` | false | Verbose logging |

## Documentation

| | |
|---|---|
| [Frontend guide](docs/frontend.md) | UI walkthrough with screenshots — start here |
| [Building](docs/building.md) | Windows, Linux, macOS build instructions |
| [Configuration](docs/configuration.md) | All flags and defaults |
| [Listeners](docs/listeners.md) | Listener types, options, TLS setup |
| [Commands](docs/commands.md) | Every agent command with args |
| [API reference](docs/api.md) | Full WebSocket action/event reference |
| [Architecture](docs/architecture.md) | Internals — request flow, crypto, DB schema |

## License

GPLv3.
