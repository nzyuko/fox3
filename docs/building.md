# Building fox3

## Prerequisites

| Dependency | Minimum | Notes |
|---|---|---|
| Go | 1.24 | Toolchain declared in `go.mod` |
| GCC / C compiler | any recent | Required for SQLite (CGO) |
| Node.js + npm | 18+ | Only needed to rebuild the frontend |

The SQLite driver (`mattn/go-sqlite3`) is a CGO package — a C compiler is **required** on every platform. The binary will not build without one.

---

## Windows

Install [Go](https://go.dev/dl/) and [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) (or any MinGW-w64 distribution). Ensure both are on `PATH`.

```powershell
git clone https://github.com/nzyuko/fox3
cd fox3

# Build
go build -o fox3_server.exe .

# Verify all packages compile
go build ./...

# Static analysis (known non-fatal warnings — see docs/architecture.md)
go vet ./...

# Run
.\fox3_server.exe --password <strong-password>
```

### Stamp a release build

```powershell
$commit = git rev-parse --short HEAD
go build -ldflags "-X github.com/nzyuko/fox3/v2/pkg.Build=$commit" -o fox3_server.exe .
```

---

## Linux

Install Go and GCC via your package manager, then build natively. Do **not** cross-compile from Windows for a production Linux binary — the CGO cross-toolchain setup is non-trivial and not documented here.

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y golang gcc git

git clone https://github.com/nzyuko/fox3
cd fox3

CGO_ENABLED=1 go build -o fox3_server .
./fox3_server --password <strong-password>
```

### Fedora / RHEL

```bash
sudo dnf install -y golang gcc git

git clone https://github.com/nzyuko/fox3
cd fox3

CGO_ENABLED=1 go build -o fox3_server .
./fox3_server --password <strong-password>
```

### Arch Linux

```bash
sudo pacman -S go gcc git

git clone https://github.com/nzyuko/fox3
cd fox3

go build -o fox3_server .
./fox3_server --password <strong-password>
```

### Notes

- The Go toolchain sets `CGO_ENABLED=1` by default when building natively, so the explicit flag is optional but recommended for clarity.
- The server binary has no runtime dependency on GCC — GCC is only needed at compile time.
- The SQLite database is created at `data/fox3.db` relative to the **working directory** where you run the server, not the binary location.

### Systemd unit (optional)

```ini
[Unit]
Description=fox3 C2 server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/fox3
ExecStart=/opt/fox3/fox3_server --password <strong-password> --rest 0.0.0.0:8080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp fox3.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fox3
```

---

## macOS

Install Go via [go.dev](https://go.dev/dl/) or Homebrew. Xcode Command Line Tools provides the C compiler.

```bash
xcode-select --install
brew install go  # or download from go.dev

git clone https://github.com/nzyuko/fox3
cd fox3
go build -o fox3_server .
./fox3_server --password <strong-password>
```

---

## Rebuilding the frontend

The compiled React assets are committed to `frontend/dist/` and served directly by the REST server. You only need to rebuild if you edit `frontend/src/`.

```bash
cd frontend
npm install
npm run build
# Output lands in frontend/dist/ — commit the result
```

The server resolves `frontend/dist/` relative to the **working directory** at startup. If the directory is not found there, it falls back to `<executable-dir>/frontend/dist/`.

---

## Known build warnings (`go vet`)

These are pre-existing issues inherited from the Merlin codebase and are non-blocking:

| Package | Warning | Impact |
|---|---|---|
| `pkg/authenticators/opaque` | non-constant format string in `fmt.Errorf` | cosmetic |
| `pkg/listeners/*/memory` | non-constant format string in `fmt.Errorf` | cosmetic |
| `pkg/servers/dns` | `return` copies lock value (`sync.Map`) | needs pointer refactor |
| `pkg/servers/doh` | `return` copies lock value (`sync.Map`) | needs pointer refactor |
| `pkg/servers/dns/memory` | passes/assigns lock by value | needs pointer refactor |
| `pkg/servers/doh/memory` | passes/assigns lock by value | needs pointer refactor |
| `pkg/services/rpc` | non-constant format string in `fmt.Errorf` | cosmetic |

The DNS/DoH vet warnings are only relevant once those listener types are wired into the factory.
