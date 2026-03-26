/*
Fox3 is a post-exploitation command and control framework.

This file is part of Fox3.
Copyright (C) 2024 Russel Van Tuyl

Fox3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Fox3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Fox3.  If not, see <http://www.gnu.org/licenses/>.
*/

// Package tcp is a raw-TCP server that receives length-prefixed JWE messages from pivot agents.
//
// # Frame format (same as the Rust transport_tcp.rs)
//
//	[4-byte little-endian length][message bytes]
//
// The server accepts connections, reads one framed message, routes it through the
// message service (JWE decrypt → agent dispatch → JWE encrypt), and writes the
// framed response back on the same connection.
package tcp

import (
	// Standard
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Fox3
	"github.com/nzyuko/fox3/v2/pkg/servers"
	message "github.com/nzyuko/fox3/v2/pkg/services/message"
)

func init() {
	servers.RegisteredServers[servers.TCP] = ""
}

// Server state constants (mirrors pkg/servers/http constants)
const (
	Stopped int = 0
	Running int = 1
	Error   int = 2
	Closed  int = 3
)

// Server is a structure for a raw-TCP server implementing servers.ServerInterface
type Server struct {
	id       uuid.UUID    // Unique identifier; also used as the listener ID looked up by the message service
	iface    string       // Network interface to bind (e.g. "0.0.0.0")
	port     int          // TCP port to listen on
	protocol int          // servers.TCP constant
	state    int          // current lifecycle state
	listener net.Listener // underlying TCP listener
}

// New creates and returns a new TCP Server from the provided options map.
func New(options map[string]string) (Server, error) {
	var s Server
	s.id = uuid.New()
	s.state = Stopped
	s.protocol = servers.TCP

	iface, ok := options["Interface"]
	if !ok {
		return s, fmt.Errorf("pkg/servers/tcp.New(): the \"Interface\" key was not found in the options map")
	}
	s.iface = iface

	port, ok := options["Port"]
	if !ok {
		return s, fmt.Errorf("pkg/servers/tcp.New(): the \"Port\" key was not found in the options map")
	}
	var err error
	s.port, err = strconv.Atoi(port)
	if err != nil {
		return s, fmt.Errorf("pkg/servers/tcp.New(): invalid port %q: %s", port, err)
	}

	return s, nil
}

// GetDefaultOptions returns the default options map used when creating a TCP listener.
func GetDefaultOptions() map[string]string {
	return map[string]string{
		"Interface": "0.0.0.0",
		"Port":      "4445",
		"Protocol":  "TCP",
	}
}

// Addr returns the address the server is (or will be) bound to.
func (s *Server) Addr() string {
	return fmt.Sprintf("%s:%d", s.iface, s.port)
}

// ConfiguredOptions returns the server's current configuration as a string map.
func (s *Server) ConfiguredOptions() map[string]string {
	return map[string]string{
		"Protocol":  s.ProtocolString(),
		"Interface": s.iface,
		"Port":      fmt.Sprintf("%d", s.port),
	}
}

// ID returns the server's unique identifier.
func (s *Server) ID() uuid.UUID { return s.id }

// Interface returns the network interface the server binds to.
func (s *Server) Interface() string { return s.iface }

// Port returns the port number the server listens on.
func (s *Server) Port() int { return s.port }

// Protocol returns the servers.TCP constant.
func (s *Server) Protocol() int { return s.protocol }

// ProtocolString returns the human-readable protocol name.
func (s *Server) ProtocolString() string { return "TCP" }

// Status returns a human-readable lifecycle state string.
func (s *Server) Status() string { return stateString(s.state) }

// SetOption updates a configurable option on the server struct.
func (s *Server) SetOption(option, value string) error {
	switch strings.ToLower(option) {
	case "interface":
		s.iface = value
	case "port":
		p, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("pkg/servers/tcp.SetOption(): invalid port %q: %s", value, err)
		}
		s.port = p
	case "protocol":
		return fmt.Errorf("pkg/servers/tcp.SetOption(): the protocol cannot be changed; create a new listener instead")
	default:
		return fmt.Errorf("pkg/servers/tcp.SetOption(): invalid option %q", option)
	}
	return nil
}

// Listen creates the underlying TCP net.Listener.  Must be called before Start().
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.Addr())
	if err != nil {
		return fmt.Errorf("pkg/servers/tcp.Listen(): %s", err)
	}
	s.listener = ln
	slog.Info("TCP server listening", "address", s.Addr(), "id", s.id)
	return nil
}

// Start begins accepting connections.  It blocks until the listener is closed and
// should be called as a goroutine.
func (s *Server) Start() {
	if s.listener == nil {
		slog.Error("pkg/servers/tcp.Start(): Listen() must be called before Start()")
		return
	}

	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("pkg/servers/tcp.Start(): panic: %v", r))
			s.state = Error
		}
	}()

	s.state = Running
	slog.Info("TCP server started", "address", s.Addr())

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.state == Closed {
				return
			}
			s.state = Error
			slog.Error(fmt.Sprintf("pkg/servers/tcp.Start(): accept error: %s", err))
			return
		}
		go s.handleConn(conn)
	}
}

const (
	tcpReadDeadline  = 30 * time.Second
	tcpWriteDeadline = 30 * time.Second
	tcpMaxMsgSize    = 10 << 20 // 10 MB
)

// handleConn services a single TCP connection: read framed request → process → write framed response.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Enforce a read deadline so stalled or half-open connections do not hold
	// a goroutine indefinitely.
	if err := conn.SetReadDeadline(time.Now().Add(tcpReadDeadline)); err != nil {
		slog.Debug(fmt.Sprintf("pkg/servers/tcp.handleConn(): SetReadDeadline: %s", err))
		return
	}

	// Read 4-byte little-endian length prefix
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		slog.Debug(fmt.Sprintf("pkg/servers/tcp.handleConn(): read length: %s", err))
		return
	}
	msgLen := binary.LittleEndian.Uint32(lenBuf[:])

	// Guard against zero-length or absurdly large messages.
	if msgLen == 0 || msgLen > tcpMaxMsgSize {
		slog.Warn(fmt.Sprintf("pkg/servers/tcp.handleConn(): invalid message length %d — dropping", msgLen))
		return
	}

	// Read message body
	body := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		slog.Debug(fmt.Sprintf("pkg/servers/tcp.handleConn(): read body: %s", err))
		return
	}

	// Route through the message service (JWE decrypt → dispatch → JWE encrypt)
	ms, err := message.NewMessageService(s.id)
	if err != nil {
		slog.Error(fmt.Sprintf("pkg/servers/tcp.handleConn(): NewMessageService: %s", err))
		return
	}

	// uuid.Nil: agent ID is embedded in the JWE body and resolved after decryption.
	rdata, err := ms.Handle(uuid.Nil, body)
	if err != nil {
		slog.Error(fmt.Sprintf("pkg/servers/tcp.handleConn(): Handle: %s", err))
		// Still send an empty response so the agent doesn't hang on read
		rdata = nil
	}

	// Switch to a write deadline before sending the response.
	if err := conn.SetWriteDeadline(time.Now().Add(tcpWriteDeadline)); err != nil {
		slog.Debug(fmt.Sprintf("pkg/servers/tcp.handleConn(): SetWriteDeadline: %s", err))
		return
	}

	// Write framed response: [4-byte LE length][response bytes]
	resp := make([]byte, 4+len(rdata))
	binary.LittleEndian.PutUint32(resp[:4], uint32(len(rdata)))
	copy(resp[4:], rdata)
	if _, err := conn.Write(resp); err != nil {
		slog.Debug(fmt.Sprintf("pkg/servers/tcp.handleConn(): write response: %s", err))
	}

	// Graceful half-close: signal that no more data will be sent.
	// This flushes the kernel's send buffer before the deferred Close().
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// Stop closes the listener and marks the server as Closed.
func (s *Server) Stop() error {
	if s.state != Running {
		return nil
	}
	if s.listener == nil {
		return fmt.Errorf("pkg/servers/tcp.Stop(): server was never started")
	}
	err := s.listener.Close()
	s.state = Closed
	return err
}

// stateString converts a state constant to a human-readable string.
func stateString(st int) string {
	switch st {
	case Stopped:
		return "Stopped"
	case Running:
		return "Running"
	case Error:
		return "Error"
	case Closed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", st)
	}
}
