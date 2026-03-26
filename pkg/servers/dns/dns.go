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

// Package dns contains structures and methods to create, manage, and operate standalone DNS C2 servers
package dns

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	mdns "github.com/miekg/dns"

	"github.com/nzyuko/fox3/v2/pkg/servers"
	message2 "github.com/nzyuko/fox3/v2/pkg/services/message"
)

func init() {
	servers.RegisteredServers[servers.DNS] = ""
}

const (
	Stopped int = 0
	Running int = 1
	Error   int = 2
	Closed  int = 3
)

// Server is a structure for a standalone DNS C2 server that implements the ServerInterface
type Server struct {
	id         uuid.UUID
	listenerID uuid.UUID // overrides id in message service calls when set by the DoH-DNS hybrid
	iface      string
	port       int
	protocol   int
	state      int
	domain     string
	psk        string
	udpServer  *mdns.Server
	tcpServer  *mdns.Server
	// chunkBuf holds partially received chunked DNS messages per agent.
	// Agents that need to send payloads larger than a single DNS query split
	// them across multiple queries, each marked with sequence/total metadata.
	chunkBuf   sync.Map // uuid.UUID -> *chunkBuffer
}

// chunkBuffer accumulates base32-decoded chunks for a single multi-query message.
type chunkBuffer struct {
	mu      sync.Mutex
	chunks  map[int][]byte // seq -> decoded chunk data
	total   int
	created time.Time
}

// SetListenerID tells the server which listener UUID to pass to NewMessageService.
// The DoH-DNS hybrid listener calls this so both its DoH and DNS servers share
// the same listener pipeline instead of each using their own server UUID.
func (s *Server) SetListenerID(id uuid.UUID) { s.listenerID = id }

func (s *Server) effectiveListenerID() uuid.UUID {
	if s.listenerID != uuid.Nil {
		return s.listenerID
	}
	return s.id
}

func New(options map[string]string) (Server, error) {
	var err error
	var s Server
	s.id = uuid.New()
	s.state = Stopped
	s.protocol = servers.DNS

	s.iface, _ = options["Interface"]
	if s.iface == "" {
		return s, fmt.Errorf("the \"Interface\" key was not found in the options map and is required")
	}

	port, ok := options["Port"]
	if !ok {
		return s, fmt.Errorf("the \"Port\" key was not found in the options map and is required")
	}
	s.port, err = strconv.Atoi(port)
	if err != nil {
		return s, fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
	}

	s.domain = options["Domain"]
	if s.domain == "" {
		s.domain = "fox3.local"
	}
	if !strings.HasSuffix(s.domain, ".") {
		s.domain = s.domain + "."
	}

	s.psk, ok = options["PSK"]
	if !ok {
		return s, fmt.Errorf("the \"PSK\" key was not found in the options map and is required")
	}

	return s, nil
}

func (s *Server) Addr() string          { return fmt.Sprintf("%s:%d", s.iface, s.port) }
func (s *Server) ID() uuid.UUID         { return s.id }
func (s *Server) Interface() string      { return s.iface }
func (s *Server) Port() int              { return s.port }
func (s *Server) Protocol() int          { return s.protocol }
func (s *Server) ProtocolString() string { return "DNS" }
func (s *Server) String() string         { return s.ProtocolString() }

func (s *Server) ConfiguredOptions() map[string]string {
	options := make(map[string]string)
	options["Protocol"] = s.ProtocolString()
	options["Interface"] = s.iface
	options["Port"] = fmt.Sprintf("%d", s.port)
	options["Domain"] = s.domain
	return options
}

func (s *Server) SetOption(option string, value string) error {
	var err error
	switch strings.ToLower(option) {
	case "interface":
		s.iface = value
	case "port":
		s.port, err = strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("there was an error converting the port to an integer: %s", err.Error())
		}
	case "protocol":
		return fmt.Errorf("the protocol can not be changed; create a new listener instead")
	case "psk":
		s.psk = value
	case "domain":
		s.domain = value
		if !strings.HasSuffix(s.domain, ".") {
			s.domain = s.domain + "."
		}
	default:
		return fmt.Errorf("invalid option: %s", option)
	}
	return nil
}

// Listen is a no-op for DNS servers (miekg/dns manages its own listeners)
func (s *Server) Listen() error {
	addr := fmt.Sprintf("%s:%d", s.iface, s.port)

	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		s.dnsHandler(w, r)
	})

	s.udpServer = &mdns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: handler,
	}

	s.tcpServer = &mdns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: handler,
	}

	return nil
}

// Start starts UDP and TCP DNS servers
func (s *Server) Start() {
	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("The DNS server on %s:%d paniced: %v", s.iface, s.port, r))
		}
	}()

	s.state = Running

	// Start chunk buffer TTL reaper to prevent memory leaks from orphaned partial messages
	go s.chunkBufReaper()

	// Start UDP in a goroutine
	go func() {
		slog.Info(fmt.Sprintf("Starting DNS UDP server on %s:%d for domain %s", s.iface, s.port, s.domain))
		if err := s.udpServer.ListenAndServe(); err != nil {
			slog.Error(fmt.Sprintf("DNS UDP server error: %s", err))
			s.state = Error
		}
	}()

	// TCP runs in the current goroutine (Start is called as a goroutine by the listener service)
	slog.Info(fmt.Sprintf("Starting DNS TCP server on %s:%d for domain %s", s.iface, s.port, s.domain))
	if err := s.tcpServer.ListenAndServe(); err != nil {
		slog.Error(fmt.Sprintf("DNS TCP server error: %s", err))
		s.state = Error
	}
}

func (s *Server) Status() string {
	switch s.state {
	case Stopped:
		return "Stopped"
	case Running:
		return "Running"
	case Error:
		return "Error"
	case Closed:
		return "Closed"
	default:
		return "Undefined"
	}
}

func (s *Server) Stop() error {
	if s.state != Running {
		return nil
	}
	var errStr string
	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			errStr += fmt.Sprintf("UDP: %s; ", err)
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			errStr += fmt.Sprintf("TCP: %s; ", err)
		}
	}
	if errStr != "" {
		return fmt.Errorf("error stopping DNS server: %s", errStr)
	}
	s.state = Closed
	return nil
}

func GetDefaultOptions(protocol int) map[string]string {
	options := make(map[string]string)
	options["Interface"] = "0.0.0.0"
	options["Port"] = "53"
	options["Protocol"] = "DNS"
	options["Domain"] = "fox3.local"
	return options
}

// dnsMaxDecodedBytes is the maximum number of bytes we will accept in the
// base32-encoded subdomain payload.  A single UDP DNS query is limited to
// 512 bytes total (4096 with EDNS), so a 4 KB cap on the decoded payload
// is generous while still preventing memory-exhaustion attacks.
const dnsMaxDecodedBytes = 4096

// dnsHandler processes incoming DNS queries and returns C2 data in TXT records
func (s *Server) dnsHandler(w mdns.ResponseWriter, r *mdns.Msg) {
	if len(r.Question) == 0 {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]

	// Reject obviously malformed or excessively long names before any processing.
	if len(q.Name) > 253 {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	slog.Debug("DNS query received", "name", q.Name, "type", mdns.TypeToString[q.Qtype], "remote", w.RemoteAddr())

	// Only handle TXT and AAAA queries for our domain
	if q.Qtype != mdns.TypeTXT && q.Qtype != mdns.TypeAAAA {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	if !strings.HasSuffix(q.Name, s.domain) {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	// Extract subdomain: <base32data>...<agentID>.<domain>
	subdomain := strings.TrimSuffix(q.Name, "."+s.domain)
	if subdomain == q.Name {
		subdomain = strings.TrimSuffix(q.Name, s.domain)
	}

	parts := strings.Split(subdomain, ".")
	if len(parts) < 2 {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	// Last label is agent ID (32 hex chars, no dashes)
	agentHex := parts[len(parts)-1]
	if len(agentHex) != 32 {
		slog.Debug("DNS: agent ID label has unexpected length", "label", agentHex, "len", len(agentHex))
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}
	agentID, err := uuid.Parse(insertDashes(agentHex))
	if err != nil {
		slog.Debug(fmt.Sprintf("DNS: error parsing agent ID %s: %s", agentHex, err))
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	// Remaining labels are base32-encoded data.
	// Check for multi-query chunk marker: first label starts with lowercase "m"
	// followed by 2-hex-digit sequence and 2-hex-digit total (e.g., "m0003").
	dataLabels := parts[:len(parts)-1]
	isChunked := len(dataLabels) > 0 && len(dataLabels[0]) == 5 && dataLabels[0][0] == 'm'

	var agentData []byte
	var sendResponse bool

	if isChunked {
		seq64, serr := strconv.ParseInt(dataLabels[0][1:3], 16, 32)
		tot64, terr := strconv.ParseInt(dataLabels[0][3:5], 16, 32)
		if serr != nil || terr != nil || tot64 < 1 {
			m := new(mdns.Msg)
			m.SetRcode(r, mdns.RcodeFormatError)
			_ = w.WriteMsg(m)
			return
		}
		seq := int(seq64)
		total := int(tot64)

		// Decode this chunk's data (labels after the marker)
		chunkEncoded := strings.ToUpper(strings.Join(dataLabels[1:], ""))
		chunkData, derr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(chunkEncoded)
		if derr != nil {
			slog.Debug(fmt.Sprintf("DNS: error decoding chunked data: %s", derr))
			m := new(mdns.Msg)
			m.SetRcode(r, mdns.RcodeFormatError)
			_ = w.WriteMsg(m)
			return
		}

		// Buffer the chunk
		val, _ := s.chunkBuf.LoadOrStore(agentID, &chunkBuffer{chunks: make(map[int][]byte), total: total, created: time.Now()})
		cb := val.(*chunkBuffer)
		cb.mu.Lock()
		cb.total = total
		cb.chunks[seq] = chunkData
		complete := len(cb.chunks) >= total
		if complete {
			// Reassemble in order
			var assembled []byte
			for i := 0; i < total; i++ {
				assembled = append(assembled, cb.chunks[i]...)
			}
			agentData = assembled
		}
		cb.mu.Unlock()

		if complete {
			s.chunkBuf.Delete(agentID)
			sendResponse = true
		} else {
			// Intermediate chunk: ACK with empty TXT response
			responseMsg := new(mdns.Msg)
			responseMsg.SetReply(r)
			responseMsg.Authoritative = true
			_ = w.WriteMsg(responseMsg)
			return
		}
	} else {
		// Single-query message (backward compatible)
		encodedData := strings.ToUpper(strings.Join(dataLabels, ""))

		// Guard against crafted names that would decode to huge payloads.
		if len(encodedData)*5/8 > dnsMaxDecodedBytes {
			slog.Warn("DNS: encoded payload exceeds size limit — dropping", "encoded_len", len(encodedData), "remote", w.RemoteAddr())
			m := new(mdns.Msg)
			m.SetRcode(r, mdns.RcodeFormatError)
			_ = w.WriteMsg(m)
			return
		}

		var derr error
		agentData, derr = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encodedData)
		if derr != nil {
			slog.Debug(fmt.Sprintf("DNS: error decoding data: %s", derr))
			m := new(mdns.Msg)
			m.SetRcode(r, mdns.RcodeFormatError)
			_ = w.WriteMsg(m)
			return
		}
		sendResponse = true
	}

	_ = sendResponse // always true at this point

	// Delegate to message service using the effective listener ID (hybrid or own server ID).
	ms, err := message2.NewMessageService(s.effectiveListenerID())
	if err != nil {
		slog.Error(fmt.Sprintf("DNS: error getting message service: %s", err))
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	rdata, err := ms.Handle(agentID, agentData)
	if err != nil {
		slog.Error(fmt.Sprintf("DNS: error handling message from %s: %s", agentID, err))
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	// Build TXT response
	responseMsg := new(mdns.Msg)
	responseMsg.SetReply(r)
	responseMsg.Authoritative = true

	if len(rdata) > 0 {
		if q.Qtype == mdns.TypeTXT {
			encoded := base64.StdEncoding.EncodeToString(rdata)
			var txtStrings []string
			for len(encoded) > 0 {
				end := 255
				if end > len(encoded) {
					end = len(encoded)
				}
				txtStrings = append(txtStrings, encoded[:end])
				encoded = encoded[end:]
			}
			rr := &mdns.TXT{
				Hdr: mdns.RR_Header{
					Name:   q.Name,
					Rrtype: mdns.TypeTXT,
					Class:  mdns.ClassINET,
					Ttl:    0,
				},
				Txt: txtStrings,
			}
			responseMsg.Answer = append(responseMsg.Answer, rr)
		} else if q.Qtype == mdns.TypeAAAA {
			// Chunk into 16-byte IPv6 blocks (AAAA records)
			for len(rdata) > 0 {
				chunk := make([]byte, 16)
				n := copy(chunk, rdata)
				rdata = rdata[n:]
				rr := &mdns.AAAA{
					Hdr: mdns.RR_Header{
						Name:   q.Name,
						Rrtype: mdns.TypeAAAA,
						Class:  mdns.ClassINET,
						Ttl:    0,
					},
					AAAA: net.IP(chunk),
				}
				responseMsg.Answer = append(responseMsg.Answer, rr)
			}
		}
	}

	_ = w.WriteMsg(responseMsg)
}

// chunkBufReaper periodically removes stale partial chunk buffers to prevent memory leaks.
func (s *Server) chunkBufReaper() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if s.state != Running {
			return
		}
		now := time.Now()
		s.chunkBuf.Range(func(key, val any) bool {
			cb := val.(*chunkBuffer)
			cb.mu.Lock()
			age := now.Sub(cb.created)
			cb.mu.Unlock()
			if age > 30*time.Second {
				slog.Debug("DNS: expiring stale chunk buffer", "agent", key, "age", age)
				s.chunkBuf.Delete(key)
			}
			return true
		})
	}
}

func insertDashes(hex string) string {
	if len(hex) != 32 {
		return hex
	}
	return hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}
