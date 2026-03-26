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

// Package doh contains structures and methods to create, manage, and operate DNS-over-HTTPS servers
package doh

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/nzyuko/fox3/v2/pkg/client/message"
	"github.com/nzyuko/fox3/v2/pkg/client/message/memory"
	"github.com/nzyuko/fox3/v2/pkg/core"
	"github.com/nzyuko/fox3/v2/pkg/core/crypto"
	"github.com/nzyuko/fox3/v2/pkg/servers"
	message2 "github.com/nzyuko/fox3/v2/pkg/services/message"
)

func init() {
	servers.RegisteredServers[servers.DOH] = ""
}

const (
	Stopped int = 0
	Running int = 1
	Error   int = 2
	Closed  int = 3
)

// Server is a structure for a DNS-over-HTTPS server that implements the ServerInterface
type Server struct {
	id         uuid.UUID
	listenerID uuid.UUID // overrides id in message service calls when set by the DoH-DNS hybrid
	iface      string
	port       int
	protocol   int
	state      int
	transport  *http.Server
	listener   net.Listener
	x509Cert   string
	x509Key    string
	urls       []string
	psk        string
	jwtKey     string
	jwtLeeway  time.Duration
	domain     string // The DNS domain to match queries against
	chunkBuf   sync.Map // uuid.UUID -> *chunkBuffer for multi-query reassembly
}

// SetListenerID tells the server which listener UUID to pass to NewMessageService.
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
	s.protocol = servers.DOH

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

	s.domain, _ = options["Domain"]
	if s.domain == "" {
		s.domain = "fox3.local"
	}
	// Ensure domain ends with a dot for DNS matching
	if !strings.HasSuffix(s.domain, ".") {
		s.domain = s.domain + "."
	}

	if cert, ok := options["X509Cert"]; ok {
		s.x509Cert = cert
	}
	if key, ok := options["X509Key"]; ok {
		s.x509Key = key
	}

	urls, _ := options["URLS"]
	if urls == "" {
		s.urls = []string{"/dns-query"}
	} else {
		s.urls = strings.Split(urls, ",")
	}

	s.psk, ok = options["PSK"]
	if !ok {
		return s, fmt.Errorf("the \"PSK\" key was not found in the options map and is required")
	}

	jwtKey, ok := options["JWTKey"]
	if !ok {
		return s, fmt.Errorf("the \"JWTKey\" key was not found in the options map and is required")
	}
	jwt, err := base64.StdEncoding.DecodeString(jwtKey)
	if err != nil {
		return s, fmt.Errorf("there was an error base64 decoding the provided JWT Key %s: %s", jwtKey, err)
	}
	if len(jwt) != 32 {
		return s, fmt.Errorf("the provided JWT key was %d bytes but must be 32 bytes", len(jwt))
	}
	s.jwtKey = jwtKey

	leeway, ok := options["JWTLeeway"]
	if !ok {
		return s, fmt.Errorf("the \"JWTLeeway\" key was not found in the options map and is required")
	}
	s.jwtLeeway, err = time.ParseDuration(leeway)
	if err != nil {
		return s, fmt.Errorf("there was an error parsing the JWTLeeway duration %s: %s", leeway, err)
	}
	return s, nil
}

func (s *Server) Addr() string             { return fmt.Sprintf("%s:%d", s.iface, s.port) }
func (s *Server) ID() uuid.UUID            { return s.id }
func (s *Server) Interface() string         { return s.iface }
func (s *Server) Port() int                 { return s.port }
func (s *Server) Protocol() int             { return s.protocol }
func (s *Server) ProtocolString() string    { return "DOH" }
func (s *Server) String() string            { return s.ProtocolString() }

func (s *Server) ConfiguredOptions() map[string]string {
	options := make(map[string]string)
	options["Protocol"] = s.ProtocolString()
	options["Interface"] = s.iface
	options["Port"] = fmt.Sprintf("%d", s.port)
	options["URLS"] = strings.Join(s.urls, ",")
	options["JWTKey"] = s.jwtKey
	options["JWTLeeway"] = s.jwtLeeway.String()
	options["X509Cert"] = s.x509Cert
	options["X509Key"] = s.x509Key
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
			return fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
		}
	case "protocol":
		return fmt.Errorf("the protocol can not be changed; create a new listener instead")
	case "psk":
		s.psk = value
	case "urls":
		s.urls = strings.Split(value, ",")
	case "x509cert":
		s.x509Cert = value
	case "x509key":
		s.x509Key = value
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

func (s *Server) Listen() (err error) {
	err = s.generateServer()
	if err != nil {
		err = fmt.Errorf("there was an error generating a new %s server: %s", s, err)
		slog.Error(err.Error())
		return
	}
	s.listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.iface, s.port))
	if err != nil {
		err = fmt.Errorf("there was an error creating a listener for the %s server: %s", s, err)
		slog.Error(err.Error())
		return
	}
	return
}

func (s *Server) Start() {
	var g errgroup.Group
	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("The %s server on %s:%d paniced:\r\n%v+\r\n", s.ProtocolString(), s.iface, s.port, r.(error)))
		}
	}()

	// Start chunk buffer TTL reaper to prevent memory leaks from orphaned partial messages
	go s.chunkBufReaper()

	g.Go(func() error {
		s.state = Running
		return s.transport.ServeTLS(s.listener, s.x509Cert, s.x509Key)
	})

	if err := g.Wait(); err != nil {
		if err != http.ErrServerClosed {
			s.state = Error
			slog.Error(fmt.Sprintf("there was an error with the %s server on %s:%d %s", s.ProtocolString(), s.iface, s.port, err.Error()))
		}
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

func (s *Server) Stop() (err error) {
	if s.state != Running {
		return nil
	}
	if s.transport == nil {
		return fmt.Errorf("the %s server on %s:%d was never started", s.ProtocolString(), s.iface, s.port)
	}
	err = s.transport.Close()
	if err != nil {
		return fmt.Errorf("there was an error stopping the DoH server:\r\n%s", err.Error())
	}
	s.state = Closed
	return
}

func GetDefaultOptions(protocol int) map[string]string {
	options := make(map[string]string)
	options["Interface"] = "127.0.0.1"
	options["Port"] = "8443"
	options["Protocol"] = "DOH"
	options["Domain"] = "fox3.local"
	options["JWTKey"] = base64.StdEncoding.EncodeToString([]byte(core.RandStringBytesMaskImprSrc(32)))
	options["JWTLeeway"] = "1m"
	options["URLS"] = "/dns-query"

	current, err := os.Getwd()
	if err != nil {
		slog.Error(fmt.Sprintf("there was an error getting the current working directory: %s", err))
	}
	options["X509Cert"] = filepath.Join(current, "data", "x509", "server.crt")
	options["X509Key"] = filepath.Join(current, "data", "x509", "server.key")
	return options
}

func (s *Server) generateServer() error {
	jwt, err := base64.StdEncoding.DecodeString(s.jwtKey)
	if err != nil {
		return fmt.Errorf("there was an error base64 decoding the provided JWT Key %s: %s", s.jwtKey, err)
	}

	pskHash := sha256.Sum256([]byte(s.psk))

	mux := http.NewServeMux()
	for _, url := range s.urls {
		mux.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
			s.dohHandler(w, r, jwt, pskHash[:])
		})
	}

	s.transport = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.iface, s.port),
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.Default(),
	}

	certificates, err := crypto.GetTLSCertificates(s.x509Cert, s.x509Key)
	if err != nil {
		m := fmt.Sprintf("Certificate was not found at: \"%s\"\n", s.x509Cert)
		m += "Creating in-memory x.509 certificate used for this session only"
		slog.Info(m)
		memory.NewRepository().Add(message.NewMessage(message.Note, m))
		s.x509Key = ""
		s.x509Cert = ""
		certificates, err = crypto.GenerateTLSCert(nil, nil, nil, nil, nil, nil, true)
		if err != nil {
			return err
		}
	}

	insecure, err := crypto.CheckInsecureFingerprint(*certificates)
	if err != nil {
		return err
	}
	if insecure {
		m := fmt.Sprintf("Insecure publicly distributed Fox3 x.509 testing certificate in use for %s server on %s:%d\n", s.ProtocolString(), s.iface, s.port)
		slog.Info(m)
		memory.NewRepository().Add(message.NewMessage(message.Note, m))
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{*certificates}} // #nosec G402
	s.transport.TLSConfig = &tlsConfig
	return nil
}

// dohHandler processes RFC 8484 DNS-over-HTTPS requests
func (s *Server) dohHandler(w http.ResponseWriter, r *http.Request, jwtKey, psk []byte) {
	slog.Debug("New DoH connection", "remote address", r.RemoteAddr, "method", r.Method)

	// Only accept POST with application/dns-message
	if r.Method != http.MethodPost {
		// Also support GET with ?dns= parameter per RFC 8484
		if r.Method == http.MethodGet {
			s.dohHandleGET(w, r, jwtKey, psk)
			return
		}
		w.WriteHeader(404)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/dns-message" {
		w.WriteHeader(404)
		return
	}

	// Read DNS wire format message
	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error(fmt.Sprintf("DoH: error reading request body: %s", err))
		w.WriteHeader(500)
		return
	}

	rdata := s.processDNSMessage(body, jwtKey, psk)

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	_, _ = w.Write(rdata)
}

// dohHandleGET handles RFC 8484 GET requests with ?dns= base64url query parameter
func (s *Server) dohHandleGET(w http.ResponseWriter, r *http.Request, jwtKey, psk []byte) {
	accept := r.Header.Get("Accept")
	if accept != "application/dns-message" {
		w.WriteHeader(404)
		return
	}

	dnsParam := r.URL.Query().Get("dns")
	if dnsParam == "" {
		w.WriteHeader(400)
		return
	}

	body, err := base64.RawURLEncoding.DecodeString(dnsParam)
	if err != nil {
		slog.Error(fmt.Sprintf("DoH: error decoding GET dns parameter: %s", err))
		w.WriteHeader(400)
		return
	}

	rdata := s.processDNSMessage(body, jwtKey, psk)

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	_, _ = w.Write(rdata)
}

// processDNSMessage parses a DNS wire format message, extracts agent data, and returns a DNS response
func (s *Server) processDNSMessage(body []byte, jwtKey, psk []byte) []byte {
	// Parse DNS message
	var dnsMsg dns.Msg
	err := dnsMsg.Unpack(body)
	if err != nil {
		slog.Error(fmt.Sprintf("DoH: error unpacking DNS message: %s", err))
		return buildDNSError(&dnsMsg, dns.RcodeFormatError)
	}

	if len(dnsMsg.Question) == 0 {
		return buildDNSError(&dnsMsg, dns.RcodeFormatError)
	}

	q := dnsMsg.Question[0]

	// Only handle TXT and AAAA queries for our domain
	if q.Qtype != dns.TypeTXT && q.Qtype != dns.TypeAAAA {
		return buildDNSError(&dnsMsg, dns.RcodeRefused)
	}

	if !strings.HasSuffix(q.Name, s.domain) {
		return buildDNSError(&dnsMsg, dns.RcodeRefused)
	}

	// Extract data from subdomain labels
	// Format: <base32data>.<agentID>.<domain>
	subdomain := strings.TrimSuffix(q.Name, "."+s.domain)
	if subdomain == q.Name {
		subdomain = strings.TrimSuffix(q.Name, s.domain)
	}

	parts := strings.Split(subdomain, ".")
	if len(parts) < 2 {
		return buildDNSError(&dnsMsg, dns.RcodeNameError)
	}

	// Last label is agent ID
	agentHex := parts[len(parts)-1]
	agentID, err := uuid.Parse(insertDashes(agentHex))
	if err != nil {
		slog.Error(fmt.Sprintf("DoH: error parsing agent ID %s: %s", agentHex, err))
		return buildDNSError(&dnsMsg, dns.RcodeNameError)
	}

	// Remaining labels contain base32-encoded data.
	// Check for multi-query chunk marker: first label starts with lowercase "m"
	// followed by 2-hex-digit sequence and 2-hex-digit total (e.g., "m0003").
	dataLabels := parts[:len(parts)-1]
	isChunked := len(dataLabels) > 0 && len(dataLabels[0]) == 5 && dataLabels[0][0] == 'm'

	var agentData []byte

	if isChunked {
		seq64, serr := strconv.ParseInt(dataLabels[0][1:3], 16, 32)
		tot64, terr := strconv.ParseInt(dataLabels[0][3:5], 16, 32)
		if serr != nil || terr != nil || tot64 < 1 {
			return buildDNSError(&dnsMsg, dns.RcodeFormatError)
		}
		seq := int(seq64)
		total := int(tot64)

		chunkEncoded := strings.ToUpper(strings.Join(dataLabels[1:], ""))
		chunkData, derr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(chunkEncoded)
		if derr != nil {
			slog.Debug(fmt.Sprintf("DoH: error decoding chunked data: %s", derr))
			return buildDNSError(&dnsMsg, dns.RcodeFormatError)
		}

		val, _ := s.chunkBuf.LoadOrStore(agentID, &chunkBuffer{chunks: make(map[int][]byte), total: total, created: time.Now()})
		cb := val.(*chunkBuffer)
		cb.mu.Lock()
		cb.total = total
		cb.chunks[seq] = chunkData
		complete := len(cb.chunks) >= total
		if complete {
			var assembled []byte
			for i := 0; i < total; i++ {
				assembled = append(assembled, cb.chunks[i]...)
			}
			agentData = assembled
		}
		cb.mu.Unlock()

		if !complete {
			// ACK intermediate chunk
			responseMsg := new(dns.Msg)
			responseMsg.SetReply(&dnsMsg)
			responseMsg.Authoritative = true
			packed, _ := responseMsg.Pack()
			return packed
		}
		s.chunkBuf.Delete(agentID)
	} else {
		encodedData := strings.ToUpper(strings.Join(dataLabels, ""))
		var derr error
		agentData, derr = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encodedData)
		if derr != nil {
			slog.Error(fmt.Sprintf("DoH: error decoding agent data: %s", derr))
			return buildDNSError(&dnsMsg, dns.RcodeFormatError)
		}
	}

	// Delegate to message service using the effective listener ID (hybrid or own server ID).
	ms, err := message2.NewMessageService(s.effectiveListenerID())
	if err != nil {
		slog.Error(fmt.Sprintf("DoH: error getting message service: %s", err))
		return buildDNSError(&dnsMsg, dns.RcodeServerFailure)
	}

	rdata, err := ms.Handle(agentID, agentData)
	if err != nil {
		slog.Error(fmt.Sprintf("DoH: error handling message from %s: %s", agentID, err))
		return buildDNSError(&dnsMsg, dns.RcodeServerFailure)
	}

	// Build DNS TXT response with base32-encoded response data
	responseMsg := new(dns.Msg)
	responseMsg.SetReply(&dnsMsg)
	responseMsg.Authoritative = true

	if len(rdata) > 0 {
		if q.Qtype == dns.TypeTXT {
			encoded := base64.StdEncoding.EncodeToString(rdata)
			// Chunk into 255-byte TXT strings
			var txtStrings []string
			for len(encoded) > 0 {
				end := 255
				if end > len(encoded) {
					end = len(encoded)
				}
				txtStrings = append(txtStrings, encoded[:end])
				encoded = encoded[end:]
			}
			rr := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Txt: txtStrings,
			}
			responseMsg.Answer = append(responseMsg.Answer, rr)
		} else if q.Qtype == dns.TypeAAAA {
			// Chunk into 16-byte IPv6 blocks (AAAA records)
			for len(rdata) > 0 {
				chunk := make([]byte, 16)
				n := copy(chunk, rdata)
				rdata = rdata[n:]
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					AAAA: net.IP(chunk),
				}
				responseMsg.Answer = append(responseMsg.Answer, rr)
			}
		}
	}

	packed, err := responseMsg.Pack()
	if err != nil {
		slog.Error(fmt.Sprintf("DoH: error packing DNS response: %s", err))
		return buildDNSError(&dnsMsg, dns.RcodeServerFailure)
	}
	return packed
}

// buildDNSError creates a DNS error response
func buildDNSError(req *dns.Msg, rcode int) []byte {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	packed, _ := m.Pack()
	return packed
}

// chunkBuffer accumulates base32-decoded chunks for a single multi-query message.
type chunkBuffer struct {
	mu      sync.Mutex
	chunks  map[int][]byte
	total   int
	created time.Time
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
				slog.Debug("DoH: expiring stale chunk buffer", "agent", key, "age", age)
				s.chunkBuf.Delete(key)
			}
			return true
		})
	}
}

// insertDashes converts a 32-char hex string to UUID format with dashes
func insertDashes(hex string) string {
	if len(hex) != 32 {
		return hex
	}
	return hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}
