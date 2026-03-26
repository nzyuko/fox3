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

// Package dohdns implements a hybrid DNS-over-HTTPS + DNS listener.
//
// Both the DoH HTTPS endpoint and the plain DNS server share a single listener UUID,
// so the same transformer pipeline (PSK, JWE key, transforms) processes traffic from
// both transports.  Agents can attempt DoH first and fall back to DNS (AAAA → TXT)
// without the server needing separate listener configurations.
//
// Option keys accepted in the options map:
//
//	Name, Description, PSK, Transforms, Authenticator  – same as other listeners
//	JWTKey, JWTLeeway                                  – DoH HTTPS JWT config
//	X509Cert, X509Key                                  – TLS certificates for DoH
//	DOHInterface, DOHPort, DOHURLs                     – DoH server bind config
//	DNSInterface, DNSPort, Domain                      – DNS server bind + domain
package dohdns

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/nzyuko/fox3/v2/pkg/fox3-message"

	"github.com/nzyuko/fox3/v2/pkg/authenticators"
	"github.com/nzyuko/fox3/v2/pkg/authenticators/none"
	"github.com/nzyuko/fox3/v2/pkg/authenticators/opaque"
	"github.com/nzyuko/fox3/v2/pkg/core/crypto"
	"github.com/nzyuko/fox3/v2/pkg/listeners"
	"github.com/nzyuko/fox3/v2/pkg/logging"
	"github.com/nzyuko/fox3/v2/pkg/servers"
	"github.com/nzyuko/fox3/v2/pkg/services/agent"
	"github.com/nzyuko/fox3/v2/pkg/transformer"
)

// compositeServer wraps the DoH and DNS servers under a single servers.ServerInterface
// so the standard listener-service Start/Stop/Listen machinery works unchanged.
// It holds servers.ServerInterface values to avoid importing the concrete server
// packages and causing an import cycle through pkg/services/message.
type compositeServer struct {
	id  uuid.UUID
	doh servers.ServerInterface
	dns servers.ServerInterface
}

func (c *compositeServer) ID() uuid.UUID          { return c.id }
func (c *compositeServer) Addr() string           { return fmt.Sprintf("DoH:%s DNS:%s", c.doh.Addr(), c.dns.Addr()) }
func (c *compositeServer) Interface() string      { return c.doh.Interface() }
func (c *compositeServer) Port() int              { return c.doh.Port() }
func (c *compositeServer) Protocol() int          { return servers.DOH } // primary
func (c *compositeServer) ProtocolString() string { return "DOHDNS" }
func (c *compositeServer) String() string         { return "DOHDNS" }

func (c *compositeServer) ConfiguredOptions() map[string]string {
	opts := c.doh.ConfiguredOptions()
	dnsOpts := c.dns.ConfiguredOptions()
	opts["DNSInterface"] = dnsOpts["Interface"]
	opts["DNSPort"] = dnsOpts["Port"]
	return opts
}

func (c *compositeServer) SetOption(option, value string) error {
	lo := strings.ToLower(option)
	if strings.HasPrefix(lo, "dns") {
		return c.dns.SetOption(strings.TrimPrefix(lo, "dns"), value)
	}
	return c.doh.SetOption(option, value)
}

// Listen prepares both servers for accepting connections.
func (c *compositeServer) Listen() error {
	if err := c.doh.Listen(); err != nil {
		return fmt.Errorf("dohdns compositeServer.Listen() DoH: %s", err)
	}
	if err := c.dns.Listen(); err != nil {
		return fmt.Errorf("dohdns compositeServer.Listen() DNS: %s", err)
	}
	return nil
}

// Start launches both servers.  DNS is run in a background goroutine; DoH blocks
// (the callers already wrap this in go server.Start()).
func (c *compositeServer) Start() {
	go c.dns.Start()
	c.doh.Start()
}

// Stop shuts down both servers.
func (c *compositeServer) Stop() error {
	var errs []string
	if err := c.doh.Stop(); err != nil {
		errs = append(errs, "DoH: "+err.Error())
	}
	if err := c.dns.Stop(); err != nil {
		errs = append(errs, "DNS: "+err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("dohdns Stop: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (c *compositeServer) Status() string { return c.doh.Status() }

// Listener is the hybrid DoH+DNS aggregate listener.
type Listener struct {
	id           uuid.UUID
	composite    *compositeServer
	auth         authenticators.Authenticator
	transformers []transformer.Transformer
	description  string
	name         string
	options      map[string]string
	psk          []byte
	jwt          []byte
	agentService *agent.Service
}

// NewDoHDNSListener creates a hybrid listener backed by both a DoH and a DNS server.
// The caller (pkg/services/listeners) is responsible for pre-generating id and for
// calling SetListenerID(id) on both concrete servers before passing them as
// servers.ServerInterface values here.  This avoids an import cycle through
// pkg/services/message.
func NewDoHDNSListener(id uuid.UUID, doh servers.ServerInterface, dns servers.ServerInterface, options map[string]string) (listener Listener, err error) {
	listener.id = id

	listener.name = options["Name"]
	if listener.name == "" {
		return listener, fmt.Errorf("a listener name must be provided")
	}
	listener.description = options["Description"]

	if pskVal, ok := options["PSK"]; ok {
		h := sha256.Sum256([]byte(pskVal))
		listener.psk = h[:]
	}
	if jwtVal, ok := options["JWTKey"]; ok {
		listener.jwt, err = base64.StdEncoding.DecodeString(jwtVal)
		if err != nil {
			return listener, fmt.Errorf("pkg/listeners/dohdns.NewDoHDNSListener(): invalid JWTKey: %s", err)
		}
	}

	if _, ok := options["Transforms"]; ok {
		listener.transformers, err = transformer.BuildPipeline(options["Transforms"])
		if err != nil {
			return listener, fmt.Errorf("pkg/listeners/dohdns.NewDoHDNSListener(): %s", err)
		}
	}

	if _, ok := options["Authenticator"]; ok {
		switch strings.ToLower(options["Authenticator"]) {
		case "opaque":
			listener.auth, err = opaque.NewAuthenticator()
			if err != nil {
				return listener, fmt.Errorf("pkg/listeners/dohdns.NewDoHDNSListener(): authenticator error: %s", err)
			}
		default:
			listener.auth = none.NewAuthenticator()
		}
	} else {
		listener.auth = none.NewAuthenticator()
	}

	listener.composite = &compositeServer{
		id:  id,
		doh: doh,
		dns: dns,
	}

	listener.agentService = agent.NewAgentService()
	listener.options = options
	return listener, nil
}

// DefaultOptions returns sensible defaults for a DoH-DNS hybrid listener.
func DefaultOptions() map[string]string {
	opts := make(map[string]string)
	opts["Name"] = "My DoH-DNS Listener"
	opts["Authenticator"] = "OPAQUE"
	opts["Description"] = "Hybrid DoH+DNS Listener (agent tries DoH first, falls back to DNS)"
	opts["PSK"] = "fox3"
	opts["Transforms"] = "jwe,json"
	return opts
}

// Listener interface implementation ─────────────────────────────────────────

func (l *Listener) ID() uuid.UUID                               { return l.id }
func (l *Listener) Addr() string                               { return l.composite.Addr() }
func (l *Listener) Authenticator() authenticators.Authenticator { return l.auth }
func (l *Listener) Description() string                         { return l.description }
func (l *Listener) Name() string                               { return l.name }
func (l *Listener) Options() map[string]string                 { return l.options }
func (l *Listener) Protocol() int                              { return listeners.DOHDNS }
func (l *Listener) PSK() string                               { return string(l.psk) }
func (l *Listener) Status() string                            { return l.composite.Status() }
func (l *Listener) String() string                            { return l.name }
func (l *Listener) Transformers() []transformer.Transformer   { return l.transformers }

func (l *Listener) Server() *servers.ServerInterface {
	var si servers.ServerInterface = l.composite
	return &si
}

func (l *Listener) Authenticate(id uuid.UUID, data interface{}) (messages.Base, error) {
	return l.auth.Authenticate(id, data)
}

func (l *Listener) ConfiguredOptions() map[string]string {
	opts := l.composite.ConfiguredOptions()
	opts["ID"] = l.id.String()
	opts["Name"] = l.name
	opts["Description"] = l.description
	opts["Authenticator"] = l.auth.String()
	opts["Transforms"] = ""
	for _, t := range l.transformers {
		opts["Transforms"] += fmt.Sprintf("%s,", t)
	}
	opts["PSK"] = l.options["PSK"]
	return opts
}

func (l *Listener) Construct(msg messages.Base, key []byte) (data []byte, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "message", fmt.Sprintf("%+v", msg))

	lifetime, _ := l.agentService.Lifetime(msg.ID)
	if l.agentService.Authenticated(msg.ID) {
		msg.Token, err = crypto.GetJWT(msg.ID, lifetime, l.jwt)
		if err != nil {
			return nil, fmt.Errorf("pkg/listeners/dohdns.Construct(): JWT error: %s", err)
		}
	}
	if len(key) == 0 {
		key = l.psk
	}
	for i := len(l.transformers); i > 0; i-- {
		if i == len(l.transformers) {
			data, err = l.transformers[i-1].Construct(msg, key)
		} else {
			data, err = l.transformers[i-1].Construct(data, key)
		}
		if err != nil {
			return nil, fmt.Errorf("pkg/listeners/dohdns.Construct(): transformer error: %s", err)
		}
	}
	return
}

func (l *Listener) Deconstruct(data, key []byte) (messages.Base, error) {
	if len(key) == 0 {
		key = l.psk
	}
	for _, t := range l.transformers {
		ret, err := t.Deconstruct(data, key)
		if err != nil {
			return messages.Base{}, err
		}
		switch v := ret.(type) {
		case []uint8:
			data = v
		case string:
			data = []byte(v)
		case messages.Base:
			return v, nil
		default:
			return messages.Base{}, fmt.Errorf("pkg/listeners/dohdns.Deconstruct(): unhandled type: %T", ret)
		}
	}
	return messages.Base{}, fmt.Errorf("pkg/listeners/dohdns.Deconstruct(): unable to transform data into messages.Base")
}

func (l *Listener) SetOption(option, value string) error {
	var key string
	var err error
	switch strings.ToLower(option) {
	case "authenticator":
		switch strings.ToLower(value) {
		case "opaque":
			l.auth, err = opaque.NewAuthenticator()
			if err != nil {
				return err
			}
		default:
			l.auth = none.NewAuthenticator()
		}
		key = "Authenticator"
	case "description":
		l.description = value
		key = "Description"
	case "name":
		l.name = value
		key = "Name"
	case "psk":
		h := sha256.Sum256([]byte(value))
		l.psk = h[:]
		key = "PSK"
	case "transforms":
		tl, err := transformer.BuildPipeline(value)
		if err != nil {
			return fmt.Errorf("pkg/listeners/dohdns.SetOption(): %s", err)
		}
		l.transformers = tl
		key = "Transforms"
	default:
		if serr := l.composite.SetOption(option, value); serr != nil {
			return fmt.Errorf("pkg/listeners/dohdns.SetOption(): %s", serr)
		}
		return nil
	}
	if _, ok := l.options[key]; !ok {
		return fmt.Errorf("pkg/listeners/dohdns.SetOption(): invalid key %q", key)
	}
	l.options[key] = value
	return nil
}
