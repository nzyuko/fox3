// Package dns contains structures and repositories to create, store, and manage DNS Agent listeners
package dns

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/nzyuko/fox3/v2/pkg/fox3-message"

	"github.com/nzyuko/fox3/v2/pkg/authenticators"
	"github.com/nzyuko/fox3/v2/pkg/authenticators/none"
	"github.com/nzyuko/fox3/v2/pkg/authenticators/opaque"
	"github.com/nzyuko/fox3/v2/pkg/listeners"
	"github.com/nzyuko/fox3/v2/pkg/logging"
	"github.com/nzyuko/fox3/v2/pkg/servers"
	"github.com/nzyuko/fox3/v2/pkg/services/agent"
	"github.com/nzyuko/fox3/v2/pkg/transformer"
)

type Listener struct {
	server       servers.ServerInterface
	auth         authenticators.Authenticator
	transformers []transformer.Transformer
	description  string
	name         string
	options      map[string]string
	psk          []byte
	agentService *agent.Service
}

func NewDNSListener(server servers.ServerInterface, options map[string]string) (listener Listener, err error) {
	listener.name = options["Name"]
	if listener.name == "" {
		return listener, fmt.Errorf("a listener name must be provided")
	}
	listener.server = server
	listener.description = options["Description"]

	if _, ok := options["PSK"]; ok {
		psk := sha256.Sum256([]byte(options["PSK"]))
		listener.psk = psk[:]
	}

	if _, ok := options["Transforms"]; ok {
		listener.transformers, err = transformer.BuildPipeline(options["Transforms"])
		if err != nil {
			return listener, fmt.Errorf("pkg/listeners/dns.NewDNSListener(): %s", err)
		}
	}

	if _, ok := options["Authenticator"]; ok {
		switch strings.ToLower(options["Authenticator"]) {
		case "opaque":
			listener.auth, err = opaque.NewAuthenticator()
			if err != nil {
				return listener, fmt.Errorf("pkg/listeners/dns.NewDNSListener(): authenticator error: %s", err)
			}
		default:
			listener.auth = none.NewAuthenticator()
		}
	}
	listener.agentService = agent.NewAgentService()
	listener.options = options
	return listener, nil
}

func DefaultOptions() map[string]string {
	options := make(map[string]string)
	options["Name"] = "My DNS Listener"
	options["Authenticator"] = "OPAQUE"
	options["Description"] = "Default DNS Listener"
	options["PSK"] = "fox3"
	options["Transforms"] = "jwe,json"
	return options
}

func (l *Listener) Addr() string                               { return l.server.Addr() }
func (l *Listener) Authenticator() authenticators.Authenticator { return l.auth }
func (l *Listener) Description() string                         { return l.description }
func (l *Listener) ID() uuid.UUID                               { return l.server.ID() }
func (l *Listener) Name() string                                { return l.name }
func (l *Listener) Options() map[string]string                  { return l.options }
func (l *Listener) Protocol() int                               { return listeners.DNS }
func (l *Listener) PSK() string                                 { return string(l.psk) }
func (l *Listener) Server() *servers.ServerInterface            { return &l.server }
func (l *Listener) Status() string                              { return l.server.Status() }
func (l *Listener) String() string                              { return l.name }
func (l *Listener) Transformers() []transformer.Transformer     { return l.transformers }

func (l *Listener) Authenticate(id uuid.UUID, data interface{}) (messages.Base, error) {
	return l.auth.Authenticate(id, data)
}

func (l *Listener) ConfiguredOptions() map[string]string {
	options := l.server.ConfiguredOptions()
	options["ID"] = l.server.ID().String()
	options["Name"] = l.name
	options["Description"] = l.description
	options["Authenticator"] = l.auth.String()
	options["Transforms"] = ""
	for _, transform := range l.transformers {
		options["Transforms"] += fmt.Sprintf("%s,", transform)
	}
	options["PSK"] = l.options["PSK"]
	return options
}

// Construct — DNS listener has no JWT since there are no HTTP headers in DNS
func (l *Listener) Construct(msg messages.Base, key []byte) (data []byte, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "message", fmt.Sprintf("%+v", msg))
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
			return nil, fmt.Errorf("pkg/listeners/dns.Construct(): transformer error: %s", err)
		}
	}
	return
}

func (l *Listener) Deconstruct(data, key []byte) (messages.Base, error) {
	if len(key) == 0 {
		key = l.psk
	}
	for _, transform := range l.transformers {
		ret, err := transform.Deconstruct(data, key)
		if err != nil {
			return messages.Base{}, err
		}
		switch ret.(type) {
		case []uint8:
			data = ret.([]byte)
		case string:
			data = []byte(ret.(string))
		case messages.Base:
			return ret.(messages.Base), nil
		default:
			return messages.Base{}, fmt.Errorf("pkg/listeners/dns.Deconstruct(): unhandled data type: %T", ret)
		}
	}
	return messages.Base{}, fmt.Errorf("pkg/listeners/dns.Deconstruct(): unable to transform data")
}

func (l *Listener) SetOption(option string, value string) error {
	var err error
	var key string
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
		psk := sha256.Sum256([]byte(value))
		l.psk = psk[:]
		err = l.server.SetOption(option, value)
		key = "PSK"
	case "transforms":
		tl, err := transformer.BuildPipeline(value)
		if err != nil {
			return fmt.Errorf("pkg/listeners/dns.SetOption(): %s", err)
		}
		l.transformers = tl
		key = "Transforms"
	default:
		err = l.server.SetOption(option, value)
		if err != nil {
			return err
		}
		return nil
	}
	_, ok := l.options[key]
	if !ok {
		return fmt.Errorf("pkg/listeners/dns.SetOption(): invalid key: \"%s\"", key)
	}
	l.options[key] = value
	return nil
}
