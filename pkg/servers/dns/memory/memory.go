package memory

import (
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/nzyuko/fox3/v2/pkg/servers/dns"
)

type Repository struct {
	servers map[uuid.UUID]dns.Server
	sync.Mutex
}

var serverMap = make(map[uuid.UUID]dns.Server)

func NewRepository() *Repository {
	return &Repository{servers: serverMap, Mutex: sync.Mutex{}}
}

func (r *Repository) Add(server dns.Server) error {
	if r.servers == nil {
		r.Lock()
		r.servers = make(map[uuid.UUID]dns.Server)
		r.Unlock()
	}
	if _, ok := r.servers[server.ID()]; ok {
		return fmt.Errorf("DNS server %s already exists", server.ID())
	}
	r.Lock()
	r.servers[server.ID()] = server
	r.Unlock()
	return nil
}

func (r *Repository) SetOption(id uuid.UUID, option, value string) error {
	server, err := r.Server(id)
	if err != nil {
		return err
	}
	r.Lock()
	defer r.Unlock()
	err = server.SetOption(option, value)
	if err != nil {
		return err
	}
	r.servers[server.ID()] = server
	return nil
}

func (r *Repository) Server(id uuid.UUID) (dns.Server, error) {
	r.Lock()
	defer r.Unlock()
	for _, s := range r.servers {
		if s.ID() == id {
			return s, nil
		}
	}
	return dns.Server{}, fmt.Errorf("DNS server %s does not exist", id)
}

func (r *Repository) Servers() []dns.Server {
	var found []dns.Server
	r.Lock()
	defer r.Unlock()
	for _, s := range r.servers {
		found = append(found, s)
	}
	return found
}

func (r *Repository) Remove(id uuid.UUID) {
	server, err := r.Server(id)
	if err == nil {
		r.Lock()
		defer r.Unlock()
		delete(serverMap, server.ID())
	}
}

func (r *Repository) Update(server dns.Server) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.servers[server.ID()]; !ok {
		return fmt.Errorf("DNS server %s does not exist", server.ID())
	}
	r.servers[server.ID()] = server
	return nil
}
