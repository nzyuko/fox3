package memory

import (
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/nzyuko/fox3/v2/pkg/servers/doh"
)

type Repository struct {
	servers map[uuid.UUID]doh.Server
	sync.Mutex
}

var serverMap = make(map[uuid.UUID]doh.Server)

func NewRepository() *Repository {
	return &Repository{servers: serverMap, Mutex: sync.Mutex{}}
}

func (r *Repository) Add(server doh.Server) error {
	if r.servers == nil {
		r.Lock()
		r.servers = make(map[uuid.UUID]doh.Server)
		r.Unlock()
	}
	if _, ok := r.servers[server.ID()]; ok {
		return fmt.Errorf("a DoH server with ID %s already exists", server.ID())
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

func (r *Repository) Server(id uuid.UUID) (doh.Server, error) {
	r.Lock()
	defer r.Unlock()
	for _, s := range r.servers {
		if s.ID() == id {
			return s, nil
		}
	}
	return doh.Server{}, fmt.Errorf("DoH server %s does not exist", id)
}

func (r *Repository) Servers() []doh.Server {
	var found []doh.Server
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

func (r *Repository) Update(server doh.Server) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.servers[server.ID()]; !ok {
		return fmt.Errorf("DoH server %s does not exist and can't be updated", server.ID())
	}
	r.servers[server.ID()] = server
	return nil
}
