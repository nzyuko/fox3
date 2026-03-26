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

// Package memory is an in-memory database used to store and retrieve TCP servers
package memory

import (
	// Standard
	"fmt"
	"sync"

	// 3rd Party
	"github.com/google/uuid"

	// Fox3
	"github.com/nzyuko/fox3/v2/pkg/servers/tcp"
)

// Repository implements tcp.Repository with an in-memory map
type Repository struct {
	servers map[uuid.UUID]tcp.Server
	sync.Mutex
}

var serverMap = make(map[uuid.UUID]tcp.Server)

// NewRepository returns a new in-memory TCP server repository
func NewRepository() *Repository {
	return &Repository{servers: serverMap}
}

func (r *Repository) Add(server tcp.Server) error {
	if r.servers == nil {
		r.Lock()
		r.servers = make(map[uuid.UUID]tcp.Server)
		r.Unlock()
	}
	if _, ok := r.servers[server.ID()]; ok {
		return fmt.Errorf("pkg/servers/tcp/memory.Add(): a server with ID %s already exists", server.ID())
	}
	r.Lock()
	r.servers[server.ID()] = server
	r.Unlock()
	return nil
}

func (r *Repository) Remove(id uuid.UUID) {
	r.Lock()
	defer r.Unlock()
	delete(r.servers, id)
}

func (r *Repository) Server(id uuid.UUID) (tcp.Server, error) {
	r.Lock()
	defer r.Unlock()
	s, ok := r.servers[id]
	if !ok {
		return tcp.Server{}, fmt.Errorf("pkg/servers/tcp/memory.Server(): server %s does not exist", id)
	}
	return s, nil
}

func (r *Repository) Servers() []tcp.Server {
	r.Lock()
	defer r.Unlock()
	var out []tcp.Server
	for _, s := range r.servers {
		out = append(out, s)
	}
	return out
}

func (r *Repository) SetOption(id uuid.UUID, option, value string) error {
	r.Lock()
	defer r.Unlock()
	s, ok := r.servers[id]
	if !ok {
		return fmt.Errorf("pkg/servers/tcp/memory.SetOption(): server %s does not exist", id)
	}
	if err := s.SetOption(option, value); err != nil {
		return fmt.Errorf("pkg/servers/tcp/memory.SetOption(): %s", err)
	}
	r.servers[id] = s
	return nil
}

func (r *Repository) Update(server tcp.Server) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.servers[server.ID()]; !ok {
		return fmt.Errorf("pkg/servers/tcp/memory.Update(): server %s does not exist", server.ID())
	}
	r.servers[server.ID()] = server
	return nil
}
