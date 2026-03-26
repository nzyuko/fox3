// Package memory is an in-memory repository for storing and managing harvested credentials
package memory

import (
	"fmt"
	"sync"
	
	"github.com/nzyuko/fox3/v2/pkg/credentials"
)

// Repository is the structure that implements the in-memory repository for interacting with Credentials
type Repository struct {
	sync.Mutex
	creds map[string]credentials.Info // creds is a map of all credential Info tracking structures
}

// repo is the in-memory datastore singleton
var repo *Repository

// NewRepository creates and returns a new in-memory repository for interacting with Credentials
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			Mutex: sync.Mutex{},
			creds: make(map[string]credentials.Info),
		}
	}
	return repo
}

// Add the credential to the repository
func (r *Repository) Add(info credentials.Info) {
	r.Lock()
	defer r.Unlock()
	r.creds[info.ID()] = info
}

// Remove deletes a credential by ID
func (r *Repository) Remove(id string) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.creds[id]; !ok {
		return fmt.Errorf("pkg/credentials/memory.Remove(): credential %s does not exist", id)
	}
	delete(r.creds, id)
	return nil
}

// GetAll returns all Credential tracking structures as map to be iterated over
func (r *Repository) GetAll() map[string]credentials.Info {
	r.Lock()
	defer r.Unlock()
	// Create a copy to prevent race conditions during iteration
	copyCreds := make(map[string]credentials.Info, len(r.creds))
	for k, v := range r.creds {
		copyCreds[k] = v
	}
	return copyCreds
}

// GetInfo returns the credential tracking structure for the associated ID
func (r *Repository) GetInfo(id string) (credentials.Info, error) {
	r.Lock()
	defer r.Unlock()
	info, ok := r.creds[id]
	if !ok {
		return nil, fmt.Errorf("pkg/credentials/memory.GetInfo(): unable to find structure for credential %s", id)
	}
	return info, nil
}

// ClearAll removes all stored credentials
func (r *Repository) ClearAll() {
	r.Lock()
	defer r.Unlock()
	r.creds = make(map[string]credentials.Info)
}
