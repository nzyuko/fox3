// Package credentials provides interfaces and structures for managing harvested credentials
package credentials

import (
	"time"

	"github.com/google/uuid"
)

// Info is a tracking structure that contains information about a harvested credential
type Info interface {
	// ID returns the unique identifier for the credential
	ID() string
	// Domain returns the domain or machine name
	Domain() string
	// Username returns the username
	Username() string
	// Password returns the plaintext password if available
	Password() string
	// Hash returns the NTLM or other hash if available
	Hash() string
	// Source returns where the credential was harvested from (e.g., LSA, SAM, Vault)
	Source() string
	// AgentID returns the UUID of the agent that harvested the credential
	AgentID() uuid.UUID
	// Created returns the creation time
	Created() time.Time
}

// Credential contains the basic data for a tracked credential
type Credential struct {
	id       string
	domain   string
	username string
	password string
	hash     string
	source   string
	agentID  uuid.UUID
	created  time.Time
}

// ID returns the unique identifier for the credential
func (c *Credential) ID() string {
	return c.id
}

// Domain returns the domain or machine name
func (c *Credential) Domain() string {
	return c.domain
}

// Username returns the username
func (c *Credential) Username() string {
	return c.username
}

// Password returns the plaintext password if available
func (c *Credential) Password() string {
	return c.password
}

// Hash returns the NTLM or other hash if available
func (c *Credential) Hash() string {
	return c.hash
}

// Source returns where the credential was harvested from
func (c *Credential) Source() string {
	return c.source
}

// AgentID returns the UUID of the agent that harvested the credential
func (c *Credential) AgentID() uuid.UUID {
	return c.agentID
}

// Created returns the creation time
func (c *Credential) Created() time.Time {
	return c.created
}

// NewInfo creates and returns a new Credential Info tracking structure
func NewInfo(domain, username, password, hash, source string, agentID uuid.UUID) Info {
	return &Credential{
		id:       uuid.New().String(),
		domain:   domain,
		username: username,
		password: password,
		hash:     hash,
		source:   source,
		agentID:  agentID,
		created:  time.Now().UTC(),
	}
}

// Repository is an interface for a basic CRUD datastore for Credentials
type Repository interface {
	// Add inserts a new credential
	Add(info Info)
	// Remove deletes a credential by ID
	Remove(id string) error
	// GetAll returns all stored credentials
	GetAll() map[string]Info
	// GetInfo returns a specific credential by ID
	GetInfo(id string) (Info, error)
	// ClearAll removes all stored credentials
	ClearAll()
}
