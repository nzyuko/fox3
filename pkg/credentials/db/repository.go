package db

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	pkgdb "github.com/nzyuko/fox3/v2/pkg/db"
	"github.com/nzyuko/fox3/v2/pkg/credentials"
)

// Repository is the GORM-backed credential repository.
type Repository struct {
	db *gorm.DB
}

var repo *Repository

// NewRepository returns the singleton DB-backed credential repository.
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{db: pkgdb.DB}
	}
	return repo
}

// Add persists a new credential to the database.
func (r *Repository) Add(info credentials.Info) {
	model := pkgdb.CredentialModel{
		ID:       info.ID(),
		Domain:   info.Domain(),
		Username: info.Username(),
		Password: info.Password(),
		Hash:     info.Hash(),
		Source:   info.Source(),
		AgentID:  info.AgentID().String(),
		Created:  info.Created(),
	}
	r.db.Create(&model)
}

// Remove deletes a credential by ID.
func (r *Repository) Remove(id string) error {
	result := r.db.Delete(&pkgdb.CredentialModel{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("credential %s not found", id)
	}
	return nil
}

// GetAll returns all stored credentials.
func (r *Repository) GetAll() map[string]credentials.Info {
	var models []pkgdb.CredentialModel
	r.db.Find(&models)
	result := make(map[string]credentials.Info, len(models))
	for _, m := range models {
		result[m.ID] = modelToInfo(m)
	}
	return result
}

// GetInfo returns a specific credential by ID.
func (r *Repository) GetInfo(id string) (credentials.Info, error) {
	var m pkgdb.CredentialModel
	if err := r.db.First(&m, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("credential %s not found: %w", id, err)
	}
	return modelToInfo(m), nil
}

// ClearAll removes all credentials.
func (r *Repository) ClearAll() {
	r.db.Where("1 = 1").Delete(&pkgdb.CredentialModel{})
}

func modelToInfo(m pkgdb.CredentialModel) credentials.Info {
	agentID, _ := uuid.Parse(m.AgentID)
	return &dbCredential{
		id:       m.ID,
		domain:   m.Domain,
		username: m.Username,
		password: m.Password,
		hash:     m.Hash,
		source:   m.Source,
		agentID:  agentID,
		created:  m.Created,
	}
}

// dbCredential is a concrete implementation of credentials.Info backed by DB data.
type dbCredential struct {
	id       string
	domain   string
	username string
	password string
	hash     string
	source   string
	agentID  uuid.UUID
	created  time.Time
}

func (c *dbCredential) ID() string           { return c.id }
func (c *dbCredential) Domain() string       { return c.domain }
func (c *dbCredential) Username() string     { return c.username }
func (c *dbCredential) Password() string     { return c.password }
func (c *dbCredential) Hash() string         { return c.hash }
func (c *dbCredential) Source() string       { return c.source }
func (c *dbCredential) AgentID() uuid.UUID   { return c.agentID }
func (c *dbCredential) Created() time.Time   { return c.created }
