// Package credentials provides a service used to interact with harvested credentials globally
package credentials

import (
	"github.com/google/uuid"

	infoCreds "github.com/nzyuko/fox3/v2/pkg/credentials"
	creddb "github.com/nzyuko/fox3/v2/pkg/credentials/db"
)

// Service holds references to repositories to manage Credential objects
type Service struct {
	credRepo infoCreds.Repository
}

// memoryService is an in-memory instantiation of the Credential service
var memoryService *Service

// NewCredentialService is a factory to create a Credential service to be used by frontends or APIs
func NewCredentialService() *Service {
	if memoryService == nil {
		memoryService = &Service{
			credRepo: creddb.NewRepository(),
		}
	}
	return memoryService
}

// Add creates and saves a new credential
func (s *Service) Add(domain, username, password, hash, source string, agentID uuid.UUID) infoCreds.Info {
	info := infoCreds.NewInfo(domain, username, password, hash, source, agentID)
	s.credRepo.Add(info)
	return info
}

// Remove deletes a credential
func (s *Service) Remove(id string) error {
	return s.credRepo.Remove(id)
}

// GetAll returns a slice of all credentials
func (s *Service) GetAll() []infoCreds.Info {
	var returnCreds []infoCreds.Info
	for _, cred := range s.credRepo.GetAll() {
		returnCreds = append(returnCreds, cred)
	}
	return returnCreds
}

// GetInfo returns a specific credential by ID
func (s *Service) GetInfo(id string) (infoCreds.Info, error) {
	return s.credRepo.GetInfo(id)
}

// ClearAll removes all credentials
func (s *Service) ClearAll() {
	s.credRepo.ClearAll()
}
