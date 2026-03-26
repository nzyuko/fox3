package dns

import "github.com/google/uuid"

type Repository interface {
	Add(server Server) error
	Remove(id uuid.UUID)
	Server(id uuid.UUID) (Server, error)
	Servers() []Server
	SetOption(id uuid.UUID, option, value string) error
	Update(server Server) error
}
