package dns

import "github.com/google/uuid"

type Repository interface {
	Add(listener Listener) error
	Exists(name string) bool
	List() func(string) []string
	Listeners() []Listener
	ListenerByID(id uuid.UUID) (Listener, error)
	ListenerByName(name string) (Listener, error)
	RemoveByID(id uuid.UUID) error
	SetOption(id uuid.UUID, option, value string) error
}
