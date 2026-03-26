package dohdns

import "github.com/google/uuid"

// Repository is the storage interface for DoH-DNS hybrid listeners.
type Repository interface {
	Add(listener Listener) error
	Exists(name string) bool
	Listeners() []Listener
	ListenerByID(id uuid.UUID) (Listener, error)
	ListenerByName(name string) (Listener, error)
	RemoveByID(id uuid.UUID) error
	SetOption(id uuid.UUID, option, value string) error
}
