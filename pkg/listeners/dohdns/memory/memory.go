package memory

import (
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/nzyuko/fox3/v2/pkg/listeners/dohdns"
)

// Repository is an in-memory store for DoH-DNS hybrid listeners.
type Repository struct {
	listeners map[uuid.UUID]dohdns.Listener
	sync.Mutex
}

var listenerMap = make(map[uuid.UUID]dohdns.Listener)

func NewRepository() *Repository {
	return &Repository{listeners: listenerMap}
}

func (r *Repository) Add(l dohdns.Listener) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.listeners[l.ID()]; ok {
		return fmt.Errorf("DoH-DNS listener %s already exists", l.ID())
	}
	r.listeners[l.ID()] = l
	return nil
}

func (r *Repository) Exists(name string) bool {
	r.Lock()
	defer r.Unlock()
	for _, l := range r.listeners {
		if l.Name() == name {
			return true
		}
	}
	return false
}

func (r *Repository) Listeners() []dohdns.Listener {
	r.Lock()
	defer r.Unlock()
	var out []dohdns.Listener
	for _, l := range r.listeners {
		out = append(out, l)
	}
	return out
}

func (r *Repository) ListenerByID(id uuid.UUID) (dohdns.Listener, error) {
	r.Lock()
	defer r.Unlock()
	if l, ok := r.listeners[id]; ok {
		return l, nil
	}
	return dohdns.Listener{}, fmt.Errorf("DoH-DNS listener %s does not exist", id)
}

func (r *Repository) ListenerByName(name string) (dohdns.Listener, error) {
	r.Lock()
	defer r.Unlock()
	for _, l := range r.listeners {
		if l.Name() == name {
			return l, nil
		}
	}
	return dohdns.Listener{}, fmt.Errorf("DoH-DNS listener %q does not exist", name)
}

func (r *Repository) RemoveByID(id uuid.UUID) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.listeners[id]; !ok {
		return fmt.Errorf("DoH-DNS listener %s does not exist", id)
	}
	delete(listenerMap, id)
	return nil
}

func (r *Repository) SetOption(id uuid.UUID, option, value string) error {
	r.Lock()
	defer r.Unlock()
	l, ok := r.listeners[id]
	if !ok {
		return fmt.Errorf("DoH-DNS listener %s does not exist", id)
	}
	if err := l.SetOption(option, value); err != nil {
		return err
	}
	r.listeners[id] = l
	return nil
}
