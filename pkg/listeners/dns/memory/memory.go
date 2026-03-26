package memory

import (
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/nzyuko/fox3/v2/pkg/listeners/dns"
)

type Repository struct {
	listeners map[uuid.UUID]dns.Listener
	sync.Mutex
}

var listenerMap = make(map[uuid.UUID]dns.Listener)

func NewRepository() *Repository {
	return &Repository{listeners: listenerMap, Mutex: sync.Mutex{}}
}

func (r *Repository) Add(listener dns.Listener) error {
	if r.listeners == nil {
		r.Lock()
		r.listeners = make(map[uuid.UUID]dns.Listener)
		r.Unlock()
	}
	if _, ok := r.listeners[listener.ID()]; ok {
		return fmt.Errorf("DNS listener %s already exists", listener.ID())
	}
	r.Lock()
	r.listeners[listener.ID()] = listener
	r.Unlock()
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

func (r *Repository) List() func(string) []string {
	return func(line string) []string {
		var names []string
		for _, l := range r.listeners {
			names = append(names, l.Name())
		}
		return names
	}
}

func (r *Repository) Listeners() []dns.Listener {
	r.Lock()
	defer r.Unlock()
	var found []dns.Listener
	for _, l := range r.listeners {
		found = append(found, l)
	}
	return found
}

func (r *Repository) ListenerByID(id uuid.UUID) (dns.Listener, error) {
	r.Lock()
	defer r.Unlock()
	if l, ok := r.listeners[id]; ok {
		return l, nil
	}
	return dns.Listener{}, fmt.Errorf("DNS listener %s does not exist", id)
}

func (r *Repository) ListenerByName(name string) (dns.Listener, error) {
	r.Lock()
	defer r.Unlock()
	for _, l := range r.listeners {
		if l.Name() == name {
			return l, nil
		}
	}
	return dns.Listener{}, fmt.Errorf("DNS listener %s does not exist", name)
}

func (r *Repository) RemoveByID(id uuid.UUID) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.listeners[id]; !ok {
		return fmt.Errorf("DNS listener %s does not exist", id)
	}
	delete(listenerMap, id)
	return nil
}

func (r *Repository) SetOption(id uuid.UUID, option, value string) error {
	r.Lock()
	defer r.Unlock()
	l, ok := r.listeners[id]
	if !ok {
		return fmt.Errorf("DNS listener %s does not exist", id)
	}
	err := l.SetOption(option, value)
	if err != nil {
		return err
	}
	r.listeners[id] = l
	return nil
}
