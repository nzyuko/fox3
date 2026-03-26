// Package screenshots provides storage and retrieval of agent screen captures.
package screenshots

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nzyuko/fox3/v2/pkg/db"
	"github.com/nzyuko/fox3/v2/pkg/events"
)

// Screenshot represents a single captured screen image.
type Screenshot struct {
	ID      string
	AgentID uuid.UUID
	Data    []byte // PNG image bytes
	Note    string
	Created time.Time
}

// Service manages screenshot storage.
type Service struct {
	mu    sync.RWMutex
	items map[string]*Screenshot
}

var svc *Service

// NewService returns the singleton screenshot service.
func NewService() *Service {
	if svc == nil {
		svc = &Service{items: make(map[string]*Screenshot)}
		// Load from DB
		svc.loadFromDB()
	}
	return svc
}

// Add stores a new screenshot.
func (s *Service) Add(agentID uuid.UUID, data []byte, note string) *Screenshot {
	sc := &Screenshot{
		ID:      uuid.New().String(),
		AgentID: agentID,
		Data:    data,
		Note:    note,
		Created: time.Now().UTC(),
	}

	s.mu.Lock()
	s.items[sc.ID] = sc
	s.mu.Unlock()

	// Persist to DB
	s.saveToDB(sc)

	// Publish event
	events.Publish(events.Event{
		Type: events.EventScreenshot,
		Payload: map[string]string{
			"screenshot_id": sc.ID,
			"agent_id":      agentID.String(),
		},
	})

	slog.Info("Screenshot stored", "id", sc.ID, "agent", agentID, "size", len(data))
	return sc
}

// GetAll returns all screenshot metadata (no image data to save memory).
func (s *Service) GetAll() []*Screenshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Screenshot, 0, len(s.items))
	for _, sc := range s.items {
		out = append(out, sc)
	}
	return out
}

// GetByAgent returns screenshots for a specific agent.
func (s *Service) GetByAgent(agentID uuid.UUID) []*Screenshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Screenshot
	for _, sc := range s.items {
		if sc.AgentID == agentID {
			out = append(out, sc)
		}
	}
	return out
}

// Get returns a single screenshot by ID.
func (s *Service) Get(id string) (*Screenshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.items[id]
	if !ok {
		return nil, fmt.Errorf("screenshot %s not found", id)
	}
	return sc, nil
}

// Remove deletes a screenshot.
func (s *Service) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return fmt.Errorf("screenshot %s not found", id)
	}
	delete(s.items, id)
	s.deleteFromDB(id)
	return nil
}

// RemoveByAgent removes all screenshots belonging to the given agent.
func (s *Service) RemoveByAgent(agentID uuid.UUID) {
	items := s.GetByAgent(agentID)
	for _, sc := range items {
		_ = s.Remove(sc.ID)
	}
}

// ── DB persistence ──────────────────────────────────────────────────────────

func (s *Service) saveToDB(sc *Screenshot) {
	if db.DB == nil {
		return
	}
	model := db.ScreenshotModel{
		ID:      sc.ID,
		AgentID: sc.AgentID.String(),
		Data:    sc.Data,
		Note:    sc.Note,
		Created: sc.Created,
	}
	db.DB.Create(&model)
}

func (s *Service) deleteFromDB(id string) {
	if db.DB == nil {
		return
	}
	db.DB.Delete(&db.ScreenshotModel{}, "id = ?", id)
}

func (s *Service) loadFromDB() {
	if db.DB == nil {
		return
	}
	var models []db.ScreenshotModel
	db.DB.Find(&models)
	for _, m := range models {
		agentID, _ := uuid.Parse(m.AgentID)
		s.items[m.ID] = &Screenshot{
			ID:      m.ID,
			AgentID: agentID,
			Data:    m.Data,
			Note:    m.Note,
			Created: m.Created,
		}
	}
	if len(models) > 0 {
		slog.Info(fmt.Sprintf("Loaded %d screenshots from database", len(models)))
	}
}
