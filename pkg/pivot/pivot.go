// Package pivot tracks parent-child agent relationships (SMB/TCP linking).
package pivot

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nzyuko/fox3/v2/pkg/db"
	"github.com/nzyuko/fox3/v2/pkg/events"
)

// Pivot describes a parent→child agent link.
type Pivot struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	ParentAgentID uuid.UUID `json:"parent_agent_id"`
	ChildAgentID  uuid.UUID `json:"child_agent_id"`
	Protocol      string    `json:"protocol"` // "smb" or "tcp"
	Created       time.Time `json:"created"`
}

// Service manages pivot relationships.
type Service struct {
	mu     sync.RWMutex
	pivots map[string]*Pivot
	nameN  int // auto-increment for p0, p1, ...
}

var svc *Service

// NewService returns the singleton pivot service.
func NewService() *Service {
	if svc == nil {
		svc = &Service{pivots: make(map[string]*Pivot)}
		svc.loadFromDB()
	}
	return svc
}

// Add creates a new pivot relationship.
func (s *Service) Add(parentID, childID uuid.UUID, protocol, name string) *Pivot {
	s.mu.Lock()
	if name == "" {
		name = fmt.Sprintf("p%d", s.nameN)
		s.nameN++
	}
	p := &Pivot{
		ID:            uuid.New().String(),
		Name:          name,
		ParentAgentID: parentID,
		ChildAgentID:  childID,
		Protocol:      protocol,
		Created:       time.Now().UTC(),
	}
	s.pivots[p.ID] = p
	s.mu.Unlock()

	s.saveToDB(p)

	events.Publish(events.Event{
		Type: events.EventPivotCreate,
		Payload: map[string]string{
			"pivot_id":  p.ID,
			"parent_id": parentID.String(),
			"child_id":  childID.String(),
			"protocol":  protocol,
		},
	})

	slog.Info("Pivot created", "id", p.ID, "parent", parentID, "child", childID, "proto", protocol)
	return p
}

// Remove deletes a pivot.
func (s *Service) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pivots[id]
	if !ok {
		return fmt.Errorf("pivot %s not found", id)
	}
	delete(s.pivots, id)
	s.deleteFromDB(id)

	events.Publish(events.Event{
		Type: events.EventPivotRemove,
		Payload: map[string]string{
			"pivot_id":  id,
			"parent_id": p.ParentAgentID.String(),
			"child_id":  p.ChildAgentID.String(),
		},
	})
	return nil
}

// GetAll returns all pivots.
func (s *Service) GetAll() []*Pivot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Pivot, 0, len(s.pivots))
	for _, p := range s.pivots {
		out = append(out, p)
	}
	return out
}

// GetByAgent returns pivots involving a specific agent (as parent or child).
func (s *Service) GetByAgent(agentID uuid.UUID) []*Pivot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Pivot
	for _, p := range s.pivots {
		if p.ParentAgentID == agentID || p.ChildAgentID == agentID {
			out = append(out, p)
		}
	}
	return out
}

// RemoveByAgent removes all pivots involving the given agent (as parent or child).
func (s *Service) RemoveByAgent(agentID uuid.UUID) {
	// Collect IDs under read lock, then remove under write lock
	pivots := s.GetByAgent(agentID)
	for _, p := range pivots {
		_ = s.Remove(p.ID)
	}
}

// ── DB persistence ──────────────────────────────────────────────────────────

func (s *Service) saveToDB(p *Pivot) {
	if db.DB == nil {
		return
	}
	model := db.PivotModel{
		ID:            p.ID,
		Name:          p.Name,
		ParentAgentID: p.ParentAgentID.String(),
		ChildAgentID:  p.ChildAgentID.String(),
		Protocol:      p.Protocol,
		Created:       p.Created,
	}
	db.DB.Create(&model)
}

func (s *Service) deleteFromDB(id string) {
	if db.DB == nil {
		return
	}
	db.DB.Delete(&db.PivotModel{}, "id = ?", id)
}

func (s *Service) loadFromDB() {
	if db.DB == nil {
		return
	}
	var models []db.PivotModel
	db.DB.Find(&models)
	for _, m := range models {
		parentID, _ := uuid.Parse(m.ParentAgentID)
		childID, _ := uuid.Parse(m.ChildAgentID)
		s.pivots[m.ID] = &Pivot{
			ID:            m.ID,
			Name:          m.Name,
			ParentAgentID: parentID,
			ChildAgentID:  childID,
			Protocol:      m.Protocol,
			Created:       m.Created,
		}
		s.nameN++
	}
	if len(models) > 0 {
		slog.Info(fmt.Sprintf("Loaded %d pivots from database", len(models)))
	}
}
