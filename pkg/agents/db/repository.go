package db

import (
	"encoding/json"
	"github.com/nzyuko/fox3/v2/pkg/agents"
	"github.com/nzyuko/fox3/v2/pkg/db"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository() *Repository {
	r := &Repository{db: db.DB}
	// On startup, mark all previously-alive agents as dead.
	// They must re-register before being shown as active in the UI.
	r.db.Model(&db.AgentModel{}).Where("alive = ?", true).Update("alive", false)
	return r
}

func (r *Repository) Add(agent agents.Agent) error {
	ips, _ := json.Marshal(agent.Host().IPs)
	model := db.AgentModel{
		ID:            agent.ID().String(),
		Alive:         agent.Alive(),
		Authenticated: agent.Authenticated(),
		Initial:       agent.Initial(),
		Checkin:       agent.StatusCheckin(),
		Secret:        agent.Secret(),
		Note:          agent.Note(),
		Host: db.HostModel{
			AgentID:      agent.ID().String(),
			Name:         agent.Host().Name,
			Platform:     agent.Host().Platform,
			Architecture: agent.Host().Architecture,
			IPs:          string(ips),
		},
		Process: db.ProcessModel{
			AgentID:   agent.ID().String(),
			PID:       agent.Process().ID,
			Name:      agent.Process().Name,
			UserName:  agent.Process().UserName,
			Domain:    agent.Process().Domain,
			Integrity: agent.Process().Integrity,
		},
		Comms: db.CommsModel{
			AgentID:  agent.ID().String(),
			Protocol: agent.Comms().Proto,
			Sleep:    0, // Convert Wait string to int if needed, but keeping it simple for now
			Jitter:   int(agent.Comms().Skew),
			Padding:  agent.Comms().Padding,
		},
	}
	return r.db.Create(&model).Error
}

func (r *Repository) Get(id uuid.UUID) (agents.Agent, error) {
	var model db.AgentModel
	err := r.db.Preload("Host").Preload("Process").Preload("Comms").First(&model, "id = ?", id.String()).Error
	if err != nil {
		return agents.Agent{}, err
	}

	var ips []string
	json.Unmarshal([]byte(model.Host.IPs), &ips)

	// Since NewAgent is private or returns a private struct, we use it and then update fields via setters
	agent, err := agents.NewAgent(id, model.Secret, nil, model.Initial)
	if err != nil {
		return agents.Agent{}, err
	}

	agent.UpdateAlive(model.Alive)
	agent.UpdateAuthenticated(model.Authenticated)
	agent.UpdateStatusCheckin(model.Checkin)
	agent.UpdateNote(model.Note)
	
	agent.UpdateHost(agents.Host{
		Architecture: model.Host.Architecture,
		Name:         model.Host.Name,
		Platform:     model.Host.Platform,
		IPs:          ips,
	})
	
	agent.UpdateProcess(agents.Process{
		ID:        model.Process.PID,
		Integrity: model.Process.Integrity,
		Name:      model.Process.Name,
		UserName:  model.Process.UserName,
		Domain:    model.Process.Domain,
	})
	
	agent.UpdateComms(agents.Comms{
		Proto:   model.Comms.Protocol,
		Skew:    int64(model.Comms.Jitter),
		Padding: model.Comms.Padding,
		// Wait handling needs more care if we want full fidelity
	})

	return agent, nil
}

func (r *Repository) GetAll() (allAgents []agents.Agent) {
	var models []db.AgentModel
	r.db.Preload("Host").Preload("Process").Preload("Comms").Find(&models)
	for _, m := range models {
		id, _ := uuid.Parse(m.ID)
		a, _ := r.Get(id)
		allAgents = append(allAgents, a)
	}
	return
}

func (r *Repository) Remove(id uuid.UUID) error {
	return r.db.Delete(&db.AgentModel{}, "id = ?", id.String()).Error
}

func (r *Repository) Log(id uuid.UUID, message string) error {
	// For now, still use the file logger or implement a DB logger
	// Let's stick to the file logger for now as it's already implemented in Agent.Log()
	a, err := r.Get(id)
	if err != nil {
		return err
	}
	a.Log(message)
	return nil
}

func (r *Repository) Update(agent agents.Agent) error {
	// Implement full update logic
	return r.db.Transaction(func(tx *gorm.DB) error {
		id := agent.ID().String()
		if err := tx.Model(&db.AgentModel{}).Where("id = ?", id).Updates(map[string]interface{}{
			"alive":         agent.Alive(),
			"authenticated": agent.Authenticated(),
			"checkin":       agent.StatusCheckin(),
			"note":          agent.Note(),
			"secret":        agent.Secret(),
		}).Error; err != nil {
			return err
		}
		
		ips, _ := json.Marshal(agent.Host().IPs)
		if err := tx.Model(&db.HostModel{}).Where("agent_id = ?", id).Updates(map[string]interface{}{
			"name":         agent.Host().Name,
			"platform":     agent.Host().Platform,
			"architecture": agent.Host().Architecture,
			"ips":          string(ips),
		}).Error; err != nil {
			return err
		}

		if err := tx.Model(&db.ProcessModel{}).Where("agent_id = ?", id).Updates(map[string]interface{}{
			"pid":       agent.Process().ID,
			"name":      agent.Process().Name,
			"user_name": agent.Process().UserName,
			"domain":    agent.Process().Domain,
			"integrity": agent.Process().Integrity,
		}).Error; err != nil {
			return err
		}

		if err := tx.Model(&db.CommsModel{}).Where("agent_id = ?", id).Updates(map[string]interface{}{
			"protocol": agent.Comms().Proto,
			"jitter":   int(agent.Comms().Skew),
			"padding":  agent.Comms().Padding,
		}).Error; err != nil {
			return err
		}
		return nil
	})
}

// Simple wrappers for specific updates
func (r *Repository) UpdateAlive(id uuid.UUID, alive bool) error {
	return r.db.Model(&db.AgentModel{}).Where("id = ?", id.String()).Update("alive", alive).Error
}

func (r *Repository) UpdateAuthenticated(id uuid.UUID, authenticated bool) error {
	return r.db.Model(&db.AgentModel{}).Where("id = ?", id.String()).Update("authenticated", authenticated).Error
}

func (r *Repository) UpdateBuild(id uuid.UUID, build agents.Build) error {
	return nil // Build info usually fixed after first checkin
}

func (r *Repository) UpdateComms(id uuid.UUID, comms agents.Comms) error {
	return r.db.Model(&db.CommsModel{}).Where("agent_id = ?", id.String()).Updates(map[string]interface{}{
		"protocol": comms.Proto,
		"jitter":   int(comms.Skew),
		"padding":  comms.Padding,
	}).Error
}

func (r *Repository) UpdateHost(id uuid.UUID, host agents.Host) error {
	ips, _ := json.Marshal(host.IPs)
	return r.db.Model(&db.HostModel{}).Where("agent_id = ?", id.String()).Updates(map[string]interface{}{
		"name":         host.Name,
		"platform":     host.Platform,
		"architecture": host.Architecture,
		"ips":          string(ips),
	}).Error
}

func (r *Repository) UpdateInitial(id uuid.UUID, t time.Time) error {
	return r.db.Model(&db.AgentModel{}).Where("id = ?", id.String()).Update("initial", t).Error
}

func (r *Repository) UpdateListener(id, listener uuid.UUID) error {
	return nil // Not tracked in basic models yet
}

func (r *Repository) UpdateProcess(id uuid.UUID, process agents.Process) error {
	return r.db.Model(&db.ProcessModel{}).Where("agent_id = ?", id.String()).Updates(map[string]interface{}{
		"pid":       process.ID,
		"name":      process.Name,
		"user_name": process.UserName,
		"domain":    process.Domain,
		"integrity": process.Integrity,
	}).Error
}

func (r *Repository) UpdateNote(id uuid.UUID, note string) error {
	return r.db.Model(&db.AgentModel{}).Where("id = ?", id.String()).Update("note", note).Error
}

func (r *Repository) UpdateStatusCheckin(id uuid.UUID, t time.Time) error {
	return r.db.Model(&db.AgentModel{}).Where("id = ?", id.String()).Update("checkin", t).Error
}

func (r *Repository) AddLinkedAgent(id uuid.UUID, link uuid.UUID) error {
	// Needs a Join table for full implementation
	return nil
}

func (r *Repository) RemoveLinkedAgent(id uuid.UUID, link uuid.UUID) error {
	return nil
}
