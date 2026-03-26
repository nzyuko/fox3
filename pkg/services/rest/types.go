package rest

import (
	"time"

	"github.com/google/uuid"
)

// AgentResponse defines the JSON structure for an agent.
type AgentResponse struct {
	ID          string   `json:"id"`
	Platform    string   `json:"platform"`
	Host        string   `json:"host"`
	User        string   `json:"user"`
	Process     string   `json:"process"`
	Status      string   `json:"status"`
	Alive       bool     `json:"alive"`
	Note        string   `json:"note"`
	Integrity   int      `json:"integrity"`
	Links       []string `json:"links"`
	LastCheckin string   `json:"last_checkin"`
	Sleep       string   `json:"sleep"`
}

// JobResponse defines the JSON structure for a job.
type JobResponse struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	Command string `json:"command"`
	Status  string `json:"status"`
	Created string `json:"created"`
	Sent    string `json:"sent"`
	Output  string `json:"output,omitempty"`
}

// ListenerResponse defines the JSON structure for a listener.
type ListenerResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	BindAddr    string `json:"bind_addr"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// CredentialResponse defines the JSON structure for a credential.
type CredentialResponse struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Source   string `json:"source"`
	AgentID  string `json:"agent_id"`
	Created  string `json:"created"`
}

// ScreenshotResponse is the JSON shape returned to the frontend.
type ScreenshotResponse struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	Note    string `json:"note"`
	Size    int    `json:"size"`
	Created string `json:"created"`
}

// PivotResponse is the JSON shape for pivot metadata.
type PivotResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ParentAgentID string `json:"parent_agent_id"`
	ChildAgentID  string `json:"child_agent_id"`
	Protocol      string `json:"protocol"`
	Created       string `json:"created"`
}

// GraphNode represents an entity in the topology graph.
type GraphNode struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Group     string `json:"group"` // "server", "listener", "agent"
	Integrity int    `json:"integrity,omitempty"`
	Status    string `json:"status,omitempty"`
}

// GraphEdge represents a connection between two nodes.
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// TopologyResponse is the entire dataset required by the topology graph.
type TopologyResponse struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// agentRealStatus returns Active/Delayed/Dead based on last checkin time.
func agentRealStatus(checkin time.Time, wait string) string {
	if checkin.IsZero() {
		return "Init"
	}
	now := time.Now()
	var active, dead time.Duration
	if wait != "" {
		d, err := time.ParseDuration(wait)
		if err == nil && d > 0 {
			active = d
			dead = d * 3
		}
	}
	if active == 0 {
		active = 60 * time.Second
		dead = 300 * time.Second
	}
	if now.Sub(checkin) > dead {
		return "Dead"
	}
	if now.Sub(checkin) > active {
		return "Delayed"
	}
	return "Active"
}

// uuidToStrings converts a slice of UUIDs to strings.
func uuidToStrings(ids []uuid.UUID) []string {
	res := make([]string, len(ids))
	for i, id := range ids {
		res[i] = id.String()
	}
	return res
}
