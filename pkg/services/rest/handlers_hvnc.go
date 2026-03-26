package rest

import (
	"fmt"
	"log/slog"

	"github.com/nzyuko/fox3/v2/pkg/modules/hvnc"

	"github.com/google/uuid"
)

// ── WS action handlers for HVNC ────────────────────────────────────────────

func (h *wsHub) handleHvncStatus(payload map[string]any) (any, error) {
	agentID, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}
	session := hvnc.GetSession(agentID)
	if session == nil {
		return map[string]any{"active": false}, nil
	}
	_, width, height, seq := session.Frame()
	return map[string]any{
		"active":    true,
		"conn_id":   session.ConnID.String(),
		"width":     width,
		"height":    height,
		"frame_seq": seq,
	}, nil
}

func (h *wsHub) handleHvncStart(payload map[string]any) (any, error) {
	agentID, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}
	quality := getString(payload, "quality")
	if quality == "" {
		quality = "50"
	}
	result, err := h.server.jobService.Add(agentID, "hvnc_start", []string{quality})
	if err != nil {
		return nil, err
	}
	return map[string]string{"message": result}, nil
}

func (h *wsHub) handleHvncStop(payload map[string]any) (any, error) {
	agentID, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}
	result, err := h.server.jobService.Add(agentID, "hvnc_stop", nil)
	if err != nil {
		return nil, err
	}
	return map[string]string{"message": result}, nil
}

func (h *wsHub) handleHvncInput(payload map[string]any) (any, error) {
	agentID, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}

	msg := uint32(getFloat(payload, "msg"))
	wparam := uint32(getFloat(payload, "wparam"))
	lparam := uint32(getFloat(payload, "lparam"))

	slog.Debug("HVNC SendInput via WS", "agent", agentID, "msg", msg, "wparam", wparam, "lparam", lparam)
	hvnc.SendInput(agentID, msg, wparam, lparam)
	return nil, nil
}

func (h *wsHub) handleHvncLaunch(payload map[string]any) (any, error) {
	agentID, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}
	action := hvnc.ActionFromString(getString(payload, "action"))
	if action == 0 {
		return nil, fmt.Errorf("unknown action: %s", getString(payload, "action"))
	}
	hvnc.SendControl(agentID, action)
	return map[string]string{"status": "ok"}, nil
}

func (h *wsHub) handleHvncQuality(payload map[string]any) (any, error) {
	agentID, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}
	quality := getString(payload, "quality")
	if quality == "" {
		return nil, fmt.Errorf("quality required")
	}
	result, err := h.server.jobService.Add(agentID, "hvnc_start", []string{quality})
	if err != nil {
		return nil, err
	}
	return map[string]string{"message": result}, nil
}

// getFloat extracts a float64 from a JSON-decoded map (numbers decode as float64).
func getFloat(p map[string]any, key string) float64 {
	if v, ok := p[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0
}
