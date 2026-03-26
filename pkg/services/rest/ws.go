package rest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nzyuko/fox3/v2/pkg/events"
	"github.com/nzyuko/fox3/v2/pkg/modules/hvnc"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ── WebSocket protocol types ────────────────────────────────────────────────

// wsRequest is a client→server message.
type wsRequest struct {
	ID      string         `json:"id"`      // correlation ID
	Action  string         `json:"action"`  // e.g. "job.create"
	Payload map[string]any `json:"payload"` // action-specific data
}

// wsResponse is a server→client reply to a request.
type wsResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"` // always "response"
	Success bool   `json:"success"`
	Payload any    `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
}

// wsEvent is a server→client push event.
type wsEvent struct {
	Type    string `json:"type"`  // always "event"
	Event   string `json:"event"` // event name
	Payload any    `json:"payload,omitempty"`
}

// framePool could theoretically recycle HVNC frame buffers to reduce GC pressure.
// However, broadcastBinary sends the same []byte slice to every client's channel,
// and each client's writePump consumes it asynchronously. Returning the buffer to
// the pool after broadcastBinary returns would allow it to be reused for the next
// frame while slow clients still hold a reference, causing corrupted reads.
// A safe alternative would require copying the slice per client, which negates
// the benefit of pooling. Therefore we allocate a fresh buffer per frame.
//
// var framePool = sync.Pool{
//     New: func() any { return make([]byte, 0, 64*1024) },
// }

// ── Hub ─────────────────────────────────────────────────────────────────────

type wsHub struct {
	mu      sync.Mutex
	clients map[*wsClient]struct{}
	server  *Server
}

type wsClient struct {
	conn   *websocket.Conn
	send   chan []byte // text messages (JSON events/responses)
	binary chan []byte // binary messages (HVNC frames)
	hub    *wsHub
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		return isLocalhostOrigin(origin)
	},
}

func newWSHub(s *Server) *wsHub {
	return &wsHub{
		clients: make(map[*wsClient]struct{}),
		server:  s,
	}
}

// run subscribes to the global event bus and broadcasts enriched events to all WS clients.
func (h *wsHub) run() {
	go h.hvncFramePusher() // Dedicated goroutine — never blocked by slow event enrichment

	ch := events.Subscribe()
	defer events.Unsubscribe(ch)

	for evt := range ch {
		msg := h.enrichEvent(evt)
		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		h.broadcast(data)
	}
}

// hvncFramePusher reads complete frame data from FrameReady and pushes each
// frame as a binary WS message. Every frame is pushed (no seq dedup) so that
// burst arrivals from agent checkins are all delivered to the frontend.
func (h *wsHub) hvncFramePusher() {
	var pushCount, dropCount uint64
	statsTicker := time.NewTicker(2 * time.Second)
	defer statsTicker.Stop()

	for {
		select {
		case <-statsTicker.C:
			if pushCount > 0 || dropCount > 0 {
				slog.Info("hvncFramePusher stats", "pushed", pushCount, "dropped", dropCount, "clients", h.clientCount())
				pushCount = 0
				dropCount = 0
			}
		case frame, ok := <-hvnc.FrameReady:
			if !ok {
				return
			}
			if h.clientCount() == 0 {
				dropCount++
				continue
			}

			// Build binary frame: 16-byte agentID + 4-byte LE width + 4-byte LE height + JPEG
			agentBytes, _ := frame.AgentID.MarshalBinary()
			buf := make([]byte, 16+4+4+len(frame.Data))
			copy(buf[0:16], agentBytes)
			buf[16] = byte(frame.Width)
			buf[17] = byte(frame.Width >> 8)
			buf[18] = byte(frame.Width >> 16)
			buf[19] = byte(frame.Width >> 24)
			buf[20] = byte(frame.Height)
			buf[21] = byte(frame.Height >> 8)
			buf[22] = byte(frame.Height >> 16)
			buf[23] = byte(frame.Height >> 24)
			copy(buf[24:], frame.Data)

			h.broadcastBinary(buf)
			pushCount++
		}
	}
}


func (h *wsHub) broadcast(data []byte) {
	h.mu.Lock()
	clients := make([]*wsClient, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		select {
		case c.send <- data:
		default:
			// slow client — drop
			slog.Warn("WS: dropping slow client")
			h.removeClient(c)
		}
	}
}

// broadcastBinary sends a binary message to all connected WS clients.
// Used for HVNC frame streaming — drops frames for slow clients.
func (h *wsHub) broadcastBinary(data []byte) {
	h.mu.Lock()
	clients := make([]*wsClient, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		select {
		case c.binary <- data:
		default:
			// Drop frame for slow consumer (don't disconnect — just skip frame)
		}
	}
}

func (h *wsHub) addClient(c *wsClient) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	slog.Info("WS UI client connected", "clients", h.clientCount())
}

func (h *wsHub) removeClient(c *wsClient) {
	h.mu.Lock()
	h.removeClientLocked(c)
	h.mu.Unlock()
}

func (h *wsHub) removeClientLocked(c *wsClient) {
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
		close(c.binary)
	}
}

func (h *wsHub) clientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// ── Event enrichment ────────────────────────────────────────────────────────

func (h *wsHub) enrichEvent(evt events.Event) wsEvent {
	msg := wsEvent{Type: "event", Event: string(evt.Type)}

	switch evt.Type {
	case events.EventAgentCheckin:
		if p, ok := evt.Payload.(map[string]string); ok {
			if uid, err := uuid.Parse(p["agent_id"]); err == nil {
				if a, err := h.server.agentService.Agent(uid); err == nil {
					msg.Payload = AgentResponse{
						ID:          a.ID().String(),
						Platform:    a.Host().Platform + "/" + a.Host().Architecture,
						Host:        a.Host().Name,
						User:        a.Process().UserName,
						Process:     a.Process().Name,
						Status:      agentRealStatus(a.StatusCheckin(), a.Comms().Wait),
						Note:        a.Note(),
						Integrity:   a.Process().Integrity,
						Links:       uuidToStrings(a.Links()),
						LastCheckin: a.StatusCheckin().UTC().Format(time.RFC3339),
						Sleep:       a.Comms().Wait,
					}
				}
			}
		}
	case events.EventAgentRemoved:
		msg.Payload = evt.Payload
	case events.EventJobComplete:
		if p, ok := evt.Payload.(map[string]string); ok {
			agentIDStr := p["agent_id"]
			if uid, err := uuid.Parse(agentIDStr); err == nil {
				// Get latest jobs for this agent so we include the completed one with output
				table, err := h.server.jobService.GetTableActiveWithResults(uid)
				if err == nil {
					var jobs []JobResponse
					for _, row := range table {
						if len(row) >= 5 {
							j := JobResponse{
								ID:      row[0],
								AgentID: agentIDStr,
								Command: row[1],
								Status:  row[2],
								Created: row[3],
								Sent:    row[4],
							}
							if len(row) == 6 {
								j.Output = row[5]
							}
							jobs = append(jobs, j)
						}
					}
					msg.Payload = map[string]any{
						"agent_id": agentIDStr,
						"jobs":     jobs,
					}
				}
			}
		}
	case events.EventListenerStart, events.EventListenerStop:
		msg.Payload = evt.Payload
	default:
		msg.Payload = evt.Payload
	}

	return msg
}

// ── HTTP upgrade handler ────────────────────────────────────────────────────

// ServeWS upgrades an authenticated HTTP request to a WebSocket connection.
// Auth is already handled by AuthMiddleware (JWT via header or ?token= query param).
func (h *wsHub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WS upgrade failed", "error", err)
		return
	}

	client := &wsClient{
		conn:   conn,
		send:   make(chan []byte, 256),
		binary: make(chan []byte, 64), // HVNC frames — larger buffer for burst delivery
		hub:    h,
	}
	h.addClient(client)

	go client.writePump()
	go client.readPump()
}

// ── Client read/write pumps ─────────────────────────────────────────────────

const (
	wsPongWait   = 60 * time.Second
	wsPingPeriod = 30 * time.Second
	wsWriteWait  = 10 * time.Second
)

func (c *wsClient) readPump() {
	defer func() {
		c.hub.removeClient(c)
		c.conn.Close()
	}()
	c.conn.SetReadLimit(65536)
	c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Debug("WS read error", "error", err)
			}
			return
		}
		c.handleMessage(message)
	}
}

func (c *wsClient) writePump() {
	ticker := time.NewTicker(wsPingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case frame, ok := <-c.binary:
			if !ok {
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ── Action dispatch ─────────────────────────────────────────────────────────

func (c *wsClient) handleMessage(raw []byte) {
	var req wsRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		c.sendResponse(req.ID, false, nil, "invalid JSON")
		return
	}

	handler, ok := actionHandlers[req.Action]
	if !ok {
		c.sendResponse(req.ID, false, nil, fmt.Sprintf("unknown action: %s", req.Action))
		return
	}

	result, err := handler(c.hub, req.Payload)
	if err != nil {
		c.sendResponse(req.ID, false, nil, err.Error())
		return
	}
	c.sendResponse(req.ID, true, result, "")
}

func (c *wsClient) sendResponse(id string, success bool, payload any, errMsg string) {
	resp := wsResponse{
		ID:      id,
		Type:    "response",
		Success: success,
		Payload: payload,
		Error:   errMsg,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	select {
	case c.send <- data:
	default:
	}
}

// actionFunc processes a WS action and returns a response payload.
type actionFunc func(h *wsHub, payload map[string]any) (any, error)

var actionHandlers = map[string]actionFunc{
	// Queries
	"stats.get":          (*wsHub).handleStatsGet,
	"agents.list":        (*wsHub).handleAgentsList,
	"agents.get":         (*wsHub).handleAgentsGet,
	"jobs.list":          (*wsHub).handleJobsList,
	"jobs.clear":         (*wsHub).handleJobsClear,
	"listeners.list":     (*wsHub).handleListenersList,
	"listeners.options":  (*wsHub).handleListenersOptions,
	"credentials.list":   (*wsHub).handleCredentialsList,
	"screenshots.list":   (*wsHub).handleScreenshotsList,
	"screenshots.image":  (*wsHub).handleScreenshotsImage,
	"topology.get":       (*wsHub).handleTopologyGet,
	"pivots.list":        (*wsHub).handlePivotsList,
	// Mutations
	"job.create":        (*wsHub).handleJobCreate,
	"listener.create":   (*wsHub).handleListenerCreate,
	"listener.start":    (*wsHub).handleListenerStart,
	"listener.stop":     (*wsHub).handleListenerStop,
	"listener.delete":   (*wsHub).handleListenerDelete,
	"agent.delete":      (*wsHub).handleAgentDelete,
	"agent.note":        (*wsHub).handleAgentNote,
	"credential.create": (*wsHub).handleCredentialCreate,
	"credential.delete": (*wsHub).handleCredentialDelete,
	"pivot.create":      (*wsHub).handlePivotCreate,
	"pivot.delete":      (*wsHub).handlePivotDelete,
	"screenshot.create": (*wsHub).handleScreenshotCreate,
	"screenshot.delete": (*wsHub).handleScreenshotDelete,
	"hvnc.status":       (*wsHub).handleHvncStatus,
	"hvnc.start":        (*wsHub).handleHvncStart,
	"hvnc.stop":         (*wsHub).handleHvncStop,
	"hvnc.input":        (*wsHub).handleHvncInput,
	"hvnc.launch":       (*wsHub).handleHvncLaunch,
	"hvnc.quality":      (*wsHub).handleHvncQuality,
}

// ── Action handlers ─────────────────────────────────────────────────────────

func getString(p map[string]any, key string) string {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringSlice(p map[string]any, key string) []string {
	v, ok := p[key]
	if !ok {
		return nil
	}
	switch arr := v.(type) {
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return arr
	}
	return nil
}

func getStringMap(p map[string]any, key string) map[string]string {
	v, ok := p[key]
	if !ok {
		// Try treating the entire payload as the map (for listener.create)
		return nil
	}
	switch m := v.(type) {
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
		return out
	case map[string]string:
		return m
	}
	return nil
}

func (h *wsHub) handleJobCreate(payload map[string]any) (any, error) {
	agentIDStr := getString(payload, "agent_id")
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id: %s", agentIDStr)
	}
	jobType := getString(payload, "type")
	args := getStringSlice(payload, "args")

	result, err := h.server.jobService.Add(agentID, jobType, args)
	if err != nil {
		return nil, err
	}
	return map[string]string{"message": result}, nil
}

func (h *wsHub) handleListenerCreate(payload map[string]any) (any, error) {
	// The payload IS the options map
	options := make(map[string]string, len(payload))
	for k, v := range payload {
		if s, ok := v.(string); ok {
			options[k] = s
		}
	}

	listener, err := h.server.ls.NewListener(options)
	if err != nil {
		return nil, err
	}

	bindAddr := listener.Addr()
	if listener.Server() != nil {
		reqServer := *listener.Server()
		bindAddr = fmt.Sprintf("%s:%d", reqServer.Interface(), reqServer.Port())
	}

	resp := ListenerResponse{
		ID:          listener.ID().String(),
		Name:        listener.Name(),
		Protocol:    options["Protocol"],
		BindAddr:    bindAddr,
		Status:      listener.Status(),
		Description: listener.Description(),
	}

	// Publish event
	events.Publish(events.Event{
		Type:    events.EventListenerStart,
		Payload: map[string]string{"listener_id": listener.ID().String()},
	})

	return resp, nil
}

func (h *wsHub) handleListenerStart(payload map[string]any) (any, error) {
	uid, err := uuid.Parse(getString(payload, "id"))
	if err != nil {
		return nil, fmt.Errorf("invalid listener id")
	}
	if err := h.server.ls.Start(uid); err != nil {
		return nil, err
	}
	events.Publish(events.Event{
		Type:    events.EventListenerStart,
		Payload: map[string]string{"listener_id": uid.String()},
	})
	return map[string]string{"status": "started"}, nil
}

func (h *wsHub) handleListenerStop(payload map[string]any) (any, error) {
	uid, err := uuid.Parse(getString(payload, "id"))
	if err != nil {
		return nil, fmt.Errorf("invalid listener id")
	}
	if err := h.server.ls.Stop(uid); err != nil {
		return nil, err
	}
	events.Publish(events.Event{
		Type:    events.EventListenerStop,
		Payload: map[string]string{"listener_id": uid.String()},
	})
	return map[string]string{"status": "stopped"}, nil
}

func (h *wsHub) handleListenerDelete(payload map[string]any) (any, error) {
	uid, err := uuid.Parse(getString(payload, "id"))
	if err != nil {
		return nil, fmt.Errorf("invalid listener id")
	}
	if err := h.server.ls.Remove(uid); err != nil {
		return nil, err
	}
	events.Publish(events.Event{
		Type:    events.EventListenerStop,
		Payload: map[string]string{"listener_id": uid.String(), "deleted": "true"},
	})
	return map[string]string{"status": "deleted"}, nil
}

func (h *wsHub) handleAgentDelete(payload map[string]any) (any, error) {
	uid, err := uuid.Parse(getString(payload, "id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent id")
	}
	h.server.agentService.Remove(uid)
	h.server.pivotService.RemoveByAgent(uid)
	h.server.screenshotService.RemoveByAgent(uid)
	return map[string]string{"status": "removed"}, nil
}

func (h *wsHub) handleAgentNote(payload map[string]any) (any, error) {
	uid, err := uuid.Parse(getString(payload, "id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent id")
	}
	note := getString(payload, "note")
	if err := h.server.agentService.UpdateNote(uid, note); err != nil {
		return nil, err
	}
	return map[string]string{"status": "updated"}, nil
}

func (h *wsHub) handleCredentialCreate(payload map[string]any) (any, error) {
	agentID := uuid.Nil
	if s := getString(payload, "agent_id"); s != "" {
		if parsed, err := uuid.Parse(s); err == nil {
			agentID = parsed
		}
	}
	c := h.server.credService.Add(
		getString(payload, "domain"),
		getString(payload, "username"),
		getString(payload, "password"),
		getString(payload, "hash"),
		getString(payload, "source"),
		agentID,
	)
	return CredentialResponse{
		ID:       c.ID(),
		Domain:   c.Domain(),
		Username: c.Username(),
		Password: c.Password(),
		Hash:     c.Hash(),
		Source:   c.Source(),
		AgentID:  c.AgentID().String(),
		Created:  c.Created().String(),
	}, nil
}

func (h *wsHub) handleCredentialDelete(payload map[string]any) (any, error) {
	id := getString(payload, "id")
	if id == "" {
		return nil, fmt.Errorf("id required")
	}
	if err := h.server.credService.Remove(id); err != nil {
		return nil, err
	}
	return map[string]string{"status": "deleted"}, nil
}

// ── Query handlers ──────────────────────────────────────────────────────────

func (h *wsHub) handleStatsGet(_ map[string]any) (any, error) {
	return map[string]int{
		"agents":      len(h.server.agentService.Agents()),
		"listeners":   len(h.server.ls.Listeners()),
		"credentials": len(h.server.credService.GetAll()),
	}, nil
}

func (h *wsHub) handleAgentsList(_ map[string]any) (any, error) {
	var agents []AgentResponse
	for _, a := range h.server.agentService.Agents() {
		agents = append(agents, AgentResponse{
			ID:          a.ID().String(),
			Platform:    a.Host().Platform + "/" + a.Host().Architecture,
			Host:        a.Host().Name,
			User:        a.Process().UserName,
			Process:     a.Process().Name,
			Status:      agentRealStatus(a.StatusCheckin(), a.Comms().Wait),
			Alive:       a.Alive(),
			Note:        a.Note(),
			Integrity:   a.Process().Integrity,
			Links:       uuidToStrings(a.Links()),
			LastCheckin: a.StatusCheckin().UTC().Format(time.RFC3339),
			Sleep:       a.Comms().Wait,
		})
	}
	if agents == nil {
		agents = []AgentResponse{}
	}
	return agents, nil
}

func (h *wsHub) handleAgentsGet(payload map[string]any) (any, error) {
	uid, err := uuid.Parse(getString(payload, "id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent id")
	}
	a, err := h.server.agentService.Agent(uid)
	if err != nil {
		return nil, fmt.Errorf("agent not found")
	}
	return AgentResponse{
		ID:          a.ID().String(),
		Platform:    a.Host().Platform + "/" + a.Host().Architecture,
		Host:        a.Host().Name,
		User:        a.Process().UserName,
		Process:     a.Process().Name,
		Status:      agentRealStatus(a.StatusCheckin(), a.Comms().Wait),
		Alive:       a.Alive(),
		Note:        a.Note(),
		Integrity:   a.Process().Integrity,
		Links:       uuidToStrings(a.Links()),
		LastCheckin: a.StatusCheckin().UTC().Format(time.RFC3339),
		Sleep:       a.Comms().Wait,
	}, nil
}

func (h *wsHub) handleJobsList(payload map[string]any) (any, error) {
	uid, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}
	table, err := h.server.jobService.GetTableActiveWithResults(uid)
	if err != nil {
		return nil, err
	}
	var resp []JobResponse
	for _, row := range table {
		if len(row) >= 5 {
			j := JobResponse{
				ID:      row[0],
				AgentID: uid.String(),
				Command: row[1],
				Status:  row[2],
				Created: row[3],
				Sent:    row[4],
			}
			if len(row) == 6 {
				j.Output = row[5]
			}
			resp = append(resp, j)
		}
	}
	if resp == nil {
		resp = []JobResponse{}
	}
	return resp, nil
}

func (h *wsHub) handleJobsClear(payload map[string]any) (any, error) {
	uid, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}
	err = h.server.jobService.ClearCompleted(uid)
	if err != nil {
		return nil, err
	}
	return map[string]string{"status": "ok"}, nil
}

func (h *wsHub) handleListenersList(_ map[string]any) (any, error) {
	var listeners []ListenerResponse
	for _, l := range h.server.ls.Listeners() {
		bindAddr := l.Addr()
		proto := "Unknown"
		if l.Server() != nil {
			reqServer := *l.Server()
			bindAddr = fmt.Sprintf("%s:%d", reqServer.Interface(), reqServer.Port())
			proto = reqServer.ProtocolString()
		} else {
			proto = fmt.Sprintf("%d", l.Protocol())
		}
		listeners = append(listeners, ListenerResponse{
			ID:          l.ID().String(),
			Name:        l.Name(),
			Protocol:    proto,
			BindAddr:    bindAddr,
			Status:      l.Status(),
			Description: l.Description(),
		})
	}
	if listeners == nil {
		listeners = []ListenerResponse{}
	}
	return listeners, nil
}

func (h *wsHub) handleListenersOptions(payload map[string]any) (any, error) {
	proto := getString(payload, "protocol")
	if proto == "" {
		return nil, fmt.Errorf("protocol required")
	}
	options, err := h.server.ls.DefaultOptions(proto)
	if err != nil {
		return nil, err
	}
	return options, nil
}

func (h *wsHub) handleCredentialsList(_ map[string]any) (any, error) {
	creds := h.server.credService.GetAll()
	var resp []CredentialResponse
	for _, c := range creds {
		resp = append(resp, CredentialResponse{
			ID:       c.ID(),
			Domain:   c.Domain(),
			Username: c.Username(),
			Password: c.Password(),
			Hash:     c.Hash(),
			Source:   c.Source(),
			AgentID:  c.AgentID().String(),
			Created:  c.Created().String(),
		})
	}
	if resp == nil {
		resp = []CredentialResponse{}
	}
	return resp, nil
}

func (h *wsHub) handleScreenshotsList(_ map[string]any) (any, error) {
	var resp []ScreenshotResponse
	for _, sc := range h.server.screenshotService.GetAll() {
		resp = append(resp, ScreenshotResponse{
			ID:      sc.ID,
			AgentID: sc.AgentID.String(),
			Note:    sc.Note,
			Size:    len(sc.Data),
			Created: sc.Created.Format(time.RFC3339),
		})
	}
	if resp == nil {
		resp = []ScreenshotResponse{}
	}
	return resp, nil
}

func (h *wsHub) handleScreenshotsImage(payload map[string]any) (any, error) {
	id := getString(payload, "id")
	if id == "" {
		return nil, fmt.Errorf("id required")
	}
	sc, err := h.server.screenshotService.Get(id)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":   sc.ID,
		"data": base64.StdEncoding.EncodeToString(sc.Data),
	}, nil
}

func (h *wsHub) handleTopologyGet(_ map[string]any) (any, error) {
	resp := TopologyResponse{
		Nodes: make([]GraphNode, 0),
		Edges: make([]GraphEdge, 0),
	}

	tsID := "TEAMSERVER-CORE"
	resp.Nodes = append(resp.Nodes, GraphNode{
		ID:    tsID,
		Label: "Fox3 Teamserver",
		Group: "server",
	})

	listeners := h.server.ls.Listeners()
	for _, l := range listeners {
		lid := l.ID().String()
		proto := "Unknown"
		if l.Server() != nil {
			proto = (*l.Server()).ProtocolString()
		} else {
			proto = fmt.Sprintf("%d", l.Protocol())
		}
		resp.Nodes = append(resp.Nodes, GraphNode{
			ID:    lid,
			Label: fmt.Sprintf("[%s] %s", proto, l.Name()),
			Group: "listener",
		})
		resp.Edges = append(resp.Edges, GraphEdge{From: tsID, To: lid})
	}

	agents := h.server.agentService.Agents()
	for _, a := range agents {
		aid := a.ID().String()
		resp.Nodes = append(resp.Nodes, GraphNode{
			ID:        aid,
			Label:     fmt.Sprintf("%s (%s)", a.Host().Name, a.Host().Platform),
			Group:     "agent",
			Integrity: a.Process().Integrity,
			Status:    agentRealStatus(a.StatusCheckin(), a.Comms().Wait),
		})

		if h.server.agentService.IsChild(a.ID()) {
			parentID := uuid.Nil
			for _, p := range agents {
				for _, link := range p.Links() {
					if link == a.ID() {
						parentID = p.ID()
						break
					}
				}
				if parentID != uuid.Nil {
					break
				}
			}
			if parentID != uuid.Nil {
				resp.Edges = append(resp.Edges, GraphEdge{From: parentID.String(), To: aid})
				continue
			}
		}

		lid := a.Listener()
		if lid != uuid.Nil {
			resp.Edges = append(resp.Edges, GraphEdge{From: lid.String(), To: aid})
		} else {
			resp.Edges = append(resp.Edges, GraphEdge{From: tsID, To: aid})
		}
	}

	return resp, nil
}

func (h *wsHub) handlePivotsList(_ map[string]any) (any, error) {
	pivots := h.server.pivotService.GetAll()
	var resp []PivotResponse
	for _, p := range pivots {
		resp = append(resp, PivotResponse{
			ID:            p.ID,
			Name:          p.Name,
			ParentAgentID: p.ParentAgentID.String(),
			ChildAgentID:  p.ChildAgentID.String(),
			Protocol:      p.Protocol,
			Created:       p.Created.Format(time.RFC3339),
		})
	}
	if resp == nil {
		resp = []PivotResponse{}
	}
	return resp, nil
}

// ── Pivot mutations (moved from handlers_pivots.go) ─────────────────────────

func (h *wsHub) handlePivotCreate(payload map[string]any) (any, error) {
	parentID, err := uuid.Parse(getString(payload, "parent_agent_id"))
	if err != nil {
		return nil, err
	}
	childID, err := uuid.Parse(getString(payload, "child_agent_id"))
	if err != nil {
		return nil, err
	}
	proto := getString(payload, "protocol")
	if proto == "" {
		proto = "tcp"
	}
	name := getString(payload, "name")

	p := h.server.pivotService.Add(parentID, childID, proto, name)
	return PivotResponse{
		ID: p.ID, Name: p.Name,
		ParentAgentID: p.ParentAgentID.String(),
		ChildAgentID:  p.ChildAgentID.String(),
		Protocol:      p.Protocol,
		Created:       p.Created.Format(time.RFC3339),
	}, nil
}

func (h *wsHub) handlePivotDelete(payload map[string]any) (any, error) {
	id := getString(payload, "id")
	if id == "" {
		return nil, fmt.Errorf("id required")
	}
	if err := h.server.pivotService.Remove(id); err != nil {
		return nil, err
	}
	return map[string]string{"status": "deleted"}, nil
}

// ── Screenshot mutations (moved from handlers_screenshots.go) ───────────────

func (h *wsHub) handleScreenshotCreate(payload map[string]any) (any, error) {
	agentID, err := uuid.Parse(getString(payload, "agent_id"))
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id")
	}
	dataB64 := getString(payload, "data")
	if dataB64 == "" {
		return nil, fmt.Errorf("data (base64) required")
	}
	imgData, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 data: %w", err)
	}
	note := getString(payload, "note")

	sc := h.server.screenshotService.Add(agentID, imgData, note)
	return ScreenshotResponse{
		ID: sc.ID, AgentID: sc.AgentID.String(), Note: sc.Note,
		Size: len(sc.Data), Created: sc.Created.Format(time.RFC3339),
	}, nil
}

func (h *wsHub) handleScreenshotDelete(payload map[string]any) (any, error) {
	id := getString(payload, "id")
	if id == "" {
		return nil, fmt.Errorf("id required")
	}
	if err := h.server.screenshotService.Remove(id); err != nil {
		return nil, err
	}
	return map[string]string{"status": "deleted"}, nil
}
