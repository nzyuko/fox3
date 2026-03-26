// Package rportfwd implements reverse (remote) TCP port-forwarding through Fox3 agents.
//
// The agent listens on a port on the target network. When a remote client
// connects, the agent relays data back through the C2 channel. The server
// then connects to a configured forward host:port and bridges the two streams.
//
// Unlike local port forward (portfwd), where the server binds a local port,
// rportfwd sends a job to the agent instructing it to bind a port. Data flows:
//
//	remote client → agent(listen port) → C2 → server → forward host:port
//
// The agent uses the same jobs.SOCKS job type with a synthetic SOCKS5 handshake,
// but the agent initiates connections rather than receiving them.

package rportfwd

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	fox3Job "github.com/nzyuko/fox3/v2/pkg/fox3-message/jobs"
)

// ── Per-channel state ────────────────────────────────────────────────────────

type rChan struct {
	agentID uuid.UUID
	conn    net.Conn // outbound TCP connection to the forward target
	sendIdx int      // next index going to the agent
	recvIdx int      // next expected index from the agent
	jobID   string
	token   uuid.UUID
	pending map[int][]byte
	mu      sync.Mutex
}

// ── Module state ─────────────────────────────────────────────────────────────

// channels tracks active reverse port-forward channels keyed by connection UUID.
var channels sync.Map

// forwardTargets maps agent UUID → "host:port" the server should connect to.
var forwardTargets sync.Map

// JobsOut is read by the job service to deliver rportfwd data to the agent.
var JobsOut = make(chan fox3Job.Job, 1000)

// Parse handles rportfwd_start / rportfwd_stop commands from the operator.
//
// rportfwd_start args:
//
//	agent         – UUID of target agent
//	command       – "start" or "stop"
//	listen-port   – port the agent should listen on
//	forward-host  – host the server connects to when data arrives
//	forward-port  – port on the forward host
//
// rportfwd_stop args:
//
//	agent, command
func Parse(options map[string]string) ([]string, error) {
	for _, key := range []string{"agent", "command"} {
		if _, ok := options[key]; !ok {
			return nil, fmt.Errorf("rportfwd: the %q option is required", key)
		}
	}

	agentID, err := uuid.Parse(options["agent"])
	if err != nil {
		return nil, fmt.Errorf("rportfwd: invalid agent UUID: %s", err)
	}

	switch options["command"] {
	case "start":
		return startRFwd(agentID, options)
	case "stop":
		return stopRFwd(agentID)
	default:
		return nil, fmt.Errorf("rportfwd: unknown command %q", options["command"])
	}
}

func startRFwd(agentID uuid.UUID, opts map[string]string) ([]string, error) {
	for _, key := range []string{"listen-port", "forward-host", "forward-port"} {
		if _, ok := opts[key]; !ok {
			return nil, fmt.Errorf("rportfwd start: the %q option is required", key)
		}
	}

	target := fmt.Sprintf("%s:%s", opts["forward-host"], opts["forward-port"])
	forwardTargets.Store(agentID, target)

	msg := fmt.Sprintf("Reverse port forward configured for agent %s: agent listens :%s → server connects %s",
		agentID, opts["listen-port"], target)
	return []string{msg}, nil
}

func stopRFwd(agentID uuid.UUID) ([]string, error) {
	forwardTargets.Delete(agentID)

	// Close any active channels for this agent
	channels.Range(func(k, v interface{}) bool {
		ch := v.(*rChan)
		if ch.agentID == agentID {
			if ch.conn != nil {
				ch.conn.Close()
			}
			channels.Delete(k)
		}
		return true
	})

	return []string{fmt.Sprintf("Reverse port forward stopped for agent %s", agentID)}, nil
}

// CleanupAgent tears down all reverse port-forward resources for a removed agent.
func CleanupAgent(agentID uuid.UUID) {
	_, _ = stopRFwd(agentID)
}

// IsKnown returns true if id is a tracked rportfwd channel.
func IsKnown(id uuid.UUID) bool {
	_, ok := channels.Load(id)
	return ok
}

// In processes an incoming jobs.SOCKS job from the agent for a reverse port-forward channel.
// The agent sends SOCKS5-framed data: greeting (index 0), CONNECT with target info (index 1),
// then raw data (index 2+). The server connects to the forward target on the CONNECT phase.
func In(job fox3Job.Job) {
	sp, ok := job.Payload.(fox3Job.Socks)
	if !ok {
		slog.Error("rportfwd.In: unexpected job payload type, expected Socks")
		return
	}
	chanID := sp.ID

	// ── New channel: agent accepted a remote connection ──────────────────
	v, exists := channels.Load(chanID)
	if !exists {
		if sp.Close {
			return
		}
		ch := &rChan{
			agentID: job.AgentID,
			jobID:   job.ID,
			token:   job.Token,
			pending: make(map[int][]byte),
		}
		channels.Store(chanID, ch)
		v = ch
	}
	ch := v.(*rChan)

	ch.mu.Lock()
	defer ch.mu.Unlock()

	// Buffer out-of-order
	if sp.Index != ch.recvIdx {
		ch.pending[sp.Index] = append([]byte(nil), sp.Data...)
		return
	}

	curData := sp.Data
	curClose := sp.Close

	for {
		ch.recvIdx++

		if curClose {
			if ch.conn != nil {
				ch.conn.Close()
			}
			channels.Delete(chanID)
			return
		}

		switch ch.recvIdx {
		case 1:
			// Agent sent SOCKS5 greeting — reply with no-auth
			sendReply(chanID, ch, []byte{0x05, 0x00})

		case 2:
			// Agent sent CONNECT request — look up forward target and connect
			target, ok := forwardTargets.Load(ch.agentID)
			if !ok {
				// No target configured — reject
				sendReply(chanID, ch, []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				channels.Delete(chanID)
				return
			}
			conn, err := net.DialTimeout("tcp", target.(string), 10*time.Second)
			if err != nil {
				slog.Error("rportfwd: failed to connect to forward target", "target", target, "error", err)
				sendReply(chanID, ch, []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				channels.Delete(chanID)
				return
			}
			ch.conn = conn
			// Success reply
			sendReply(chanID, ch, []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			// Spawn reader from forward target back to agent
			go readForwardTarget(chanID, ch)

		default:
			// Data phase — write to forward target
			if ch.conn != nil && len(curData) > 0 {
				if _, err := ch.conn.Write(curData); err != nil {
					slog.Error("rportfwd: write to forward target failed", "id", chanID, "error", err)
					ch.conn.Close()
					channels.Delete(chanID)
					return
				}
			}
		}

		// Drain buffered
		if next, ok := ch.pending[ch.recvIdx]; ok {
			delete(ch.pending, ch.recvIdx)
			curData = next
			curClose = false
		} else {
			break
		}
	}
}

func sendReply(chanID uuid.UUID, ch *rChan, data []byte) {
	idx := ch.sendIdx
	ch.sendIdx++
	JobsOut <- fox3Job.Job{
		AgentID: ch.agentID,
		Type:    fox3Job.SOCKS,
		Payload: fox3Job.Socks{ID: chanID, Index: idx, Data: data},
		ID:      ch.jobID,
		Token:   ch.token,
	}
}

func readForwardTarget(chanID uuid.UUID, ch *rChan) {
	buf := make([]byte, 32768)
	for {
		n, err := ch.conn.Read(buf)

		ch.mu.Lock()
		idx := ch.sendIdx
		ch.sendIdx++
		ch.mu.Unlock()

		sp := fox3Job.Socks{ID: chanID, Index: idx}
		if n > 0 {
			sp.Data = append([]byte(nil), buf[:n]...)
		}
		if err != nil {
			sp.Close = true
		}

		JobsOut <- fox3Job.Job{
			AgentID: ch.agentID,
			Type:    fox3Job.SOCKS,
			Payload: sp,
			ID:      ch.jobID,
			Token:   ch.token,
		}

		if err != nil {
			if err != io.EOF {
				slog.Debug("rportfwd: forward target read error", "id", chanID, "error", err)
			}
			channels.Delete(chanID)
			return
		}
	}
}
