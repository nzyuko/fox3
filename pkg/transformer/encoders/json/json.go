/*
Fox3 is a post-exploitation command and control framework.

This file is part of Fox3.
Copyright (C) 2024 Russel Van Tuyl

Fox3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Fox3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Fox3.  If not, see <http://www.gnu.org/licenses/>.
*/

// Package json encodes and decodes Agent messages using JSON.
// It replaces the gob encoder for cross-language agent compatibility.
package json

import (
	"encoding/json"
	"fmt"
	"log/slog"

	messages "github.com/nzyuko/fox3/v2/pkg/fox3-message"
	"github.com/nzyuko/fox3/v2/pkg/fox3-message/jobs"
	"github.com/nzyuko/fox3/v2/pkg/fox3-message/opaque"
)

// Encoder implements the transformer.Transformer interface using JSON serialization.
type Encoder struct{}

// NewEncoder returns a new JSON Encoder.
func NewEncoder() *Encoder { return &Encoder{} }

// String returns the transformer name used in the pipeline configuration string.
func (e *Encoder) String() string { return "json" }

// Construct serializes a messages.Base value to JSON bytes.
// The key parameter is unused — JSON carries no encryption.
func (e *Encoder) Construct(data any, key []byte) ([]byte, error) {
	msg, ok := data.(messages.Base)
	if !ok {
		return nil, fmt.Errorf("pkg/transformer/encoders/json.Construct(): expected messages.Base, got %T", data)
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("pkg/transformer/encoders/json.Construct(): %s", err)
	}
	return b, nil
}

// Deconstruct deserializes JSON bytes into a messages.Base.
// Because Payload is interface{}, a two-pass decode recovers the concrete type
// based on the message Type field.
func (e *Encoder) Deconstruct(data, key []byte) (any, error) {
	// First pass: capture Type and raw Payload bytes without allocating concrete types yet.
	var partial struct {
		Type    messages.Type   `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(data, &partial); err != nil {
		return nil, fmt.Errorf("pkg/transformer/encoders/json.Deconstruct(): first pass: %s", err)
	}

	// Second pass: decode the full Base (Payload lands as map[string]interface{}).
	var msg messages.Base
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("pkg/transformer/encoders/json.Deconstruct(): second pass: %s", err)
	}

	// Third pass: replace the generic Payload with the correct concrete type.
	if len(partial.Payload) > 0 && string(partial.Payload) != "null" {
		switch partial.Type {
		case messages.CHECKIN:
			var info messages.AgentInfo
			if err := json.Unmarshal(partial.Payload, &info); err == nil {
				msg.Payload = info
			}

		case messages.JOBS:
			var jobList []jobs.Job
			if err := json.Unmarshal(partial.Payload, &jobList); err != nil {
				return nil, fmt.Errorf("pkg/transformer/encoders/json.Deconstruct(): JOBS payload: %s", err)
			}
			// Each Job.Payload also needs concrete type recovery.
			for i := range jobList {
				if jobList[i].Payload == nil {
					continue
				}
				raw, err := json.Marshal(jobList[i].Payload)
				if err != nil {
					continue
				}
				jobList[i].Payload = decodeJobPayload(jobList[i].Type, raw)
			}
			msg.Payload = jobList

		case messages.OPAQUE:
			var o opaque.Opaque
			if err := json.Unmarshal(partial.Payload, &o); err != nil {
				return nil, fmt.Errorf("pkg/transformer/encoders/json.Deconstruct(): OPAQUE payload: %s", err)
			}
			msg.Payload = o
		}
	}

	return msg, nil
}

// decodeJobPayload re-decodes a job Payload from its intermediate map[string]interface{}
// representation into the correct concrete struct based on the job Type.
func decodeJobPayload(t jobs.Type, raw []byte) interface{} {
	switch t {
	case jobs.CMD, jobs.CONTROL, jobs.NATIVE, jobs.MODULE:
		var c jobs.Command
		if json.Unmarshal(raw, &c) == nil {
			return c
		}
	case jobs.SHELLCODE:
		var s jobs.Shellcode
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
	case jobs.FILETRANSFER:
		var f jobs.FileTransfer
		if json.Unmarshal(raw, &f) == nil {
			return f
		}
	case jobs.RESULT:
		var r jobs.Results
		if err := json.Unmarshal(raw, &r); err == nil {
			slog.Debug("decodeJobPayload: RESULT decoded", "stdout_len", len(r.Stdout), "stderr_len", len(r.Stderr))
			return r
		} else {
			slog.Warn("decodeJobPayload: RESULT unmarshal failed", "error", err, "raw", string(raw[:min(len(raw), 200)]))
		}
	case jobs.AGENTINFO:
		var ai messages.AgentInfo
		if json.Unmarshal(raw, &ai) == nil {
			return ai
		}
	case jobs.SOCKS:
		var so jobs.Socks
		if json.Unmarshal(raw, &so) == nil {
			return so
		}
	}
	// Fallback: return as generic map.
	var generic interface{}
	_ = json.Unmarshal(raw, &generic)
	return generic
}
