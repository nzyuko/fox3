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

// Package push provides a registry that allows the job service to signal active WSS connections
// when new jobs are queued, enabling true server-push without waiting for the agent to poll.
package push

import (
	"sync"

	"github.com/google/uuid"
)

// wssChannels maps an agent UUID to a buffered signal channel owned by its active WSS handler.
var wssChannels sync.Map

// Register associates a signal channel with an agent's WSS session.
// Called by handleWSS when a WebSocket connection is established.
func Register(id uuid.UUID, ch chan struct{}) {
	wssChannels.Store(id, ch)
}

// Unregister removes the signal channel when the WSS session ends.
func Unregister(id uuid.UUID) {
	wssChannels.Delete(id)
}

// Notify delivers a non-blocking signal to the agent's WSS push goroutine.
// If the channel is already full the signal is dropped — the goroutine will
// drain any queued jobs on the next iteration anyway.
func Notify(id uuid.UUID) {
	if v, ok := wssChannels.Load(id); ok {
		select {
		case v.(chan struct{}) <- struct{}{}:
		default:
		}
	}
}
