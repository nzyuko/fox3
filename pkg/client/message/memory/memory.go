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

// Package memory provides an in-memory repository for messages
package memory

import (
	// Standard
	"fmt"
	"sync"

	// 3rd Party
	"github.com/google/uuid"

	// Internal
	"github.com/nzyuko/fox3/v2/pkg/client/message"
)

// Repository is the in-memory data structure to store messages
type Repository struct {
	messages map[uuid.UUID]*message.Message
	queue    chan *message.Message
	sync.Mutex
}

// repo is the single in-memory instantiation of the Repository
var repo *Repository

// NewRepository is a factory that returns an instantiated in-memory repository
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			messages: make(map[uuid.UUID]*message.Message),
			queue:    make(chan *message.Message, 100),
		}
	}
	return repo
}

// Add stores a message in the Repository
func (r *Repository) Add(message *message.Message) {
	r.Lock()
	r.messages[message.ID()] = message
	// Non-blocking send: drop message if queue is full to prevent deadlock
	// (channel send while holding mutex would block all operations)
	select {
	case r.queue <- message:
	default:
	}
	r.Unlock()
}

// Get retrieves a message by its ID
func (r *Repository) Get(id uuid.UUID) (msg *message.Message, err error) {
	r.Lock()
	defer r.Unlock()
	var ok bool
	msg, ok = r.messages[id]
	if !ok {
		err = fmt.Errorf("pkg/client/message/memory: message with id %s was not found in the repository", id)
	}
	return
}

// GetAll returns all messages
func (r *Repository) GetAll() (messages []*message.Message) {
	r.Lock()
	defer r.Unlock()
	for _, msg := range r.messages {
		messages = append(messages, msg)
	}
	return
}

// GetQueue returns a channel to recieve messages from
func (r *Repository) GetQueue() *message.Message {
	return <-r.queue
}
