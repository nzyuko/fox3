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

// Package memory is an in-memory repository for storing and managing Agent Jobs and associated Job tracking structures
package memory

import (
	// Standard
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Fox3 Message
	jobs2 "github.com/nzyuko/fox3/v2/pkg/fox3-message/jobs"

	// Internal
	"github.com/nzyuko/fox3/v2/pkg/jobs"
)

// Repository is the structure that implements the in-memory repository for interacting with Agent Jobs
type Repository struct {
	sync.Mutex
	jobsChannel map[uuid.UUID]chan jobs2.Job // jobsChannel contains all outgoing Jobs that need to be sent to an Agent
	jobs        map[string]jobs.Info         // jobs is a map of all Job Info tracking structures
}

// repo is the in-memory datastore
var repo *Repository

// NewRepository creates and returns a new in-memory repository for interacting with Agent Jobs
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			Mutex:       sync.Mutex{},
			jobsChannel: make(map[uuid.UUID]chan jobs2.Job),
			jobs:        make(map[string]jobs.Info),
		}
	}
	return repo
}

// Add the Job and associated Info tracking structure to the repository
func (r *Repository) Add(job jobs2.Job, info jobs.Info) {
	r.Lock()
	ch, k := r.jobsChannel[job.AgentID]
	if !k {
		ch = make(chan jobs2.Job, 10000)
		r.jobsChannel[job.AgentID] = ch
	}
	r.jobs[job.ID] = info
	r.Unlock()

	// Send to channel OUTSIDE the lock — prevents blocking all agents if one channel is full
	ch <- job
}

// AddFast enqueues a job without creating an Info tracking structure.
// Used for high-throughput tunnel traffic (SOCKS, HVNC) where per-packet tracking is unnecessary.
func (r *Repository) AddFast(job jobs2.Job) {
	r.Lock()
	ch, k := r.jobsChannel[job.AgentID]
	if !k {
		ch = make(chan jobs2.Job, 10000)
		r.jobsChannel[job.AgentID] = ch
		slog.Debug("AddFast: created new channel", "agent", job.AgentID)
	}
	r.Unlock()

	// Non-blocking send: drop packet if channel is full (backpressure)
	select {
	case ch <- job:
		slog.Debug("AddFast: enqueued", "agent", job.AgentID, "type", job.Type)
	default:
		slog.Warn("AddFast: channel full, dropped", "agent", job.AgentID)
	}
}

// Clear removes all Jobs that have not already been sent to the associated Agent
func (r *Repository) Clear(agentID uuid.UUID) error {
	r.Lock()
	defer r.Unlock()
	jobChannel, ok := r.jobsChannel[agentID]
	if !ok {
		return fmt.Errorf("pkg/jobs/memory.Get(): a channel key for Agent %s does not exist", agentID)
	}

	jobLength := len(jobChannel)
	if jobLength > 0 {
		// Empty the job channel
		for i := 0; i < jobLength; i++ {
			job := <-jobChannel
			// Update Job Info structure
			j, ok := r.jobs[job.ID]
			if ok {
				j.Cancel()
				r.jobs[job.ID] = j
			} else {
				return fmt.Errorf("invalid job %s for agent %s", job.ID, agentID)
			}
		}
	}
	return nil
}

// ClearAll removes all Jobs that have not already been sent for ALL Agents
func (r *Repository) ClearAll() error {
	for id := range r.jobsChannel {
		err := r.Clear(id)
		if err != nil {
			return fmt.Errorf("pkg/jobs/memory.ClearAll(): %s", err)
		}
	}
	return nil
}

// GetAll returns all Job Info tracking structures as map to be iterated over
func (r *Repository) GetAll() map[string]jobs.Info {
	r.Lock()
	defer r.Unlock()
	cp := make(map[string]jobs.Info, len(r.jobs))
	for k, v := range r.jobs {
		cp[k] = v
	}
	return cp
}

// GetInfo returns the Job Info tracking structure for the associate Job ID
func (r *Repository) GetInfo(jobID string) (jobs.Info, error) {
	info, ok := r.jobs[jobID]
	if !ok {
		return info, fmt.Errorf("pkg/jobs/memory.GetInfo(): unable to find structure for job %s", jobID)
	}
	return info, nil
}

// GetJobs returns all jobs waiting to be sent to the associated Agent
func (r *Repository) GetJobs(agentID uuid.UUID) (retJobs []jobs2.Job, err error) {
	r.Lock()
	defer r.Unlock()
	jobChannel, ok := r.jobsChannel[agentID]
	if !ok {
		// No jobs queued for this agent yet
		slog.Debug("GetJobs: no channel", "agent", agentID, "channels", len(r.jobsChannel))
		return
	}

	// If there are any jobs in the channel, return them
	jobLength := len(jobChannel)
	if jobLength > 0 {
		slog.Debug("GetJobs: draining", "agent", agentID, "count", jobLength)
		for i := 0; i < jobLength; i++ {
			job := <-jobChannel
			retJobs = append(retJobs, job)

			// Update Job Info map (may not exist for AddFast tunnel jobs)
			info, exists := r.jobs[job.ID]
			if exists {
				info.Send()
				r.jobs[job.ID] = info
			}
		}
	} else {
		slog.Debug("GetJobs: channel empty", "agent", agentID)
	}
	return
}

// UpdateInfo replaces the Job Info tracking structure with the one provided
func (r *Repository) UpdateInfo(info jobs.Info) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.jobs[info.ID()]; !ok {
		return fmt.Errorf("pkg/jobs/memory.UpdateInfo(): unable to find structure for job %s", info.ID())
	}
	r.jobs[info.ID()] = info
	return nil
}

// UpdateOutput stores job output in the in-memory Info struct.
func (r *Repository) UpdateOutput(jobID string, output string) error {
	r.Lock()
	defer r.Unlock()
	info, ok := r.jobs[jobID]
	if !ok {
		return nil
	}
	info.SetOutput(output)
	r.jobs[jobID] = info
	return nil
}

// ClearCompleted removes all completed/returned jobs for the given agent from the repository.
func (r *Repository) ClearCompleted(agentID uuid.UUID) error {
	r.Lock()
	defer r.Unlock()
	for id, info := range r.jobs {
		if info.AgentID() != agentID {
			continue
		}
		if info.Status() == jobs.COMPLETE || info.Status() == jobs.RETURNED || info.Status() == jobs.CANCELED {
			delete(r.jobs, id)
		}
	}
	return nil
}

// GetCompletedRows returns recently completed jobs with output for a given agent.
func (r *Repository) GetCompletedRows(agentID uuid.UUID, limit int) ([][]string, error) {
	r.Lock()
	defer r.Unlock()

	type entry struct {
		id      string
		info    jobs.Info
		created time.Time
	}
	var completed []entry
	for id, info := range r.jobs {
		if info.AgentID() != agentID {
			continue
		}
		if info.Status() != jobs.COMPLETE && info.Status() != jobs.RETURNED {
			continue
		}
		completed = append(completed, entry{id: id, info: info, created: info.Created()})
	}

	// Sort newest first
	sort.Slice(completed, func(i, j int) bool {
		return completed[i].created.After(completed[j].created)
	})

	if limit > 0 && len(completed) > limit {
		completed = completed[:limit]
	}

	var rows [][]string
	for _, e := range completed {
		var sent string
		var zeroTime time.Time
		if e.info.Sent() != zeroTime {
			sent = e.info.Sent().Format(time.RFC3339)
		}
		row := []string{
			e.id,
			e.info.Command(),
			"Complete",
			e.info.Created().Format(time.RFC3339),
			sent,
		}
		if e.info.Output() != "" {
			row = append(row, e.info.Output())
		}
		rows = append(rows, row)
	}
	return rows, nil
}
