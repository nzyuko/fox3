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

package jobs

import (
	// 3rd Party
	"github.com/google/uuid"

	// Fox3 Message
	jobs2 "github.com/nzyuko/fox3/v2/pkg/fox3-message/jobs"
)

type Repository interface {
	// Add the Job and associated Info tracking structure to the repository
	Add(job jobs2.Job, info Info)
	// AddFast enqueues a job without Info tracking (high-throughput tunnel traffic)
	AddFast(job jobs2.Job)
	// Clear removes all Jobs that have not already been sent to the associated Agent
	Clear(agentID uuid.UUID) error
	// ClearAll removes all Jobs that have not already been sent for ALL Agents
	ClearAll() error
	// GetAll returns all Job Info tracking structures as map to be iterated over
	GetAll() map[string]Info
	// GetInfo returns the Job Info tracking structure for the associate Job ID
	GetInfo(jobID string) (Info, error)
	// GetJobs returns all jobs waiting to be sent to the associated Agent
	GetJobs(agentID uuid.UUID) ([]jobs2.Job, error)
	// UpdateInfo replaces the Job Info tracking structure with the one provided
	UpdateInfo(info Info) error
	// UpdateOutput stores the job result output text in the repository
	UpdateOutput(jobID string, output string) error
	// GetCompletedRows returns recently completed jobs for an agent, newest first.
	GetCompletedRows(agentID uuid.UUID, limit int) ([][]string, error)
	// ClearCompleted removes all completed/returned jobs for the given agent from the repository
	ClearCompleted(agentID uuid.UUID) error
}
