/*
Fox3 is a post-exploitation command and control framework.

This file is part of Fox3.
Copyright (C) 2023 Russel Van Tuyl

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

// Package jobs holds the structures for Agent jobs
package jobs

import (
	// Standard
	"encoding/gob"

	// 3rd Party
	"github.com/google/uuid"
)

// init registers message types with gob that are an interface for Base.Payload
func init() {
	gob.Register([]Job{})
	gob.Register(Command{})
	gob.Register(Shellcode{})
	gob.Register(FileTransfer{})
	gob.Register(Results{})
	gob.Register(Socks{})
}

// Type is a type for job type constants
type Type int

const (
	// UNDEFINED is the default value when a Type was not set
	UNDEFINED Type = iota

	/* To Agent */

	// CMD is used to send CmdPayload messages
	CMD // CmdPayload
	// CONTROL is used to send AgentControl messages
	CONTROL // AgentControl
	// SHELLCODE is used to send shellcode messages
	SHELLCODE // Shellcode
	// NATIVE is used to send NativeCmd messages
	NATIVE // NativeCmd
	// FILETRANSFER is used to send FileTransfer messages for upload/download operations
	FILETRANSFER // FileTransfer
	// OK is used to signify that there is nothing to do, or to idle
	OK // ServerOK
	// MODULE is used to send Module messages
	MODULE // Module
	// SOCKS is used for SOCKS5 traffic between the server and agent
	SOCKS // SOCKS

	/* FROM AGENT */

	// RESULT is used by the Agent to return a result message
	RESULT
	// AGENTINFO is used by the Agent to return information about its configuration
	AGENTINFO
)

// Job is used to task an agent to run a command
type Job struct {
	AgentID uuid.UUID   // ID of the agent the job belongs to
	ID      string      // Unique identifier for each job
	Token   uuid.UUID   // A unique token for each task that acts like a CSRF token to prevent multiple job messages
	Type    Type        // The type of job it is (e.g., FileTransfer
	Payload interface{} // Embedded messages of various types
}

// Command is the structure to send a task for the agent to execute
type Command struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// Shellcode is a JSON payload containing shellcode and the method for execution
type Shellcode struct {
	Method string `json:"method"`
	Bytes  string `json:"bytes"`         // Base64 string of shellcode bytes
	PID    uint32 `json:"pid,omitempty"` // Process ID for remote injection
}

// FileTransfer is the JSON payload to transfer files between the server and agent
type FileTransfer struct {
	FileLocation string `json:"dest"`
	FileBlob     string `json:"blob"`
	IsDownload   bool   `json:"download"`
}

// Results is a JSON payload that contains the results of an executed command from an agent
type Results struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// Socks is used to transfer data from a SOCKS client through the server to the agent and back
type Socks struct {
	ID    uuid.UUID `json:"id"`
	Index int       `json:"index"`
	Data  []byte    `json:"data"`
	Close bool      `json:"close"`
}

func (t Type) String() string {
	switch t {
	case CMD:
		return "CMDPayload"
	case CONTROL:
		return "AgentControl"
	case SHELLCODE:
		return "Shellcode"
	case NATIVE:
		return "NativePayload"
	case FILETRANSFER:
		return "FileTransfer"
	case OK:
		return "OK"
	case MODULE:
		return "Module"
	case SOCKS:
		return "SOCKS"
	case RESULT:
		return "Result"
	case AGENTINFO:
		return "AgentInfo"
	case UNDEFINED:
		return "UNDEFINED"
	default:
		return "UNDEFINED"
	}
}

// IntToType converts an integer to a Type
// Used with third-party clients to convert to a Fox3 message
func IntToType(job int) Type {
	switch job {
	case 0:
		return UNDEFINED
	case 1:
		return CMD
	case 2:
		return CONTROL
	case 3:
		return SHELLCODE
	case 4:
		return NATIVE
	case 5:
		return FILETRANSFER
	case 6:
		return OK
	case 7:
		return MODULE
	case 8:
		return SOCKS
	case 9:
		return RESULT
	case 10:
		return AGENTINFO
	default:
		return UNDEFINED
	}
}
