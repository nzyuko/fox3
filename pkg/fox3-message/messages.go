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

// Package messages contain message structures used to communicate with Agents
package messages

import (
	// Standard
	"encoding/gob"
	"fmt"

	// 3rd Party
	"github.com/google/uuid"
)

// init registers message types with gob that are an interface for Base.Payload
func init() {
	gob.Register(Base{})
	gob.Register(Delegate{})
	gob.Register(AgentInfo{})
	gob.Register(SysInfo{})
}

// Type is a type for message constants
type Type int

const (
	// UNDEFINED is the default value when a Type was not set
	UNDEFINED Type = iota
	// CHECKIN is used by the Agent to identify that it is checking in with the server
	CHECKIN
	// OPAQUE is used to denote that embedded message contains an opaque structure
	OPAQUE
	// JOBS is used to denote that the embedded message contains a list of job structures
	JOBS
	// IDLE is used to notify the Agent that the server has no tasks and that the Agent should idle
	IDLE
	// KEYEXCHANGE is used to exchange encryption keys between the Agent and the server
	// This Type is used with Mythic's HTTP profile
	KEYEXCHANGE
)

// Base is the root, or outermost, message structure
// The Type field indicates what kind of message is contained in the Payload field
type Base struct {
	ID        uuid.UUID   `json:"id"`                 // ID is a unique identifier for the message
	Type      Type        `json:"type"`               // Type indicates what kind of message is contained in the Payload field (e.g. CHECKIN, JOBS, etc.)
	Payload   interface{} `json:"payload,omitempty"`  // Payload holds embedded messages (e.g. KeyExchange, AgentInfo, etc.)
	Padding   string      `json:"padding"`            // Padding is used to obfuscate and randomize the message size
	Token     string      `json:"token,omitempty"`    // Token is a JWT used to authenticate the Agent to the server
	Delegates []Delegate  `json:"delegate,omitempty"` // Delegates is a list of Delegate structures used for peer-to-peer communications
}

// Delegate used with peer-to-peer communications and embedded in Base messages
type Delegate struct {
	Listener  uuid.UUID  `json:"listener"`            // Listener is the UUID of the listener that will encode/decode the message
	Agent     uuid.UUID  `json:"agent"`               // Agent the UUID of the agent that the message is for
	Payload   []byte     `json:"payload,omitempty"`   // Payload is an embedded Base message encoded/encrypted for a child agent
	Delegates []Delegate `json:"delegates,omitempty"` // Delegates is a recursive field to support nested linked agents
}

// SysInfo contains information about the system where the agent is running
type SysInfo struct {
	Platform     string   `json:"platform,omitempty"`     // Platform is the operating system platform (e.g. Windows, Linux, etc.)
	Architecture string   `json:"architecture,omitempty"` // Architecture is the operating system architecture (e.g. x86, x64, etc.)
	UserName     string   `json:"username,omitempty"`     // UserName is the name of the user that the agent is running as
	UserGUID     string   `json:"userguid,omitempty"`     // UserGUID is the GUID of the user that the agent is running as
	Integrity    int      `json:"integrity,omitempty"`    // Integrity is the integrity level of the agent process
	HostName     string   `json:"hostname,omitempty"`     // HostName is the hostname of the system where the agent is running
	Process      string   `json:"process,omitempty"`      // Process is the name of the process the agent is running in
	Pid          int      `json:"pid,omitempty"`          // Pid is the process ID the agent is running in
	Ips          []string `json:"ips,omitempty"`          // Ips is a list of network interfaces on the system where the agent is running
	Domain       string   `json:"domain,omitempty"`       // Domain is the domain name of the user running the agent
}

// AgentInfo contains information about the agent and its configuration
type AgentInfo struct {
	Version       string  `json:"version,omitempty"`       // Version is the version of the agent
	Build         string  `json:"build,omitempty"`         // Build is the build number of the agent
	WaitTime      string  `json:"waittime,omitempty"`      // WaitTime is the time between agent checkins
	PaddingMax    int     `json:"paddingmax,omitempty"`    // PaddingMax is the maximum amount of padding to use in messages
	MaxRetry      int     `json:"maxretry,omitempty"`      // MaxRetry is the maximum number of times to retry a failed checkin before killing the agent
	FailedCheckin int     `json:"failedcheckin,omitempty"` // FailedCheckin is the number of failed checkins in a row that are allowed before killing
	Skew          int64   `json:"skew,omitempty"`          // Skew is the maximum amount of variance used to randomize the WaitTime
	Proto         string  `json:"proto,omitempty"`         // Proto is the communication protocol used to talk with the server
	SysInfo       SysInfo `json:"sysinfo,omitempty"`       // SysInfo is a SysInfo structure containing information about the system where the agent is running
	KillDate      int64   `json:"killdate,omitempty"`      // KillDate is the Unix Epoch date/time that the agent will kill itself
	JA3           string  `json:"ja3,omitempty"`           // JA3 is the JA3 fingerprint of the agent
}

// String returns the text representation of a message constant
func (t Type) String() string {
	switch t {
	case UNDEFINED:
		return "Undefined"
	case CHECKIN:
		return "StatusCheckIn"
	case JOBS:
		return "Jobs"
	case OPAQUE:
		return "OPAQUE"
	case IDLE:
		return "Idle"
	case KEYEXCHANGE:
		return "KeyExchange"
	default:
		return fmt.Sprintf("Invalid: %d", t)
	}
}
