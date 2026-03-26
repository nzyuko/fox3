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

// Package rsa holds the structures to perform RSA key exchange and authentication
package rsa

// Request used by the client to send the server it's an RSA public key
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin#eke-by-generating-client-side-rsa-keys
type Request struct {
	Action    string `json:"action"`     // staging_rsa
	PubKey    string `json:"pub_key"`    // base64 of public RSA key
	SessionID string `json:"session_id"` // 20 character string; unique session ID for this callback
	Padding   string `json:"padding,omitempty"`
}

// Response contains the derived session key encrypted with the agent's RSA key
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin#eke-by-generating-client-side-rsa-keys
type Response struct {
	Action     string `json:"action"`      // staging_rsa
	ID         string `json:"uuid"`        // new UUID for the next message
	SessionKey string `json:"session_key"` // Base64( RSAPub( new aes session key ) )
	SessionID  string `json:"session_id"`  // same 20 char string back
}
