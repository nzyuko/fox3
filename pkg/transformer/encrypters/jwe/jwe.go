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

// Package jwe encrypts/decrypts Agent messages to/from JSON Web Encryption compact serialization format
package jwe

import (
	// Standard
	"fmt"

	// 3rd Party
	"github.com/go-jose/go-jose/v3"
)

type Encrypter struct {
}

// NewEncrypter is a factory to return a structure that implements the Transformer interface
func NewEncrypter() *Encrypter {
	return &Encrypter{}
}

// Construct encrypts data using direct key agreement (dir) with AES-256-GCM.
// The key is sha256(PSK). Returns JWE compact serialization.
func (e *Encrypter) Construct(data any, key []byte) ([]byte, error) {
	switch data.(type) {
	case []uint8:
		return e.encrypt(data.([]byte), key)
	default:
		return nil, fmt.Errorf("pkg/encrypters/jwe unhandled data type for Construct(): %T", data)
	}
}

// Deconstruct takes in a JSON Web Encryption (JWE) object in the compact serialization format as bytes, decrypts it,
// and returns it that data as bytes
func (e *Encrypter) Deconstruct(data, key []byte) (any, error) {
	// Parse JWE string back into JSONWebEncryption
	jwe, err := jose.ParseEncrypted(string(data))
	if err != nil {
		return nil, fmt.Errorf("there was an error parseing the JWE string into a JSONWebEncryption object: %s", err)
	}

	// Decrypt the JWE
	return jwe.Decrypt(key)
}

// encrypt encrypts data using dir+A256GCM and returns JWE compact serialization.
func (e *Encrypter) encrypt(data, key []byte) ([]byte, error) {
	//   Keys used with AES GCM must follow the constraints in Section 8.3 of
	//   [NIST.800-38D], which states: "The total number of invocations of the
	//   authenticated encryption function shall not exceed 2^32, including
	//   all IV lengths and all instances of the authenticated encryption
	//   function with the given key".  In accordance with this rule, AES GCM
	//   MUST NOT be used with the same key value more than 2^32 times. == 4294967296

	enc, err := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT, // Direct key agreement — no PBKDF2, fast for interactive tunnels
			Key:       key},
		nil)
	if err != nil {
		return nil, fmt.Errorf("there was an error creating the JWE encryptor:\r\n%s", err)
	}

	// Encrypt the data into a JWE
	jwe, err := enc.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("there was an error encrypting the Authentication JSON object to a JWE object:\r\n%s", err)
	}

	// Serialize the data into a string
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("there was an error serializing the JWE in compact format:\r\n%s", err)
	}

	return []byte(serialized), nil
}

// String returns a string representation of the encrypter type
func (e *Encrypter) String() string {
	return "jwe"
}
