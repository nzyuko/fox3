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

// Package transformer provides encoding and encryption methods to transform Agent messages
package transformer

import (
	"fmt"
	"strings"

	b64 "github.com/nzyuko/fox3/v2/pkg/transformer/encoders/base64"
	"github.com/nzyuko/fox3/v2/pkg/transformer/encoders/gob"
	"github.com/nzyuko/fox3/v2/pkg/transformer/encoders/hex"
	jsonEncoder "github.com/nzyuko/fox3/v2/pkg/transformer/encoders/json"
	"github.com/nzyuko/fox3/v2/pkg/transformer/encrypters/aes"
	"github.com/nzyuko/fox3/v2/pkg/transformer/encrypters/jwe"
	"github.com/nzyuko/fox3/v2/pkg/transformer/encrypters/rc4"
	"github.com/nzyuko/fox3/v2/pkg/transformer/encrypters/xor"
)

type Transformer interface {
	Construct(data any, key []byte) ([]byte, error)
	Deconstruct(data, key []byte) (any, error)
	String() string
}

// BuildPipeline takes a comma-separated list of transform names and returns
// the corresponding ordered slice of Transformer implementations.
func BuildPipeline(pipeline string) ([]Transformer, error) {
	if strings.TrimSpace(pipeline) == "" {
		return nil, nil
	}

	transforms := strings.Split(pipeline, ",")
	result := make([]Transformer, 0, len(transforms))

	for _, name := range transforms {
		var t Transformer
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "aes":
			t = aes.NewEncrypter()
		case "base64-byte":
			t = b64.NewEncoder(b64.BYTE)
		case "base64-string":
			t = b64.NewEncoder(b64.STRING)
		case "hex-byte":
			t = hex.NewEncoder(hex.BYTE)
		case "hex-string":
			t = hex.NewEncoder(hex.STRING)
		case "gob-base":
			t = gob.NewEncoder(gob.BASE)
		case "gob-string":
			t = gob.NewEncoder(gob.STRING)
		case "jwe":
			t = jwe.NewEncrypter()
		case "rc4":
			t = rc4.NewEncrypter()
		case "xor":
			t = xor.NewEncrypter()
		case "json":
			t = jsonEncoder.NewEncoder()
		default:
			return nil, fmt.Errorf("transformer.BuildPipeline(): unhandled transform type: %s", name)
		}
		result = append(result, t)
	}

	return result, nil
}
