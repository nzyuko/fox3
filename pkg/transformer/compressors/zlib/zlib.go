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

// Package zlib provides Zlib (Deflate) compression/decompression for Agent messages
package zlib

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// Compressor implements the Transformer interface for Zlib compression
type Compressor struct{}

// NewCompressor is a factory that returns a structure that implements the Transformer interface
func NewCompressor() *Compressor {
	return &Compressor{}
}

// Construct takes in data, compresses it with Zlib, and returns the compressed data as bytes
func (c *Compressor) Construct(data any, key []byte) (retData []byte, err error) {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)

	switch v := data.(type) {
	case []byte:
		_, err = w.Write(v)
	case string:
		_, err = w.Write([]byte(v))
	default:
		return nil, fmt.Errorf("transformer/compressors/zlib.Construct(): unhandled concrete type %T", data)
	}

	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// Deconstruct takes in zlib-compressed bytes and decompresses it
func (c *Compressor) Deconstruct(data, key []byte) (any, error) {
	b := bytes.NewReader(data)
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// String returns the string representation of the transformer
func (c *Compressor) String() string {
	return "zlib"
}
