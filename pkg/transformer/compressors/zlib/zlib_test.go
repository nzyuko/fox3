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

package zlib

import (
	"bytes"
	"testing"
)

func TestZlibCompressor(t *testing.T) {
	compressor := NewCompressor()

	originalData := []byte("This is a test string that has some repeating repeating repeating data to compress")

	// Test Construct (Compression)
	compressed, err := compressor.Construct(originalData, nil)
	if err != nil {
		t.Fatalf("Construct failed: %v", err)
	}

	// Test Deconstruct (Decompression)
	decompressed, err := compressor.Deconstruct(compressed, nil)
	if err != nil {
		t.Fatalf("Deconstruct failed: %v", err)
	}

	decompressedBytes, ok := decompressed.([]byte)
	if !ok {
		t.Fatalf("Deconstruct returned incorrect type: %T", decompressed)
	}

	// Verify identity
	if !bytes.Equal(originalData, decompressedBytes) {
		t.Fatalf("Deconstructed data %s does not match original %s", string(decompressedBytes), string(originalData))
	}

	// Test interface string implementation
	if compressor.String() != "zlib" {
		t.Errorf("Expected string 'zlib', got '%s'", compressor.String())
	}
}
