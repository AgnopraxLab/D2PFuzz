// Copyright 2024 Fudong and Hosen
// This file is part of the D2PFuzz library.
//
// The D2PFuzz library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The D2PFuzz library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the D2PFuzz library. If not, see <http://www.gnu.org/licenses/>.

package fuzzing

// byteSliceRemoveBytes removes a random chunk of bytes from b.
func byteSliceRemoveBytes(m *Mutator, b []byte) []byte {
	if len(b) <= 1 {
		return nil
	}
	pos0 := m.Rand(len(b))
	pos1 := pos0 + m.chooseLen(len(b)-pos0)
	copy(b[pos0:], b[pos1:])
	b = b[:len(b)-(pos1-pos0)]
	return b
}

// byteSliceInsertRandomBytes inserts a chunk of random bytes into b at a random
// position.
func byteSliceInsertRandomBytes(m *Mutator, b []byte) []byte {
	pos := m.Rand(len(b) + 1)
	n := m.chooseLen(1024)
	if len(b)+n >= cap(b) {
		return nil
	}
	b = b[:len(b)+n]
	copy(b[pos+n:], b[pos:])
	for i := 0; i < n; i++ {
		b[pos+i] = byte(m.Rand(256))
	}
	return b
}

// byteSliceDuplicateBytes duplicates a chunk of bytes in b and inserts it into
// a random position.
func byteSliceDuplicateBytes(m *Mutator, b []byte) []byte {
	if len(b) <= 1 {
		return nil
	}
	src := m.Rand(len(b))
	dst := m.Rand(len(b))
	for dst == src {
		dst = m.Rand(len(b))
	}
	n := m.chooseLen(len(b) - src)
	// Use the end of the slice as scratch space to avoid doing an
	// allocation. If the slice is too small abort and try something
	// else.
	if len(b)+(n*2) >= cap(b) {
		return nil
	}
	end := len(b)
	// Increase the size of b to fit the duplicated block as well as
	// some extra working space
	b = b[:end+(n*2)]
	// Copy the block of bytes we want to duplicate to the end of the
	// slice
	copy(b[end+n:], b[src:src+n])
	// Shift the bytes after the splice point n positions to the right
	// to make room for the new block
	copy(b[dst+n:end+n], b[dst:end])
	// Insert the duplicate block into the splice point
	copy(b[dst:], b[end+n:])
	b = b[:end+n]
	return b
}

// byteSliceOverwriteBytes overwrites a chunk of b with another chunk of b.
func byteSliceOverwriteBytes(m *Mutator, b []byte) []byte {
	if len(b) <= 1 {
		return nil
	}
	src := m.Rand(len(b))
	dst := m.Rand(len(b))
	for dst == src {
		dst = m.Rand(len(b))
	}
	n := m.chooseLen(len(b) - src - 1)
	copy(b[dst:], b[src:src+n])
	return b
}

// byteSliceBitFlip flips a random bit in a random byte in b.
func byteSliceBitFlip(m *Mutator, b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	pos := m.Rand(len(b))
	b[pos] ^= 1 << uint(m.Rand(8))
	return b
}

// byteSliceXORByte XORs a random byte in b with a random value.
func byteSliceXORByte(m *Mutator, b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	pos := m.Rand(len(b))
	// In order to avoid a no-op (where the random value matches
	// the existing value), use XOR instead of just setting to
	// the random value.
	b[pos] ^= byte(1 + m.Rand(255))
	return b
}

// byteSliceSwapByte swaps two random bytes in b.
func byteSliceSwapByte(m *Mutator, b []byte) []byte {
	if len(b) <= 1 {
		return nil
	}
	src := m.Rand(len(b))
	dst := m.Rand(len(b))
	for dst == src {
		dst = m.Rand(len(b))
	}
	b[src], b[dst] = b[dst], b[src]
	return b
}

// byteSliceArithmeticUint8 adds/subtracts from a random byte in b.
func byteSliceArithmeticUint8(m *Mutator, b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	pos := m.Rand(len(b))
	v := byte(m.Rand(35) + 1)
	if m.Bool() {
		b[pos] += v
	} else {
		b[pos] -= v
	}
	return b
}

// byteSliceArithmeticUint16 adds/subtracts from a random uint16 in b.
func byteSliceArithmeticUint16(m *Mutator, b []byte) []byte {
	if len(b) < 2 {
		return nil
	}
	v := uint16(m.Rand(35) + 1)
	if m.Bool() {
		v = 0 - v
	}
	pos := m.Rand(len(b) - 1)
	enc := m.randByteOrder()
	enc.PutUint16(b[pos:], enc.Uint16(b[pos:])+v)
	return b
}

// byteSliceArithmeticUint32 adds/subtracts from a random uint32 in b.
func byteSliceArithmeticUint32(m *Mutator, b []byte) []byte {
	if len(b) < 4 {
		return nil
	}
	v := uint32(m.Rand(35) + 1)
	if m.Bool() {
		v = 0 - v
	}
	pos := m.Rand(len(b) - 3)
	enc := m.randByteOrder()
	enc.PutUint32(b[pos:], enc.Uint32(b[pos:])+v)
	return b
}

// byteSliceArithmeticUint64 adds/subtracts from a random uint64 in b.
func byteSliceArithmeticUint64(m *Mutator, b []byte) []byte {
	if len(b) < 8 {
		return nil
	}
	v := uint64(m.Rand(35) + 1)
	if m.Bool() {
		v = 0 - v
	}
	pos := m.Rand(len(b) - 7)
	enc := m.randByteOrder()
	enc.PutUint64(b[pos:], enc.Uint64(b[pos:])+v)
	return b
}

// byteSliceOverwriteInterestingUint8 overwrites a random byte in b with an interesting
// value.
func byteSliceOverwriteInterestingUint8(m *Mutator, b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	pos := m.Rand(len(b))
	b[pos] = byte(interesting8[m.Rand(len(interesting8))])
	return b
}

// byteSliceOverwriteInterestingUint16 overwrites a random uint16 in b with an interesting
// value.
func byteSliceOverwriteInterestingUint16(m *Mutator, b []byte) []byte {
	if len(b) < 2 {
		return nil
	}
	pos := m.Rand(len(b) - 1)
	v := uint16(interesting16[m.Rand(len(interesting16))])
	m.randByteOrder().PutUint16(b[pos:], v)
	return b
}

// byteSliceOverwriteInterestingUint32 overwrites a random uint16 in b with an interesting
// value.
func byteSliceOverwriteInterestingUint32(m *Mutator, b []byte) []byte {
	if len(b) < 4 {
		return nil
	}
	pos := m.Rand(len(b) - 3)
	v := uint32(interesting32[m.Rand(len(interesting32))])
	m.randByteOrder().PutUint32(b[pos:], v)
	return b
}

// byteSliceInsertConstantBytes inserts a chunk of constant bytes into a random position in b.
func byteSliceInsertConstantBytes(m *Mutator, b []byte) []byte {
	if len(b) <= 1 {
		return nil
	}
	dst := m.Rand(len(b))
	// TODO(rolandshoemaker,katiehockman): 4096 was mainly picked
	// randomly. We may want to either pick a much larger value
	// (AFL uses 32768, paired with a similar impl to chooseLen
	// which biases towards smaller lengths that grow over time),
	// or set the max based on characteristics of the corpus
	// (libFuzzer sets a min/max based on the min/max size of
	// entries in the corpus and then picks uniformly from
	// that range).
	n := m.chooseLen(4096)
	if len(b)+n >= cap(b) {
		return nil
	}
	b = b[:len(b)+n]
	copy(b[dst+n:], b[dst:])
	rb := byte(m.Rand(256))
	for i := dst; i < dst+n; i++ {
		b[i] = rb
	}
	return b
}

// byteSliceOverwriteConstantBytes overwrites a chunk of b with constant bytes.
func byteSliceOverwriteConstantBytes(m *Mutator, b []byte) []byte {
	if len(b) <= 1 {
		return nil
	}
	dst := m.Rand(len(b))
	n := m.chooseLen(len(b) - dst)
	rb := byte(m.Rand(256))
	for i := dst; i < dst+n; i++ {
		b[i] = rb
	}
	return b
}

// byteSliceShuffleBytes shuffles a chunk of bytes in b.
func byteSliceShuffleBytes(m *Mutator, b []byte) []byte {
	if len(b) <= 1 {
		return nil
	}
	dst := m.Rand(len(b))
	n := m.chooseLen(len(b) - dst)
	if n <= 2 {
		return nil
	}
	// Start at the end of the range, and iterate backwards
	// to dst, swapping each element with another element in
	// dst:dst+n (Fisher-Yates shuffle).
	for i := n - 1; i > 0; i-- {
		j := m.Rand(i + 1)
		b[dst+i], b[dst+j] = b[dst+j], b[dst+i]
	}
	return b
}

// byteSliceSwapBytes swaps two chunks of bytes in b.
func byteSliceSwapBytes(m *Mutator, b []byte) []byte {
	if len(b) <= 1 {
		return nil
	}
	src := m.Rand(len(b))
	dst := m.Rand(len(b))
	for dst == src {
		dst = m.Rand(len(b))
	}
	// Choose the random length as len(b) - max(src, dst)
	// so that we don't attempt to swap a chunk that extends
	// beyond the end of the slice
	max := dst
	if src > max {
		max = src
	}
	n := m.chooseLen(len(b) - max - 1)
	// Check that neither chunk intersect, so that we don't end up
	// duplicating parts of the input, rather than swapping them
	if src > dst && dst+n >= src || dst > src && src+n >= dst {
		return nil
	}
	// Use the end of the slice as scratch space to avoid doing an
	// allocation. If the slice is too small abort and try something
	// else.
	if len(b)+n >= cap(b) {
		return nil
	}
	end := len(b)
	b = b[:end+n]
	copy(b[end:], b[dst:dst+n])
	copy(b[dst:], b[src:src+n])
	copy(b[src:], b[end:])
	b = b[:end]
	return b
}
