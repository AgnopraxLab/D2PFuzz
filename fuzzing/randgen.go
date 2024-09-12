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

import (
	crand "crypto/rand"
	"math/rand"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// RandHex produces some random hex data
func RandHex(maxSize int) string {
	size := rand.Intn(maxSize)
	b := make([]byte, size)
	_, _ = crand.Read(b)
	return hexutil.Encode(b)
}

func RandBuff(size int) []byte {
	buf := make([]byte, size*1024)
	rand.Read(buf)
	return buf
}
