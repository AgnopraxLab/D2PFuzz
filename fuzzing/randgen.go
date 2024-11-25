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
	"encoding/binary"
	"math"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

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

// RandBigInt returns a random big.Int value
func RandBigInt() *big.Int {
	n := new(big.Int)
	n.SetInt64(math.MaxInt64)
	randNum, _ := crand.Int(crand.Reader, n)
	return randNum
}

// RandBigIntRange returns a random big.Int value within the specified range [min, max]
func RandBigIntRange(min, max *big.Int) *big.Int {
	if min.Cmp(max) >= 0 {
		return min
	}

	// Calculate the range size
	diff := new(big.Int).Sub(max, min)
	diff.Add(diff, big.NewInt(1))

	// Generate a random number
	result, _ := crand.Int(crand.Reader, diff)
	return result.Add(result, min)
}

// RandBigIntN returns a random big.Int value in range [0, n)
func RandBigIntN(n *big.Int) *big.Int {
	if n.Sign() <= 0 {
		return big.NewInt(0)
	}
	result, _ := crand.Int(crand.Reader, n)
	return result
}

// RandInt64 returns a random int64 value
func RandInt64() int64 {
	return rand.Int63()
}

// RandUint64 returns a random uint64 value
func RandUint64() uint64 {
	buf := make([]byte, 8)
	_, _ = crand.Read(buf)
	return binary.BigEndian.Uint64(buf)
}

// RandInt32 returns a random int32 value
func RandInt32() int32 {
	return rand.Int31()
}

// RandUint32 returns a random uint32 value
func RandUint32() uint32 {
	return rand.Uint32()
}

// RandFloat64 returns a random float64 value (0.0 to 1.0)
func RandFloat64() float64 {
	return rand.Float64()
}

// RandFloat32 returns a random float32 value (0.0 to 1.0)
func RandFloat32() float32 {
	return rand.Float32()
}

// RandIntRange returns a random integer within the specified range [min, max]
func RandIntRange(min, max int) int {
	return rand.Intn(max-min+1) + min
}

// RandFloat64Range returns a random float64 within the specified range [min, max]
func RandFloat64Range(min, max float64) float64 {
	return min + rand.Float64()*(max-min)
}

// RandBool returns a random boolean value
func RandBool() bool {
	return rand.Intn(2) == 1
}

// RandString generates a random string of specified length
func RandString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
