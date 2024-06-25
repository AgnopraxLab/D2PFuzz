package fuzzing

import (
	crand "crypto/rand"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"math/rand"
)

// RandHex produces some random hex data
func RandHex(maxSize int) string {
	size := rand.Intn(maxSize)
	b := make([]byte, size)
	_, _ = crand.Read(b)
	return hexutil.Encode(b)
}
