// This file is part of the go-ethereum library.
package types

import (
	"bytes"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate go run github.com/fjl/gencodec -type Withdrawal -field-override withdrawalMarshaling -out gen_withdrawal_json.go
//go:generate go run ../../rlp/rlpgen -type Withdrawal -out gen_withdrawal_rlp.go

// Withdrawal represents a validator withdrawal from the consensus layer.
type Withdrawal struct {
	Index     uint64         `json:"index"`          // monotonically increasing identifier issued by consensus layer
	Validator uint64         `json:"validatorIndex"` // index of validator associated with withdrawal
	Address   common.Address `json:"address"`        // target address for withdrawn ether
	Amount    uint64         `json:"amount"`         // value of withdrawal in Gwei
}

// field type overrides for gencodec
type withdrawalMarshaling struct {
	Index     hexutil.Uint64
	Validator hexutil.Uint64
	Amount    hexutil.Uint64
}

// Withdrawals implements DerivableList for withdrawals.
type Withdrawals []*Withdrawal

// Len returns the length of s.
func (s Withdrawals) Len() int { return len(s) }

var withdrawalSize = int(reflect.TypeOf(Withdrawal{}).Size())

func (s Withdrawals) Size() int {
	return withdrawalSize * len(s)
}

// EncodeIndex encodes the i'th withdrawal to w. Note that this does not check for errors
// because we assume that *Withdrawal will only ever contain valid withdrawals that were either
// constructed by decoding or via public API in this package.
func (s Withdrawals) EncodeIndex(i int, w *bytes.Buffer) {
	rlp.Encode(w, s[i])
}
