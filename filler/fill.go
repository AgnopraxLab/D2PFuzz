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

package filler

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

// Filler can be used to fill objects from a data source.
type Filler struct {
	data    []byte
	pointer int
	usedUp  bool
}

// NewFiller creates a new Filler.
func NewFiller(data []byte) *Filler {
	if len(data) == 0 {
		data = make([]byte, 1)
	}
	return &Filler{
		data:    data,
		pointer: 0,
		usedUp:  false,
	}
}

// incPointer increments the internal pointer
// to the next position to be read.
func (f *Filler) incPointer(i int) {
	if f.pointer+i >= len(f.data) {
		f.usedUp = true
	}
	f.pointer = (f.pointer + i) % len(f.data)
}

// Bool returns a new bool.
func (f *Filler) Bool() bool {
	b := f.Byte()
	return b > 127
}

// Byte returns a new byte.
func (f *Filler) Byte() byte {
	b := f.data[f.pointer]
	f.incPointer(1)
	return b
}

// Read implements the io.Reader interface.
func (f *Filler) Read(b []byte) (n int, err error) {
	// TODO (MariusVanDerWijden) this can be done more efficiently
	tmp := f.ByteSlice(len(b))
	for i := 0; i < len(b); i++ {
		b[i] = tmp[i]
	}
	return len(b), nil
}

// BigInt16 returns a new big int in [0, 2^16).
func (f *Filler) BigInt16() *big.Int {
	i := f.Uint16()
	return big.NewInt(int64(i))
}

// BigInt32 returns a new big int in [0, 2^32).
func (f *Filler) BigInt32() *big.Int {
	i := f.Uint32()
	return big.NewInt(int64(i))
}

// BigInt64 returns a new big int in [0, 2^64).
func (f *Filler) BigInt64() *big.Int {
	i := f.ByteSlice(8)
	return new(big.Int).SetBytes(i)
}

// BigInt256 returns a new big int in [0, 2^256).
func (f *Filler) BigInt256() *big.Int {
	i := f.ByteSlice(32)
	return new(big.Int).SetBytes(i)
}

// GasInt returns a new big int to be used as a gas value.
// With probability 254/255 its in [0, 20.000.000].
// With probability 1/255 its in [0, 2^32].
func (f *Filler) GasInt() *big.Int {
	b := f.Byte()
	if b == 253 {
		return f.BigInt32()
	} else if b == 254 {
		return f.BigInt64()
	} else if b == 255 {
		return f.BigInt256()
	}
	i := f.BigInt32()
	return i.Mod(i, big.NewInt(20000000))
}

// MemInt returns a new big int to be used as a memory or offset value.
// With probability 252/255 its in [0, 256].
// With probability 1/255 its in [0, 2^32].
// With probability 1/255 its in [0, 2^64].
// With probability 1/255 its in [0, 2^256].
func (f *Filler) MemInt() *big.Int {
	b := f.Byte()
	if b == 253 {
		return f.BigInt32()
	} else if b == 254 {
		return f.BigInt64()
	} else if b == 255 {
		return f.BigInt256()
	}
	return big.NewInt(int64(f.Byte()))
}

// ByteSlice returns a byteslice with `items` values.
func (f *Filler) ByteSlice(items int) []byte {
	// TODO (MariusVanDerWijden) this can be done way more efficiently
	b := make([]byte, items)
	if f.pointer+items < len(f.data) {
		copy(b, f.data[f.pointer:])
	} else {
		// Not enough data available
		for i := 0; i < items; {
			it := copy(b[i:], f.data[f.pointer:])
			if it == 0 {
				panic("should not happen, infinite loop")
			}
			i += it
			f.pointer = 0
		}
		f.usedUp = true
	}
	f.incPointer(items)
	return b
}

// ByteSlice256 returns a byteslice with 0..255 values.
func (f *Filler) ByteSlice256() []byte {
	return f.ByteSlice(int(f.Byte()))
}

// Uint16 returns a new uint16.
func (f *Filler) Uint16() uint16 {
	return binary.BigEndian.Uint16(f.ByteSlice(2))
}

// Uint32 returns a new uint32.
func (f *Filler) Uint32() uint32 {
	return binary.BigEndian.Uint32(f.ByteSlice(4))
}

// Uint64 returns a new uint64.
func (f *Filler) Uint64() uint64 {
	return binary.BigEndian.Uint64(f.ByteSlice(8))
}

// Reset resets a filler.
func (f *Filler) Reset() {
	f.pointer = 0
	f.usedUp = false
}

// UsedUp returns wether all bytes from the source have been used.
func (f *Filler) UsedUp() bool {
	return f.usedUp
}

// Filler addition

type Nonce [12]byte
type Pubkey [64]byte

// FillExpiration fills the expiration field with a random uint64 value.
func (f *Filler) FillExpiration() uint64 {
	return f.Uint64() // 随机生成一个 uint64 时间戳
}

// FillRest fills the Rest field with random RLP raw values.
func (f *Filler) FillRest() []rlp.RawValue {
	numValues := rand.Intn(10) // 随机生成 0-10 个 Rest 字段
	rest := make([]rlp.RawValue, numValues)
	for i := range rest {
		rest[i] = f.ByteSlice(32) // 随机填充 32 字节的值
	}
	return rest
}

// FillReplyToken generates a random reply token.
func (f *Filler) FillReplyToken() []byte {
	return f.ByteSlice(64) // 生成 64 字节的随机回复令牌
}

// FillPubkey fills the Pubkey field with a random 64-byte value.
func (f *Filler) FillPubkey() Pubkey {
	var pub Pubkey
	copy(pub[:], f.ByteSlice(64)) // 随机生成一个 64 字节的公钥
	return pub
}

// FillIP fills the IP field with a random IP address.
func (f *Filler) FillIP() net.IP {
	ipLength := 4 // 选择 IPv4 地址
	if rand.Intn(2) == 1 {
		ipLength = 16 // 50% 概率选择 IPv6 地址
	}
	return net.IP(f.ByteSlice(ipLength))
}

// FillPort generates a random port number.
func (f *Filler) FillPort() int {
	return rand.Intn(65535) // 随机生成端口号
}

// FillReqID generates a random request ID.
func (f *Filler) FillReqID() []byte {
	return f.ByteSlice(8) // 生成8字节的随机请求ID
}

// FillENRSeq generates a random ENR sequence number.
func (f *Filler) FillENRSeq() uint64 {
	return f.Uint64() // 随机生成一个uint64 ENR序列号
}

// FillNonce generates a random Nonce.
func (f *Filler) FillNonce() Nonce {
	var nonce Nonce
	copy(nonce[:], f.ByteSlice(12)) // 生成12字节的随机 Nonce
	return nonce
}

// FillChallengeData generates random challenge data.
func (f *Filler) FillChallengeData() []byte {
	return f.ByteSlice(32) // 生成32字节的随机挑战数据
}

// FillDistances generates random distances for Findnode.
func (f *Filler) FillDistances() []uint {
	return []uint{uint(rand.Uint32()), uint(rand.Uint32()), uint(rand.Uint32())} // 将uint32显式转换为uint
}

// FillMessage generates a random message.
func (f *Filler) FillMessage() []byte {
	return f.ByteSlice(64) // 生成64字节的随机消息
}

// FillENRRecords generates random ENR records.
func (f *Filler) FillENRRecords(count int) []*enr.Record {
	var records []*enr.Record
	for i := 0; i < count; i++ {
		key, _ := crypto.GenerateKey()
		var r enr.Record
		r.Set(enr.IP(f.FillIP()))
		r.Set(enr.UDP(f.FillPort()))
		r.Set(enr.TCP(f.FillPort()))
		r.Set(enode.Secp256k1(key.PublicKey))
		r.SetSeq(f.Uint64()) // 使用随机 ENR 序列号
		enode.SignV4(&r, key)
		records = append(records, &r)
	}
	return records
}

// FillNode generates a random node.
func (f *Filler) FillNode() *enode.Node {
	key, _ := crypto.GenerateKey()
	return enode.NewV4(&key.PublicKey, f.FillIP(), f.FillPort(), f.FillPort())
}

// Fill eth protocol addition

// FillProtocolVersion fills the ProtocolVersion field.
func (f *Filler) FillProtocolVersion() uint32 {
	return f.Uint32() // Random 32-bit unsigned integer
}

// FillNetworkID fills the NetworkID field.
func (f *Filler) FillNetworkID() uint64 {
	return f.Uint64() // Random 64-bit unsigned integer
}

// FillTD fills the TD (Total Difficulty) field.
func (f *Filler) FillTD() *big.Int {
	buf := make([]byte, 2024)
	_, err := rand.Read(buf)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
	}
	return new(big.Int).SetBytes(buf)
}

// FillHash fills a Hash field (32 bytes).
func (f *Filler) FillHash() [32]byte {
	var hash [32]byte
	copy(hash[:], f.ByteSlice(32))
	return hash
}

// FillForkID generates a new forkid.ID using random data from the filler.
func (f *Filler) FillForkID() forkid.ID {
	var hash [4]byte
	copy(hash[:], f.ByteSlice(4)) // Get 4 random bytes for the Hash field
	next := f.Uint64()            // Get a random uint64 for the Next field
	return forkid.ID{
		Hash: hash,
		Next: next,
	}
}

// FillRequestId generates a random request ID for network requests.
func (f *Filler) FillRequestId() uint64 {
	return f.Uint64()
}

// FillAmount generates a random amount for BlockHeader requests.
func (f *Filler) FillAmount() uint64 {
	return f.Uint64() % 100 // Arbitrary amount, can adjust as needed
}

// FillGasCap generates random gas cap values.
func (f *Filler) FillGasCap() *big.Int {
	return f.GasInt()
}

// FillTime generates a future timestamp as the expiration time.
func (f *Filler) FillTime() uint64 {
	return uint64(time.Now().Add(time.Duration(f.Uint64()%1000) * time.Second).Unix())
}
